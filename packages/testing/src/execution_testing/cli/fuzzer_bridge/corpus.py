"""
Corpus persistence and delta-debugging minimization for fuzzer cases.

A "case" is a ``FuzzerOutput``. When a case is interesting (an invariant
violation, a crash, or later a cross-client divergence), it is minimized to
the smallest still-interesting case and saved to a corpus directory as plain
JSON — already the native input format of the fuzzer bridge, so existing
tooling consumes it unchanged.

Minimization is delta-debugging (ddmin) over the case's structure:
transactions and non-sender accounts are dropped, and contract code is
truncated, keeping only reductions that preserve a caller-supplied
"still interesting" predicate.
"""

import json
from pathlib import Path
from typing import Callable, List, Set

from execution_testing.base_types import Address, Bytes

from .models import FuzzerOutput

Predicate = Callable[[FuzzerOutput], bool]


def _without_transaction(case: FuzzerOutput, index: int) -> FuzzerOutput:
    txs = list(case.transactions)
    del txs[index]
    return case.model_copy(update={"transactions": txs})


def _without_account(case: FuzzerOutput, address: Address) -> FuzzerOutput:
    accounts = dict(case.accounts)
    del accounts[address]
    return case.model_copy(update={"accounts": accounts})


def _sender_addresses(case: FuzzerOutput) -> Set[Address]:
    return {tx.from_ for tx in case.transactions} | {
        tx.to for tx in case.transactions if tx.to is not None
    }


def _truncate_code(
    case: FuzzerOutput, address: Address, length: int
) -> FuzzerOutput:
    accounts = dict(case.accounts)
    truncated = Bytes(bytes(accounts[address].code)[:length])
    accounts[address] = accounts[address].model_copy(
        update={"code": truncated}
    )
    return case.model_copy(update={"accounts": accounts})


def minimize(case: FuzzerOutput, still_interesting: Predicate) -> FuzzerOutput:
    """
    Reduce ``case`` to a locally minimal case that keeps the predicate true.

    The predicate must already be true for ``case``. Reductions that break it
    are discarded, so the result is at least as interesting as the input.
    """
    assert still_interesting(case), "predicate must hold for the input case"

    changed = True
    while changed:
        changed = False

        # Drop transactions from the end so earlier indices stay valid.
        for index in reversed(range(len(case.transactions))):
            candidate = _without_transaction(case, index)
            if still_interesting(candidate):
                case = candidate
                changed = True

        # Drop accounts that no transaction references.
        referenced = _sender_addresses(case)
        for address in list(case.accounts):
            if address in referenced:
                continue
            candidate = _without_account(case, address)
            if still_interesting(candidate):
                case = candidate
                changed = True

        # Truncate contract code by halves.
        for address, account in list(case.accounts.items()):
            code_len = len(bytes(account.code))
            if code_len == 0:
                continue
            target = code_len // 2
            while target < code_len:
                candidate = _truncate_code(case, address, target)
                if still_interesting(candidate):
                    case = candidate
                    changed = True
                    break
                target = (target + code_len + 1) // 2
                if target >= code_len:
                    break

    return case


def save_case(case: FuzzerOutput, path: Path) -> Path:
    """Write a case to ``path`` as JSON (the fuzzer bridge's input format)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        case.model_dump_json(indent=2, by_alias=True, exclude_none=True)
    )
    return path


def load_case(path: Path) -> FuzzerOutput:
    """Load a case previously written by :func:`save_case`."""
    return FuzzerOutput(**json.loads(path.read_text()))


def load_corpus(directory: Path) -> List[FuzzerOutput]:
    """Load every ``*.json`` case in ``directory``."""
    return [load_case(path) for path in sorted(directory.rglob("*.json"))]
