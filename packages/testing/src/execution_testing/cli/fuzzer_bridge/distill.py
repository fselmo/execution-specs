"""
Distill a fuzzer corpus case into a readable, reviewable spec test.

A corpus case (``FuzzerOutput`` JSON produced by ``fuzz`` or
``fuzz diff``) is a minimized, reproducible input that triggered
something interesting. Distillation turns it into a ``BlockchainTestFiller``
Python module — explicit accounts, transactions, and a provenance docstring —
that a maintainer reviews and lands as a normal test. That is how a transient
finding becomes a permanent, industry-wide regression fixture.

The rendering is deliberately faithful (exact addresses, keys, code, values)
rather than idiomatic, because the distilled test must reproduce the original
execution. ``post`` is left empty for the reviewer to fill in.
"""

from typing import Any, Dict, List

from execution_testing.cli.gentest.source_code_generator import (
    get_test_source,
)
from execution_testing.cli.gentest.test_context_providers import Provider

from .models import FuzzerAccountInput, FuzzerOutput, FuzzerTransactionInput

_TEMPLATE = "blockchain_test/fuzz_case.py.j2"


def _account_expr(account: FuzzerAccountInput) -> str:
    parts = [f"balance={int(account.balance)}"]
    if int(account.nonce) != 0:
        parts.append(f"nonce={int(account.nonce)}")
    if account.code:
        parts.append(f'code=Bytes("{bytes(account.code).hex()}")')
    if account.storage:
        items = ", ".join(
            f"{int(k)}: {int(v)}" for k, v in account.storage.items()
        )
        parts.append(f"storage={{{items}}}")
    return f"Account({', '.join(parts)})"


def _transaction_expr(
    tx: FuzzerTransactionInput, sender_var: str, to_expr: str
) -> str:
    parts = [
        f"sender={sender_var}",
        f"to={to_expr}",
        f"gas_limit={int(tx.gas)}",
        f"nonce={int(tx.nonce)}",
        f"value={int(tx.value)}",
    ]
    if tx.gas_price is not None:
        parts.append(f"gas_price={int(tx.gas_price)}")
    if tx.data:
        parts.append(f'data=Bytes("{bytes(tx.data).hex()}")')
    return f"Transaction({', '.join(parts)})"


class FuzzerDistillProvider(Provider):
    """Build the context for rendering a distilled fuzzer test."""

    case: FuzzerOutput
    fork_name: str
    reason: str
    seed: int | None = None
    generator_version: int | None = None

    model_config = {"arbitrary_types_allowed": True}

    def _sender_vars(self) -> Dict[str, str]:
        """Map each sender address (hex) to a stable local variable name."""
        mapping: Dict[str, str] = {}
        index = 0
        for address, account in self.case.accounts.items():
            if account.private_key is not None:
                mapping[str(address)] = f"sender_{index}"
                index += 1
        return mapping

    def _docstring(self) -> str:
        lines = [
            "Distilled from a fuzzer finding.",
            "",
            f"Fork: {self.fork_name}",
        ]
        if self.generator_version is not None:
            lines.append(f"Generator version: {self.generator_version}")
        if self.seed is not None:
            lines.append(f"Seed: {self.seed}")
        lines.append(f"Reason: {self.reason}")
        return "\n".join(lines)

    def get_context(self) -> Dict[str, Any]:
        """Return the template context for the distilled test."""
        sender_vars = self._sender_vars()

        senders: List[Dict[str, str]] = []
        pre_entries: List[str] = []
        for address, account in self.case.accounts.items():
            key = str(address)
            if key in sender_vars:
                var = sender_vars[key]
                assert account.private_key is not None
                senders.append(
                    {
                        "var": var,
                        "key": f"0x{bytes(account.private_key).hex()}",
                    }
                )
                pre_entries.append(f"{var}: {_account_expr(account)}")
            else:
                pre_entries.append(
                    f'Address("{key}"): {_account_expr(account)}'
                )

        tx_entries: List[str] = []
        for tx in self.case.transactions:
            sender_var = sender_vars[str(tx.from_)]
            if tx.to is None:
                to_expr = "None"
            elif str(tx.to) in sender_vars:
                to_expr = sender_vars[str(tx.to)]
            else:
                to_expr = f'Address("{tx.to}")'
            tx_entries.append(_transaction_expr(tx, sender_var, to_expr))

        return {
            "docstring": self._docstring(),
            "reason": self.reason,
            "test_name": f"fuzz_{self.fork_name.lower()}_seed{self.seed}",
            "fork_name": self.fork_name,
            "senders": senders,
            "pre_entries": pre_entries,
            "tx_entries": tx_entries,
        }


def distill_source(
    case: FuzzerOutput,
    *,
    fork_name: str,
    reason: str,
    seed: int | None = None,
    generator_version: int | None = None,
) -> str:
    """Render a distilled ``BlockchainTestFiller`` module from ``case``."""
    provider = FuzzerDistillProvider(
        case=case,
        fork_name=fork_name,
        reason=reason,
        seed=seed,
        generator_version=generator_version,
    )
    return get_test_source(provider=provider, template_path=_TEMPLATE)
