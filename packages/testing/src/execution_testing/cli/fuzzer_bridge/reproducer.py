"""
The reproducer a client team runs with zero setup.

A minimized case with one transaction becomes a state test, checked to
still fail on the client (a divergence can depend on something only a
block carries, in which case the blockchain fixture stays the
reproducer), with a narrowing table in `_info.comment`: the case as found
and one-axis variations of it, each judged by the client. The table is
the first two stages of triage done by hand in the besu#11124 report --
pin everything, vary one thing, bisect the fork -- written down where the
reader of the fixture will see it.
"""

import contextlib
import io
import json
import tempfile
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from execution_testing.base_types import Bytes, HexNumber
from execution_testing.fixtures import StateFixture
from execution_testing.forks import Fork
from execution_testing.specs.invariants import InvariantViolationWarning

from .converter import state_test_from_fuzzer
from .models import FuzzerOutput
from .runners import FixtureRunner, StateTestsUnsupportedError

Judge = Callable[[Dict[str, Any]], Optional[bool]]
"""Whether the client fails a filled state test; None when it cannot say."""


def fill_state_test(
    case: FuzzerOutput, fork: Fork, eels: Any
) -> Dict[str, Any]:
    """Fill a single-transaction case into a state fixture's JSON."""
    test = state_test_from_fuzzer(case, fork)
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InvariantViolationWarning)
            result = test.generate(t8n=eels, fixture_format=StateFixture)
    return result.fixture.json_dict_with_info()


def client_judge(runner: FixtureRunner, name: str) -> Judge:
    """A judge that hands the fixture to the client's state-test runner."""

    def judge(fixture: Dict[str, Any]) -> Optional[bool]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reproducer.json"
            path.write_text(json.dumps({name: fixture}))
            try:
                verdict = runner.run_state_file(path, [name])[name]
            except StateTestsUnsupportedError:
                return None
        return not verdict.passed

    return judge


def previous_fork(fork: Fork) -> Optional[Fork]:
    """
    The nearest ancestor whose EVM differs.

    Blob-parameter-only forks sit between the named ones (Amsterdam's
    parent is BPO2) and change no execution rule, so a bisect that
    stopped there would say nothing.
    """
    parent = fork.parent()
    return parent.non_bpo_ancestor() if parent is not None else None


def variants(
    case: FuzzerOutput, fork: Fork
) -> Iterator[Tuple[str, FuzzerOutput, Fork]]:
    """
    The case as found, then one-axis variations of it.

    Each row changes exactly one thing from "as found", so a row that
    stops diverging names a necessary ingredient and a row that keeps
    diverging rules one out. The axes are the ones any single
    transaction has; the case-specific ones (which opcode, which target)
    are the minimizer's job.
    """
    yield "as found", case, fork
    parent = previous_fork(fork)
    if parent is not None:
        yield f"on {parent.name()}", case, parent
    (tx,) = case.transactions

    def variant(label: str, mutate: Callable[[Any], None]) -> Any:
        copy = case.model_copy(deep=True)
        mutate(copy.transactions[0])
        return label, copy, fork

    if int(tx.value):
        yield variant("value 0", lambda t: setattr(t, "value", HexNumber(0)))
    yield variant(
        "gas halved", lambda t: setattr(t, "gas", HexNumber(int(t.gas) // 2))
    )
    yield variant(
        "gas doubled", lambda t: setattr(t, "gas", HexNumber(int(t.gas) * 2))
    )
    if len(tx.data):
        yield variant("no calldata", lambda t: setattr(t, "data", Bytes(b"")))
    if tx.max_fee_per_gas is not None:

        def legacy(t: Any) -> None:
            t.gas_price = t.max_fee_per_gas
            t.max_fee_per_gas = None
            t.max_priority_fee_per_gas = None

        yield variant("legacy gas pricing", legacy)
    if tx.authorization_list:
        yield variant(
            "no authorizations",
            lambda t: setattr(t, "authorization_list", None),
        )


@dataclass(frozen=True)
class NarrowingRow:
    """One line of the narrowing table."""

    label: str
    result: str
    """`diverges`, `agrees`, `unfillable`, or `not judged`."""


def narrowing_table(
    case: FuzzerOutput, fork: Fork, eels: Any, judge: Judge
) -> List[NarrowingRow]:
    """Judge every variant; a fill failure is a row, not an error."""
    rows = []
    for label, variant_case, variant_fork in variants(case, fork):
        try:
            fixture = fill_state_test(variant_case, variant_fork, eels)
        except Exception:  # noqa: BLE001 - an unfillable variant is a result
            rows.append(NarrowingRow(label, "unfillable"))
            continue
        verdict = judge(fixture)
        if verdict is None:
            rows.append(NarrowingRow(label, "not judged"))
        else:
            rows.append(
                NarrowingRow(label, "diverges" if verdict else "agrees")
            )
    return rows


def render_table(rows: List[NarrowingRow]) -> str:
    """The table as it reads inside `_info.comment`."""
    width = max(len(row.label) for row in rows)
    lines = ["Narrowing: each row varies one thing from 'as found'."]
    lines += [f"  {row.label.ljust(width)}  {row.result}" for row in rows]
    return "\n".join(lines)


def write_reproducer(
    bundle: Path,
    case: FuzzerOutput,
    fork: Fork,
    eels: Any,
    judge: Judge,
    *,
    name: str = "reproducer",
) -> Optional[Path]:
    """
    Write `reproducer_state_test.json` and `reproducer.md` into a bundle.

    Returns the state test's path when the client still fails it, else
    None with `reproducer.md` saying why the blockchain fixture stays the
    reproducer: more than one transaction, an unfillable state test, or
    a divergence that does not survive the framing.
    """
    bundle.mkdir(parents=True, exist_ok=True)
    note = bundle / "reproducer.md"
    if len(case.transactions) != 1:
        note.write_text(
            f"The case has {len(case.transactions)} transactions; a state "
            "test carries one. The blockchain fixture is the reproducer.\n"
        )
        return None
    try:
        fixture = fill_state_test(case, fork, eels)
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        note.write_text(
            "The case does not fill as a state test "
            f"({type(exc).__name__}: {exc}). The blockchain fixture is the "
            "reproducer.\n"
        )
        return None
    survives = judge(fixture)
    if survives is False:
        note.write_text(
            "The client accepts the case as a state test and rejects it as "
            "a block: the divergence depends on something only the block "
            "carries (the access list hash, block-level gas accounting). "
            "The blockchain fixture is the reproducer.\n"
        )
        return None
    rows = (
        narrowing_table(case, fork, eels, judge)
        if survives
        else [NarrowingRow("as found", "not judged")]
    )
    table = render_table(rows)
    fixture["_info"]["comment"] = table
    path = bundle / "reproducer_state_test.json"
    path.write_text(json.dumps({name: fixture}, indent=1))
    note.write_text(
        f"State test: `{path.name}` (one transaction; "
        + (
            "the client still fails it).\n\n"
            if survives
            else "not judged: the client's state-test runner is not "
            "wired).\n\n"
        )
        + "```\n"
        + table
        + "\n```\n"
    )
    return path
