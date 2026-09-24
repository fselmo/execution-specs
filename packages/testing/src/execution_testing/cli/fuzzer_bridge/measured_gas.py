"""
Gas limits derived from a measured need, for the transactions a shape owns.

A shape that declares how a transaction ends -- that it reaches the end of
its code, or runs out of gas partway -- cannot draw the gas limit that makes
it so: what the transaction needs depends on what it executes, and that is
known only by running it. So the shape draws a fraction, and the limit is
the transaction's measured need times that fraction: the case is filled
once with the transaction given ample gas, the gas its receipt shows used is
the need, and the limit is set from it. The fraction is the draw; the limit
is derived, recomputed on every replay, and never recorded as a draw.

Only owned transactions are measured. Deriving every limit would collapse
the random under- and over-provisioning that produces incidental outcomes
everywhere else to one value.
"""

import contextlib
import io
import math
import warnings
from typing import Any, Callable, Dict

from execution_testing.base_types import HexNumber
from execution_testing.fixtures import BlockchainFixture
from execution_testing.forks import Fork
from execution_testing.specs.invariants import InvariantViolationWarning

from .converter import blockchain_test_from_fuzzer
from .models import FuzzerOutput

Filler = Callable[[FuzzerOutput], Dict[str, Any]]
"""Fill a resolved case into a blockchain fixture's JSON."""


def fixture_filler(fork: Fork, t8n: Any) -> Filler:
    """A filler for a lane that holds a transition tool but no fill."""

    def fill(case: FuzzerOutput) -> Dict[str, Any]:
        test = blockchain_test_from_fuzzer(case, fork)
        with contextlib.redirect_stdout(io.StringIO()):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InvariantViolationWarning)
                result = test.generate(
                    t8n=t8n, fixture_format=BlockchainFixture
                )
        return result.fixture.json_dict_with_info()

    return fill


def _gas_used(fixture: Dict[str, Any], sender: str, nonce: int) -> int:
    """The gas a transaction's receipt shows used, by sender and nonce."""
    for block in fixture["blocks"]:
        previous = 0
        for tx, receipt in zip(
            block["transactions"], block["receipts"], strict=True
        ):
            cumulative = int(receipt["cumulativeGasUsed"], 16)
            if (
                tx["sender"].lower() == sender.lower()
                and int(tx["nonce"], 16) == nonce
            ):
                return cumulative - previous
            previous = cumulative
    raise LookupError(f"transaction {sender}/{nonce} is not in the fixture")


def resolve_measured_gas(
    case: FuzzerOutput, fork: Fork, fill: Filler
) -> FuzzerOutput:
    """
    Set each owned transaction's gas limit from its measured need.

    Owned transactions are resolved in order, each measured in the context
    of the ones before it already resolved: a lower limit can make an
    earlier transaction fail, and a later one then runs on different
    state. A later owned transaction keeps its drawn gas while an earlier
    one is measured; it cannot affect the earlier one's need. A case that
    cannot be filled for measurement raises, as its fill would: running
    the drawn gas instead would turn an owned transaction into an ordinary
    one without a trace.
    """
    if all(tx.gas_need_fraction is None for tx in case.transactions):
        return case
    cap = fork.transaction_gas_limit_cap() or int(case.env.gas_limit)
    transactions = list(case.transactions)
    for index, tx in enumerate(transactions):
        fraction = tx.gas_need_fraction
        if fraction is None:
            continue
        if fraction < 1:
            # Below the need the limit can also fall below the intrinsic
            # cost, which the out-of-gas variant must bound first.
            raise ValueError(f"gas need fraction {fraction} below 1")
        others = sum(
            int(other.gas)
            for position, other in enumerate(transactions)
            if position != index and other.block == tx.block
        )
        ample = min(cap, int(case.env.gas_limit) - others)
        probe = list(transactions)
        probe[index] = tx.model_copy(
            update={"gas": HexNumber(ample), "gas_need_fraction": None}
        )
        for later in range(index + 1, len(probe)):
            probe[later] = probe[later].model_copy(
                update={"gas_need_fraction": None}
            )
        fixture = fill(case.model_copy(update={"transactions": probe}))
        need = _gas_used(fixture, str(tx.from_), int(tx.nonce))
        gas = min(ample, math.ceil(need * fraction))
        transactions[index] = tx.model_copy(
            update={"gas": HexNumber(gas), "gas_need_fraction": None}
        )
    return case.model_copy(update={"transactions": transactions})
