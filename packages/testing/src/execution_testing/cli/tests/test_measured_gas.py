"""Gas limits set from a transaction's measured need."""

import math
import random
from dataclasses import replace
from typing import Any, Dict

import pytest

from execution_testing.base_types import Address, Bytes, HexNumber
from execution_testing.forks import Amsterdam
from execution_testing.fuzzing import fork_domains

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.converter import (
    UnresolvedGasError,
    blockchain_test_from_fuzzer,
)
from ..fuzzer_bridge.generator import (
    FAILER_ADDRESS,
    failer_code,
    generate_fuzzer_output,
)
from ..fuzzer_bridge.measured_gas import _gas_used, resolve_measured_gas
from ..fuzzer_bridge.models import FuzzerAccountInput, FuzzerOutput


def _owned_failer_case(fraction: float) -> FuzzerOutput:
    """Case 0 with its first transaction sent to a reverting failer."""
    domains = replace(
        fork_domains(Amsterdam), failing_tx_outcome_shares=(("revert", 1.0),)
    )
    code, storage = failer_code(random.Random(0), domains)
    case = generate_fuzzer_output(Amsterdam, 0)
    accounts = dict(case.accounts)
    accounts[Address(FAILER_ADDRESS)] = FuzzerAccountInput(
        balance=HexNumber(0),
        nonce=HexNumber(1),
        code=Bytes(code),
        storage=storage,
    )
    transactions = list(case.transactions)
    transactions[0] = transactions[0].model_copy(
        update={"to": Address(FAILER_ADDRESS), "gas_need_fraction": fraction}
    )
    return case.model_copy(
        update={"accounts": accounts, "transactions": transactions}
    )


def _filler() -> Any:
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]

    def fill(case: FuzzerOutput) -> Dict[str, Any]:
        return mod.fill_case(case, fork, eels)

    return fill


def test_a_case_with_an_unmeasured_limit_is_refused() -> None:
    """A lane that skips the measurement fails instead of running `gas`."""
    with pytest.raises(UnresolvedGasError, match=r"\[0\]"):
        blockchain_test_from_fuzzer(_owned_failer_case(2.0), Amsterdam)


def test_the_limit_is_the_measured_need_times_the_fraction() -> None:
    """
    The need is what the transaction used with ample gas; the resolved
    limit is that times the drawn fraction, and with it the transaction
    ends as it did with ample gas, using the same gas.
    """
    fill = _filler()
    case = _owned_failer_case(2.0)
    resolved = resolve_measured_gas(case, Amsterdam, fill)
    tx = resolved.transactions[0]
    assert tx.gas_need_fraction is None

    fixture = fill(resolved)
    need = _gas_used(fixture, str(tx.from_), int(tx.nonce))
    assert int(tx.gas) == math.ceil(need * 2.0)
    (block, *_) = fixture["blocks"]
    assert not block["receipts"][0]["status"]


def test_a_fraction_below_the_need_is_refused_until_bounded() -> None:
    """
    Below 1 the limit can fall under the intrinsic cost; the out-of-gas
    variant has to bound it before such a fraction is drawn.
    """
    with pytest.raises(ValueError, match="below 1"):
        resolve_measured_gas(_owned_failer_case(0.5), Amsterdam, _filler())
