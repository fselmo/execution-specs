from functools import partial

import pytest
from ethereum_rlp import rlp

from ethereum.exceptions import InvalidTransaction
from ethereum.london.transactions import (
    LegacyTransaction,
    validate_transaction,
)
from ethereum.utils.hexadecimal import hex_to_uint
from tests.helpers import TEST_FIXTURES

from ..helpers.fork_types_helpers import load_test_transaction

ETHEREUM_TESTS_PATH = TEST_FIXTURES["ethereum_tests"]["fixture_path"]

test_dir = f"{ETHEREUM_TESTS_PATH}/TransactionTests"

load_london_transaction = partial(load_test_transaction, network="London")


@pytest.mark.parametrize(
    "test_file_high_nonce",
    [
        "ttNonce/TransactionWithHighNonce64Minus1.json",
        "ttNonce/TransactionWithHighNonce64.json",
        "ttNonce/TransactionWithHighNonce64Plus1.json",
    ],
)
def test_high_nonce(test_file_high_nonce: str) -> None:
    test = load_london_transaction(test_dir, test_file_high_nonce)

    tx = rlp.decode_to(LegacyTransaction, test["tx_rlp"])

    with pytest.raises(InvalidTransaction):
        validate_transaction(tx)


@pytest.mark.parametrize(
    "test_file_nonce",
    [
        "ttNonce/TransactionWithHighNonce32.json",
        "ttNonce/TransactionWithHighNonce64Minus2.json",
    ],
)
def test_nonce(test_file_nonce: str) -> None:
    test = load_london_transaction(test_dir, test_file_nonce)

    tx = rlp.decode_to(LegacyTransaction, test["tx_rlp"])

    result_intrinsic_gas_cost = hex_to_uint(
        test["test_result"]["intrinsicGas"]
    )

    intrinsic_gas = validate_transaction(tx)
    assert intrinsic_gas == result_intrinsic_gas_cost
