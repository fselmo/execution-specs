"""evmone's rejection strings, old messages and new exception names."""

import pytest

from execution_testing.client_clis.clis.evmone import EvmoneExceptionMapper
from execution_testing.exceptions import TransactionException


@pytest.mark.parametrize(
    "message,exception",
    [
        pytest.param(
            "TransactionException.GAS_ALLOWANCE_EXCEEDED",
            TransactionException.GAS_ALLOWANCE_EXCEEDED,
            id="named_gas_allowance",
        ),
        pytest.param(
            "TransactionException.NONCE_IS_MAX",
            TransactionException.NONCE_IS_MAX,
            id="named_nonce_is_max",
        ),
        pytest.param(
            "gas limit reached",
            TransactionException.GAS_ALLOWANCE_EXCEEDED,
            id="older_message",
        ),
    ],
)
def test_evmone_rejections_map_by_name_or_by_message(
    message: str, exception: TransactionException
) -> None:
    """
    The Amsterdam evmone t8n reports an exception by its name; older builds
    by a message. Both map, and nothing else does.
    """
    assert EvmoneExceptionMapper().message_to_exception(message) == [exception]


def test_a_name_does_not_match_inside_a_longer_one() -> None:
    """GAS_ALLOWANCE_EXCEEDED is not the blob-gas allowance it ends."""
    found = EvmoneExceptionMapper().message_to_exception(
        "TransactionException.TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED"
    )
    assert TransactionException.GAS_ALLOWANCE_EXCEEDED not in found
