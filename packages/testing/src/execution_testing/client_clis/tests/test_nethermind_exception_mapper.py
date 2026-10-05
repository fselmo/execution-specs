"""Nethermind's RLP integer length error, on block import and the engine."""

import pytest

from execution_testing.client_clis.clis.nethermind import (
    NethermindExceptionMapper,
)
from execution_testing.exceptions import BlockException

INTEGER_LENGTH = "Unexpected length of integer value 32 at position 539"


def test_block_import_integer_length_error_reads_as_both() -> None:
    """Bare, the error may come from a header or a transaction."""
    found = NethermindExceptionMapper().message_to_exception(INTEGER_LENGTH)
    assert BlockException.INCORRECT_BLOCK_FORMAT in found
    assert BlockException.RLP_STRUCTURES_ENCODING in found


@pytest.mark.parametrize("index", [0, 5])
def test_engine_transaction_integer_length_error_is_not_the_header(
    index: int,
) -> None:
    """A transaction's error is never read as a malformed header."""
    message = f"Transaction {index} is not valid: {INTEGER_LENGTH}"
    found = NethermindExceptionMapper().message_to_exception(message)
    assert BlockException.RLP_STRUCTURES_ENCODING in found
    assert BlockException.INCORRECT_BLOCK_FORMAT not in found
