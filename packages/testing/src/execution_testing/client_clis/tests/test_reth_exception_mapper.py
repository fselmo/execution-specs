"""Reth's errors for a header field present before its fork."""

import pytest

from execution_testing.client_clis.clis.reth import RethExceptionMapper
from execution_testing.exceptions import BlockException

CONSENSUS = "an error occurred during consensus checks: "


@pytest.mark.parametrize(
    "error",
    [
        pytest.param("unexpected block access list hash", id="bal_hash"),
        pytest.param("unexpected blob gas used", id="blob_gas_used"),
    ],
)
def test_pre_fork_header_field_is_a_format_error(error: str) -> None:
    """A field the fork does not have yet is an incorrect block format."""
    found = RethExceptionMapper().message_to_exception(CONSENSUS + error)
    assert BlockException.INCORRECT_BLOCK_FORMAT in found
