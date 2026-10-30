"""Besu's block output rejections, with and without the failing rule."""

import pytest

from execution_testing.client_clis.clis.besu import BesuExceptionMapper
from execution_testing.exceptions import BlockException

BLOCK_HASH = (
    "0x5993bc1d7a44c4ad4cea179f27cd1f7f72291d538ebe7f1524c2e5811e80e862"
)
GAS_USED_MISMATCH = (
    f"Invalid block 1 ({BLOCK_HASH}): gas used mismatch "
    "(header=29971882, receipts=29951498, blockGas=29102842)"
)
OUTPUT_REJECTED = "failed to validate output of imported block"


@pytest.mark.parametrize(
    "message",
    [
        pytest.param(
            f"{OUTPUT_REJECTED} [{GAS_USED_MISMATCH}]", id="runner_rejection"
        ),
        pytest.param(GAS_USED_MISMATCH, id="log_line"),
    ],
)
def test_gas_used_mismatch_is_not_the_bloom_or_receipts(message: str) -> None:
    """A header gas used besu rejects maps to that, and only that."""
    found = BesuExceptionMapper().message_to_exception(message)
    assert found == [BlockException.INVALID_GAS_USED]


@pytest.mark.parametrize(
    "message",
    [
        pytest.param(OUTPUT_REJECTED, id="without_the_rule"),
        pytest.param(
            f"{OUTPUT_REJECTED} [Invalid block 1 ({BLOCK_HASH}): logs bloom "
            "filter mismatch (expected=0x00, actual=0x01)]",
            id="bloom_rule",
        ),
    ],
)
def test_other_output_rejections_still_read_as_bloom_or_receipts(
    message: str,
) -> None:
    """Without a gas used rule, the output check means bloom or receipts."""
    found = BesuExceptionMapper().message_to_exception(message)
    assert BlockException.INVALID_LOG_BLOOM in found
    assert BlockException.INVALID_RECEIPTS_ROOT in found
    assert BlockException.INVALID_GAS_USED not in found
