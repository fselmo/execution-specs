"""Test the rejection check of consume direct's fixture consumers."""

from typing import Any, Dict, List

import pytest

from execution_testing.client_clis.clis.geth import GethExceptionMapper
from execution_testing.client_clis.fixture_consumer_tool import (
    ExpectedRejection,
    RejectionReasonError,
    verify_rejections,
)
from execution_testing.exceptions import (
    BlockException,
    EngineAPIError,
    TransactionException,
)

MAPPER = GethExceptionMapper()
INTRINSIC_GAS_ERROR = (
    "could not apply tx 0 [0xf139]: intrinsic gas too low: "
    "have 21000, want 21001"
)
VALID_THEN_INTRINSIC_GAS = [None, TransactionException.INTRINSIC_GAS_TOO_LOW]


def result(*rejections: Dict[str, Any]) -> Dict[str, Any]:
    """Return a passing runner result with the given rejections."""
    return {"name": "test", "pass": True, "rejections": list(rejections)}


def test_matching_reason_passes() -> None:
    """A rejection whose error maps to the expected exception passes."""
    verify_rejections(
        VALID_THEN_INTRINSIC_GAS,
        result({"index": 1, "error": INTRINSIC_GAS_ERROR}),
        MAPPER,
    )


def test_wrong_reason_fails() -> None:
    """A rejection whose error maps to another exception fails."""
    with pytest.raises(RejectionReasonError) as e:
        verify_rejections(
            VALID_THEN_INTRINSIC_GAS,
            result({"index": 1, "error": "nonce too low"}),
            MAPPER,
        )
    assert "TransactionException.NONCE_MISMATCH_TOO_LOW" in str(e.value)
    assert "TransactionException.INTRINSIC_GAS_TOO_LOW" in str(e.value)


def test_unmapped_reason_fails_and_shows_the_raw_error() -> None:
    """An error the mapper does not know fails, naming error and mapper."""
    with pytest.raises(RejectionReasonError) as e:
        verify_rejections(
            VALID_THEN_INTRINSIC_GAS,
            result({"index": 1, "error": "some new client error"}),
            MAPPER,
        )
    message = str(e.value)
    assert "some new client error" in message
    assert "TransactionException.INTRINSIC_GAS_TOO_LOW" in message
    assert "GethExceptionMapper" in message


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(INTRINSIC_GAS_ERROR, id="first_alternative"),
        pytest.param("blob gas used mismatch", id="second_alternative"),
    ],
)
def test_any_expected_alternative_matches(error: str) -> None:
    """An error matching any of the `|`-joined exceptions passes."""
    expected: List[ExpectedRejection | None] = [
        [
            TransactionException.INTRINSIC_GAS_TOO_LOW,
            BlockException.INCORRECT_BLOB_GAS_USED,
        ]
    ]
    verify_rejections(expected, result({"index": 0, "error": error}), MAPPER)


def test_rejected_valid_block_fails() -> None:
    """A rejection of a block the fixture expects valid fails."""
    with pytest.raises(Exception, match="expects it to be valid") as e:
        verify_rejections(
            VALID_THEN_INTRINSIC_GAS,
            result(
                {"index": 0, "error": "nonce too low"},
                {"index": 1, "error": INTRINSIC_GAS_ERROR},
            ),
            MAPPER,
        )
    assert not isinstance(e.value, RejectionReasonError)


def test_invalid_block_without_rejection_fails() -> None:
    """An invalid block missing from the rejections fails."""
    with pytest.raises(Exception, match="reported no rejection") as e:
        verify_rejections(VALID_THEN_INTRINSIC_GAS, result(), MAPPER)
    assert not isinstance(e.value, RejectionReasonError)


def test_runner_without_rejections_is_skipped() -> None:
    """A result from a runner without the `rejections` field is skipped."""
    with pytest.warns(UserWarning, match="no `rejections` field"):
        verify_rejections(
            VALID_THEN_INTRINSIC_GAS, {"name": "test", "pass": True}, MAPPER
        )


def test_engine_json_rpc_error_with_expected_code_passes() -> None:
    """A payload expecting a JSON-RPC error is judged on its code alone."""
    verify_rejections(
        [None, EngineAPIError.InvalidParams],
        result({"index": 1, "error": "-32602: Invalid params: anything"}),
        MAPPER,
    )


@pytest.mark.parametrize(
    "error",
    [
        pytest.param("-38003: Invalid payload attributes", id="other_code"),
        pytest.param(INTRINSIC_GAS_ERROR, id="invalid_status"),
    ],
)
def test_engine_json_rpc_error_with_other_outcome_fails(error: str) -> None:
    """A payload expecting a JSON-RPC error fails on any other rejection."""
    with pytest.raises(RejectionReasonError, match="JSON-RPC error -32602"):
        verify_rejections(
            [None, EngineAPIError.InvalidParams],
            result({"index": 1, "error": error}),
            MAPPER,
        )


def test_engine_json_rpc_error_for_an_invalid_payload_fails() -> None:
    """A payload expecting an exception must not get a JSON-RPC error."""
    with pytest.raises(RejectionReasonError, match="instead of an invalid"):
        verify_rejections(
            VALID_THEN_INTRINSIC_GAS,
            result({"index": 1, "error": "-32602: " + INTRINSIC_GAS_ERROR}),
            MAPPER,
        )
