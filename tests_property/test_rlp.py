"""Properties of RLP encoding as used by the spec."""

from ethereum_rlp import Extended, rlp
from hypothesis import given

from .strategies import rlp_extended


@given(value=rlp_extended())
def test_decode_inverts_encode(value: Extended) -> None:
    """Decoding an encoding returns the original structure."""
    assert rlp.decode(rlp.encode(value)) == value


@given(value=rlp_extended())
def test_encode_is_deterministic(value: Extended) -> None:
    """Encoding the same value twice yields identical bytes."""
    assert rlp.encode(value) == rlp.encode(value)


@given(value=rlp_extended())
def test_single_small_byte_encodes_as_itself(value: Extended) -> None:
    """A single byte below 0x80 is its own RLP encoding."""
    encoded = rlp.encode(value)
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 1 and value[0] < 0x80:
            assert encoded == bytes(value)
        else:
            assert len(encoded) > len(value) or encoded == bytes(value)
