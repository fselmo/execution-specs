"""Properties of RLP encoding as used by the spec."""

from ethereum_rlp import Extended, rlp
from ethereum_types.bytes import Bytes
from hypothesis import given
from hypothesis import strategies as st

from .strategies import rlp_extended


@given(value=rlp_extended())
def test_decode_inverts_encode(value: Extended) -> None:
    """Decoding an encoding returns the original structure."""
    assert rlp.decode(rlp.encode(value)) == value


@given(byte=st.integers(min_value=0, max_value=0xFF))
def test_single_byte_encoding(byte: int) -> None:
    """
    A single byte below 0x80 is its own encoding; any other single byte is
    prefixed with 0x81.
    """
    encoded = rlp.encode(Bytes([byte]))
    if byte < 0x80:
        assert encoded == bytes([byte])
    else:
        assert encoded == bytes([0x81, byte])
