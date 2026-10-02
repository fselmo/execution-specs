"""Properties of the fixed-width numeric types the spec relies on."""

from ethereum_types.numeric import U256
from hypothesis import given

from .strategies import u256s

U256_MODULUS = 1 << 256


@given(value=u256s())
def test_be_bytes_roundtrip(value: U256) -> None:
    """Big-endian byte conversion round-trips."""
    assert U256.from_be_bytes(value.to_be_bytes32()) == value
    assert len(value.to_be_bytes32()) == 32


@given(a=u256s(), b=u256s())
def test_wrapping_add_matches_modular_arithmetic(a: U256, b: U256) -> None:
    """Wrapping addition is addition modulo 2**256."""
    assert int(a.wrapping_add(b)) == (int(a) + int(b)) % U256_MODULUS


@given(a=u256s(), b=u256s())
def test_wrapping_sub_matches_modular_arithmetic(a: U256, b: U256) -> None:
    """Wrapping subtraction is subtraction modulo 2**256."""
    assert int(a.wrapping_sub(b)) == (int(a) - int(b)) % U256_MODULUS


@given(a=u256s(), b=u256s())
def test_wrapping_mul_matches_modular_arithmetic(a: U256, b: U256) -> None:
    """Wrapping multiplication is multiplication modulo 2**256."""
    assert int(a.wrapping_mul(b)) == (int(a) * int(b)) % U256_MODULUS


@given(a=u256s(), b=u256s())
def test_add_sub_cancel(a: U256, b: U256) -> None:
    """Adding then subtracting the same value is the identity."""
    assert a.wrapping_add(b).wrapping_sub(b) == a


@given(value=u256s())
def test_signed_roundtrip(value: U256) -> None:
    """Signed reinterpretation round-trips."""
    assert U256.from_signed(value.to_signed()) == value
