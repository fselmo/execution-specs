"""
Ethereum Virtual Machine (EVM) POINT EVALUATION PRECOMPILED CONTRACT
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. contents:: Table of Contents
    :backlinks: none
    :local:

Introduction
------------

Implementation of the POINT EVALUATION precompiled contract.
"""

import hashlib
import os

from ckzg import (
    load_trusted_setup,
    verify_kzg_proof,
)

from ..gas import GAS_POINT_EVALUATION, charge_gas
from ...vm import Evm
from ...vm.exceptions import KZGProofError

FIELD_ELEMENTS_PER_BLOB = 4096
BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513  # noqa: E501
VERSIONED_HASH_VERSION_KZG = b"\x01"

# load path from ../_utils/kzg_trusted_setup.txt
TRUSTED_SETUP_PATH = os.path.join(
    os.path.dirname(__file__), "..", "_utils", "kzg_trusted_setup.txt"
)


def kzg_to_versioned_hash(commitment: bytes) -> bytes:
    return VERSIONED_HASH_VERSION_KZG + hashlib.sha256(commitment).digest()[1:]


def point_evaluation(evm: Evm) -> None:
    """
    A pre-compile that verifies a KZG proof which claims that a blob
    (represented by a commitment) evaluates to a given value at a given point.

    Parameters
    ----------
    evm :
        The current EVM frame.

    """
    charge_gas(evm, GAS_POINT_EVALUATION)

    data = evm.message.data
    if len(data) != 192:
        raise KZGProofError

    versioned_hash = data[:32]
    z = data[32:64]
    y = data[64:96]
    commitment = data[96:144]
    proof = data[144:192]


    # Verify commitment matches versioned_hash
    if kzg_to_versioned_hash(commitment) != versioned_hash:
        raise KZGProofError

    # Verify KZG proof with z and y in big endian format
    try:
        assert verify_kzg_proof(
            commitment, z, y, proof, load_trusted_setup(TRUSTED_SETUP_PATH)
        )
    except (AssertionError, RuntimeError) as e:
        raise KZGProofError from e

    # Return FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS as padded 32 byte big endian values
    evm.output = FIELD_ELEMENTS_PER_BLOB.to_bytes(
        32, "big"
    ) + BLS_MODULUS.to_bytes(32, "big")
