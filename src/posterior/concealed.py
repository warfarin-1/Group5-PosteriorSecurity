"""Concealed Boneh-Boyen signatures: Convert, CVerify and Decom.

All calls use explicit public parameters, including the same trusted CRS.
Convert returns (public signature, private opening t), or None (paper's bottom).
Decom checks only the opening; acceptance of a revealed signed message requires
both cverify(cs, vk, params) and decom(message, cs, t, params).
Messages/openings are canonical integers in [0, ORDER), never silently reduced.
"""

import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

from posterior import boneh_boyen as bb
from posterior import commit_g2, zk_proof
from posterior.cs_params import PublicParameters
from posterior.pairing import ORDER, ZERO_G2, is_valid_g1, is_valid_g2, points_equal

_INPUT_ERRORS = (TypeError, ValueError, AttributeError, IndexError, KeyError, OverflowError, ZeroDivisionError)


@dataclass(frozen=True)
class ConcealedSignature:
    proof: zk_proof.Proof
    C: tuple


def _scalar(value) -> bool:
    return type(value) is int and 0 <= value < ORDER


def _random_opening() -> int:
    return secrets.randbelow(ORDER)


def _valid_key(vk) -> bool:
    return isinstance(vk, bb.VerifyKey) and all(
        is_valid_g2(p) and not points_equal(p, ZERO_G2) for p in (vk.X, vk.Y)
    )


def convert(
    signature: bb.Signature, message: int, vk: bb.VerifyKey, params: PublicParameters
) -> Optional[Tuple[ConcealedSignature, int]]:
    """Validate the original signature before constructing its concealed form.

    Fresh uniform t includes zero, as required by perfect Pedersen hiding.
    Keep the second return value private until the message is revealed.
    """
    try:
        if not (
            _scalar(message) and isinstance(signature, bb.Signature)
            and _scalar(signature.r) and is_valid_g1(signature.s)
            and _valid_key(vk) and params.is_valid()
            and bb.verify(signature, message, vk)
        ):
            return None
    except _INPUT_ERRORS:
        return None
    t = _random_opening()
    C = commit_g2.commit(message, t, params.h2).point
    proof = zk_proof.prove(
        signature.s, t, signature.r, X=vk.X, Y=vk.Y, C=C,
        h2=params.h2, crs=params.crs,
    )
    return ConcealedSignature(proof=proof, C=C), t


def cverify(cs: ConcealedSignature, vk: bb.VerifyKey, params: PublicParameters) -> bool:
    """Verify the public concealed signature without a message or opening."""
    from posterior.serialization import validate_proof_shape

    try:
        if not (
            isinstance(cs, ConcealedSignature) and _valid_key(vk)
            and params.is_valid() and is_valid_g2(cs.C)
        ):
            return False
        validate_proof_shape(cs.proof)
        return zk_proof.verify(
            cs.proof, X=vk.X, Y=vk.Y, C=cs.C, h2=params.h2, crs=params.crs,
        )
    except _INPUT_ERRORS:
        return False


def decom(message: int, cs: ConcealedSignature, aux: int, params: PublicParameters) -> bool:
    """Check an opening (not the GS proof); combine with cverify for acceptance."""
    try:
        return (
            _scalar(message) and _scalar(aux) and isinstance(cs, ConcealedSignature)
            and params.is_valid() and is_valid_g2(cs.C)
            and commit_g2.open_commitment(commit_g2.Commitment(cs.C), message, aux, params.h2)
        )
    except _INPUT_ERRORS:
        return False
