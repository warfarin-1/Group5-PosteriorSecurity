"""Version 1 binary encodings for Proof, concealed signatures and public CRS.

Fixed order, big endian compressed BLS12-381 points (48/96 bytes), four-byte
type/version tags, exact lengths, no pickle or private witnesses. Decode checks
canonical encodings, curve/subgroup membership and shape, but does not verify
the proof or authenticate a CRS. Obtain parameters from a trusted source.
Identity is allowed inside proofs/commitments; CRS bases must be nonidentity.
"""

from posterior import gs, zk_proof
from posterior.cs_params import PublicParameters
from posterior.pairing import G2, decode_g1, decode_g2, encode_g1, encode_g2

PROOF_BYTES = 4 + 18 * 48 + 16 * 96
CS_BYTES = 4 + 96 + PROOF_BYTES
CRS_BYTES = 4 + 4 * 48 + 4 * 96
PARAMS_BYTES = 4 + 96 + CRS_BYTES


def _tuple(value, length):
    if not isinstance(value, tuple) or len(value) != length:
        raise ValueError("incorrect proof/vector shape")


def validate_proof_shape(proof):
    if not isinstance(proof, zk_proof.Proof):
        raise ValueError("expected Proof")
    for name in ("c_s", "c_xt", "c_xr", "d_w1", "d_w2"):
        _tuple(getattr(proof, name), 2)
    _tuple(proof.eq_proofs, 3)
    for eq in proof.eq_proofs:
        if not isinstance(eq, gs.EqProof):
            raise ValueError("expected EqProof")
        for matrix in (eq.pi, eq.theta):
            _tuple(matrix, 2)
            for vec in matrix:
                _tuple(vec, 2)


class _Reader:
    def __init__(self, data, tag, size):
        if not isinstance(data, bytes) or len(data) != size or data[:4] != tag:
            raise ValueError("wrong encoding type, version or length")
        self.data, self.offset = data, 4

    def take(self, size):
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def vec1(self):
        return (decode_g1(self.take(48)), decode_g1(self.take(48)))

    def vec2(self):
        return (decode_g2(self.take(96)), decode_g2(self.take(96)))


def encode_proof(proof: zk_proof.Proof) -> bytes:
    validate_proof_shape(proof)
    parts = [b"PSP1"]
    for vec in (proof.c_s, proof.c_xt, proof.c_xr):
        parts.extend(encode_g1(p) for p in vec)
    for vec in (proof.d_w1, proof.d_w2):
        parts.extend(encode_g2(p) for p in vec)
    for eq in proof.eq_proofs:
        parts.extend(encode_g2(p) for vec in eq.pi for p in vec)
        parts.extend(encode_g1(p) for vec in eq.theta for p in vec)
    return b"".join(parts)


def decode_proof(data: bytes) -> zk_proof.Proof:
    reader = _Reader(data, b"PSP1", PROOF_BYTES)
    c_s, c_xt, c_xr = reader.vec1(), reader.vec1(), reader.vec1()
    d_w1, d_w2 = reader.vec2(), reader.vec2()
    eqs = tuple(gs.EqProof(
        pi=(reader.vec2(), reader.vec2()), theta=(reader.vec1(), reader.vec1())
    ) for _ in range(3))
    return zk_proof.Proof(c_s, c_xt, c_xr, d_w1, d_w2, eqs)


def encode_cs(cs) -> bytes:
    from posterior.concealed import ConcealedSignature
    if not isinstance(cs, ConcealedSignature):
        raise ValueError("expected ConcealedSignature")
    return b"PSC1" + encode_g2(cs.C) + encode_proof(cs.proof)


def decode_cs(data: bytes):
    from posterior.concealed import ConcealedSignature
    reader = _Reader(data, b"PSC1", CS_BYTES)
    C = decode_g2(reader.take(96))
    return ConcealedSignature(decode_proof(reader.take(PROOF_BYTES)), C)


def _validate_crs(crs):
    # Also enforce the generator/identity conventions of CRS.generate().
    if not isinstance(crs, gs.CRS) or not PublicParameters(G2, crs).is_valid():
        raise ValueError("invalid CRS bases")


def encode_crs(crs: gs.CRS) -> bytes:
    _validate_crs(crs)
    return b"PSR1" + b"".join(
        [encode_g1(p) for vec in (crs.u1, crs.u2) for p in vec]
        + [encode_g2(p) for vec in (crs.v1, crs.v2) for p in vec]
    )


def decode_crs(data: bytes) -> gs.CRS:
    reader = _Reader(data, b"PSR1", CRS_BYTES)
    crs = gs.CRS(reader.vec1(), reader.vec1(), reader.vec2(), reader.vec2())
    _validate_crs(crs)
    return crs


def encode_params(params: PublicParameters) -> bytes:
    if not isinstance(params, PublicParameters) or not params.is_valid():
        raise ValueError("invalid public parameters")
    return b"PST1" + encode_g2(params.h2) + encode_crs(params.crs)


def decode_params(data: bytes) -> PublicParameters:
    reader = _Reader(data, b"PST1", PARAMS_BYTES)
    params = PublicParameters(decode_g2(reader.take(96)), decode_crs(reader.take(CRS_BYTES)))
    if not params.is_valid():
        raise ValueError("invalid public parameters")
    return params


def signature_size(cs) -> int:
    """Actual serialized public-signature bytes; excludes private t and shared CRS."""
    return len(encode_cs(cs))
