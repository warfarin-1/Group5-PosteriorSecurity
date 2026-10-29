"""CS.Setup: explicitly shared public parameters for concealed signatures.

The CRS must be obtained through a trusted setup. Valid curve points alone
cannot establish that a CRS was generated honestly or that trapdoors were erased.
"""

from dataclasses import dataclass

from posterior import commit_g2, gs, zk_proof
from posterior.pairing import G1, G2, ZERO_G1, ZERO_G2, is_valid_g2, points_equal


@dataclass(frozen=True)
class PublicParameters:
    h2: tuple
    crs: gs.CRS

    def is_valid(self) -> bool:
        try:
            vectors = (self.crs.u1, self.crs.u2, self.crs.v1, self.crs.v2)
            return (
                all(isinstance(v, tuple) and len(v) == 2 for v in vectors)
                and is_valid_g2(self.h2)
                and not points_equal(self.h2, ZERO_G2)
                and self.crs.is_valid()
                and all(not points_equal(p, ZERO_G1) for v in vectors[:2] for p in v)
                and all(not points_equal(p, ZERO_G2) for v in vectors[2:] for p in v)
                and points_equal(self.crs.u1[0], G1)
                and points_equal(self.crs.v1[0], G2)
            )
        except (TypeError, ValueError, AttributeError, IndexError, KeyError, ZeroDivisionError):
            return False


def setup(*, seed: bytes = b"concealed-signature-h2") -> PublicParameters:
    """Generate a fresh CRS and a deterministic, independent commitment base.

Share this object (or its serialized form) with every prover/verifier;
calling setup twice deliberately produces incompatible CRSs.
"""
    return PublicParameters(h2=commit_g2.setup(seed=seed), crs=zk_proof.setup())
