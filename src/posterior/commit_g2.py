"""Pedersen-in-G2 commitment (paper §5.3, part of CS.Setup / CS.Convert).

    C = g2^m . h2^t

`h2` must be a G2 generator whose discrete log relative to `g2` is
*unknown to everyone*, including whoever ran `setup`. Otherwise the
setup party could equivocate: given log_g2(h2) = k, any commitment C
can be reopened to an arbitrary message m' by picking a matching t'
(t' = (m + k*t - m') / k mod p), which breaks binding. `pairing.hash_to_g2`
is used instead of a "hash to scalar, multiply g2" shortcut precisely to
avoid this.

Security properties:
- Binding: computationally binding under the discrete-log assumption in
  G2 (finding two different (m,t) openings of the same C means finding
  log_g2(h2)).
- Hiding: perfectly hiding -- for a uniform random t, C is uniformly
  distributed over G2 regardless of m.
"""

from dataclasses import dataclass

from posterior.pairing import G2, add_g2, hash_to_g2, points_equal, scalar_mul


def setup(*, seed: bytes = b"concealed-signature-h2") -> tuple:
    """CS.Setup's h2: a nothing-up-my-sleeve G2 generator, independent of
    g2. `seed` is public and the derivation is deterministic (anyone can
    recompute and audit it), but nobody learns log_g2(h2) in the process.
    """
    return hash_to_g2(seed, domain=b"commit-g2-h2")


@dataclass(frozen=True)
class Commitment:
    point: tuple  # G2 point: g2^m . h2^t


def commit(message: int, randomness: int, h2: tuple) -> Commitment:
    """C = g2^m . h2^t.

    `randomness` (the paper's `t`) must be sampled uniformly at random
    and kept secret -- it's the decommitment key (see `open_commitment`
    and, later, `concealed.py`'s CS.Decom).
    """
    return Commitment(
        point=add_g2(scalar_mul(G2, message), scalar_mul(h2, randomness))
    )


def open_commitment(
    commitment: Commitment, message: int, randomness: int, h2: tuple
) -> bool:
    """Check whether (message, randomness) is a valid opening of `commitment`."""
    return points_equal(commitment.point, commit(message, randomness, h2).point)
