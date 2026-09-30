"""Proof of knowledge for the target pairing-product equation (paper §5.3):

    e(s, X . C . h2^-t . Y^r) = e(g1, g2)
    witness: s in G1 (hidden), t, r in Zp (hidden)

################################################################
# *** THIS FILE IS CURRENTLY AN INSECURE PLACEHOLDER. ***
################################################################

It exists only so the rest of the pipeline (concealed.py, the security
test suite, benchmarks, the demo) can be built and tested against a
stable interface while the real zero-knowledge proof construction is
developed separately. `prove`/`verify` below provide NONE of the
required security properties:

- `Proof` carries the witness (s, t, r) in the clear -- this has zero
  zero-knowledge / hiding property. Revealing t alone completely
  breaks message hiding (see `commit_g2.py`'s module docstring).
- `verify` only re-derives D from the cleartext witness and checks the
  underlying pairing equation directly -- it provides no soundness
  guarantee beyond "the witness this Proof happens to carry satisfies
  the equation", which is trivial and not a meaningful proof of
  anything.

Do not use this for anything security-relevant. It must be replaced
by a real construction (either an existing pairing-based ZK library,
or a properly-derived Groth-Sahai / Sigma-protocol construction for
this exact relation) before this project is evaluated or submitted --
see the risk/parallelisation notes for the current owner and status.
Keep the function signatures stable when replacing this file so
downstream modules don't need to change.
"""

import warnings
from dataclasses import dataclass

from posterior.pairing import G1, G2, add_g2, neg, pairing, scalar_mul

INSECURE_STUB = True
"""Importers (e.g. concealed.py) can check this flag and refuse to run
in a "submission" mode if it's still True, as a last-resort safety net
against accidentally shipping the placeholder."""


@dataclass(frozen=True)
class Proof:
    """PLACEHOLDER proof object: carries the witness in the clear.

    A real `Proof` must NOT expose s, t, or r -- it should only contain
    whatever opaque commitment/proof elements the real construction
    needs, none of which should let a verifier (or anyone who sees the
    proof) recover the witness.
    """

    s: tuple  # G1 point -- the Boneh-Boyen signature element, IN THE CLEAR
    t: int  # the commitment randomness from commit_g2 -- IN THE CLEAR
    r: int  # the Boneh-Boyen nonce -- IN THE CLEAR


def prove(s: tuple, t: int, r: int, *, X: tuple, Y: tuple, C: tuple, h2: tuple) -> Proof:
    """PLACEHOLDER: see module docstring. Real signature must match:
    `prove(s, t, r, *, X, Y, C, h2) -> Proof`.
    """
    warnings.warn(
        "zk_proof.prove() is an INSECURE PLACEHOLDER -- do not use for "
        "anything security-relevant, and do not submit it.",
        stacklevel=2,
    )
    return Proof(s=s, t=t, r=r)


def verify(proof: Proof, *, X: tuple, Y: tuple, C: tuple, h2: tuple) -> bool:
    """PLACEHOLDER: see module docstring. Real signature must match:
    `verify(proof, *, X, Y, C, h2) -> bool`.

    Re-derives D = X . C . h2^-t . Y^r from the (cleartext!) witness the
    "proof" carries, and checks e(s, D) == e(g1, g2) directly.
    """
    warnings.warn(
        "zk_proof.verify() is an INSECURE PLACEHOLDER -- do not use for "
        "anything security-relevant, and do not submit it.",
        stacklevel=2,
    )
    d = add_g2(X, C)
    d = add_g2(d, neg(scalar_mul(h2, proof.t)))
    d = add_g2(d, scalar_mul(Y, proof.r))
    return pairing(d, proof.s) == pairing(G2, G1)
