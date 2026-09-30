"""Standard Boneh-Boyen signature (paper §5.3).

This is the well-known base scheme that Concealed Signature converts --
not part of the paper's own contribution. Its unforgeability relies on
the q-SDH assumption. It also serves as our performance baseline: later
milestones compare Concealed's Convert/CVerify/Decom overhead against
plain Sign/Verify here, to quantify the cost of message-hiding.

    Setup:  (G1, G2, GT, p, g1, g2, e)
    KeyGen: sk = (x, y) <-$ Zp^2 ;  pk = (X = g2^x, Y = g2^y)
    Sign(m, sk):  r <-$ Zp ; s = g1^{1/(x + m + y*r)} ;  sigma = (s, r)
    Verify((s, r), m, pk):  accept iff e(s, X . g2^m . Y^r) == e(g1, g2)

`message` throughout is an element of Zp (an int). Use `hash_message` to
turn an arbitrary byte-string message into one.
"""

from dataclasses import dataclass

from posterior.pairing import (
    G1,
    G2,
    ORDER,
    add_g2,
    hash_to_scalar,
    pairing,
    random_scalar,
    scalar_mul,
)


@dataclass(frozen=True)
class SigningKey:
    x: int
    y: int


@dataclass(frozen=True)
class VerifyKey:
    X: tuple  # g2^x
    Y: tuple  # g2^y


@dataclass(frozen=True)
class Signature:
    s: tuple  # G1 point
    r: int


def keygen() -> tuple[SigningKey, VerifyKey]:
    x = random_scalar()
    y = random_scalar()
    return SigningKey(x, y), VerifyKey(X=scalar_mul(G2, x), Y=scalar_mul(G2, y))


def sign(message: int, sk: SigningKey) -> Signature:
    """message must already be an element of Zp (see `hash_message`)."""
    while True:
        r = random_scalar()
        exponent = (sk.x + message + sk.y * r) % ORDER
        if exponent != 0:
            break
    inv = pow(exponent, -1, ORDER)
    return Signature(s=scalar_mul(G1, inv), r=r)


def verify(signature: Signature, message: int, vk: VerifyKey) -> bool:
    # D = X . g2^m . Y^r  (additive notation: X + m*g2 + r*Y)
    d = add_g2(vk.X, scalar_mul(G2, message))
    d = add_g2(d, scalar_mul(vk.Y, signature.r))
    return pairing(d, signature.s) == pairing(G2, G1)


def hash_message(data: bytes) -> int:
    """Map an arbitrary byte-string message to Zp so it can be signed."""
    return hash_to_scalar(data, domain=b"boneh-boyen-message")
