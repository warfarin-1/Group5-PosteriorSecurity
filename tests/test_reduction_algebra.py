"""Algebra behind the unforgeability reduction (docs/SECURITY_ARGUMENT.md §3).

The reduction R knows k = log_g2(h2) and, from a concealed forgery, an
extracted witness (s, t', r) and the claimed opening (m*, t*). It outputs the
Boneh-Boyen pair (s, r) on m' = m* + k (t* - t'). These tests check that
identity on real objects. They do not prove the reduction (that needs the
exponent-extractability assumption EE; the GS extractor itself is not run).
"""

from posterior import boneh_boyen as bb
from posterior.pairing import G2, ORDER, add_g2, random_scalar, scalar_mul


def _setup():
    sk, vk = bb.keygen()
    k = random_scalar()
    h2 = scalar_mul(G2, k)  # reduction-style h2 with known dlog
    return sk, vk, k, h2


def _commit(m, t, h2):
    return add_g2(scalar_mul(G2, m), scalar_mul(h2, t))


def _m_prime(m_star, t_star, t_ext, k):
    return (m_star + k * (t_star - t_ext)) % ORDER


def test_honest_case_gives_bb_signature_on_claimed_message():
    sk, vk, k, h2 = _setup()
    m, t = random_scalar(), random_scalar()
    sig = bb.sign(m, sk)
    C = _commit(m, t, h2)
    # honest extraction: t' = t, so m' = m
    assert _m_prime(m, t, t, k) == m
    assert bb.verify(sig, m, vk)
    # and the concealed relation holds with (s, t, r)
    from posterior.pairing import pairing, G1, neg
    A = add_g2(add_g2(vk.X, C), add_g2(neg(scalar_mul(h2, t)), scalar_mul(vk.Y, sig.r)))
    assert pairing(A, sig.s) == pairing(G2, G1)


def test_unequal_extracted_and_opened_t_yields_signature_on_shifted_message():
    """A forger who knows k can open C differently from the witness inside the
    proof; the reduction then extracts a BB signature on m' != m*."""
    sk, vk, k, h2 = _setup()
    m_fresh = random_scalar()
    sig = bb.sign(m_fresh, sk)
    t_ext = random_scalar()          # exponent used inside the proof
    m_star, t_star = random_scalar(), random_scalar()
    # choose the opening so that m* + k (t* - t') = m_fresh  (needs k!)
    t_star = (t_ext + (m_fresh - m_star) * pow(k, -1, ORDER)) % ORDER
    C = _commit(m_star, t_star, h2)
    assert _m_prime(m_star, t_star, t_ext, k) == m_fresh
    # the witness (s, t', r) satisfies the concealed equation for this C
    from posterior.pairing import pairing, G1, neg
    Cp = _commit(m_star, t_star, h2)
    A = add_g2(add_g2(vk.X, Cp), add_g2(neg(scalar_mul(h2, t_ext)), scalar_mul(vk.Y, sig.r)))
    assert pairing(A, sig.s) == pairing(G2, G1)
    assert bb.verify(sig, m_fresh, vk) and m_fresh != m_star


def test_reopening_a_commitment_reveals_dlog_of_h2():
    """Case m' = m_i with t' != t*: R2 recovers k = (m_i - m*)/(t* - t')."""
    _, _, k, h2 = _setup()
    m_i, t_i = random_scalar(), random_scalar()
    m_star = random_scalar()
    t_star = (t_i + (m_i - m_star) * pow(k, -1, ORDER)) % ORDER  # forger's re-opening
    from posterior.pairing import points_equal
    assert points_equal(_commit(m_i, t_i, h2), _commit(m_star, t_star, h2))
    assert _m_prime(m_star, t_star, t_i, k) == m_i
    recovered = ((m_i - m_star) * pow(t_star - t_i, -1, ORDER)) % ORDER
    assert recovered == k
