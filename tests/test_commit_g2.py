"""Correctness + binding/hiding sanity tests for the Pedersen-in-G2 commitment."""

from posterior.commit_g2 import commit, open_commitment, setup
from posterior.pairing import G2, ORDER, points_equal, random_scalar


def test_commit_then_open_succeeds():
    h2 = setup()
    t = random_scalar()
    c = commit(42, t, h2)
    assert open_commitment(c, 42, t, h2)


def test_wrong_message_fails_to_open():
    h2 = setup()
    t = random_scalar()
    c = commit(5, t, h2)
    assert not open_commitment(c, 6, t, h2)


def test_wrong_randomness_fails_to_open():
    h2 = setup()
    t = random_scalar()
    c = commit(5, t, h2)
    assert not open_commitment(c, 5, (t + 1) % ORDER, h2)


def test_different_messages_give_different_commitments():
    # Not a hiding test (hiding is a distributional/statistical claim,
    # not "commitments never collide") -- just a sanity check that we
    # didn't accidentally build a constant or message-independent point.
    h2 = setup()
    c1 = commit(0, random_scalar(), h2)
    c2 = commit(1, random_scalar(), h2)
    assert not points_equal(c1.point, c2.point)


def test_setup_is_deterministic_and_independent_of_g2():
    h2_a = setup()
    h2_b = setup()
    assert points_equal(h2_a, h2_b)
    assert not points_equal(h2_a, G2)


def test_different_seeds_give_different_h2():
    h2_default = setup()
    h2_other = setup(seed=b"a-different-seed")
    assert not points_equal(h2_default, h2_other)


def test_boundary_message_and_randomness():
    h2 = setup()
    for m, t in ((0, 0), (0, 1), (1, 0), (ORDER - 1, ORDER - 1)):
        c = commit(m, t, h2)
        assert open_commitment(c, m, t, h2)
