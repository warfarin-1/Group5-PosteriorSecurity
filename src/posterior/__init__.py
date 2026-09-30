"""Concealed Signature implementation (Posterior Security, CCS 2025, §5.3).

Implements the paper's Concealed Signature construction: a standard
Boneh-Boyen signature is converted so the signed message is hidden
behind a commitment, verified via a pairing-based zero-knowledge proof.
The paper's Incognito Signature construction (its other contribution)
is out of scope here and is not implemented in this codebase.
"""
