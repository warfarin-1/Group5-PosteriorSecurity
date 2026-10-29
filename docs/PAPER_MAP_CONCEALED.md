# Concealed Boneh–Boyen: construction-to-code map

Scope: the Concealed construction described in the local reproduction plan
§3 (paper §5.3). The old root `PAPER_MAP.md` concerns Incognito background,
which is not implemented here. This map describes the actual code; it does
not certify a security reduction or equivalence of every proof-system detail.

## Notation and public inputs

The paper writes group products multiplicatively; `pairing.py` exposes
additive G1/G2 arithmetic. Thus `g2^m h2^t` becomes
`add_g2(scalar_mul(G2, m), scalar_mul(h2, t))`.
The backend calls pairing with **G2 first, G1 second**:
`pairing(Q, P)` represents the mathematical `e(P, Q)`.
Scalars are in `Z_p`, with `p = pairing.ORDER`; messages supplied to the
concealed API are canonical integers, or `boneh_boyen.hash_message(bytes)`.

| Construction step | Mathematical relation | Actual implementation |
|---|---|---|
| BB KeyGen | `X=g2^x`, `Y=g2^y` | `boneh_boyen.keygen` |
| BB Sign | choose r; `s=g1^(1/(x+m+yr))` | `boneh_boyen.sign`; resample when denominator is zero |
| BB Verify | `e(s, X g2^m Y^r)=e(g1,g2)` | `boneh_boyen.verify` |
| CS Setup | independent h2 and proof CRS | `cs_params.setup`, returning `PublicParameters(h2, crs)` |
| Commitment base | h2 with unknown discrete log to g2 | `commit_g2.setup`, domain-separated hash to G2 |
| Convert rejection | invalid BB signature yields bottom | `concealed.convert`: validation then BB verification; returns `None` |
| Convert commitment | sample uniform t; `C=g2^m h2^t` | `_random_opening`, `commit_g2.commit`; t can be zero |
| Convert proof | prove concealed BB verification relation | `zk_proof.prove(..., crs=params.crs)` |
| CVerify | verify proof with X,Y,C,h2,CRS | `concealed.cverify` → `zk_proof.verify` → `gs.verify_ppes` |
| Decom | `C=g2^m h2^t` | `concealed.decom` → `commit_g2.open_commitment` |
| Public output | `(proof,C)`; private auxiliary t | `ConcealedSignature` plus separate returned opening |

Setup lives in **`cs_params.py`**, despite older plan pseudocode referring
to `concealed.setup`. All participants must share the same parameters.
For a revealed *signed* message, require both CVerify and Decom.

## How the target relation becomes three PPEs

The concealed verification relation is
`e(s, X C h2^(-t) Y^r) = e(g1,g2)`.
`zk_proof.prove` represents exponents using hidden group elements:
`xt=g1^t`, `xr=g1^r`, `w1=h2^(-t)`, `w2=Y^r`.
`zk_proof._equations` builds:

| Equation | Purpose |
|---|---|
| E1: `e(s,XC) e(s,w1) e(s,w2)=e(g1,g2)` | concealed BB verification |
| E2: `e(g1,w1) e(xt,h2)=1` | ties w1 and xt to the same exponent t |
| E3: `e(g1,w2) e(xr,Y^-1)=1` | ties w2 and xr to the same exponent r |

The three proofs share commitments `c_s`, `c_xt`, `c_xr`, `d_w1`, `d_w2`;
they cannot be treated as independent statements with unrelated witnesses.
`gs.prove_ppe` and `gs.verify_ppes` implement the matrix-based pairing proof.
The current verifier batches equations with fresh random coefficients.
This is Groth–Sahai code, not the older plan's optional Fiat–Shamir Sigma path.
Extraction concerns group elements; recovering scalar t/r would require
discrete logarithms. The exact paper reduction remains a review obligation.

## Evidence map

| Claim or engineering property | Evidence |
|---|---|
| Correctness and transport | `test_b_assembly.py`, `test_concealed.py`, `test_serialization.py` |
| Opening binding and wrong-message rejection | `test_concealed.py`, `test_edge_cases.py` |
| Repeated t leaks relative messages | `test_edge_cases.py::test_reused_opening_leaks_message_difference` |
| Proof and statement integrity | `test_unforgeability.py`, commitment-splicing test in `test_concealed.py` |
| Canonical scalars and malformed fields | `test_b_assembly.py`, `test_edge_cases.py` |
| Canonical encodings/subgroups/shared CRS | `test_serialization.py` |
| Message hiding smoke test, not a proof | `test_message_hiding.py` (8 trials); GS simulator remains A's task |
| Runtime and actual byte sizes | `bench/run_bench_concealed.py`, `bench/plot_results.py` |

Proof: 18 G1 + 16 G2 = 2400 bytes of compressed points + 4-byte tag.
CS: 96-byte C + tagged proof + 4-byte CS tag = **2504 bytes**.
Parameters are 680 bytes, shared separately. The BB comparison uses an
80-byte point/scalar payload, without a custom BB encoding header.

AI assisted this map and the Part C evaluation on 2026-10-30.
