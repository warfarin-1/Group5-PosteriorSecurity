# Individual Q&A preparation and rehearsal plan

Scheduling, actual attendance and sign-off remain TO FILL. No invitations
have been sent. Everyone should answer questions across all components.

## Rehearsal format

Hold a 60-minute rehearsal: 20 minutes slides/demo, 30 minutes randomly
assigned questions, 10 minutes corrections. Rotate questioner and respondent;
give one person 60–90 seconds to answer, then compare against code/evidence.
Run a second rehearsal after corrections. Confirm the actual course Q&A rules
with the teaching team; the local plan expects a 40-minute individual session.

| Round | Date/time | Questioner | Respondent | Gaps to review |
|---|---|---|---|---|
| Full walkthrough | TO FILL | TO FILL | all | TO FILL |
| Cross-component questions | TO FILL | TO FILL | rotate A/B/C/D | TO FILL |
| Final timed rehearsal | TO FILL | TO FILL | all | TO FILL |

## Question bank with answer anchors

1. **What is posterior message hiding?** Convert an existing standard
   signature so public verification works without disclosing its message.
   It does not anonymize the signer. See scope and paper-to-code map.
2. **Who needs the signing key?** BB Sign needs sk; Convert needs the valid
   signature, message, vk and public parameters, not sk.
3. **What does BB verification check?**
   `e(s, X g2^m Y^r)=e(g1,g2)`; explain group/scalar notation and nonce.
4. **Why hash to G2 for h2?** A known log of h2 relative to g2 allows finding
   alternative openings and breaks commitment binding.
5. **What do t and r represent?** t is fresh opening randomness; r is BB's
   original signing nonce. They are different and both hidden by the proof.
6. **Why three PPEs?** E1 checks the concealed BB relation; E2/E3 link group
   encodings of t/r through shared commitments. See `zk_proof._equations`.
7. **What can the verifier see?** CS=(proof,C), vk and common parameters;
   it needs neither the message, original signature nor opening.
8. **Does Decom authenticate a signature?** No. It checks the opening only.
   Accept a revealed signed message only after CVerify AND Decom.
9. **Why share a CRS?** A newly generated CRS is incompatible with existing
   proofs. Public serialization supports another process with the same CRS.
10. **What does trusted setup mean here?** Generation samples extraction
    trapdoors; their compromise threatens privacy. Point validation cannot
    establish honest generation or secure destruction.
11. **Does parsing prove validity?** No. It checks wire format/subgroups;
    call CVerify to authenticate the decoded proof.
12. **Is the identity point always invalid?** No. Parameters disallow it;
    proof/commitment components can include it, e.g. m=t=0 yields identity C.
13. **What happens when t is reused?** Commitment differences cancel h2^t
    and expose encoded message differences; small candidate differences are
    guessable. Fresh independent sampling is required.
14. **How do you measure overhead?** Time real public APIs sequentially,
    20 samples after one warmup, report median/IQR. Explain included validation
    and excluded setup/keygen/encoding before stating ratios.
15. **Why isn't CS size just proof size?** CS adds a G2 commitment and a
    type tag. 2504 B includes tags; 680 B parameters are shared separately.
16. **What do the security tests establish?** Successful workflows and
    rejection behavior for tested inputs; not q-SDH/SXDH or a security proof.
17. **Does the 8-trial game establish hiding?** No, it is a smoke test with
    insufficient statistical power. GS simulator/security review remains A's.
18. **Can you extract integer t/r?** The GS interface works with group
    elements; integer extraction would generally need discrete logarithms.
19. **Does the CBDC demo prove a valid balance or positive amount?** No.
    CLI input formatting is not a cryptographic range/balance proof.
20. **How is Incognito evaluated?** Run the official pinned external Rust
    implementation; cite its revision, command and settings. Do not claim
    authorship or directly rank its speed against a different construction.
21. **How is the release cleaned?** An allowlisted ZIP builder excludes
    environments, Git metadata, caches and local process records; manifest
    hashes and extraction smoke checks provide integrity evidence.
22. **What did AI assist with?** State the scope in `docs/PROVENANCE.md`;
    members still need to understand and verify each submitted component.

## Evaluation sheet

Question number: TO FILL · respondent: TO FILL · elapsed: TO FILL.
Was the answer correct, bounded by evidence, and traceable to a function?
Write one correction and one file to review. Do not invent rehearsal results.
