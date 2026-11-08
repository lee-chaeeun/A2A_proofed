# What this experiment establishes

Research question: **What additional protection do TPM-based identity proofs provide
beyond standard A2A endpoint authentication, and which benefits depend on signer
isolation, channel binding, or hardware assumptions?**

The study uses real A2A SDK discovery, JSON-RPC messages and task artifacts. The
agents are scripted and the task is a synthetic receipt, rather than model inference
or verified execution of useful work.

## The four essential comparisons

1. **Start with endpoint validation and authenticated TLS.** C+tls includes the
   signed-card endpoint policy. This handles the original different-address and
   unauthenticated-hijack attacks. Plain local HTTP (C+url) is a diagnostic ablation,
   not a representative secured production baseline. Stolen TLS credentials are an
   explicit capability escalation above that baseline.
2. **Compare software and TPM-emulator proofs under the same relay conditions.**
   V3 adds S-env+tls and compares it with S-env+cb, T+tls and T+cb. Endpoint selection,
   TLS credentials, freshness and attacker signing access are held constant for these
   fixtures. Software and emulated TPM proofs match for the tested relay property, not
   for every signed field (the envelope signs extra context; the TPM quote carries PCR
   evidence) or every custody scenario (F21's copied assets differ).
3. **Test active protocol manipulation and dispatch continuity.** Retained pre-fix
   traces show binding downgrades for both S-env+cb and T+cb, a cross-policy oracle
   for T+cb, and (on an isolated copy of the archived v2 source) a job delivered to a
   replacement connection holding only A's TLS credentials. The fixed matrix rejects
   the binding attacks. Networked cases for S-env+cb and swtpm-backed T+cb refuse a
   connection replacement before any task byte is handed to the transport, fail closed
   on a split connection, refuse a certificate swap before dialing, and recover only
   through a new explicit decision; a 60-trial churn budget per policy produced no
   attacker receipt. They do not establish universal relay resistance, transparent
   retry, proxy support or OS-level enforcement.
4. **Retain emulator cloning as a boundary test.** F21 accepts after the attacker
   copies emulator state and restores the public synthetic PCR value. This shows that
   ordinary emulator storage can reproduce the signing capability. It does not
   establish the behaviour of a physical TPM. The software isolated signer was not
   copied in that fixture, so F21 is not a matched key-type comparison.

## Hardware and workload claims

We evaluate TPM-based authentication using a software TPM emulator. This supports
conclusions about protocol integration and behaviour under the tested attacker
capabilities. Hardware-enforced key non-exportability and resistance to
physical-device cloning are not evaluated. Where matched software signing provides
equivalent protection, we attribute the result to the authentication protocol rather
than TPM hardware.

PCR 16 contains an operator-supplied synthetic configuration value. Checking that
value demonstrates configuration comparison; it does not measure the actual agent
program, model, running workload or safe behaviour. F18 also shows that a successful
check does not guarantee the value remains unchanged until task receipt.

Signer access is stipulated by a PID-to-label gate under one OS account. Hardware
protection, OS isolation, production enrollment and requester-authentication
controls remain untested. An attacker with both the TLS credential and proof-signer
access succeeds in F20.

## How to interpret the evidence

The retained fixed V3 matrix (`results/v3/20261107-203206`) has 24 cells: six honest
controls deliver to A; the six attacker cells across the two +cb policies reject; four
predictions missed because the chosen-nonce rewrite also breaks the attacker's unbound
proof, while the untouched relay still defeats the +tls proof controls. The final rerun
(`results/v3-final/20261108-000017`, declared schema with decision and recipient
predicted separately) matches 24/24 on both. These hand-selected counts are coverage,
not population risk estimates.

Offline reappraisal reuses production code and trusts recorded transport facts; it is
shared-code consistency with cryptographic recomputation where applicable. The
release-evidence checker (`a2aid audit-release`) is a **structural** audit of
cooperative logs, requester-observed TLS facts and controller attribution, joined by
explicit ids and requester sequence numbers; it recomputes order and equality, reports
each check by trust source, cannot audit an empty or partial run clean, and is shown
to flag the corrupted copies listed in `RESULTS_V3_CORRECTIONS.md` (its first version
passed five of the reviewer's corruptions; version 2 requires declared decision counts,
exact event paths and typed context equality). It is not tamper-proof evidence, not an
independent cryptographic appraisal, and not a formal security proof. The final 24/24
agreement includes eight deliberate attacker successes on the unbound policies; it is a
reproducibility check against revised expectations, not a security score. Records of the
pre-final runs lack the ids it needs and are reported as an unsupported historical
schema, not audited.

See `RESULTS_V3_FINAL.md` for exact counts and identities and
`../paper/a2a-identity/BASELINE_V3_REVIEW.md` for the review that motivated them.
Frozen predictions, raw matrices and prior reports are retained; corrections are
appended as dated addenda and do not retroactively convert failed predictions into
successes.
