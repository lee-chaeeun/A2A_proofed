# Results and their interpretation

The implementation integrates a device-resident post-quantum identity credential and
TPM-format attestation with A2A, and separately transports and appraises RISC Zero task
proofs. The rationale for physical key protection is in
[HARDWARE_AND_PTV.md](HARDWARE_AND_PTV.md); it is separate from these measurements.

## Post-quantum identity (final prototype)

Primary run: `pq-identity/results/pq/20261108-153049` (corrected producer, 8 Nov 2026).
Integration rerun: `pq-identity/results/pq-integration/20261108-164204`.
Reports: [pq-identity/RESULTS_PQ_CORRECTIONS.md](../pq-identity/RESULTS_PQ_CORRECTIONS.md) (current),
[pq-identity/RESULTS_PQ_IDENTITY.md](../pq-identity/RESULTS_PQ_IDENTITY.md) (pre-correction, dated pointer).

- Device gate: within 17 minutes of a declared 60-minute window, the wolfTPM firmware TPM
  created an ML-DSA-65 primary key (1952-byte public key, `fixedTPM|fixedParent|
  sensitiveDataOrigin|userWithAuth|noDA|sign`), made it persistent and signed 3309-byte
  signatures through the sign-sequence commands; CIRCL verifies them under the same FIPS 204
  context string; wrong authValue gives `TPM_RC_BAD_AUTH`; the key survives a restart.
  Evidence: `pq-identity/results/audit/20261108T130125Z-pq-gate/`.
- Matrix: 8 arms × (12 scenarios + 4 boundary controls) = 128 cells, all as predicted in
  the final run and identically in the rerun; composite `audit-pq` v2 exit 0 (35 proofs
  re-verified valid, 84 invalid as recorded, 25 declared attacker deliveries, 16 verified
  dispatches, 95 verified non-dispatches, no orphan receipt or duplicate id). The first
  corrected execution (`results/pq/20261108-152809`, same 128 outcomes) was stopped by the
  audit gate and is retained with its note; the pre-correction runs stay in the research tree.
- Binding, not algorithm: the relay with A's TLS credentials (P8) is delivered to under
  every `+tls` arm and rejected under every `+cb` arm, for ECDSA, software ML-DSA and
  device ML-DSA alike; active rewrites (P9) and the connection swap before dispatch (P10)
  fail everywhere.
- Custody: a copy of the application volume plus TLS credentials (P6) impersonates A only
  under `PQ-file+cb`; the gated and device keys are not copied with the volume. Boundary
  controls make the simulated boundary explicit: authorized signer access (X1) and a copy
  of the emulator's state directory with its journal key (X2) reproduce the device key.
- Trust chain: TLS credentials plus the classical signer (P12) defeat `EC-env+cb` but no
  PQ arm; a response cannot pick another enrolled key, algorithm, a fresh key under A's id
  or a key whose enrolled id the registry replaced (P4, P5, X3, X4). What is enforced is
  the pinned algorithm, key id and public key; the registry's version field is a label.
  This is a capability surrogate, not a quantum attack; cards, TLS and the lab CA remain classical.
- Cost (`results/pq-bench/20261108-132255`, 30 samples over a fixed 306-byte message, one
  host): ML-DSA-65 keygen/sign/verify medians 178/243/141 µs against P-256 14/34/75 µs;
  device signature 2408 µs per bridge call of which 804 µs are TPM commands; signed
  contexts 271–310 bytes per arm; loopback challenge-to-proof 1.4–2.6 ms (ECDSA),
  1.9–2.6 ms (software ML-DSA), 3.8–4.9 ms (device) in the two final executions.
- Audit controls: seventeen mutations of the final run (ten original, seven from the
  review that found the earlier audit accepting broken release evidence as clean) return
  the exit codes frozen beforehand (`results/audit/20261108T143109Z-pq-audit-controls/`,
  `fixtures/pq-audit-controls-expected.json`); the runner treats audit, controls and tests
  as gates (`scripts/test_pq_runner.sh`).
- ZK over PQ transport: the task goes through the identity requester's guarded send.
  Regressions with server counters (`internal/zk/pq_transport_test.go`): a server that
  closes the proof connection after a valid proof receives zero task requests on its
  replacement connection; an implicit reconnect is refused before the dial; an interrupted
  request is reported unknown; a fresh decision recovers. One genuine-receipt smoke test
  (`results/zk-pq-smoke/20261108-154419`) delivers the honest task and rejects B with no
  task sent; the 52-cell ZK results are unchanged.

The emulator is software and its state is a file; the custody claims are conditional on a
device enforcing the private-state and authorization boundary modeled here. No FIPS
validation, no statement about ML-DSA's security and no end-to-end post-quantum
security is claimed.

## Classical identity

Primary run: `identity/results/v3-final/20261108-004047`.

- 24/24 decisions and recipients match the declared expectations: six deliveries to A,
  eight to B under the selected weaker policies, ten with no recipient.
- Against a relay with A's TLS key but no extra signing capability, bound software-envelope
  and TPM-quote policies both reject the relay. This isolates the effect of the protocol;
  it does not compare physical extraction resistance.
- Proof is tied to the signer's own TLS connection, and guarded dispatch refuses a
  replacement connection. Separate continuity tests cover both proof types.
- Churn: T+cb has 30 honest deliveries and 30 refusals, with no B receipts. S-env+cb has
  30 honest deliveries, 28 refusals and two client-unknown outcomes, with no B receipts.
- Broad reference matrix: `identity/results/v2/20261107-194025`, 21 fixtures × 11 policies,
  201 applicable cells out of 231 and 199 prediction matches. It covers file copying,
  fresh/replayed proofs, signer access, transport controls and emulator cloning.

The copied source is final. Earlier comparison observations do not represent a second
installable code version. The emulator's copyable state and synthetic PCR cannot establish
physical key protection or actual executing workload integrity.

## Computation proofs

Primary run: `zk-component/results/zk/20261108-111817`.
Integration rerun: `zk-component/results/zk-integration/20261108-112143`.

- 13 fixtures × four policies, 52/52 expected outcomes in each execution.
- Nine network exchanges, seven new genuine proofs, zero cache hits in the primary run.
- Z6 and Z7 use byte-identical receipt and challenge: Pinned authorizes the historical
  result; Current requires the authority's current commitment. VI/VTI enforce the distinction.
- A fresh challenge with obsolete input is accepted by V0/VT, demonstrating the need for
  input authorization beyond freshness.
- Wrong-context acceptances 3/8; unauthorized-input approvals 5/12; legitimate denials 0/12.
  These are overlapping, hand-selected coverage groups, not population attack rates.
- Oracle re-verification: ten receipt/image pairs, seven verified and three rejected.
  Seven expected weak-policy attack successes remain explicitly visible.
- The schema-2 evidence controls include unmodified plus 24 mutations; only unmodified is
  clean. The oracle checks retained bytes, inventory completeness and event-derived ledgers.

All policies use ZK. No signature-only comparison, physical TPM result, combined TPM/ZK
handshake, model-honesty result or empirical privacy improvement is claimed.

## Reading the evidence

PQ `matrix.csv`/`matrix.jsonl` give decision and recipient per cell; `appraisals.jsonl`
separates proof verdict stages from dispatch; `cells/<fixture>_<arm>/decision.json`
holds the raw proof-v4 bytes, requester events and connection records;
`controller-events.jsonl` records gate connections with access-list verdicts, device
command traces and receipts; `enrollment-registry.json` (public keys only) and
`registry-overrides.json` (the X4 rotation) are the audit's trust anchors;
`pq-audit-summary.json` and `pq-audit.md` are the retained audit reports.

Identity `matrix.csv` summarizes fixture/policy outcomes; `appraisals.jsonl` separates
proof acceptance from dispatch; per-cell receipt logs identify A/B observations;
`release-audit-summary.json` summarizes structural checks.

ZK `decisions.jsonl` separates `proof_valid`, context/input checks, `approval_allowed` and
`approval_inserted`; `receipts/` holds actual proof bytes; `events.jsonl` and `ledgers.json`
support action ordering and duplicate checks; `oracle-summary.json` reports re-verification.

A clean audit means supported evidence agrees with the declared semantics, including
expected weak-policy failures. It does not mean every policy is secure, and it does not
protect against coordinated fabrication by trusted observers.
