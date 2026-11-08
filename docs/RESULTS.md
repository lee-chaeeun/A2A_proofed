# Results and their interpretation

The implementation integrates TPM-format attestation with A2A and separately transports
and appraises RISC Zero task proofs. The rationale for physical key protection is in
[HARDWARE_AND_PTV.md](HARDWARE_AND_PTV.md); it is separate from these measurements.

## Identity

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

Identity `matrix.csv` summarizes fixture/policy outcomes; `appraisals.jsonl` separates
proof acceptance from dispatch; per-cell receipt logs identify A/B observations;
`release-audit-summary.json` summarizes structural checks.

ZK `decisions.jsonl` separates `proof_valid`, context/input checks, `approval_allowed` and
`approval_inserted`; `receipts/` holds actual proof bytes; `events.jsonl` and `ledgers.json`
support action ordering and duplicate checks; `oracle-summary.json` reports re-verification.

A clean audit means supported evidence agrees with the declared semantics, including
expected weak-policy failures. It does not mean every policy is secure, and it does not
protect against coordinated fabrication by trusted observers.
