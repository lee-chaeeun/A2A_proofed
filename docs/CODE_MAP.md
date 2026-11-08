# Code map

Start with `pq-identity/` for the current integrated implementation. The other two directories retain the final code paths for the paper's separately measured classical and standalone ZK studies. They share an ancestor and module name (`a2aid`); run Go commands inside one component rather than creating a workspace that combines duplicate modules.

## Read the pipeline in this order

1. `cmd/a2aid/main.go`: CLI and lab provisioning.
2. `internal/wire/wire.go` and `internal/registry/registry.go`: payloads, policies and trusted enrollment.
3. `internal/agent/agent.go`, `internal/gate/gate.go`, `internal/pqdev/` and `tools/pqtpm/`: who signs and through which boundary.
4. `internal/pqsig/pqsig.go`: the authenticated context and signature checks.
5. `internal/verifier/verifier.go`, `transport.go`, `store.go`: appraisal, connection pinning and single-use delivery.
6. `internal/zk/requester.go`, `policy.go`, `authority.go`: task delivery, verified-result authorization and approval.
7. `zk/methods/guest/src/main.rs` and `zk/host/src/bin/`: the proved program and Rust wrappers.
8. `internal/pqaudit/`, `internal/audit/`, `internal/zk/oracle.go`: checking retained observations.

The A2A SDK, CIRCL, wolfTPM, wolfSSL, go-tpm and RISC Zero are dependencies, not local forks. `internal/cardsig` adapts the official A2A sample. The Go harness, policies, C bridge and small Rust application are project code; the underlying cryptographic algorithms are upstream work. See [ATTRIBUTION.md](ATTRIBUTION.md).

## Annotated main-component tree

Every source, test, script and build-input file is listed below. Generated binaries, toolchain checkouts, raw result rows and fixture data are described separately so they do not obscure the source tree.

```text
pq-identity/
  PQ_CORRECTION_PLAN.md  # Frozen correction plan retained to make its pre-run hash checkable
  README.md  # Component-specific setup, policy and measurement instructions
  RESULTS_PQ_CORRECTIONS.md  # Before/after validation record for the final corrections
  RESULTS_PQ_IDENTITY.md  # Current PQ outcomes and pointers to retained evidence
  cmd/a2aid/main.go  # CLI commands; lab CA, enrollment and provisioning; process startup; matrix and audit entry points
  go.mod  # Go module, language baseline and direct dependencies
  go.sum  # Go dependency checksums
  internal/agent/agent.go  # A2A agent executor: challenge responses, synthetic jobs and receipt logging
  internal/agent/cose.go  # Construct the classical software-envelope response
  internal/agent/zk.go  # Handle zk_task and return the proof-carrying task artifact
  internal/audit/audit.go  # Structural release-evidence checker: event paths, sessions, contexts, connections and receipts
  internal/audit/audit_test.go  # Structural checker invariants and corrupted-record cases
  internal/cardsig/cardsig.go  # Canonicalize, sign and verify Agent Cards; adapted from the official A2A sample
  internal/controller/controller.go  # Local experiment controller, deployment labels, configuration and cooperative event log
  internal/ctl/ctl.go  # Client used to call the controller and emit experiment events
  internal/gate/gate.go  # Harness signer service; check process labels and route permitted signing requests
  internal/gate/gate_env_test.go  # Matched gated software signers and their request contexts
  internal/matrix/integration_test.go  # Opt-in full matrix integration (requires the relevant lab/proof tools)
  internal/matrix/matrix.go  # Execute scenario-policy cells and the PQ attack/boundary drivers
  internal/matrix/races.go  # Deterministic and randomized release-race trials
  internal/matrix/reverify.go  # Recheck retained classical appraisals and label what can be recomputed
  internal/matrix/runtime.go  # Source/build provenance, dependency and platform metadata, run-path helpers
  internal/matrix/summary.go  # Aggregate outcomes by fixture class and policy into tables
  internal/matrix/traces.go  # Export compact scenario traces for inspection
  internal/pqaudit/pqaudit.go  # Composite PQ audit: inventory + structural release checks + signature/context re-verification
  internal/pqaudit/pqaudit_test.go  # Composite audit and real-CLI mutations over the six-cell test fixture
  internal/pqdev/fwtpm.go  # Start/stop temporary firmware TPMs and copy emulator state for the clone control
  internal/pqdev/pqdev.go  # Invoke the C bridge; create, read, sign with and evict a device key
  internal/pqdev/pqdev_test.go  # Opt-in emulator create/sign/negative/restart/evict test
  internal/pqsig/acvp_test.go  # CIRCL/NIST ACVP vectors and invalid ML-DSA signatures
  internal/pqsig/bench.go  # Measure signature sizes and software/device timings
  internal/pqsig/pqsig.go  # Canonical proof-v4 context; strict decoding; ML-DSA and ECDSA signing/verification
  internal/pqsig/pqsig_test.go  # Canonical context, algorithm/key pinning and signature rejection cases
  internal/ptv/fuzz_test.go  # Fuzz malformed encodings and decoding/normalization boundaries
  internal/ptv/ptv.go  # Encode and validate the PTV-inspired routine envelope, including evidence/proof rules
  internal/registry/registry.go  # Resolve enrolled publisher, endpoint, TLS name and proof-key pins
  internal/senv/fuzz_test.go  # Fuzz malformed encodings and decoding/normalization boundaries
  internal/senv/senv.go  # Classical software-signed COSE envelope and its strict verifier
  internal/tpmsig/fuzz_test.go  # Fuzz malformed encodings and decoding/normalization boundaries
  internal/tpmsig/swtpm.go  # Start, stop and provision classical swtpm instances
  internal/tpmsig/tpmsig.go  # TPM public-key and quote encoding, signing and appraisal
  internal/verifier/binding_regression_test.go  # Binding downgrade, exporter substitution and policy-oracle regressions
  internal/verifier/churn_test.go  # Honest delivery and forced connection churn with recorded server outcomes
  internal/verifier/continuity_final_test.go  # Final five-case software/TPM continuity tests
  internal/verifier/continuity_test.go  # Connection replacement and transport sealing regressions
  internal/verifier/review_regression_test.go  # Strict evidence fields, nonce-session and verifier regressions
  internal/verifier/store.go  # Issued nonce sessions, claim/release state and replay/expiry handling
  internal/verifier/testkit_test.go  # Reusable certificates, servers and signer fixtures for requester tests
  internal/verifier/tpm_e2e_test.go  # TPM-backed verifier integration
  internal/verifier/transport.go  # TLS connection recording, exporters, transport seal and dispatch tracing
  internal/verifier/util.go  # Requester encoding and validation helpers
  internal/verifier/verifier.go  # Requester appraisal and delivery lifecycle; PQ copy has the shared GuardedSend operation
  internal/verifier/verifier_test.go  # Core appraisal, replay and acceptance-rule tests
  internal/wire/fuzz_test.go  # Fuzz malformed encodings and decoding/normalization boundaries
  internal/wire/wire.go  # A2A payload types, closed policy parsing, binding context and URL normalization
  internal/zk/authority.go  # Authorized snapshot history, request contracts and single-use approval ledgers
  internal/zk/bridge.go  # Call prover/verifier subprocesses and validate the image-scoped proof cache
  internal/zk/bridge_cache_test.go  # Proof-cache image isolation and stub-prover controls
  internal/zk/commit.go  # Commitment and journal encoding shared by the Go application
  internal/zk/fixtures.go  # Generate deterministic requests, authority records and synthetic input openings
  internal/zk/http.go  # ZK worker HTTP integration and request handling helpers
  internal/zk/integration_test.go  # Opt-in full matrix integration (requires the relevant lab/proof tools)
  internal/zk/inventory.go  # Declared evaluation inventory and evidence schema
  internal/zk/matrix.go  # Run the 13-fixture, four-policy result-authorization matrix
  internal/zk/oracle.go  # Reverify receipts and reconstruct decisions/approval ledgers from retained evidence
  internal/zk/oracle_arith.go  # Oracle-side independent sums and commitments
  internal/zk/oracle_test.go  # ZK evidence/ledger audit controls; legacy-dependent cases can skip
  internal/zk/policy.go  # Apply V0, VT, VI and VTI to a verified journal and stored request
  internal/zk/pq_smoke_test.go  # Opt-in emulator-backed PQ-to-genuine-ZK smoke test
  internal/zk/pq_transport_test.go  # Bound ZK transport: honest, replacement, refused retry, recovery, unknown and wrong-key cases
  internal/zk/requester.go  # Appraise delivery transport, send zk_task and validate the returned artifact
  internal/zk/requester_root.go  # Install the caller-selected lab CA roots for the ZK requester
  internal/zk/transport_test.go  # C+tls appraisal before delivery, with real HTTPS and server counters
  internal/zk/zk_test.go  # Result contracts, policy decisions, commitments and duplicate suppression
  scripts/build_pq_toolchain.sh  # Fetch pinned wolfSSL/wolfTPM commits and build the emulator and bridge locally
  scripts/cleanup.sh  # Stop the lab processes and clean their process records
  scripts/matrix.sh  # Run the broad classical identity fixture matrix
  scripts/pq_audit_controls.py  # Mutate copies of PQ evidence and assert 17 frozen exit-code expectations
  scripts/pq_matrix.sh  # Run the gated PQ matrix, audit, asserted controls and race tests
  scripts/setup.sh  # Build and provision the disposable local lab
  scripts/smoke.sh  # Small classical identity lab check
  scripts/test.sh  # Classical test-suite wrapper
  scripts/test_pq_runner.sh  # Inject runner-stage failures; use A2AID_RUNNER_TEST_BIN for the real-audit case
  scripts/test_v3final_runner.sh  # Inject failures into the focused classical runner
  scripts/v3final.sh  # Focused classical identity, continuity and audit/test gates
  scripts/zk_oracle_controls.py  # Mutate ZK evidence copies and assert oracle classifications
  tools/pqtpm/LICENSE  # GPLv3 license for the linked C bridge
  tools/pqtpm/Makefile  # Compile the bridge against task-local wolfTPM/wolfSSL static libraries
  tools/pqtpm/README.md  # Bridge protocol, build and device-command explanation
  tools/pqtpm/pqtpm.c  # GPLv3 C bridge: native TPM CreatePrimary, ReadPublic, sign/verify sequence commands
  zk/Cargo.lock  # Exact host dependency resolution
  zk/Cargo.toml  # Rust workspace and pinned crate family
  zk/host/Cargo.toml  # Declare zkprove, zkverify and zkfake binaries and host dependencies
  zk/host/src/bin/zkfake.rs  # Generate explicitly fake receipts for negative controls only
  zk/host/src/bin/zkprove.rs  # Read a witness, build a genuine succinct receipt, return proof/journal and timing
  zk/host/src/bin/zkverify.rs  # Strict verification under the caller-pinned image ID; reject dev mode and malformed inputs
  zk/host/tests/verify.rs  # Rust genuine-receipt, bad-image, tamper and fake-receipt verification tests
  zk/image-id.json  # Machine-readable guest build identifier metadata
  zk/image-id.txt  # Pinned expected guest image identifier
  zk/methods/Cargo.toml  # Guest-build package and risc0-build dependency
  zk/methods/build.rs  # Compile/embed the guest methods through risc0-build
  zk/methods/guest/Cargo.lock  # Exact guest dependency resolution
  zk/methods/guest/Cargo.toml  # Guest crate and hash dependencies
  zk/methods/guest/src/main.rs  # Proved bounded-sum computation; recompute commitment and publish the 61-byte journal
  zk/methods/src/lib.rs  # Expose generated guest ELF and image identifier to the host
  zk/proof-cache/README.md  # Cache layout and why generated cached receipts are not shipped
```

## File index across the three studies

I = classical identity; Z = standalone ZK; P = integrated PQ component. A missing link means the file is not part of that study. Matching paths can differ: the P requester includes the corrected shared guard, and its audit composes the final structural checker. The table describes responsibility, not byte equivalence.

| File | I | Z | P | Responsibility |
|---|---|---|---|---|
| `PQ_CORRECTION_PLAN.md` | - | - | [P](../pq-identity/PQ_CORRECTION_PLAN.md) | Frozen correction plan retained to make its pre-run hash checkable |
| `README.md` | [I](../identity/README.md) | [Z](../zk-component/README.md) | [P](../pq-identity/README.md) | Component-specific setup, policy and measurement instructions |
| `RESULTS_PQ_CORRECTIONS.md` | - | - | [P](../pq-identity/RESULTS_PQ_CORRECTIONS.md) | Before/after validation record for the final corrections |
| `RESULTS_PQ_IDENTITY.md` | - | - | [P](../pq-identity/RESULTS_PQ_IDENTITY.md) | Current PQ outcomes and pointers to retained evidence |
| `SCOPE_AND_LIMITATIONS.md` | [I](../identity/SCOPE_AND_LIMITATIONS.md) | - | - | Classical experiment scope and limits |
| `cmd/a2aid/main.go` | [I](../identity/cmd/a2aid/main.go) | [Z](../zk-component/cmd/a2aid/main.go) | [P](../pq-identity/cmd/a2aid/main.go) | CLI commands; lab CA, enrollment and provisioning; process startup; matrix and audit entry points |
| `go.mod` | [I](../identity/go.mod) | [Z](../zk-component/go.mod) | [P](../pq-identity/go.mod) | Go module, language baseline and direct dependencies |
| `go.sum` | [I](../identity/go.sum) | [Z](../zk-component/go.sum) | [P](../pq-identity/go.sum) | Go dependency checksums |
| `internal/agent/agent.go` | [I](../identity/internal/agent/agent.go) | [Z](../zk-component/internal/agent/agent.go) | [P](../pq-identity/internal/agent/agent.go) | A2A agent executor: challenge responses, synthetic jobs and receipt logging |
| `internal/agent/cose.go` | [I](../identity/internal/agent/cose.go) | [Z](../zk-component/internal/agent/cose.go) | [P](../pq-identity/internal/agent/cose.go) | Construct the classical software-envelope response |
| `internal/agent/zk.go` | - | [Z](../zk-component/internal/agent/zk.go) | [P](../pq-identity/internal/agent/zk.go) | Handle zk_task and return the proof-carrying task artifact |
| `internal/audit/audit.go` | [I](../identity/internal/audit/audit.go) | [Z](../zk-component/internal/audit/audit.go) | [P](../pq-identity/internal/audit/audit.go) | Structural release-evidence checker: event paths, sessions, contexts, connections and receipts |
| `internal/audit/audit_test.go` | [I](../identity/internal/audit/audit_test.go) | [Z](../zk-component/internal/audit/audit_test.go) | [P](../pq-identity/internal/audit/audit_test.go) | Structural checker invariants and corrupted-record cases |
| `internal/cardsig/cardsig.go` | [I](../identity/internal/cardsig/cardsig.go) | [Z](../zk-component/internal/cardsig/cardsig.go) | [P](../pq-identity/internal/cardsig/cardsig.go) | Canonicalize, sign and verify Agent Cards; adapted from the official A2A sample |
| `internal/controller/controller.go` | [I](../identity/internal/controller/controller.go) | [Z](../zk-component/internal/controller/controller.go) | [P](../pq-identity/internal/controller/controller.go) | Local experiment controller, deployment labels, configuration and cooperative event log |
| `internal/ctl/ctl.go` | [I](../identity/internal/ctl/ctl.go) | [Z](../zk-component/internal/ctl/ctl.go) | [P](../pq-identity/internal/ctl/ctl.go) | Client used to call the controller and emit experiment events |
| `internal/gate/gate.go` | [I](../identity/internal/gate/gate.go) | [Z](../zk-component/internal/gate/gate.go) | [P](../pq-identity/internal/gate/gate.go) | Harness signer service; check process labels and route permitted signing requests |
| `internal/gate/gate_env_test.go` | - | - | [P](../pq-identity/internal/gate/gate_env_test.go) | Matched gated software signers and their request contexts |
| `internal/matrix/integration_test.go` | [I](../identity/internal/matrix/integration_test.go) | [Z](../zk-component/internal/matrix/integration_test.go) | [P](../pq-identity/internal/matrix/integration_test.go) | Opt-in full matrix integration (requires the relevant lab/proof tools) |
| `internal/matrix/matrix.go` | [I](../identity/internal/matrix/matrix.go) | [Z](../zk-component/internal/matrix/matrix.go) | [P](../pq-identity/internal/matrix/matrix.go) | Execute scenario-policy cells and the PQ attack/boundary drivers |
| `internal/matrix/races.go` | [I](../identity/internal/matrix/races.go) | [Z](../zk-component/internal/matrix/races.go) | [P](../pq-identity/internal/matrix/races.go) | Deterministic and randomized release-race trials |
| `internal/matrix/reverify.go` | [I](../identity/internal/matrix/reverify.go) | [Z](../zk-component/internal/matrix/reverify.go) | [P](../pq-identity/internal/matrix/reverify.go) | Recheck retained classical appraisals and label what can be recomputed |
| `internal/matrix/runtime.go` | [I](../identity/internal/matrix/runtime.go) | [Z](../zk-component/internal/matrix/runtime.go) | [P](../pq-identity/internal/matrix/runtime.go) | Source/build provenance, dependency and platform metadata, run-path helpers |
| `internal/matrix/summary.go` | [I](../identity/internal/matrix/summary.go) | [Z](../zk-component/internal/matrix/summary.go) | [P](../pq-identity/internal/matrix/summary.go) | Aggregate outcomes by fixture class and policy into tables |
| `internal/matrix/traces.go` | [I](../identity/internal/matrix/traces.go) | [Z](../zk-component/internal/matrix/traces.go) | [P](../pq-identity/internal/matrix/traces.go) | Export compact scenario traces for inspection |
| `internal/pqaudit/pqaudit.go` | - | - | [P](../pq-identity/internal/pqaudit/pqaudit.go) | Composite PQ audit: inventory + structural release checks + signature/context re-verification |
| `internal/pqaudit/pqaudit_test.go` | - | - | [P](../pq-identity/internal/pqaudit/pqaudit_test.go) | Composite audit and real-CLI mutations over the six-cell test fixture |
| `internal/pqdev/fwtpm.go` | - | - | [P](../pq-identity/internal/pqdev/fwtpm.go) | Start/stop temporary firmware TPMs and copy emulator state for the clone control |
| `internal/pqdev/pqdev.go` | - | - | [P](../pq-identity/internal/pqdev/pqdev.go) | Invoke the C bridge; create, read, sign with and evict a device key |
| `internal/pqdev/pqdev_test.go` | - | - | [P](../pq-identity/internal/pqdev/pqdev_test.go) | Opt-in emulator create/sign/negative/restart/evict test |
| `internal/pqsig/acvp_test.go` | - | - | [P](../pq-identity/internal/pqsig/acvp_test.go) | CIRCL/NIST ACVP vectors and invalid ML-DSA signatures |
| `internal/pqsig/bench.go` | - | - | [P](../pq-identity/internal/pqsig/bench.go) | Measure signature sizes and software/device timings |
| `internal/pqsig/pqsig.go` | - | - | [P](../pq-identity/internal/pqsig/pqsig.go) | Canonical proof-v4 context; strict decoding; ML-DSA and ECDSA signing/verification |
| `internal/pqsig/pqsig_test.go` | - | - | [P](../pq-identity/internal/pqsig/pqsig_test.go) | Canonical context, algorithm/key pinning and signature rejection cases |
| `internal/ptv/fuzz_test.go` | [I](../identity/internal/ptv/fuzz_test.go) | [Z](../zk-component/internal/ptv/fuzz_test.go) | [P](../pq-identity/internal/ptv/fuzz_test.go) | Fuzz malformed encodings and decoding/normalization boundaries |
| `internal/ptv/ptv.go` | [I](../identity/internal/ptv/ptv.go) | [Z](../zk-component/internal/ptv/ptv.go) | [P](../pq-identity/internal/ptv/ptv.go) | Encode and validate the PTV-inspired routine envelope, including evidence/proof rules |
| `internal/registry/registry.go` | [I](../identity/internal/registry/registry.go) | [Z](../zk-component/internal/registry/registry.go) | [P](../pq-identity/internal/registry/registry.go) | Resolve enrolled publisher, endpoint, TLS name and proof-key pins |
| `internal/senv/fuzz_test.go` | [I](../identity/internal/senv/fuzz_test.go) | [Z](../zk-component/internal/senv/fuzz_test.go) | [P](../pq-identity/internal/senv/fuzz_test.go) | Fuzz malformed encodings and decoding/normalization boundaries |
| `internal/senv/senv.go` | [I](../identity/internal/senv/senv.go) | [Z](../zk-component/internal/senv/senv.go) | [P](../pq-identity/internal/senv/senv.go) | Classical software-signed COSE envelope and its strict verifier |
| `internal/tpmsig/fuzz_test.go` | [I](../identity/internal/tpmsig/fuzz_test.go) | [Z](../zk-component/internal/tpmsig/fuzz_test.go) | [P](../pq-identity/internal/tpmsig/fuzz_test.go) | Fuzz malformed encodings and decoding/normalization boundaries |
| `internal/tpmsig/swtpm.go` | [I](../identity/internal/tpmsig/swtpm.go) | [Z](../zk-component/internal/tpmsig/swtpm.go) | [P](../pq-identity/internal/tpmsig/swtpm.go) | Start, stop and provision classical swtpm instances |
| `internal/tpmsig/tpmsig.go` | [I](../identity/internal/tpmsig/tpmsig.go) | [Z](../zk-component/internal/tpmsig/tpmsig.go) | [P](../pq-identity/internal/tpmsig/tpmsig.go) | TPM public-key and quote encoding, signing and appraisal |
| `internal/verifier/binding_regression_test.go` | [I](../identity/internal/verifier/binding_regression_test.go) | [Z](../zk-component/internal/verifier/binding_regression_test.go) | [P](../pq-identity/internal/verifier/binding_regression_test.go) | Binding downgrade, exporter substitution and policy-oracle regressions |
| `internal/verifier/churn_test.go` | [I](../identity/internal/verifier/churn_test.go) | [Z](../zk-component/internal/verifier/churn_test.go) | [P](../pq-identity/internal/verifier/churn_test.go) | Honest delivery and forced connection churn with recorded server outcomes |
| `internal/verifier/continuity_final_test.go` | [I](../identity/internal/verifier/continuity_final_test.go) | [Z](../zk-component/internal/verifier/continuity_final_test.go) | [P](../pq-identity/internal/verifier/continuity_final_test.go) | Final five-case software/TPM continuity tests |
| `internal/verifier/continuity_test.go` | [I](../identity/internal/verifier/continuity_test.go) | [Z](../zk-component/internal/verifier/continuity_test.go) | [P](../pq-identity/internal/verifier/continuity_test.go) | Connection replacement and transport sealing regressions |
| `internal/verifier/review_regression_test.go` | [I](../identity/internal/verifier/review_regression_test.go) | [Z](../zk-component/internal/verifier/review_regression_test.go) | [P](../pq-identity/internal/verifier/review_regression_test.go) | Strict evidence fields, nonce-session and verifier regressions |
| `internal/verifier/store.go` | [I](../identity/internal/verifier/store.go) | [Z](../zk-component/internal/verifier/store.go) | [P](../pq-identity/internal/verifier/store.go) | Issued nonce sessions, claim/release state and replay/expiry handling |
| `internal/verifier/testkit_test.go` | [I](../identity/internal/verifier/testkit_test.go) | [Z](../zk-component/internal/verifier/testkit_test.go) | [P](../pq-identity/internal/verifier/testkit_test.go) | Reusable certificates, servers and signer fixtures for requester tests |
| `internal/verifier/tpm_e2e_test.go` | [I](../identity/internal/verifier/tpm_e2e_test.go) | [Z](../zk-component/internal/verifier/tpm_e2e_test.go) | [P](../pq-identity/internal/verifier/tpm_e2e_test.go) | TPM-backed verifier integration |
| `internal/verifier/transport.go` | [I](../identity/internal/verifier/transport.go) | [Z](../zk-component/internal/verifier/transport.go) | [P](../pq-identity/internal/verifier/transport.go) | TLS connection recording, exporters, transport seal and dispatch tracing |
| `internal/verifier/util.go` | [I](../identity/internal/verifier/util.go) | [Z](../zk-component/internal/verifier/util.go) | [P](../pq-identity/internal/verifier/util.go) | Requester encoding and validation helpers |
| `internal/verifier/verifier.go` | [I](../identity/internal/verifier/verifier.go) | [Z](../zk-component/internal/verifier/verifier.go) | [P](../pq-identity/internal/verifier/verifier.go) | Requester appraisal and delivery lifecycle; PQ copy has the shared GuardedSend operation |
| `internal/verifier/verifier_test.go` | [I](../identity/internal/verifier/verifier_test.go) | [Z](../zk-component/internal/verifier/verifier_test.go) | [P](../pq-identity/internal/verifier/verifier_test.go) | Core appraisal, replay and acceptance-rule tests |
| `internal/wire/fuzz_test.go` | [I](../identity/internal/wire/fuzz_test.go) | [Z](../zk-component/internal/wire/fuzz_test.go) | [P](../pq-identity/internal/wire/fuzz_test.go) | Fuzz malformed encodings and decoding/normalization boundaries |
| `internal/wire/wire.go` | [I](../identity/internal/wire/wire.go) | [Z](../zk-component/internal/wire/wire.go) | [P](../pq-identity/internal/wire/wire.go) | A2A payload types, closed policy parsing, binding context and URL normalization |
| `internal/zk/authority.go` | - | [Z](../zk-component/internal/zk/authority.go) | [P](../pq-identity/internal/zk/authority.go) | Authorized snapshot history, request contracts and single-use approval ledgers |
| `internal/zk/bridge.go` | - | [Z](../zk-component/internal/zk/bridge.go) | [P](../pq-identity/internal/zk/bridge.go) | Call prover/verifier subprocesses and validate the image-scoped proof cache |
| `internal/zk/bridge_cache_test.go` | - | [Z](../zk-component/internal/zk/bridge_cache_test.go) | [P](../pq-identity/internal/zk/bridge_cache_test.go) | Proof-cache image isolation and stub-prover controls |
| `internal/zk/commit.go` | - | [Z](../zk-component/internal/zk/commit.go) | [P](../pq-identity/internal/zk/commit.go) | Commitment and journal encoding shared by the Go application |
| `internal/zk/fixtures.go` | - | [Z](../zk-component/internal/zk/fixtures.go) | [P](../pq-identity/internal/zk/fixtures.go) | Generate deterministic requests, authority records and synthetic input openings |
| `internal/zk/http.go` | - | [Z](../zk-component/internal/zk/http.go) | [P](../pq-identity/internal/zk/http.go) | ZK worker HTTP integration and request handling helpers |
| `internal/zk/integration_test.go` | - | [Z](../zk-component/internal/zk/integration_test.go) | [P](../pq-identity/internal/zk/integration_test.go) | Opt-in full matrix integration (requires the relevant lab/proof tools) |
| `internal/zk/inventory.go` | - | [Z](../zk-component/internal/zk/inventory.go) | [P](../pq-identity/internal/zk/inventory.go) | Declared evaluation inventory and evidence schema |
| `internal/zk/matrix.go` | - | [Z](../zk-component/internal/zk/matrix.go) | [P](../pq-identity/internal/zk/matrix.go) | Run the 13-fixture, four-policy result-authorization matrix |
| `internal/zk/oracle.go` | - | [Z](../zk-component/internal/zk/oracle.go) | [P](../pq-identity/internal/zk/oracle.go) | Reverify receipts and reconstruct decisions/approval ledgers from retained evidence |
| `internal/zk/oracle_arith.go` | - | [Z](../zk-component/internal/zk/oracle_arith.go) | [P](../pq-identity/internal/zk/oracle_arith.go) | Oracle-side independent sums and commitments |
| `internal/zk/oracle_test.go` | - | [Z](../zk-component/internal/zk/oracle_test.go) | [P](../pq-identity/internal/zk/oracle_test.go) | ZK evidence/ledger audit controls; legacy-dependent cases can skip |
| `internal/zk/policy.go` | - | [Z](../zk-component/internal/zk/policy.go) | [P](../pq-identity/internal/zk/policy.go) | Apply V0, VT, VI and VTI to a verified journal and stored request |
| `internal/zk/pq_smoke_test.go` | - | - | [P](../pq-identity/internal/zk/pq_smoke_test.go) | Opt-in emulator-backed PQ-to-genuine-ZK smoke test |
| `internal/zk/pq_transport_test.go` | - | - | [P](../pq-identity/internal/zk/pq_transport_test.go) | Bound ZK transport: honest, replacement, refused retry, recovery, unknown and wrong-key cases |
| `internal/zk/requester.go` | - | [Z](../zk-component/internal/zk/requester.go) | [P](../pq-identity/internal/zk/requester.go) | Appraise delivery transport, send zk_task and validate the returned artifact |
| `internal/zk/requester_root.go` | - | [Z](../zk-component/internal/zk/requester_root.go) | [P](../pq-identity/internal/zk/requester_root.go) | Install the caller-selected lab CA roots for the ZK requester |
| `internal/zk/transport_test.go` | - | [Z](../zk-component/internal/zk/transport_test.go) | [P](../pq-identity/internal/zk/transport_test.go) | C+tls appraisal before delivery, with real HTTPS and server counters |
| `internal/zk/zk_test.go` | - | [Z](../zk-component/internal/zk/zk_test.go) | [P](../pq-identity/internal/zk/zk_test.go) | Result contracts, policy decisions, commitments and duplicate suppression |
| `scripts/build_pq_toolchain.sh` | - | - | [P](../pq-identity/scripts/build_pq_toolchain.sh) | Fetch pinned wolfSSL/wolfTPM commits and build the emulator and bridge locally |
| `scripts/cleanup.sh` | [I](../identity/scripts/cleanup.sh) | [Z](../zk-component/scripts/cleanup.sh) | [P](../pq-identity/scripts/cleanup.sh) | Stop the lab processes and clean their process records |
| `scripts/matrix.sh` | [I](../identity/scripts/matrix.sh) | [Z](../zk-component/scripts/matrix.sh) | [P](../pq-identity/scripts/matrix.sh) | Run the broad classical identity fixture matrix |
| `scripts/pq_audit_controls.py` | - | - | [P](../pq-identity/scripts/pq_audit_controls.py) | Mutate copies of PQ evidence and assert 17 frozen exit-code expectations |
| `scripts/pq_matrix.sh` | - | - | [P](../pq-identity/scripts/pq_matrix.sh) | Run the gated PQ matrix, audit, asserted controls and race tests |
| `scripts/setup.sh` | [I](../identity/scripts/setup.sh) | [Z](../zk-component/scripts/setup.sh) | [P](../pq-identity/scripts/setup.sh) | Build and provision the disposable local lab |
| `scripts/smoke.sh` | [I](../identity/scripts/smoke.sh) | [Z](../zk-component/scripts/smoke.sh) | [P](../pq-identity/scripts/smoke.sh) | Small classical identity lab check |
| `scripts/test.sh` | [I](../identity/scripts/test.sh) | [Z](../zk-component/scripts/test.sh) | [P](../pq-identity/scripts/test.sh) | Classical test-suite wrapper |
| `scripts/test_pq_runner.sh` | - | - | [P](../pq-identity/scripts/test_pq_runner.sh) | Inject runner-stage failures; use A2AID_RUNNER_TEST_BIN for the real-audit case |
| `scripts/test_v3final_runner.sh` | [I](../identity/scripts/test_v3final_runner.sh) | [Z](../zk-component/scripts/test_v3final_runner.sh) | [P](../pq-identity/scripts/test_v3final_runner.sh) | Inject failures into the focused classical runner |
| `scripts/v3final.sh` | [I](../identity/scripts/v3final.sh) | [Z](../zk-component/scripts/v3final.sh) | [P](../pq-identity/scripts/v3final.sh) | Focused classical identity, continuity and audit/test gates |
| `scripts/zk_oracle_controls.py` | - | [Z](../zk-component/scripts/zk_oracle_controls.py) | [P](../pq-identity/scripts/zk_oracle_controls.py) | Mutate ZK evidence copies and assert oracle classifications |
| `tools/pqtpm/LICENSE` | - | - | [P](../pq-identity/tools/pqtpm/LICENSE) | GPLv3 license for the linked C bridge |
| `tools/pqtpm/Makefile` | - | - | [P](../pq-identity/tools/pqtpm/Makefile) | Compile the bridge against task-local wolfTPM/wolfSSL static libraries |
| `tools/pqtpm/README.md` | - | - | [P](../pq-identity/tools/pqtpm/README.md) | Bridge protocol, build and device-command explanation |
| `tools/pqtpm/pqtpm.c` | - | - | [P](../pq-identity/tools/pqtpm/pqtpm.c) | GPLv3 C bridge: native TPM CreatePrimary, ReadPublic, sign/verify sequence commands |
| `zk/Cargo.lock` | - | [Z](../zk-component/zk/Cargo.lock) | [P](../pq-identity/zk/Cargo.lock) | Exact host dependency resolution |
| `zk/Cargo.toml` | - | [Z](../zk-component/zk/Cargo.toml) | [P](../pq-identity/zk/Cargo.toml) | Rust workspace and pinned crate family |
| `zk/host/Cargo.toml` | - | [Z](../zk-component/zk/host/Cargo.toml) | [P](../pq-identity/zk/host/Cargo.toml) | Declare zkprove, zkverify and zkfake binaries and host dependencies |
| `zk/host/src/bin/zkfake.rs` | - | [Z](../zk-component/zk/host/src/bin/zkfake.rs) | [P](../pq-identity/zk/host/src/bin/zkfake.rs) | Generate explicitly fake receipts for negative controls only |
| `zk/host/src/bin/zkprove.rs` | - | [Z](../zk-component/zk/host/src/bin/zkprove.rs) | [P](../pq-identity/zk/host/src/bin/zkprove.rs) | Read a witness, build a genuine succinct receipt, return proof/journal and timing |
| `zk/host/src/bin/zkverify.rs` | - | [Z](../zk-component/zk/host/src/bin/zkverify.rs) | [P](../pq-identity/zk/host/src/bin/zkverify.rs) | Strict verification under the caller-pinned image ID; reject dev mode and malformed inputs |
| `zk/host/tests/verify.rs` | - | [Z](../zk-component/zk/host/tests/verify.rs) | [P](../pq-identity/zk/host/tests/verify.rs) | Rust genuine-receipt, bad-image, tamper and fake-receipt verification tests |
| `zk/image-id.json` | - | [Z](../zk-component/zk/image-id.json) | [P](../pq-identity/zk/image-id.json) | Machine-readable guest build identifier metadata |
| `zk/image-id.txt` | - | [Z](../zk-component/zk/image-id.txt) | [P](../pq-identity/zk/image-id.txt) | Pinned expected guest image identifier |
| `zk/methods/Cargo.toml` | - | [Z](../zk-component/zk/methods/Cargo.toml) | [P](../pq-identity/zk/methods/Cargo.toml) | Guest-build package and risc0-build dependency |
| `zk/methods/build.rs` | - | [Z](../zk-component/zk/methods/build.rs) | [P](../pq-identity/zk/methods/build.rs) | Compile/embed the guest methods through risc0-build |
| `zk/methods/guest/Cargo.lock` | - | [Z](../zk-component/zk/methods/guest/Cargo.lock) | [P](../pq-identity/zk/methods/guest/Cargo.lock) | Exact guest dependency resolution |
| `zk/methods/guest/Cargo.toml` | - | [Z](../zk-component/zk/methods/guest/Cargo.toml) | [P](../pq-identity/zk/methods/guest/Cargo.toml) | Guest crate and hash dependencies |
| `zk/methods/guest/src/main.rs` | - | [Z](../zk-component/zk/methods/guest/src/main.rs) | [P](../pq-identity/zk/methods/guest/src/main.rs) | Proved bounded-sum computation; recompute commitment and publish the 61-byte journal |
| `zk/methods/src/lib.rs` | - | [Z](../zk-component/zk/methods/src/lib.rs) | [P](../pq-identity/zk/methods/src/lib.rs) | Expose generated guest ELF and image identifier to the host |
| `zk/proof-cache/README.md` | - | [Z](../zk-component/zk/proof-cache/README.md) | [P](../pq-identity/zk/proof-cache/README.md) | Cache layout and why generated cached receipts are not shipped |

## Fixtures, retained evidence and supporting files

| Path or pattern | What it contains |
|---|---|
| `fixtures/manifest-pq.json`, `predictions-pq.md` | Declared PQ scenarios and expected decisions/recipients |
| `fixtures/pq-audit-controls-expected.json` | Frozen expected classifications for 17 audit controls |
| `fixtures/manifest*.json`, `predictions*.md` | Selectable classical scenario definitions and expectations; version labels describe fixtures, not alternate source releases |
| `fixtures/testdata/pq-mini-run/` | Six-cell evidence fixture for audit and runner regressions |
| `fixtures/zk/requests.json`, `authority.json`, `openings.json`, `predictions.json` | Synthetic task contracts, authorized history, disclosed inputs and ZK expectations |
| `fixtures/zk/legacy-inventory-v1.json` | Explicit inventory for a limited historical replay view |
| `zk/host/testdata/` | Genuine receipt and image identifier used by Rust negative controls |
| `zk/image-id.txt`, `image-id.json` | Locally pinned guest identifier, not a worker-selected value |
| `results/` | Selected observations supporting the paper; [EVIDENCE.md](EVIDENCE.md) explains each repeated file type |
| `.toolchain/`, `bin/`, `run/`, `zk/target/` | Generated locally; excluded from publication |

## Repository-level files

| File | Responsibility |
|---|---|
| `README.md` | Project overview and first check |
| `Makefile` | Short entry points for tests, evidence checks and emulator build/test |
| `scripts/check.py` | Build/test orchestration; audits temporary copies or separate output directories |
| `.gitignore` | Generated-file exclusions, with an exception for Rust `src/bin/*.rs` sources |
| `LICENSE`, `NOTICE` | Apache license and upstream attribution; the C bridge has its own GPLv3 license |
| `docs/REPRODUCING.md` | Prerequisites, exact working directories and fresh-run instructions |
| `docs/PIPELINE.md` | Identity-to-result flow and trust boundaries |
| `docs/EVIDENCE.md` | Output formats and audit interpretation |
| `docs/RESULTS.md`, `THREAT_MODEL.md`, `HARDWARE_AND_PTV.md` | Findings, capabilities and hardware/PTV assumptions |
| `docs/TOOLS.md`, `ATTRIBUTION.md` | Upstream links, versions, code origins and licenses |
| `docs/ARTIFACT_INVENTORY.md`, `PROVENANCE.md`, `OMISSIONS.md` | Which observations are shipped and how publication differs from the research workspace |
| `docs/REVIEW.md`, `SUBMISSION_READINESS.md` | Independent review, performed checks and remaining limits |
| `docs/PROVENANCE_MANIFEST.json` | Hash/size inventory of published files, including Rust executable sources |
| `docs/packaging/check_package.py` | Check declared Rust binaries, source-file guide coverage, links and secret patterns |
| `docs/packaging/test_package.py` | Reproduce missing-Rust-source and broad-Git-ignore packaging failures |
| `docs/packaging/update_manifest.py`, `verify_manifest.py` | Refresh or verify the publication inventory |
| `paper/paper-draft.md` | Editable combined manuscript |
| `paper/main.tex`, `md2tex.py`, `latexmkrc` | Editable TeX, Markdown conversion and compiler setting |
| `paper/README-BUILD.txt` | Direct TeX and Markdown editing workflows |
| `paper/fonts/` | Template fonts and their license |
| `paper/a2a-identity-paper.pdf`, `a2a-identity-latex.zip`, `SHA256SUMS` | Rendered paper, self-contained source and hashes |
| `paper/CLAIM_EVIDENCE_TABLE.md` | Mapping from manuscript claims to retained observations |

The source map is checked by `make package-check`. If a new source file is added, update this guide before refreshing the publication manifest.
