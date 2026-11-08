# PQ identity correction plan (frozen before editing, 8 November 2026)

Scope: the two P1 findings and the P2 wording findings of
`paper/a2a-identity/REVIEW_PQ_IDENTITY.md`, plus the runner defect (`audit-pq ... || true`)
and the non-asserting mutation script. No new algorithm, arm, scenario or dataset. The
native emulator ML-DSA demonstration (gate evidence `results/audit/20261108T130125Z-pq-gate/`)
is not touched. Retained runs, frozen predictions and `fixtures/manifest-pq.json` are not
rewritten; a corrected run produces new records under new paths.

## Pre-edit state (recorded in `results/audit/<ts>-pqcorr-prefix/`)
* source hashes of the research tree (`sha256-source.txt`), snapshot tarball of source,
  fixtures, scripts, tools and the manuscript (`source-pre-correction.tar.gz`);
* the pre-edit binary `bin/a2aid` (sha256 `4a7b1634…`) copied as `a2aid-pre-correction`;
* reproduction of the reviewer's transport characterization (overlay test against the
  research `internal/zk`, pre-edit source): PASS = the undesirable delivery reproduced;
* reproduction of the seven reviewer evidence mutations with the pre-edit binary: all exit 0;
* `audit-release` v2 on an unmodified copy of the final run: exit 2 (32 unsupported).

## Corrections
1. **Guarded send for the ZK task (bound transports).** Extract the identity requester's
   release guard (single-use authorization per issued session, typed authorization and
   dispatch contexts, transport seal, pre-send connection check, refused reconnect,
   unknown-outcome classification, connection-id tracing) into one `GuardedSend` used by
   both the synthetic-job `Release` and the ZK requester for `PQ-device+cb`. The ZK task
   is the only message sent; no synthetic job. A client error after the request was
   written is reported as "unknown", never as "not delivered"; tests resolve it with
   server counters. Recovery = a new `Dispatch` (new connection, new nonce, new proof, new
   decision). The `C+tls` ZK baseline keeps its documented semantics (card/endpoint/TLS
   appraisal, no nonce session, no seal).
2. **Composite PQ audit (`audit-pq` v2).** Per declared cell: strict loading of
   inventory, decision records, sessions and controller events (any parse error ->
   malformed, never ignored); the structural release invariants of checker v2 (events,
   multiplicity, ordering, tokens, connection continuity, typed contexts, session join,
   receipt joins by decision id + token + exporter, receipt multiplicity, release
   cardinality, duplicate decision ids, orphan receipts, inventory coverage) composed
   with proof re-verification under the registry (algorithm/kid pin, strict context
   decode, expected context rebuilt from the issued session, expiry window relative to a
   *parsed* appraisal time inside the session's validity, signature). Typed timestamps:
   an unparseable `appraised_at` is malformed. Records that lack the schema-2 fields are
   `unsupported` (never upgraded). Exit codes keep their meaning: 0 complete and clean
   (declared attacker deliveries listed), 1 disagreement/violation/orphan/duplicate,
   2 incomplete/malformed/unsupported (1 wins).
3. **Producer adjustments needed for the composite audit to apply to every path**
   (recorded schema stays 2; new records are "evidence schema 2, producer revision 2"):
   early rejections (connect failure) now carry the typed decision context; the
   concurrent-delivery and nonce-burn drivers go through the same lifecycle helpers as
   `Run` (schema, id, context, challenge/proof/appraised events) instead of hand-built
   decisions. Old records are read by the same checker and classified unsupported where
   they lack fields; they are not edited.
4. **Runner gates.** `scripts/pq_matrix.sh` fails on build/setup/matrix/audit/controls/test
   failure (no `|| true`), validates the run-path handoff, cleans its temp file by trap;
   the mutation script asserts every expected exit code from a frozen expectation table
   and exits non-zero on any mismatch; `scripts/test_pq_runner.sh` injects failures with
   stubs (audit rejection; a control that unexpectedly exits clean; failed matrix).
5. **Descriptions.** Signed context: same field coverage, measured per-arm byte lengths
   from the corrected run; the 306-byte benchmark message is labelled as such. Registry
   `Version`: described as a label; what is enforced is the pinned algorithm, key id and
   public key (X4 = enrolled key id and version label changed; rejection at the kid
   stage). No rotation/revocation protocol claimed.
6. **Public emulator build.** `a2a-proof-binding-public/pq-identity/scripts/build_pq_toolchain.sh`
   run once from the public copy into its own `.toolchain/` (logs, CMake caches, commits,
   binary hashes retained under `results/audit/<ts>-public-toolchain-build/`); then the
   opt-in device test against that backend.

## Expected classifications of the audit controls (frozen before running them on corrected evidence)
| control | expected exit |
|---|---|
| unmodified | 0 |
| removed cell | 2 |
| duplicate decision record | 1 (duplicate decision id and declared count both fail; 1 wins) |
| altered context bytes (accepted decision) | 1 |
| changed signature (accepted decision) | 1 |
| substituted registry public key | 1 |
| proof removed, accept kept | 1 |
| unknown algorithm label | 2 |
| policy downgrade in a decision | 1 (inventory/decision policy contradiction) |
| forged accept flag on a rejected cell | 1 |
| R1 remove all requester events (accepted bound delivery) | 2 (unsupported: no auditable event record) |
| R2 dispatch connection 999, reused=false | 1 |
| R3 dispatch context action changed | 1 |
| R4 issued sessions removed | 2 (required record missing) |
| R5 appraisal time `not-a-time` | 2 (malformed typed timestamp) |
| R6 duplicated job_received receipt | 1 |
| R7 receipt decision id, token, exporter changed | 1 (orphan receipt; sent dispatch without receipt) |

## Rerun budget and acceptance
* At most two corrected matrix attempts plus one integration rerun; every attempt retained.
* Predictions for all 128 cells unchanged (`fixtures/predictions-pq.md`, `manifest-pq.json`).
* Accept when: the corrected ZK path refuses the connection replacement with zero task
  receipts at the replacement (server counter) while honest delivery and fresh-decision
  recovery deliver exactly once; the composite audit exits 0 on the corrected final run
  and the rerun, and all seventeen controls return their expected codes; the runner's
  failure-injection tests return non-zero at each injected stage; `go test -race` passes;
  the opt-in device test passes against the public-copy build; the genuine-receipt
  PQ-device+cb smoke test (one honest, one impostor) passes.
