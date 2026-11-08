# RESULTS — ZK integration and evidence-check corrections (8 Nov 2026)

Scope: the findings of `../paper/a2a-identity/REVIEW_ZK_COMPONENT.md`. The guest,
prover and verifier (`zk/`), the fixtures, the frozen predictions and every retained run
are unchanged; the corrections are in the Go transport/worker/matrix/oracle code and
in the reporting. Plan declared first: `ZK_CORRECTION_PLAN.md` (sha256 `850d9f21…`,
recorded with the pre-edit hashes in `results/audit/20261108T105409Z-zkcorr-prefix/`).

## Identities

| item | value |
|---|---|
| pre-edit snapshot | `results/audit/20261108T105409Z-zkcorr-prefix/` (117 files, tarball `9b44cb20…`; `a2aid 67c25ccf…` kept as `a2aid-pre-correction`; `zkprove 803006cd…`, `zkverify c96cd581…`, `zkfake d3928458…`) |
| before-fix reproductions | `results/audit/20261108T105605Z-zk-before-fix/` |
| run-time snapshot (producer of the new run) | `results/audit/20261108T111816Z-zkcorr-snapshot/` (124 files, tarball `7c540bd8…`, `a2aid 8405b852…`; Rust binaries unchanged) |
| **new retained run (evidence schema 2)** | `results/zk/20261108-111817` (`snapshot-id.txt` → the run-time snapshot; `provenance.json` a2aid `8405b852…`) |
| integration rerun | `results/zk-integration/20261108-112143` (log `results/zk/zk-integration-test-corrected.log`) |
| final snapshot (checker as reported here) | `results/audit/20261108T112430Z-zkcorr-final-snapshot/` (tarball `d686e653…`, `a2aid 48592e76…`; differs from the run-time snapshot only in `internal/zk/oracle.go` (classification of a ledgers.json overclaim as incomplete), `internal/zk/oracle_test.go` and `scripts/zk_oracle_controls.py`; the producer code is identical) |
| after-fix oracle controls | legacy view of run `…002724`: `results/audit/20261108T111037Z-zk-oracle-controls-after-legacyview/`; schema-2 run `…111817`: `results/audit/20261108T112131Z-zk-oracle-controls-after-schema2/` |
| legacy replay/audit views of the schema-1 runs | `results/audit/20261108T112526Z-zk-legacy-view-20261108-002724/`, `results/audit/20261108T112527Z-zk-legacy-view-20261108-003306/` (the retained run directories were not written) |
| previous retained runs (schema 1) | `results/zk/20261108-002724`, `results/zk-integration/20261108-003306`, unchanged |

## 1. Before / after

### Unsigned-card dispatch (review P1)
The reviewer's characterization test, compiled against an isolated extraction of the
pre-edit snapshot: **PASS = reproduced** (1 task POST to a trusted-TLS server with an
unsigned card; `…zk-before-fix/unsigned-card-characterization-pre-edit.log`). The same
test against the final snapshot: **FAIL, "did not reproduce: unsigned Agent Card was
rejected before task delivery"** (`…zkcorr-final-snapshot/unsigned-card-characterization-post-fix.log`).
The rejecting regressions are `internal/zk/transport_test.go` (7 tests over real HTTPS
A2A servers with server-side GET/POST counters): valid signed card + enrolled TLS →
1 task POST and a returned result; unsigned card, tampered signed card, card signed by
an unenrolled publisher (unknown kid and impersonated kid), trusted certificate with a
different enrolled name, untrusted certificate → **0 task POSTs**; policies `T+cb`,
`S-env+cb`, `S-env`, `T`, `P+cb`, `C`, `C+url`, `bogus` → refused before any request
(0 GETs, 0 POSTs); request-id mismatch, wrong artifact type, worker error, undecodable
receipt → error and nil bytes.

### Oracle false-clean cases (review P1/P1/P2), actual CLI on copies
Before (pre-edit binary, `…zk-before-fix/oracle-controls-pre-edit/controls.json`) and
after (final binary; legacy view of run `…002724` and schema-2 run `…111817`):

| mutation | before | after (legacy view) | after (schema 2) |
|---|---|---|---|
| unmodified | exit 0, 52 clean | exit 0: 52 agree, 7 expected attack successes | exit 0: 52 agree, 7 expected attack successes |
| all four Z4 rows removed | **exit 0, 48 clean** | exit 2: 4 incomplete | exit 2: 4 incomplete |
| first row duplicated | **exit 0, 53 clean** | exit 2: 1 malformed (two rows for Z1/V0) | exit 2 |
| every receipt file replaced by `not-a-receipt` | **exit 0, 52 clean** | exit 2: 52 malformed (bytes ≠ content address) | exit 2: 52 malformed |
| every `approval_inserted` event neutralized (sequence kept) | **exit 0, 52 clean** (events removed) | exit 2: 23 incomplete (19 claimed inserts without event, 4 Z11 counts unsupported) | exit 2: 42 incomplete (+ ledgers.json unsupported) |

Further after-fix controls (both views unless stated): one receipt file removed → exit
2 (16 incomplete: every evaluation referencing Z1's bytes); row hash pointed at another
retained receipt → exit 1 (evidence mismatch: re-verified journal differs); row journal
altered → exit 1; `proof_valid` true on the corrupted Z9a receipt → exit 1;
`proof_valid` false on the genuine Z1 receipt → exit 1; row expected image id changed
→ exit 2 (rows cannot choose the trust anchor); one approval event neutralized → exit 2;
orphan approval event → exit 1; approval event duplicated → exit 1; approval event
receipt changed → exit 1; prior Z1/V0 approval neutralized before the duplicate
delivery → exit 1 (Z1/V0 disagreement; Z11/V0 count unsupported); approval flag flipped
without an event → exit 2; events truncated mid-line, sequence gap, sequence duplicate →
exit 2 (stream unusable, every evaluation malformed); unknown policy string → exit 2;
null request record → exit 2 (16 incomplete); short challenge hex → exit 2; decision
marker neutralized → exit 1 in the legacy view (its insert becomes an orphan) and exit 2
in schema 2 (insert still attributed by evaluation id, marker missing); malformed
decision row → exit 2. Raw outputs with the binary hash: `controls.json` and one
directory per case in the two control directories.

Two declared outcomes changed in kind, both stated here: "removal" of approval or
marker events is performed by neutralizing the event (keeping its sequence number)
because a real removal leaves a gap that the strict loader already classifies as
unusable; and a ledger dump or row that claims MORE approvals than the events support
is classified as incomplete (claim without evidence), while fewer is a violation.

## 2. What changed

### Transport (`internal/zk/requester.go`)
Closed policy set: only `C+tls` is implemented; everything else returns
`ErrUnsupportedTransportPolicy` before any network activity. After identity `Connect`,
the identity component's own non-proof `Appraise` (signed card under the enrolled
publisher key, endpoint equality, authenticated peer with the enrolled TLS name,
invariant finalization) runs BEFORE `SendMessage`; `Accept == false` →
`ErrTransportRejected`, no task bytes. No nonce session is issued or consumed and the
identity `Release` (synthetic job) is never called. The exchange trace records the
transport verdict (`transport.*`) and `task_sent`. Malformed artifacts, unexpected
type/schema, request-id mismatch, worker-declared error and unusable receipt bytes
return an error and nil bytes. Challenge binding stays a check on the verified journal.

### Proof cache (`internal/zk/bridge.go`, `zk/proof-cache/README.md`)
`Prove` with a cache directory first resolves the local prover build's embedded image
id (`zkprove --image-id`, 64 hex) and fails closed if that is unavailable; entries live
under `proof-cache/v2/<image id>/<sha256(inputs)>.json` and are served only if they
carry that image id, a receipt whose sha256 matches the recorded hash within the size
bound, and a journal for the requested challenge; a fresh prover response is validated
the same way and must report the build's image id. The 20 flat v1 entries (empty image
prefix) are retained and never read. Regression (`bridge_cache_test.go`, labelled unit
tests with stub provers): two builds with identical inputs get separate entries and are
each served only their own; tampered entries (hash, image, bytes, journal, challenge)
are re-proved; a legacy flat entry is never served; an unresolvable build identity
fails closed with a cache and proves without one; a response whose image id differs
from the build is rejected and not cached. The requester's verification anchor remains
its own pinned `zk/image-id.txt`.

### Producer evidence schema 2 (`matrix.go`, `inventory.go`, `policy.go`, `authority.go`)
`run-inventory.json` is written before the lab boots (52 evaluations with evaluation
id `<fixture>/<policy>`, ordinal, request, contract, pinned version, ledger id,
declared expected image id with Z9b's deliberately wrong one, network/reuse flags and
the frozen prediction). Rows carry `evidence_schema: 2`, `evaluation_id`, `ordinal`,
`ledger_id`, `decision_seq`, `approval_seq`. Every evaluation, including a verification
failure, records one `zk_decision` marker; an insert records one `approval_inserted`
event immediately after it inside the same authority critical section (head read →
input check → single-use insert; the mutex scope is unchanged). Ledgers have ids;
`ledgers.json` dumps the final approvals; `run-stats.json` separates A2A exchanges,
worker-reported new proofs, cache hits, new cache files, replayed and fake receipts.
Unknown policy strings are refused by `Evaluate` (`ErrUnknownPolicy`), never run as V0.

### Oracle v2 (`oracle.go`, `oracle_arith.go`, `scripts/zk_oracle_controls.py`)
Completeness and uniqueness against the declared inventory; strict loaders (null or
duplicate request records, bad challenge hex, unknown contracts or policies, malformed
or truncated lines, nonpositive/duplicate/gap/out-of-order sequence numbers); exactly
one marker per evaluation, bound to the row's `decision_seq` and to the ordinal order;
every referenced receipt read with a size bound, hashed, matched to its filename and
the row, and re-verified with the pinned `zkverify` under the INVENTORY's expected
image id (one run per unique pair, 10 for either retained run: 7 verified, 3 rejected);
verifier status and verified journal must equal the row; the ledger is reconstructed
from approval events (attributed by evaluation id, or in the legacy view by adjacency to
the marker) and compared with each row's insert flag, `approval_count_after` and
`ledgers.json`; duplicate suppression is derived from an earlier approval of the same
request in the same ledger, never from the fixture name. Sums, commitments and journal
decoding use the oracle's own routines (equality with the production encodings is
asserted by `TestOracleArithmeticEqualsProduction`); the verifier CLI is a shared,
hash-recorded component, not an independent proof-system implementation. Outcome
classes agree / disagree / violation / evidence_mismatch / incomplete / malformed; exit
0 complete and clean (expected weak-policy attack successes listed: Z3 V0+VI, Z4 V0+VT,
Z5 V0, Z7 V0+VT), 1 observed disagreement/violation/evidence mismatch, 2 incomplete,
malformed or unsupported (1 wins when both). Schema-1 runs are scored only through the
separately identified legacy replay/audit view (`--legacy-inventory
fixtures/zk/legacy-inventory-v1.json`, declared on 2026-11-08 from the plan table, the
predictions and the pinned image id recorded in the run provenance) whose summary lists
its five limitations; without it a schema-1 run is "unsupported" (exit 2).

## 3. New schema-2 run `results/zk/20261108-111817`
Inventory declared 11:18:17Z, before the lab booted (run start 11:18:17.159Z). 9 A2A
exchanges, all 9 with transport verdict accept (signed card kid `A-card-k1` valid,
endpoint equal, TLS peer `a.a2aid.test` = enrolled name), 9 results delivered; 7 new
genuine proofs (worker-reported 22.1–23.6 s), **0 cache hits**, 7 new v2 cache files,
1 replayed receipt (Z3), 1 fake receipt (Z10); Z6 and Z7 byte-identical. **52/52 cells
match the frozen predictions**; wrong-context accepted 3/8, unsafe approvals 5/12,
legitimate denied 0/12. Oracle v2 (schema-2 mode): 52 declared, 52 rows, 52 agree, 0
disagreements, 0 violations, 0 evidence mismatches, 0 incomplete, 0 malformed, 7
expected attack successes, verifier `c96cd581…` matching the run provenance, exit 0.
The opt-in integration test (`A2AID_ZK_INTEGRATION=1`) re-ran matrix + oracle once more
into `results/zk-integration/20261108-112143` with the same counts (7 new proofs, 0
cache hits, 52/52, oracle exit 0; PASS in 169 s).

## 4. Tests
`go test -race -count=1 ./...`: all packages ok (zk: transport 7, cache 5, oracle 2
suites × 13 cases, policy/marker/arithmetic 6; log in the final snapshot).
`cargo test --release` in `zk/`: 4 host tests over the retained genuine receipt (pinned
id equals the embedded guest, verifies, wrong id and flipped byte rejected). The Rust
binaries were not rebuilt (hashes unchanged from the original run).

## 5. Reporting corrections (also appended to `RESULTS_ZK.md`)
1. **Predictions timestamp.** `fixtures/zk/predictions.json` says `frozen_at
   2026-11-08T01:20:00Z`; its file mtime is 01:16:12 local time (UTC+1, i.e. 00:16Z),
   and the failed attempt `results/zk/20261108-002012` (started 00:20:12Z) already
   contains a byte-identical copy (`predictions-frozen.json`, sha256 `b9f0a8df…`, the
   same as today's file). The value was written as local time and mislabeled "Z"; the
   file existed unchanged before the first matrix started. The plan hash
   (`results/zk/PLAN.sha256`, 00:06:31Z) is a separate, correct pre-run record whose
   table already states the intended outcomes. The JSON value itself is not changed.
2. **Snapshot timing.** `results/audit/20261108T003236Z-zk-snapshot` was taken after
   the retained run started (00:27Z); it is linked to the run by hash equality of all
   25 provenance entries, not a pre-run snapshot. The new run's snapshot
   (`…111816Z-zkcorr-snapshot`) was taken before its start (11:18:17Z).
3. **Exchange accounting.** Each matrix has 9 A2A exchanges and 7 newly generated
   proofs; the 52 cells include local reuse/modification appraisals (Z7 reuses Z6's
   bytes and task, Z9a/Z9b re-appraise Z1's bytes, Z11 re-delivers Z1's result). Not 52
   network tasks, not 52 proving trials.
4. **Transport baseline.** After repair the component uses the signed-card /
   enrolled-endpoint / authenticated-TLS baseline (`C+tls`); it does not measure a
   combined TPM+ZK or +cb+ZK defence, and it refuses those policies.
5. **Openings.** The synthetic openings are published (`fixtures/zk/openings.json`);
   they are absent from the journal, not "never published". No empirical privacy
   advantage was measured.
6. **What is tested.** ZK is present in every policy; the experiment measures
   task-context and input-authorization checks over verified journals, not the
   necessity of ZK over signatures. No signature-only arm exists.
7. The original retained run's 52/52 and its central Pinned/Current result stand; the
   defects were in the offline scorer and the transport guard, not in the proof system.

## 6. Remaining assumptions
Trusted: the declared inventory (written by the producer before execution), the fixture
authority history, the openings, the lab CA and registry, the pinned verifier binary,
the serialized ledger. The oracle validates structure and recomputes business
authorization; it does not reimplement RISC Zero. The approval is a simulated row.
Coverage counts are over hand-selected fixtures. No prover identity, honest-agent or
model property is established by a receipt.

## 7. Commands (from `a2a-identity-zkp/`)
```
export RISC0_HOME=$PWD/.toolchain PATH=$PWD/.toolchain/bin:$HOME/.cargo/bin:$PATH
GOFLAGS=-buildvcs=false go build -o bin/a2aid ./cmd/a2aid
bin/a2aid zk-matrix --run-path-file /tmp/zkrun && bin/a2aid zk-oracle --results "$(cat /tmp/zkrun)" --verify-bin zk/target/release/zkverify
bin/a2aid zk-oracle --results results/zk/20261108-002724 --legacy-inventory fixtures/zk/legacy-inventory-v1.json --out results/audit/<ts>-zk-legacy-view   # schema-1 run, read only
python3 -I scripts/zk_oracle_controls.py --bin bin/a2aid --run <run> --out results/audit/<ts>-controls [--legacy-inventory fixtures/zk/legacy-inventory-v1.json] --verify-bin zk/target/release/zkverify
GOFLAGS=-buildvcs=false go test -race -count=1 ./... ; (cd zk && cargo test --release)
```
