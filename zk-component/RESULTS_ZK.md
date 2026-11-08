# RESULTS — proof-carrying A2A task results (RISC Zero component), 8 Nov 2026

Optional component in the `a2a-identity-zkp/` copy of the finalized identity repo
(`a2a-identity/` is untouched). Plan and frozen predictions: `ZK_COMPONENT_PLAN.md`
(sha256 `8d16b2a6…`, `results/zk/PLAN.sha256`) and `fixtures/zk/predictions.json`
(frozen 2026-11-08T01:20Z, copied into the run as `predictions-frozen.json`).

**Research question.** Can an A2A requester reject a genuine proof for the wrong task
or an obsolete input, while accepting a delayed proof for a task that explicitly
requested the historical snapshot? **Measured answer, in this testbed:** yes, when
the relying party checks the verified journal against its own stored request
challenge (task context) and against the trusted authority's commitment under the
request's declared snapshot contract (Pinned vs Current). The same genuine receipt,
byte-identical and with the same challenge, is approved under the Pinned contract
and denied by the input-checking policies under the Current contract (Z6 vs Z7).
This is a reference integration and regression suite over established mechanisms
(task binding, commitments, snapshot contracts), not a novelty claim.

## What was built
* **Guest** (`zk/methods/guest`, RISC Zero zkVM, one fixed image, id
  `4f1e028eacb440660d0a69e4f8ff6aa24724bc62ceaf61cb24a02d67a62e7b8b`, pinned locally
  in `zk/image-id.txt`): private witness = portfolio id, snapshot version, 32-byte
  salt, four bounded u32 holdings (≤ 2^20); it recomputes the commitment
  `SHA-256("a2aid-zk-commit-v1" ‖ 0 ‖ portfolio ‖ 0 ‖ version u32 LE ‖ salt ‖ h1..h4 u32 LE)`
  and the Boolean `sum ≤ 100` (u64 accumulation) and commits the canonical journal
  `schema u32=1 ‖ challenge[16] ‖ commitment[32] ‖ limit u64 ‖ pass u8` (61 bytes).
  Holdings, sum and salt are never published; the guest never accepts a Boolean.
* **Prover / verifier CLIs** (`zkprove`, `zkverify`; JSON on stdin/stdout, bounded
  input/output, exit codes): both refuse to run with `RISC0_DEV_MODE` set; the
  verifier takes the expected image id from the CALLER and rejects fake (dev-mode)
  receipts explicitly before verification; the prover refuses to emit a fake receipt.
  `zkfake` is a labelled test-only tool that produces a dev-mode receipt for the
  rejection control. Receipts are succinct (223,348 bytes), transported base64 in a
  `zk_result` DataPart (bounded at 2 MiB), with content hash.
* **Go** (`internal/zk`, `internal/agent/zk.go`, `wire.ZKTask/ZKResult`,
  `a2aid zk-fixtures | zk-matrix | zk-oracle`): trusted fixture authority (ordered
  commitments, read-only to the worker), requester request store (128-bit challenge,
  contract, authorized version, expected worker, server-assigned A2A task id),
  serialized approval ledger (head read + input check + single-use insert under one
  mutex; linearization point = the ledger insert; an explicit `zk_decision` event is
  recorded there), four policies, subprocess bridge with proof cache, and the offline
  business-decision oracle. Identity commands are unchanged and need no Rust.
* **Transport:** real a2a-go discovery and `SendMessage` over the existing
  authenticated-TLS baseline (`C+tls`, enrolled name `a.a2aid.test`); task id taken
  from the server's `Task`. One requester-side change to the identity code: a
  configurable per-request HTTP timeout (default unchanged at 20 s; 15 min for
  `zk_task`, because the worker proves inside the request).

## Feasibility gate (declared maximum 90 min)
`results/zk/feasibility/feasibility.json`. Task-local toolchain via `rzup` 0.6.0 into
`a2a-identity-zkp/.toolchain` (`RISC0_HOME`; 3.2 GB; cargo-risczero 3.0.6, r0vm 3.0.6,
risc0 rust 1.97.0; host rustc 1.93.0; crates pinned to 3.0.6, `Cargo.lock` sha256
`6aae83af…`). rzup also symlinks `cargo-risczero`/`r0vm` into `~/.cargo/bin` and
registers a `risc0` rustup toolchain (user-level, reversible; no privileged change).
Gate start 2026-11-08T00:05:36Z → first genuine proof 00:17:56Z (**12 min**), proof
wall time 23.6 s on CPU (20 threads, 62 GB RAM, no GPU). Checks on that receipt:
pinned id verifies (13 ms); wrong image id → "claim digest does not match"; flipped
byte → "proof is invalid"; garbage → undecodable; `zkfake` receipt → "fake/dev receipt
rejected" (kind `fake`); `RISC0_DEV_MODE=1` in the environment → both CLIs exit
before doing anything. Journal challenge and commitment equal the request and the
authority's v1 commitment (Go/Rust encodings agree).

## Retained run `results/zk/20261108-002724`
Snapshot `results/audit/20261108T003236Z-zk-snapshot/` (tarball sha256 `8eca03bf…`;
all 25 source files hashed in the run's `provenance.json` match the snapshot; binaries
`zkprove 803006cd…`, `zkverify c96cd581…`, `zkfake d3928458…`, `a2aid 67c25ccf…`).
Two earlier attempts are retained with notes: `20261108-002012` (every delivery timed
out: 20 s identity HTTP timeout < 24 s proof) and `20261108-002316` (52/52 matrix, but
the oracle mis-scored one row through a heuristic decision point; replaced by the
explicit marker).

9 A2A exchanges, 7 new genuine proofs (22.9–23.7 s each, measured at the worker),
1 replayed receipt (Z3, 10 ms round trip), 1 fake receipt (Z10, 43 ms); proof cache
`zk/proof-cache` keyed by image id and all inputs (20 cached proofs across the three
attempts). Z6 and Z7 used the identical receipt `df671004…` and challenge; Z3 replayed
Z1's receipt `f5d06c87…`. Repeated verification is a regression check, not
independent proving trials.

**Matrix: 52/52 cells match the frozen predictions** (13 fixtures × V0/VT/VI/VTI).

| fixture | V0 | VT | VI | VTI | proof valid | pass |
|---|---|---|---|---|---|---|
| Z1 honest Pinned v1 (80 ≤ 100) | ✓ | ✓ | ✓ | ✓ | yes | yes |
| Z2 honest Current at v2 (120 > 100) | – | – | – | – | yes | no |
| Z3 request A's genuine receipt delivered for request B | ✓ | – | ✓ | – | yes | yes |
| Z3P positive control: B's own correctly bound proof | ✓ | ✓ | ✓ | ✓ | yes | yes |
| Z4 B's challenge, REAL proof over obsolete v1, Current at v2 | ✓ | ✓ | – | – | yes | yes |
| Z5 wrong challenge and obsolete v1 under Current | ✓ | – | – | – | yes | yes |
| Z6 delayed Pinned(v1) result after the authority moved to v2 | ✓ | ✓ | ✓ | ✓ | yes | yes |
| Z7 identical bytes and challenge as Z6, Current contract at v2 | ✓ | ✓ | – | – | yes | yes |
| Z8 genuine failing journal, outer metadata claims pass | – | – | – | – | yes | no |
| Z9a one byte flipped in Z1's receipt | – | – | – | – | **no** | – |
| Z9b requester pinned a different image id | – | – | – | – | **no** | – |
| Z10 dev-mode receipt through the production verifier | – | – | – | – | **no** | – |
| Z11 Z1's result delivered a second time | – | – | – | – | yes | yes |

Metrics (denominators = policy-cells in which the condition holds; coverage, not
prevalence): wrong-context receipts accepted **3/8** (V0 and VI in Z3, V0 in Z5);
unsafe approvals with an input not authorized under the contract **5/12** (V0, VT in
Z4 and Z7; V0 in Z5); legitimate approvals denied **0/12**. Every policy approved the
honest historical control Z6 and the positive control Z3P exactly once; Z11 added no
approval under any policy (single-use ledger).

**Offline oracle** (`a2aid zk-oracle`, `oracle.md`): recomputes sums and commitments
from `fixtures/zk/openings.json`, joins the trusted request contracts with the
ordered `zk_decision` / `authority_update` events, and derives each policy's correct
decision without calling the production evaluator or reading its accept flag as
expectation: 52 scored, 0 incomplete, 0 disagreements. Controls on copies
(`oracle-controls/controls.json`): missing request record → incomplete (exit 2);
contract challenge changed → 2 disagreements (exit 1); journal commitment rewritten →
incomplete (no matching opening, exit 2); authority reset reordered before Z7's
decision → 2 disagreements; decision markers removed → incomplete; receipt files
removed → 52 incomplete; recorded approval flag flipped → disagreement; malformed
JSON → exit 2. The oracle trusts the fixture authority history and the openings and
takes receipt validity from the pinned verifier's recorded status.

**Tests.** `go test -race -count=1 ./...`: all packages ok (zk unit tests: encodings,
policy semantics, ledger; oracle over the retained run and without markers).
`cargo test --release` in `zk/`: 4 host tests over the retained genuine receipt
(pinned id equals the embedded guest, verifies, canonical journal, wrong id and
flipped byte rejected). Opt-in networked integration
`A2AID_ZK_INTEGRATION=1 go test -run TestIntegration_ZKMatrixAndOracle ./internal/zk`:
PASS (`results/zk/zk-integration-test.log`); it re-ran the whole matrix over A2A with fresh challenges into `results/zk-integration/20261108-003306` (52/52 cells matched, oracle 52 scored, 0 incomplete, 0 disagreements), i.e. a second independent execution with newly generated proofs.

## Interpretation and limits
* A valid RISC Zero receipt proves that the pinned guest ran on SOME witness whose
  commitment and Boolean appear in the journal. It proves nothing about which machine
  proved, whether the worker is honest, whether the inputs are authoritative or
  current, or the worker's model/program. Combining it with the identity policies
  does not show that the identified device computed locally; proving can be outsourced.
* The decisive observation is Z6/Z7: the proof stays cryptographically valid while
  its authorization to trigger the dependent action changes with the stored contract.
  Z4 is the case a nonce alone cannot fix (fresh challenge, real proof, obsolete input).
* The dependent action is a simulated approval row; no transfer. V0/VT/VI are
  deliberately incomplete controls, not recommended deployments.
* Trusted: the fixture authority history, the openings held by worker and oracle
  (disclosed in `fixtures/zk/openings.json` for reproducibility; not private), the
  guest build and pinned image id, the verifier binary, the lab CA, the serialized
  ledger. Challenge reuse between Z6 and Z7 is a controlled comparison only.
* Timings are from one host (CPU proving, succinct receipts); no performance or
  privacy claim beyond "the journal publishes the Boolean, challenge and commitment".
  The read-to-write race ablation, extra circuits, benchmarks, standards proposal and
  the identity × ZK cross product were not run.

## Commands (from `a2a-identity-zkp/`)
```
export RISC0_HOME=$PWD/.toolchain PATH=$PWD/.toolchain/bin:$HOME/.cargo/bin:$PATH   # task-local toolchain
(cd zk && cargo build --release && ./target/release/zkprove --image-id | python3 -c 'import json,sys;print(json.load(sys.stdin)["image_id_hex"])' > image-id.txt)
GOFLAGS=-buildvcs=false go build -o bin/a2aid ./cmd/a2aid
bin/a2aid zk-fixtures fixtures/zk            # new random salts (changes every commitment)
bin/a2aid zk-matrix --run-path-file /tmp/zkrun && bin/a2aid zk-oracle --results $(cat /tmp/zkrun)
(cd zk && cargo test --release)
GOFLAGS=-buildvcs=false go test -race -count=1 ./...
```

## Addendum (8 Nov 2026, after `REVIEW_ZK_COMPONENT.md`) — corrections; see `RESULTS_ZK_CORRECTIONS.md`
The genuine proofs, the 52/52 matrix and the Pinned/Current result above are unchanged.
The following statements in this file are corrected or qualified:
1. **Transport.** "Real a2a-go discovery and SendMessage over the existing authenticated-TLS
   baseline (C+tls)" was incomplete for the retained run: the ZK requester called identity
   `Connect` (TLS name enforced) but never ran the card appraisal, so an unsigned card would
   have received the task (reviewer reproduction; reproduced again before the fix). Since the
   correction, `Dispatch` runs the full non-proof appraisal (signed card under the enrolled
   publisher key, endpoint equality, enrolled TLS name) before any task bytes and refuses every
   policy other than `C+tls`. The component measures no TPM+ZK or +cb+ZK defense.
2. **Oracle.** The oracle described above (now "v1") scored whatever rows existed: removing a
   fixture (48 clean), duplicating a row (53 clean), replacing every receipt file, or removing
   every approval event still returned exit 0. Oracle v2 validates the declared inventory,
   re-verifies every retained receipt with the pinned verifier, reconstructs the ledgers from
   events and derives duplicate suppression from ledger history. The retained run `…002724`
   and the integration run `…003306` are now scored through the separately identified legacy
   replay view (`results/audit/20261108T11252[67]Z-zk-legacy-view-*`): 52 agree, exit 0, with
   the view's limitations stated. A new schema-2 run `results/zk/20261108-111817` (inventory
   declared first, snapshot `results/audit/20261108T111816Z-zkcorr-snapshot`) reproduces
   52/52 with oracle v2 exit 0.
3. **Proof cache.** "keyed by image id and all inputs" was not true of the worker path: the
   worker never set the image field, so entries were keyed by an empty prefix plus inputs.
   Entries are now stored under `proof-cache/v2/<image id resolved from the prover build>/`;
   the 20 flat entries are retained and never read. The new run had 0 cache hits and 7 new
   proofs (recorded separately in `run-stats.json`).
4. **Predictions timestamp.** `frozen_at 2026-11-08T01:20:00Z` is a local-time value (CET,
   UTC+1) wrongly suffixed `Z`: the file's mtime is 00:16:12Z, the plan hash was recorded at
   00:06:31Z, and a byte-identical copy (sha256 `b9f0a8df…`) sits in the run that started at
   00:20:12Z. The string is left as it is; pre-specification rests on the hashed plan and the
   copies inside the retained runs.
5. **Snapshot timing.** `results/audit/20261108T003236Z-zk-snapshot` was taken after the
   retained run started (00:27:24Z); the 25 matching provenance hashes link it to the run, but
   it is not a pre-run snapshot.
6. **Counting.** Each 52-cell matrix comes from 9 A2A exchanges plus local reuse/modification
   evaluations (Z7, Z9a, Z9b, Z11); "9 A2A exchanges" above is right, "A2A requests dispatched:
   10" in the old summary counted Z7's reused request record.
7. **Openings / scope.** The synthetic openings are published for reproducibility and are
   absent from the journal (not "never published"); no privacy advantage was measured. ZK
   verification is present in every policy; the experiment tests task/input authorization
   checks, not the necessity of ZK over signatures (no signature-only arm).

## Addendum (8 Nov 2026, after `REVIEW_ZK_COMPONENT.md`) — see `RESULTS_ZK_CORRECTIONS.md`
* **Transport.** Before the correction the ZK requester sent the task after identity
  `Connect` alone, which does not reject an invalid card; a trusted-TLS server with an
  UNSIGNED card received the task (reproduced). The requester now runs the full
  signed-card / endpoint / enrolled-TLS appraisal before any task bytes and refuses every
  policy other than `C+tls`; the component never implemented the proof or channel-binding
  handshake and does not measure a TPM+ZK or +cb+ZK defence.
* **Oracle.** The oracle above (v1) scored whatever rows existed and trusted row fields:
  removing a fixture, duplicating a row, replacing every receipt file or removing every
  approval event still returned exit 0 (reproduced). Oracle v2 requires the inventory
  declared before execution, re-verifies the retained receipt bytes with the pinned
  verifier, reconstructs ledgers from events and derives duplicate suppression from
  ledger history; all those cases now exit 1 or 2 as declared. The statement that the
  oracle "does not call the production evaluator" was true, but it did call the
  production commitment/sum helpers; v2 uses its own routines and names the verifier
  CLI as the shared component.
* **Cache.** The worker's proof cache was keyed by an empty image prefix (the image
  field was never set); it is now namespaced by the prover build's resolved image id
  (`proof-cache/v2/<image>/`), entries are validated, and the old flat entries are kept
  but never read.
* **New run** `results/zk/20261108-111817` (evidence schema 2, inventory first,
  snapshot `results/audit/20261108T111816Z-zkcorr-snapshot`): 52/52, oracle v2 exit 0,
  9 exchanges, 7 new proofs, 0 cache hits; integration rerun
  `results/zk-integration/20261108-112143` identical counts. The retained run
  `20261108-002724` is unchanged; its legacy replay/audit view is
  `results/audit/20261108T112526Z-zk-legacy-view-20261108-002724/`.
* **Facts corrected in the text above.** (1) `predictions.json`'s `frozen_at
  2026-11-08T01:20:00Z` is a local-time value mislabeled as UTC: the file's mtime is
  00:16Z and the failed attempt started at 00:20:12Z already contains a byte-identical
  copy; the pre-run plan hash (00:06:31Z) is the correct pre-specification record.
  (2) The 00:32Z snapshot was taken after the 00:27Z run start; hash equality links it,
  it is not pre-run. (3) "9 A2A exchanges, 7 new genuine proofs" is the right count; the
  summary line "A2A requests dispatched: 10" counted Z7's reused request. (4) The
  openings are published for reproducibility and merely absent from the journal; no
  privacy advantage was measured. (5) ZK is present in every policy; the experiment tests
  context/input authorization, not the necessity of ZK over signatures.
