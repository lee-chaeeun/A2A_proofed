# ZK correction plan — transport enforcement, oracle completeness, receipt binding, ledger reconciliation, cache identity

Declared 2026-11-08 (UTC) before any corrected result was collected, in response to
`../paper/a2a-identity/REVIEW_ZK_COMPONENT.md`. Working tree `a2a-identity-zkp/`;
`a2a-identity/` stays unchanged. Pre-edit snapshot:
`results/audit/20261108T105409Z-zkcorr-prefix/` (117 source/test/fixture/script/doc
files, tarball sha256 `9b44cb20…`, binaries `a2aid 67c25ccf…`, `zkprove 803006cd…`,
`zkverify c96cd581…`, `zkfake d3928458…`; a copy of the pre-edit `a2aid` is kept there
as `a2aid-pre-correction`). This file's sha256 is recorded in the same directory
once frozen. Original runs (`results/zk/20261108-002724`,
`results/zk-integration/20261108-003306`, the two failed attempts, the feasibility
directory, `results/reviewer-zk/…`), `fixtures/zk/predictions.json`, the openings and
the authority are not modified; new outputs go to `results/audit/…` and to a new
versioned run directory.

Not in scope: new circuit, guest change, dataset, model call, Adaption spending,
cloud proving, hardware, identity × ZK cross product, signature-only arm, paper /
TeX / PDF / converter / ZIP edits (pending notes only).

## 1. Before-fix reproductions (on copies, with the pre-edit binary and source)
1. Unsigned-card dispatch: the reviewer's characterization test compiled against an
   isolated extraction of the pre-edit snapshot. Expected: PASS = the undesired POST
   was observed (1 task POST, dispatch error only from the server's deliberate 500).
2. Four false-clean oracle cases through the pre-edit `a2aid zk-oracle` on copies of
   the retained run: remove all Z4 rows → 48 scored clean, exit 0; duplicate the first
   row → 53 scored clean, exit 0; replace every receipt file with `not-a-receipt` →
   52 clean, exit 0; remove every `approval_inserted` event → 52 clean, exit 0.

## 2. Intended fixes

### 2.1 Transport (`internal/zk/requester.go`)
* Supported transport policy is exactly the declared baseline `C+tls`. Any other
  value (including `C`, `C+url`, `T+cb`, `S-env+cb`) is refused before any network
  activity with an explicit error; the component does not implement the identity
  proof / channel-binding handshake and never labels Connect-only traffic as
  attested or channel-bound.
* After identity `Connect`, the full non-proof appraisal (`Appraise` with an empty
  nonce, which performs the signed-card, enrolled-publisher, endpoint-equality and
  enrolled-TLS-name checks and `finalize`) runs BEFORE the `zk_task` is sent. It
  issues or consumes no nonce session and never calls `Release`, so the identity
  component's synthetic job is never dispatched. `Accept == false` → no task POST.
* The exchange record carries the transport verdict (card present/valid/kid,
  endpoint equality, TLS authenticated / name match, accept, failure stage).
* Malformed artifacts, unexpected artifact type/schema, request-id mismatch and
  unusable receipt bytes return an error AND no receipt bytes. Challenge/context
  binding remains a check on the verified journal; trusted outer metadata is never
  a substitute.

### 2.2 Proof cache (`internal/zk/bridge.go`, `internal/agent/zk.go`)
* Before any cache lookup the bridge resolves the trusted local prover build's
  embedded image id (`zkprove --image-id`), validates it (64 hex) and uses it as the
  cache namespace: `proof-cache/v2/<image-id>/<sha256(inputs)>.json`. If a cache
  directory is configured and the build identity cannot be resolved, `Prove` fails
  closed. Cached entries are accepted only if `ok`, `image_id_hex` equals the resolved
  id, the receipt decodes within the size bound, its sha256 equals the recorded hash
  and the journal parses with the request's challenge. The fresh prover response is
  validated the same way. The requester's verification anchor is unchanged (its own
  pinned `zk/image-id.txt`), never the worker's claimed id.
* The 20 existing flat (`v1`, unqualified) entries are left in place and never read;
  this is stated in the cache directory README.

### 2.3 Producer evidence schema 2 (`matrix.go`, `policy.go`, `authority.go`)
* `run-inventory.json` is written BEFORE the lab boots: the 52 expected evaluations
  (13 fixtures × 4 policies) with `evaluation_id` (`<fixture>/<policy>`), ordinal,
  request id, contract, pinned version, ledger id, declared expected image id
  (pinned for all, the deliberately wrong id for Z9b), whether the fixture performs a
  network exchange, reuse links (Z7 → Z6, Z11 → Z1, Z9a/Z9b → Z1's bytes) and the
  frozen prediction.
* Each decision row carries `evidence_schema: 2`, `evaluation_id`, `ordinal`,
  `ledger_id`, `decision_seq` (the sequence number of its `zk_decision` marker) and
  `approval_seq` (0 when nothing was inserted). The `zk_decision` and
  `approval_inserted` events carry `evaluation_id` and `ledger_id`; the marker and
  the insert are consecutive events inside the same authority critical section
  (head read → input check → single-use insert; unchanged atomicity).
* Ledgers have ids; the shared Z1/Z11 ledger group and the per-fixture isolation are
  declared in the inventory. The run writes `ledgers.json` (final approvals per
  ledger) and records cache hits separately from newly generated proofs.
* Unknown policy strings are refused by `Evaluate` (error), never evaluated as V0.

### 2.4 Oracle v2 (`oracle.go`, new helpers)
Inputs: inventory, rows, requests, events, receipts, openings, the pinned verifier
binary (reused, recorded by sha256; not an independent proof-system implementation)
and small independent arithmetic/commitment routines (tested equal to the production
helpers on vectors; the scorer does not call the production helpers or `Evaluate`).
Checks, each with a declared outcome class:
* Inventory: schema, 52 unique keys, known fixtures/policies, exactly one row per key;
  missing / duplicate / unexpected / unknown → `incomplete` or `malformed` (exit 2).
* Request records: non-null, unique ids, 32-hex challenge, known contract, pinned
  version ≥ 1; rows must reference a declared request with the inventory's request
  id and contract.
* Events: positive, strictly increasing, gap-free sequence numbers; scanner errors
  and malformed lines → exit 2; exactly one `zk_decision` marker per evaluation id,
  matching the row's `decision_seq`, fixture, policy, request and ledger.
* Receipts: every referenced file read with a size bound, sha256 recomputed and
  required to equal the filename and the row; the pinned verifier re-run once per
  unique (receipt hash, declared expected image id) pair with an in-audit cache;
  status and, on success, verified journal bytes must equal the row; the expected
  image id comes from the inventory, never from the row (a row whose id differs from
  the declared one is `malformed`).
* Ledger: approvals reconstructed per ledger from `approval_inserted` events; an
  observed approval requires its insert event immediately after its marker with
  matching evaluation, request, policy, receipt hash, ledger and commitment; a
  denied/suppressed evaluation requires its absence; orphan or duplicate insertions,
  field mismatches and `approval_count_after` ≠ reconstructed count are violations.
  Duplicate suppression is DERIVED: an evaluation whose policy semantics approve but
  whose ledger already holds an approval for the request (from earlier events) must
  insert nothing; nothing is keyed on the fixture name `Z11`.
* Exit codes: 0 = complete, well-formed, no disagreement or violation (expected
  weak-policy attack successes are counted and listed, not hidden); 1 = observed
  disagreement, violation or evidence contradiction (verifier status/journal/hash
  differ from the row, false `proof_valid`); 2 = incomplete, malformed or
  unsupported evidence. 1 takes precedence over 2 in the exit code; both counts are
  always printed.
* Legacy (schema 1) runs: a separately identified replay/audit view
  (`--legacy-inventory fixtures/zk/legacy-inventory-v1.json`, declared from the
  original plan table and predictions) joins markers by declared ordinal, takes
  ledger grouping from the declared inventory and joins approvals by adjacency; its
  summary names these limitations and the producer schema. No historical field is
  invented; outputs go under `results/audit/`, never into the retained run.

## 3. Expected control outcomes (after the fix)
Transport (local HTTPS A2A servers with request counters): valid signed card +
enrolled TLS → task POST 1, result returned; trusted TLS + unsigned card → 0 task
POSTs, error names the card; tampered signed card → 0; card signed by an unenrolled
publisher → 0; trusted certificate for a different name → 0 (connect-tls); untrusted
certificate → 0 (handshake); policies `T+cb`, `S-env+cb`, `C`, `C+url` → 0 requests
of any kind, explicit refusal. Malformed artifact / request-id mismatch → error and
nil bytes.

Oracle, through the actual CLI on copies (legacy view of the retained run and the
new schema-2 run): unmodified → exit 0, 52 scored, 0 incomplete, 0 violations;
Z4 rows removed → exit 2 (4 missing); duplicated row → exit 2; receipts replaced
(same filename) → exit 2 (hash ≠ filename, 52 affected); one receipt file removed →
exit 2; row receipt hash changed to another retained receipt → exit 1 (verified
journal differs); row journal altered → exit 1; `proof_valid` flipped true on Z9a →
exit 1; `proof_valid` flipped false on Z1 → exit 1; row expected image id changed →
exit 2; all approval events removed → exit 2 (claimed approvals without insert
events); one approval event removed (Z1/VTI) → exit 2; orphan approval event added →
exit 1; approval event duplicated → exit 1; approval event request/policy/receipt
changed → exit 1; prior approval removed before the duplicate delivery (Z1/V0
insert deleted) → exit 1 or 2 (Z1/V0 claimed insert lacks its event → incomplete;
with the row flag also cleared the Z11/V0 non-insert becomes a disagreement → 1);
events truncated mid-line → exit 2; sequence renumbered with a gap or duplicate →
exit 2; unknown policy string in a row → exit 2; null request record → exit 2.

Cache (unit tests with labelled stub provers): same inputs under two stub builds
yield two separate entries, each build is served only its own; a tampered cached
receipt hash forces re-proving; a legacy flat entry is never read; a prover whose
image id cannot be resolved fails closed when a cache directory is set.

## 4. Bounded validation
* `go test -race -count=1 ./...` (new transport, cache, oracle and arithmetic
  tests; the oracle tests reuse the retained genuine receipts and the built pinned
  verifier and skip when absent).
* `cargo test --release` in `zk/` (unchanged guest/verifier; four host tests).
* Oracle controls above via `scripts/zk_oracle_controls.py` with the rebuilt binary,
  results under `results/audit/<ts>-zk-oracle-controls-after/`, plus the before-fix
  reproduction under `…-before/`.
* One new schema-2 matrix run (`results/zk/<new-run>/`, inventory first, linked to a
  post-edit snapshot) and its oracle; proofs are regenerated only because challenges
  are fresh per request (cache hits and new proofs are counted separately). The
  opt-in integration test re-runs matrix + oracle once more.
* Reporting: `RESULTS_ZK_CORRECTIONS.md`, dated addenda in `RESULTS_ZK.md`, README,
  and pending notes in `../paper/a2a-identity/PAPER_CORRECTIONS_PENDING.md`.
