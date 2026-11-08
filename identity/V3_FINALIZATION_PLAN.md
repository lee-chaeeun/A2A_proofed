# V3 finalization plan — close the remaining evidence gaps

Declared before execution on 2026-11-07 (UTC timestamp and SHA-256 of this file are
recorded in `results/audit/<ts>-v3final-prefix/PLAN.sha256`). This is a new plan for
new runs; it is not a retrospective preregistration of the retained v3 runs
(`results/v3-repro/20261107-202528`, `results/v3/20261107-203206`,
`results/v2-postv3fix/20261107-203958`), which stay unchanged together with
`fixtures/manifest-v3.json` and `fixtures/predictions-v3.md`.

## Scope (and what is out of scope)

In scope: accounting corrections, a real structural release-evidence checker with
negative controls, deterministic connection-continuity cases for S-env+cb and
swtpm-backed T+cb with the principal threat-model attacker, a declared churn budget,
a historical pre-fix continuity statement backed either by an adapted v2-archive test
or by an explicit downgrade of the claim, a final hashed snapshot, a narrow rerun, and
a reconciled manuscript. Out of scope: hardware TPMs, model inference, mTLS requester
authentication, containers/OS isolation, ZK proofs, full v1/v2 matrix reruns, long
fuzz campaigns, paid services.

## Starting state (confirmed from retained CSVs, not prose)

* Fixed V3 matrix `results/v3/20261107-203206`: 24 cells, 20 prediction matches,
  **4** misses (V3_S-env+tls, V3_T+tls, V4_S-env+tls, V4_T+tls). Six honest V1 cells
  deliver to A. The generated summary's "0/0 honest" is an F1/F2 label filter.
* Pre-fix reproduction `results/v3-repro/20261107-202528`: 24 cells, 17 matches,
  7 misses = the same four +tls misses plus V3_S-env+cb, V3_T+cb and V4_T+cb
  accepting to B (the reproduced defect; the frozen predictions were post-fix).
* `fixtures/predictions-v3.md` change log says "six" misses; that count is wrong for
  the fixed run and is corrected by an appended, dated addendum (never edited).
* No retained pre-fix continuity (close-then-swap) execution exists under `results/`.
* `audit-release` trusts the recorded accept flag, copies the recipient, hard-codes
  "A", expects a field the matrix schema drops, and its negative control bypasses
  the checking path. Its retained output is kept as a historical artifact.

## Capabilities (attacker model used by every new case)

* **F15 / principal threat model**: B holds A's server TLS certificate and private
  key, can be placed at A's name by the resolver, can contact honest A, has **no**
  proof key and **no** signer access. Used for close-then-swap, split-connection and
  churn.
* **Cert-swap**: the replacement server presents a different certificate, valid under
  the lab root for the *other* enrolled name (`b.a2aid.test`), or a self-contained
  certificate for A's name that the requester's root does not trust.
* **Existing test** (`TestContinuity_ProofConnectionPinned`) keeps its stronger B
  (A's certificate **and** A's software signer) and is relabelled accordingly.
* Honest cases use A only. Stolen TLS credentials remain an explicit escalation over
  the secured TLS baseline.

## Test cases and expected outcomes

### 1. Accounting and prediction schema
* New manifest `fixtures/manifest-v3-final.json` with explicit per-fixture `class`
  (`honest` | `malicious` | `ablation`) and, per policy, a separate
  `expected_decision` (accept/reject) and `expected_recipient` (A/B/none).
  Expected: identical decisions and recipients to the retained fixed run (6 honest
  → A; V2 +cb reject; V3/V4 +cb reject; V3/V4 +tls reject with recipient none;
  C and +tls cells of V2 → B). The four former "misses" are now *predicted* as
  reject/none and explained as attack-script self-defeat; V2 is the attack that
  succeeds under +tls.
* Summary counts honest rejections from the `class` field, reports decision match
  and recipient match separately, and the per-version attribution.

### 2. Release-evidence checker (`a2aid audit-release`, new implementation)
Instrumentation per decision (exported in `decision.json` and emitted to the
controller): stable `decision_id`; expected enrolled deployment (label and enrolled
deployment id from the registry); policy, action, audience, nonce (session id);
job token; per-connection records (`conn_id`, requester-observed peer-certificate
SHA-256, exporter hex, dial sequence); requester-local ordered events with sequence
numbers (`connect`, `card_fetched`, `challenge_sent`, `proof_received`,
`appraised`, `authorized`, `sealed`, `dispatch_attempt`, `sent`,
`refused_reconnect`, `ack`, `unknown_outcome`) each carrying the `conn_id` where
applicable; server receipts (`job_received`) carrying token, recipient label and
deployment id, and the receiving connection's own exporter hex.

Checker (no call into `Appraise`/`finalize`; joins by ids): for every decision in
the declared run inventory
* authorization precedes dispatch_attempt precedes sent in requester sequence;
* dispatch connection == proof connection (the connection whose exporter the proof
  was checked against; for non-+cb the connection that carried the proof), and its
  peer certificate equals the discovery connection's peer certificate under +tls;
* every receipt joins a token of that decision, names the expected enrolled
  deployment (derived from the decision's expected label through the registry, never
  a literal), and its server-side exporter equals the requester's dispatch
  connection exporter when both are present;
* refused reconnect ⇒ no `sent`, no receipt; rejected decision ⇒ no token, no
  dispatch, no receipt (verified non-dispatch); `sent` without receipt ⇒
  insufficient evidence; one business release per token; malformed JSON, unknown
  policy, missing joins, missing cells ⇒ explicit non-clean categories.
* Trust classes per check: `recomputed` (equality/order over retained records),
  `requester_tls_observation`, `cooperative_event`, `copied_appraisal` (the
  recorded accept flag; conditional). Cross-process order beyond causal ids is
  stipulated by the trusted controller and is labelled so.
* Exit status: 0 clean; 1 any violation; 2 no violation but insufficient evidence,
  unsupported historical schema, malformed input or inventory mismatch.

Negative controls run as mutated **copies** through the same checker entry point the
CLI uses: missing receipt for a sent dispatch (expect insufficient, exit 2); missing
connection evidence (insufficient, 2); wrong recipient (violation, 1); dispatch on a
different connection (violation, 1); changed context between authorization and
dispatch (violation, 1); removed authorization (violation, 1); reordered requester
events (violation, 1); duplicate business release (violation, 1); malformed JSON
(malformed, 2); missing cell versus inventory (incomplete, 2); legitimate rejected
attempt with no dispatch (clean, 0); the retained v3 run with the old schema
(unsupported historical schema, 2). The unmodified final run must be clean (0).

### 3. Continuity coverage (S-env+cb and swtpm-backed T+cb, real SDK HTTPS)
Barriers are requester hooks at `after-connect`, `after-appraise` and
`before-dispatch` (nil in production), plus bounded waits on receipt channels.
A and B each keep a receipt log (token, exporter, time); delivery is asserted from
those logs, never from `JobReleased` alone.
1. Uninterrupted honest proof and receipt at A. Expect: one A receipt whose exporter
   equals the requester's dispatch connection exporter; no B receipt.
2. Valid proof at A; forced close before task send; next dial mapped to B (TLS
   cert/key only). Expect: `refused_reconnect` before any task bytes, no B receipt,
   no A receipt, dials counted.
3. Discovery and proof separated onto two connections (close after discovery).
   Expect, documented: either fail-closed rejection at appraisal (two distinct
   exporters in one decision) or acceptance with dispatch pinned to the proof
   connection; stale first-connection evidence never authorizes dispatch.
4. Connection replacement with a different certificate / enrolled name. Expect:
   sealed requester refuses before dialing (layer = seal); the no-seal **ablation**
   (labelled, not production) is refused by TLS name validation (layer = tls).
5. Honest close before dispatch, then a NEW decision with fresh challenge and proof
   to A. Expect: decision 1 refused pre-send with no receipt; decision 2 delivers
   exactly one A receipt; A's log holds exactly one token overall.
Churn: 60 trials per defended policy (S-env+cb, T+cb), half with the proof
connection closed before dispatch; count attempts, accepted appraisals, dispatch
attempts, refused reconnects, sent, A receipts (from the server log, matched to
tokens), B receipts, acks and errors. Expect: A receipts == uninterrupted trials,
B receipts == 0, refused == interrupted trials. If T+cb churn cannot complete it is
reported as untested, not substituted.

Historical P0-B: adapt a minimal close-then-swap test to the archived v2 source
(`results/audit/20261107T191625Z-v2snapshot/source-v2.tar.gz`, sha256
`4d5b73cf…`) in an isolated temporary tree; record file hashes, capabilities (TLS
cert/key only) and the outcome. If the v2 code delivers to B, that is the pre-fix
reproduction; if the adaptation is impractical, the claim stays "identified by
inspection; fixed path regression-tested".

### 4. Final snapshot, rerun, manuscript
* Snapshot all source, tests, fixtures, scripts, `go.mod`/`go.sum`, plans and
  docs (no `run/`, `results/`, `bin/`, credentials) as a tarball with per-file
  SHA-256; build `bin/a2aid` with `-trimpath` from the tree and from the extracted
  snapshot and record both hashes.
* Rerun only: the 24-cell V3 subset with `manifest-v3-final.json` into
  `results/v3-final/`; continuity and churn tests writing evidence under the same
  run directory; the checker over the matrix run, the continuity evidence and the
  negative-control suite; `go test -race -count=1 ./...`; the opt-in
  `A2AID_INTEGRATION=1` and swtpm-backed checks, reporting skipped vs passed.
* Budget: one matrix rerun (≈1 min), one continuity/churn pass (≤ 2 × 60 trials),
  one test pass, at most two retries for environment failures (retained as failed
  attempts). No full v1/v2 reruns, no fuzz.
* `RESULTS_V3_FINAL.md` with exact counts, identities and a claim-to-evidence table;
  README and `SCOPE_AND_LIMITATIONS.md` updates; `paper-draft.md` first, then
  `main.tex` and the PDF, with the current PDF/TeX preserved under
  `v3-reviewed-md-only/` before overwrite.

## Evidence needed before any claim is stated
Matrix CSV/JSONL and per-cell records for the rerun; continuity evidence directory
with per-case decision records and both receipt logs; checker output (JSONL,
summary, exit codes) for the clean run and every negative control; test logs with
pass/skip per test; snapshot hashes linked from the run's provenance.
