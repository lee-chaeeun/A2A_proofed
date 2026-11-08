# a2a-identity-zkp — the identity testbed plus an OPTIONAL proof-carrying task-result component

This directory is a copy of the finalized `../a2a-identity/` (which stays untouched) with
one added, separately runnable component: RISC Zero proof-carrying A2A task results
(`internal/zk`, `zk/`, `fixtures/zk`, `a2aid zk-*`). Every identity command below works
without Rust or the prover installed. See `RESULTS_ZK.md` and `ZK_COMPONENT_PLAN.md`.

## ZK component (optional)

Dependencies (task-local; no privileged change): Rust 1.93 host toolchain via rustup,
`rzup` 0.6.0 downloaded into `.toolchain/bin`, `RISC0_HOME=$PWD/.toolchain` with
cargo-risczero 3.0.6, r0vm 3.0.6 and the risc0 rust 1.97.0 guest toolchain (rzup also
symlinks `cargo-risczero`/`r0vm` into `~/.cargo/bin` and registers a `risc0` rustup
toolchain; 3.2 GB). Crates pinned to risc0 3.0.6 (`zk/Cargo.lock`). CPU proving:
≈24 s per succinct proof on this host, 16 GB RAM recommended by RISC Zero.

```bash
export RISC0_HOME=$PWD/.toolchain PATH=$PWD/.toolchain/bin:$HOME/.cargo/bin:$PATH
(cd zk && cargo build --release && ./target/release/zkprove --image-id | python3 -c 'import json,sys;print(json.load(sys.stdin)["image_id_hex"])' > image-id.txt)
GOFLAGS=-buildvcs=false go build -o bin/a2aid ./cmd/a2aid
./scripts/setup.sh                                   # identity lab (A is the ZK worker)
bin/a2aid zk-matrix --run-path-file /tmp/zkrun       # writes run-inventory.json FIRST, then 13 fixtures × 4 policies over real A2A HTTPS
bin/a2aid zk-oracle --results "$(cat /tmp/zkrun)"    # oracle v2 (exit 0 clean / 1 disagreement, violation, evidence mismatch / 2 incomplete, malformed, unsupported)
bin/a2aid zk-oracle --results results/zk/20261108-002724 --legacy-inventory fixtures/zk/legacy-inventory-v1.json --out results/audit/<ts>-legacy-view   # schema-1 runs: separately identified replay view
python3 -I scripts/zk_oracle_controls.py --bin bin/a2aid --run <run> --out results/audit/<ts>-controls --verify-bin zk/target/release/zkverify   # 25 mutation controls on copies
```

Transport: the requester delivers `zk_task` only after the full `C+tls` appraisal (signed
Agent Card under the enrolled publisher key, endpoint equality, authenticated TLS peer with
the enrolled name); every other identity policy is refused before any network activity. The
component does not run the TPM / channel-binding handshake.

Outputs: `results/zk/<run>/` with `run-inventory.json` (declared before execution),
`decisions.{csv,jsonl}` (evidence schema 2: evaluation id, ledger id, decision/approval
sequence links), `requests.json`, `events.jsonl` (ordered authority updates, one decision
marker per evaluation, approval inserts), `ledgers.json`, `exchanges.jsonl` (bounded A2A
trace with the transport verdict, receipt hashes only), `receipts/<sha256>.bin`,
`predictions-frozen.json`, `provenance.json`, `run-stats.json` (exchanges, new proofs vs
cache hits), `summary.md`, `oracle.{jsonl,md}`, `oracle-summary.json` (verifier identity,
limitations, expected weak-policy attack successes). The oracle re-runs the pinned
`zkverify` on every referenced receipt (a shared component, not an independent proof
system) and recomputes sums/commitments with its own routines. Proof cache:
`zk/proof-cache/v2/<prover build image id>/`; the flat v1 entries are never read. Synthetic
private openings live in `fixtures/zk/openings.json` (disclosed for reproducibility; absent
from the journal, not private); the public authority history in `fixtures/zk/authority.json`.
See `RESULTS_ZK.md`, `RESULTS_ZK_CORRECTIONS.md`, `ZK_COMPONENT_PLAN.md`, `ZK_CORRECTION_PLAN.md`.

---

# a2a-identity — can an A2A requester tell deployment A from a copy of it? (identity component)

Local, zero-token experiment for Apart Research's Swarm Alignment hackathon (Track 3).
Two scripted A2A agents (honest **A**, attacker **B**) run on real `a2a-go` v2 JSON-RPC
endpoints over loopback HTTP **and HTTPS**. A requester/verifier compares identity
policies against attack fixtures. Two `swtpm` TPM 2.0 emulators hold the attestation
keys; every signature in the run is genuine.

* **v1** (6 Nov 2026): 5 policies × 13 fixtures. Retained run `results/full/20261106-231737`,
  report `REPORT.md`, predictions `fixtures/predictions.md`. A review (`../paper/a2a-identity/REVIEW.md`)
  then found three verifier defects; the v1 run and code snapshot are kept unchanged
  (`results/audit/<ts>/source-v1.tar.gz`, hashes, the characterization test and its output).
* **v2** (7 Nov 2026): repaired verifier, 11 policies × 21 fixtures, randomized race
  trials, per-appraisal accounting, offline reverification, provenance. Results in
  `RESULTS_V2.md`; predictions frozen in `fixtures/predictions-v2.md` / `manifest-v2.json`.
* **v3** (7 Nov 2026): active binding attacks, domain-separated proofs, fail-closed
  transport sealing and S-env+tls baseline. See `RESULTS_V3.md` and the review corrections
  in `../paper/a2a-identity/BASELINE_V3_REVIEW.md`.
* **v3-final** (8 Nov 2026): the review's gaps closed — per-decision release evidence
  (decision ids, ordered requester events, per-connection fingerprints/exporters, receipt
  joins), a structural release-evidence checker with negative controls (`internal/audit`,
  `a2aid audit-release`), continuity cases and churn for S-env+cb **and** swtpm-backed
  T+cb with a proof-key-less attacker, a pre-fix connection-swap reproduction on the
  archived v2 source, an explicit fixture/recipient prediction schema, and a hashed
  snapshot linked to the retained run `results/v3-final/20261108-000017`. See
  `RESULTS_V3_FINAL.md` and `V3_FINALIZATION_PLAN.md`.

**Research scope:** What additional protection do TPM-based identity proofs provide beyond
standard A2A endpoint authentication, and which benefits depend on signer isolation,
channel binding, or hardware assumptions? Read [SCOPE_AND_LIMITATIONS.md](SCOPE_AND_LIMITATIONS.md)
before interpreting results. The experiment uses TPM emulators; physical key protection
and actual workload integrity are untested.

## Policies (v2 vocabulary: `Base[+url|+tls|+cb]`)

| Policy | What the requester verifies |
|---|---|
| **C** | Enrolled publisher's JWS (ES256) signature on the Agent Card only |
| **S-file** | C + fresh 32-byte challenge signed with a software key stored **inside** the application volume |
| **S-iso** | C + the same challenge signed by an isolated software signer **behind the access-controlled gate** (token + socket ACL) |
| **S-env** (v2) | C + a COSE_Sign1 envelope (attester, nonce, action, audience, policy, iat, exp) signed by the **isolated software signer**: a software envelope control with different signed fields from P; no PCR claim |
| **T** | C + fresh `TPM2_Quote` (restricted ECC P-256 AK inside swtpm) over PCR 16, checked against the enrolled AK and the operator's PCR reference |
| **P** | T + PTV draft-01 routine-mode envelope (`PTV_PROVE_RESP`, CBOR, COSE_Sign1 by the same AK via `TPM2_Hash` ticket + `TPM2_Sign`); outer and inner signatures verified independently; routine band must carry evidence and no proof |
| **+url** (v2) | the signed card must declare the discovery endpoint (normalized equality, redirects refused, fail closed, checked before any nonce is issued) |
| **+tls** (v2) | HTTPS, standard chain validation under the lab root for the URL's name, TLS 1.3, **and** the authenticated peer must carry the enrolled name of the expected deployment (implies +url) |
| **+cb** (current v3-final) | Uses the RFC 9266 exporter primitive. ProofContext binds domain, exact policy, nonce and the signer-derived connection exporter. Request-controlled binding downgrades are rejected. Before the task is handed to the transport the requester seals it (new dials refused before connecting) and requires exactly one recorded TLS connection equal to the proof connection; a dropped proof connection fails closed and a new explicit decision obtains a fresh proof (implies +tls). The v2 derivation was vulnerable to active rewriting and v2 dispatch was not pinned. |

Policy labels are retained across versions, but v3 changes the signed proof context.
Use the retained versioned artifacts when describing older formats. Identical outcomes
on the old fixtures do not establish identical code or complete protocol equivalence.

## Commands

Setup (clean emulator state, lab CA and server certificates, provisions both deployments):

```bash
./scripts/setup.sh
```

Tests (unit, emulator end-to-end, race detector, then 20 s fuzz budgets):

```bash
./scripts/test.sh
```

Smoke (F1 under all eleven policies):

```bash
./scripts/smoke.sh
```

Full v2 matrix (21 fixtures × 11 policies, 500 race trials, offline reverification, traces; ~2.5 min):

```bash
./scripts/matrix.sh
```

v3-final: hashed snapshot, byte-identical build from it, the 24-cell V3 rerun, continuity
and churn evidence for both defended policies, release-evidence audits (clean run,
negative controls, historical schema) and the test passes (~2 min):

```bash
./scripts/v3final.sh
```

Structural release-evidence audit of a run (exit 0 no unexpected violation, 1 unexpected
violation, 2 incomplete/unsupported/malformed); also works on the continuity evidence:

```bash
bin/a2aid audit-release --results results/v3-final/<run-id>
```

Networked integration test (needs the lab ports free, i.e. no matrix running):

```bash
A2AID_INTEGRATION=1 GOFLAGS=-buildvcs=false go test -count=1 -run Integration -v ./internal/matrix
```

Offline reverification of any retained run:

```bash
bin/a2aid reverify --results results/v2/<run-id>
```

Deterministic adversarial-fixture discovery (no credentials, no network):

```bash
bin/a2aid discover --planner mock --plans 300
```

Adaption-backed discovery, dry run only (lists models, prints the free dataset
estimate and the budget ledger; makes no paid call):

```bash
ADAPTION_API_KEY=… bin/a2aid discover --planner adaption --dry-run
```

Cleanup (kills emulators and helpers, deletes `run/` including TPM state, keys and certificates):

```bash
./scripts/cleanup.sh
```

## Outputs per v2 run (`results/v2/<run-id>/`)

* `provenance.json` — run id, UTC start/end, binary and per-file source hashes, manifest and predictions hashes, dependency versions, every command the runner executed.
* `manifest-frozen.json`, `predictions-frozen.md` — the expectations as they were at run time.
* `appraisals.csv` / `.jsonl` — **one row per requester decision** (F12/F13 export both): policy, expected identity, typed attacker capabilities, endpoint equality, TLS peer and name match, channel-binding match, card/session/nonce/signature/quote/envelope verdicts, crypto acceptance, failure stage and PTV code, dispatch attempted, job token, observed recipient (from `job_received(token)`), ack, PCR at receipt, configuration-changed flag, unauthorized-recipient flag, legitimate-rejection flag, keys used (typed owner labels), invokers, materials, signer attribution, custody flag, telemetry completeness.
* `matrix.csv` / `.jsonl` — one row per cell with expected vs observed result, releases, receipts, duplicate flags.
* `summary.md` — decision grid, counts with denominators, divergences, race-trial table, per-appraisal table.
* `races/<policy>.jsonl` — every randomized trial (seed, delays, latencies, winner, releases, receipts).
* `reverify.md` / `.jsonl` — offline re-derivation of every cryptographic verdict vs the recorded decision.
* `cells/<cell>/` — `decision.json` (decisions, session store dump, raw evidence; since v3-final also `decision_id`, `connections[]` with peer-cert fingerprint and exporter, discovery/proof/pinned/dispatch connection ids, `job_sent`, dial counters and sequence-numbered `requester_events`), `requester-trace.jsonl` (every A2A request/response and the fetched card), `controller-events.jsonl` (now including `req_event` mirrors and receipts with the recipient's own exporter and the echoed decision id).
* `run-inventory.json` (v3-final) — every cell the run will execute with class and expected decision/recipient, written before execution; `release-audit.{md,jsonl}` and `release-audit-summary.json` — the structural release-evidence audit; `continuity/<policy>/` — the continuity/churn evidence when produced by `scripts/v3final.sh`.
* `copy-manifest-*.json` — exactly what B received in each copy/clone fixture; `traces/` — sanitized paired traces.

No private keys, AK passwords, signer tokens, TLS keys or emulator state are written
under `results/`; they live only under `run/`, which `cleanup.sh` removes. The
requester's own TLS exporter value is recorded per decision (needed for offline
reverification; it has no value after the connection closes).

## Layout

```
cmd/a2aid/            setup | provision | publish-card | controller | gate | agent | matrix | reverify | traces | discover | audit-release | zk-fixtures | zk-inventory | zk-matrix | zk-oracle | version
internal/zk/          OPTIONAL proof-carrying task results: commitment/journal encodings, trusted fixture authority, Pinned/Current contracts, policies V0/VT/VI/VTI, serialized approval ledger, C+tls-appraised transport, image-qualified prover/verifier bridge, pre-declared inventory + fixture matrix, offline oracle v2 (+ legacy replay view)
zk/                   Rust workspace: single guest (bounded-sum predicate), zkprove / zkverify CLIs (dev mode refused), zkfake (test-only), image-id.txt, proof-cache/
internal/tpmsig/      go-tpm direct API against swtpm: AK provisioning, quote, ticketed sign, hardened quote verification, swtpm start/clone
internal/cardsig/     Agent Card JWS sign/verify (adapted from the official a2a-samples Go sample)
internal/ptv/         PTV draft-01 routine slice: CBOR messages, COSE_Sign1, strict schema (required fields, evidence bstr), freshness, error codes
internal/senv/        v2 matched software envelope (COSE_Sign1 by the isolated software key)
internal/wire/        policy vocabulary and parser, challenge/evidence payloads, URL normalization, channel-bound nonce
internal/gate/        signer access boundary: SO_PEERCRED pid→label ACL in front of each TPM socket and software signer (harness-enforced)
internal/controller/  independent event log per cell (cooperative telemetry, not a hostile-process oracle)
internal/agent/       scripted A2A agent (a2asrv) on HTTP+HTTPS with honest and attacker modes, exporter-derived channel binding
internal/verifier/    requester + verifier: policies, TLS/URL enforcement at connect, atomic one-use nonce store with expiry, acceptance invariants, offline reappraisal
internal/matrix/      fixtures, process orchestration, typed ground truth, per-appraisal accounting, races, provenance, reverify, traces, integration test
internal/audit/       structural release-evidence checker (joins records by ids, recomputes order/equality, trust classes, negative controls in audit_test.go)
internal/discover/    optional adversarial-fixture discovery: allowlisted mutation interpreter, spec oracle, mock planner, Adaption client, credit ledger
fixtures/             v1: predictions.md, manifest.json; v2: predictions-v2.md, manifest-v2.json; v3: manifest-v3.json, predictions-v3.md (frozen, addendum appended); v3-final: manifest-v3-final.json, predictions-v3-final.md
scripts/              setup.sh, test.sh, smoke.sh, matrix.sh, cleanup.sh
results/audit/        pre-change hashes, v1 source tarball, review audit reproduction, fuzz logs, discovery finding
```

## Harness assumptions (read before citing numbers)

* All processes run under one OS account. The **gate** enforces the socket boundary by
  mapping the peer pid to a label registered by the runner; this is harness-enforced,
  not OS-enforced. Admin endpoints (gate, agents, controller) are unauthenticated
  loopback HTTP and are never reachable by the requester logic.
* Name resolution is a static map in the requester and in B's relay client (no DNS);
  the address-hijack fixtures change that map. TLS validation itself is standard
  (`crypto/tls`, lab root CA, TLS 1.3); `InsecureSkipVerify` is never set.
* The AK password, isolated-signer token and TLS key live outside the copied volume.
  Fixtures grant them only where the capability list says so.
* The swtpm emulator's state directory is an ordinary file tree; F19/F21 copy it to
  show what that implies. Nothing here says anything about hardware TPMs.
* Controller events are emitted by the cooperating processes; the runner flags
  missing telemetry per appraisal instead of treating silence as "no attack".
* The in-memory release flag gives at most one dispatch per nonce within one verifier
  process; it is not durable exactly-once execution and restarts were not tested.

## Versions

Go 1.27.1 · a2a-go/v2 v2.3.1 · go-tpm v0.9.8 · go-cose v1.3.0 · fxamacker/cbor v2.10.0 ·
golang-jwt/jwt v5.3.1 · golang.org/x/sys v0.40.0 · swtpm 0.10.2 · PTV draft-01, 29 Sep 2026.
`tpm2-tools` is not used; `go-tpm` talks to swtpm directly. Builds need `GOFLAGS=-buildvcs=false`
on this host (the parent directory is not a usable git checkout).

The generated summaries of the retained v3 runs and the initial release-oracle description
contain known reporting gaps; the reviewer corrections in `RESULTS_V3.md` and
`BASELINE_V3_REVIEW.md`, and the final accounting in `RESULTS_V3_FINAL.md`, take precedence.
Raw run outputs and frozen predictions remain unchanged. The checker (version 2, evidence
schema 2) reports the records of runs before `results/v3-final/20261108-004047` as an
unsupported historical schema rather than auditing them. `RESULTS_V3_CORRECTIONS.md` records
the checker/runner defects found by the final review, their before/after reproductions and the
factual corrections (ten TLS receipts are 5 at A and 5 at B; 24/24 is expected-result
agreement including eight attacker successes; three attempts were within the retry allowance).
