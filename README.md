# Valid Proofs, Wrong Decisions: Identity and Task Binding in A2A

Curated publication copy of two local experiments built for the Swarm Alignment Hackathon
(Track 3, November 6–8, 2026) by Chae Eun Lee (independent, no institutional affiliation). Paper: [`paper/a2a-identity-paper.pdf`](paper/a2a-identity-paper.pdf)
(editorial source `paper/paper-draft.md`). Status and open items: [`docs/SUBMISSION_READINESS.md`](docs/SUBMISSION_READINESS.md).

**Question.** When does a cryptographically valid proof justify an action in an
Agent2Agent (A2A) workflow? Two scripted-agent experiments share one problem, *binding*:
an identity proof must be bound to the endpoint and connection that receives the task, and
a computation proof must be bound to the task and the input snapshot the requester authorized.

**Main findings (hand-selected fixtures on software emulators; not attack rates).**
- Enrolled endpoint checks and authenticated TLS stop copy, replay, different-address and
  credential-less hijack fixtures. Against a relay that holds the honest agent's TLS
  certificate and key, only a second proof bound to the TLS connection (RFC 9266 exporter)
  rejects delivery, identically for a software-signed envelope and an emulated-TPM quote.
  No hardware advantage is shown: swtpm is software and its state is a file.
- Two defects in this project's own requester were reproduced on archived code and
  repaired: a request-controlled binding mode (downgrade), and dispatch of the task to a
  replacement connection after a valid proof. The repaired requester pins dispatch to the
  proof connection; interrupted honest deliveries then fail until a new decision.
- Genuine RISC Zero receipts travelled over the same A2A transport. One byte-identical
  receipt was approved for a request pinned to a historical snapshot and denied for a
  request contracting on the current snapshot; a fresh challenge did not prevent approval
  of a proof over obsolete input under policies that do not check the input commitment.
- The offline checkers of both components initially accepted incomplete or corrupted
  evidence; the replacements use declared inventories, re-verify receipt bytes, and are
  exercised with corrupted copies (before/after controls retained).

## Layout
| path | content |
|---|---|
| `identity/` | Go source, tests, fixtures and scripts of the identity experiment (`a2aid`), its reports, and retained evidence under `identity/results/` (final run `v3-final/20261108-004047`, v2 matrix, pre-fix reproductions, checker controls). |
| `zk-component/` | The identity tree plus the proof-carrying task-result component: `internal/zk`, `internal/agent/zk.go`, `zk/` (RISC Zero guest, `zkprove`/`zkverify`/`zkfake` CLIs, pinned `Cargo.lock` and image id), ZK fixtures, reports, and evidence under `zk-component/results/` (final run `zk/20261108-111817`, first run, controls, snapshots' hash lists). |
| `paper/` | Markdown source, generated `main.tex`, converter, fonts, PDF, self-contained LaTeX ZIP. |
| `docs/` | Threat model, results summary, provenance manifest, artifact inventory, attribution, omissions, review history, packaging scripts, submission readiness. |

The two components share ancestry: `zk-component/` was copied from `identity/` at the
identity component's final snapshot and then extended; `docs/PROVENANCE.md` lists the
files that differ. Which component supports each paper claim is in
`docs/RESULTS.md` and `paper/CLAIM_EVIDENCE_TABLE.md`.

## Prerequisites
- Go 1.27 (module downloads from proxy.golang.org on first build). Tests and the offline
  checkers need nothing else.
- Identity lab runs (`scripts/setup.sh`, `scripts/v3final.sh`): `swtpm` 0.10.x and
  `swtpm_setup` on PATH, loopback ports 9100/9101/9102/9110/9443/9444 free. Setup generates
  a fresh disposable lab CA, TLS keys, registry and emulator state under `run/` (gitignored).
- ZK proving/verifying: Rust 1.93 host toolchain and the RISC Zero toolchain (risc0 3.0.6
  via `rzup`; ~3 GB, downloaded by `rzup`), see `zk-component/README.md`. CPU proving takes
  about 23 s per proof on a 20-thread host.

## Quick verification (offline, no toolchain downloads beyond Go modules)
```sh
cd identity && go test -race -count=1 ./...                                   # ~15 s
go build -o bin/a2aid ./cmd/a2aid
cp -r results/v3-final/20261108-004047 /tmp/idrun && bin/a2aid audit-release --results /tmp/idrun   # checker v2, exit 0 (writes into the given dir; audit a copy)
cd ../zk-component && go test -race -count=1 ./...                            # transport, cache, policy tests; oracle tests skip without zkverify
python3 docs/packaging/verify_manifest.py                                     # from the repository root: every file matches docs/PROVENANCE_MANIFEST.json
```

## Re-verifying the retained genuine receipts (needs the Rust/RISC Zero toolchain, no proving)
```sh
cd zk-component/zk && cargo build --release --bin zkverify && cd ..
bin/a2aid zk-oracle --results results/zk/20261108-111817 --verify-bin zk/target/release/zkverify --out /tmp/zk-oracle-out
# expected: declared=52 rows=52 agree=52 ... exit=0; 10 unique receipt/image pairs re-verified (7 valid, 3 rejected)
(cd zk && cargo test --release)   # 4 host tests over a retained genuine receipt
```
Building `zk/` compiles the guest with the RISC Zero toolchain (several minutes); it does not
generate proofs. Generating new proofs and re-running the networked matrix
(`bin/a2aid zk-matrix`, opt-in integration test) needs the identity lab and about three
minutes of CPU proving per matrix.

## Not in this copy
Local toolchains, Rust build output, compiled binaries, the lab `run/` directory (private
CA/TLS keys and emulator state of the original runs, regenerated fresh by setup), proof-cache
entries, copied-run trees of the mutation controls (their summaries and CLI logs are kept),
source tarballs and binaries inside snapshot directories (hash lists kept), earlier paper
versions and task prompts. Full detail: `docs/OMISSIONS.md`. The complete development record
remains in the private research trees `a2a-identity/` and `a2a-identity-zkp/`.

Retained run records contain the original workspace path of the machine that produced them
(`/home/<user>/aisafety/swarmalign/...`) inside provenance, command and log files; they are
published byte-identical so that hashes match the research trees (`docs/PROVENANCE.md`).

## Pre-sprint and third-party code
`internal/cardsig` adapts the official a2a-samples Go signed-card sample (pre-sprint code).
Everything else was written during the sprint. Licence: Apache-2.0 (`LICENSE`, `NOTICE`);
dependencies and their licences: `docs/ATTRIBUTION.md`.

Nothing in this copy has been uploaded, pushed or submitted.
