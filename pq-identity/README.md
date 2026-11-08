# Post-quantum identity over A2A with an emulated device signer

This component extends the identity application with the `a2aid-proof-v4` credential: a
canonical CBOR context signed with ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final))
or, as the matched classical control, ECDSA P-256. The ML-DSA key of the `PQ-device` arms is
created and kept inside a TPM 2.0 v1.85 emulator (the wolfTPM firmware TPM) and used
through real TPM commands; the requester verifies every proof with an independent library
(CIRCL) under a public key pinned at enrollment. The emulator is software: its state is a
file, and no physical key-protection measurement is claimed.

## Tools and source

- [A2A Go SDK](https://github.com/a2aproject/a2a-go) v2.3.1: discovery, JSON-RPC and data parts.
- [wolfTPM](https://github.com/wolfSSL/wolfTPM) commit `1362e1e5` (firmware TPM with the v1.85 ML-DSA commands) on [wolfSSL](https://github.com/wolfSSL/wolfssl) commit `0ac786e0`; both GPLv3, built task-locally by `scripts/build_pq_toolchain.sh`. See wolfTPM's `docs/FWTPM.md` and `docs/fwtpm/post-quantum.md`.
- [CIRCL](https://github.com/cloudflare/circl) v1.6.5, package `sign/mldsa/mldsa65`: requester-side verification, software ML-DSA control signers and the NIST ACVP vectors.
- [swtpm](https://github.com/stefanberger/swtpm) 0.10.2 and [go-tpm](https://github.com/google/go-tpm) 0.9.8: unchanged classical TPM quote of the identity component (libtpms had no ML-DSA code at the time).
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html): TLS exporter in the signed context of the `+cb` arms.

Package responsibilities: `internal/pqsig` canonical context, encoding and verification
stages for ML-DSA-65 / ES256; `internal/pqdev` the emulator lifecycle and the bridge
calls; `tools/pqtpm` the C bridge (GPLv3, executed as a subprocess, never sees a software
key); `internal/gate` the harness signer service with the `EC-env`, `PQ-env` and device
signers; `internal/registry` the per-deployment pins (algorithm, key id and public key;
the version field is a label, not an enforced counter); `internal/verifier` appraisal and
the single release guard `GuardedSend` (sealed transport, dispatch pinned to the proof
connection) used by the synthetic job and by the ZK task; `internal/matrix` the PQ
fixtures and copy/relay/clone scenarios; `internal/pqaudit` the composite offline audit
(structural release invariants of `internal/audit` plus proof re-verification).
The remaining application packages share the classical and standalone ZK implementation. The PQ copy includes the corrected shared delivery guard and audit integration. The unused discovery/paid-inference command was removed for publication; no paper experiment uses it.

## Arms and custodies

| Arm | Algorithm | Key custody | Proof bound to the signer's own TLS connection |
|---|---|---|---|
| C+tls | none (card signature, endpoint, TLS) | — | — |
| EC-env+tls / EC-env+cb | ECDSA P-256 | gated signer service | no / yes |
| PQ-env+tls / PQ-env+cb | ML-DSA-65 | gated signer service | no / yes |
| PQ-file+cb | ML-DSA-65 | seed file in the application volume | yes |
| PQ-device+tls / PQ-device+cb | ML-DSA-65 | key created and held by the firmware-TPM emulator, used through the gated device signer | no / yes |

Every proof arm signs a canonical context with the same fields (version, role, exact
policy, algorithm, key id, expected deployment, requester, action, nonce, expiry, session,
exporter or empty); the bytes differ per arm (271–310 bytes in the honest cells). The
requester rebuilds the expected context from its own session and the registry; a response
cannot choose its algorithm, key id or exporter. Twelve scenarios (P1–P12)
and four boundary controls (X1–X4) are defined in `fixtures/manifest-pq.json` with the
frozen predictions in `fixtures/predictions-pq.md`. All processes share one OS account; the
gate's access list and the emulator's state directories are simulated boundaries.

## Build and check retained results

From this directory (Go only; no emulator or toolchain needed):

```sh
go build -o bin/a2aid ./cmd/a2aid
go test -race -count=1 ./...
bin/a2aid audit-pq --results results/pq/20261108-153049 --out /tmp/a2a-proofed-pq-check
python3 -I scripts/pq_audit_controls.py --bin bin/a2aid --run results/pq/20261108-153049 --out /tmp/a2a-proofed-pq-controls
scripts/test_pq_runner.sh
```

`audit-pq` (v2) composes, per declared cell, the structural release invariants of the
identity checker (strict loading, event order and multiplicity, typed contexts, issued
session, proof-to-dispatch connection continuity, receipt joins by decision id, token and
exporter, cardinality, duplicate ids, orphan receipts) with re-verification of every
retained proof under the registry recorded with the run (expected context rebuilt from
the issued session, parsed appraisal time inside the session validity), and compares the
result with the declared inventory. Exit 0 = complete and clean (declared attacker
deliveries listed), 1 = disagreement, violation, orphan receipt or duplicate id, 2 =
incomplete, malformed or unsupported. Records without the schema-2 fields are
unsupported, never upgraded. Without `--out` it writes its reports into the run directory;
keep the retained reports unchanged by giving another output directory. The control
script asserts seventeen mutation outcomes against `fixtures/pq-audit-controls-expected.json`
and exits non-zero on any mismatch; `scripts/test_pq_runner.sh` injects stage failures
into the runner with stubs. Device-dependent tests skip unless opted in (`A2AID_PQ_DEVICE=1`,
`A2AID_PQ_ZK_SMOKE=1`); inspect skips. The bound-transport regressions
(`internal/zk/pq_transport_test.go`) run by default over real HTTPS with a software test key.

## Toolchain and fresh runs

The emulator and the bridge need the pinned wolfSSL and wolfTPM commits, CMake and Ninja
(about five minutes; network access to clone; nothing system-wide is replaced):

```sh
scripts/build_pq_toolchain.sh        # .toolchain/wolfssl, .toolchain/wolftpm, tools/pqtpm/pqtpm
A2AID_PQ_DEVICE=1 go test -race -run TestDevice ./internal/pqdev
scripts/pq_matrix.sh                 # gated: setup (two swtpm and two fwtpm instances), 128 cells, audit, asserted controls, tests
```

Setup resets live state under `run/`, including the emulators' state directories and
disposable lab credentials; do not run simultaneous labs. The ZK smoke test over the
PQ-device+cb transport additionally needs the RISC Zero toolchain and the built `zk/`
binaries (see [zk-component](../zk-component/README.md)).

[Corrections and current evidence](RESULTS_PQ_CORRECTIONS.md), [current result summary](RESULTS_PQ_IDENTITY.md), [correction plan](PQ_CORRECTION_PLAN.md), [repository results summary](../docs/RESULTS.md),
[artifact inventory](../docs/ARTIFACT_INVENTORY.md), [hardware, PQ and PTV](../docs/HARDWARE_AND_PTV.md),
[tool links and attribution](../docs/TOOLS.md).

The repository-wide [code map](../docs/CODE_MAP.md), [pipeline](../docs/PIPELINE.md) and [reproduction guide](../docs/REPRODUCING.md) explain each source file and the full workflow. `make check` from the repository root checks retained evidence without modifying it.
