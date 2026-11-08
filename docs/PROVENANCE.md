# Provenance

`PROVENANCE_MANIFEST.json` lists every published file with its SHA-256, size, source path
in the research workspace and origin class. `packaging/build_public_copy.py` is the
allowlist that produced the copy; `packaging/verify_manifest.py` re-checks every hash and
reports unlisted files. All files are byte-identical copies of their sources except one:

| published file | packaging-only change |
|---|---|
| `paper/main.tex` | font path `../fonts/` → `fonts/` so the paper builds inside this tree; the manifest records both hashes |

This curated tree is **not** identical to any archived experimental snapshot: it omits
directories (see `OMISSIONS.md`) and adds `README.md`, `.gitignore`, `docs/` and
`paper/README-BUILD.txt`.

## Mapping to the archived snapshots and final runs
| component | final run | producer snapshot (hash lists in this copy) | binary recorded in the run |
|---|---|---|---|
| identity | `identity/results/v3-final/20261108-004047` | `identity/results/audit/20261107T234045Z-v3final-snapshot/` (`sha256-source-v3final.txt`, tarball sha256 `8772d156…`; byte-identical builds from tree and snapshot) | `a2aid` `9d91bdbd…` |
| computation (producer) | `zk-component/results/zk/20261108-111817` | `zk-component/results/audit/20261108T111816Z-zkcorr-snapshot/` (`sha256-source.txt`, `files.txt`, tarball sha256 `7c540bd8…`) | `a2aid` `8405b852…`; `zkprove 803006cd…`, `zkverify c96cd581…`, `zkfake d3928458…` |
| computation (checker as reported) | — | `zk-component/results/audit/20261108T112430Z-zkcorr-final-snapshot/` (differs from the producer snapshot only in `internal/zk/oracle.go`, `oracle_test.go`, `scripts/zk_oracle_controls.py`; see `files-changed-since-run-snapshot.txt`) | `a2aid` `48592e76…` |

The source files in `identity/` and `zk-component/` are the research trees' files at the
time of packaging (8 Nov 2026 after the ZK correction task). To compare them with a
snapshot, hash the files named in the snapshot's list, e.g.
`cd zk-component && sha256sum -c results/audit/20261108T112430Z-zkcorr-final-snapshot/sha256-source.txt`
(documentation files edited after the snapshot, such as README or results reports, will
differ; code, fixtures and scripts should match).

## Shared ancestry of the two components
`zk-component/` was copied from `identity/` at the identity component's final state and
extended. Differences between the two trees outside the ZK additions:
`cmd/a2aid/main.go` (zk subcommands), `internal/agent/agent.go` (zk_task dispatch),
`internal/wire/wire.go` (ZKTask/ZKResult), `internal/verifier/verifier.go` and
`transport.go` (configurable `HTTPTimeout`, default unchanged at 20 s), `README.md`.
Additions: `internal/agent/zk.go`, `internal/zk/`, `zk/`, `fixtures/zk/`,
`scripts/zk_oracle_controls.py`, the ZK reports and plans. The identity results cited in
the paper come from `identity/`; the ZK results from `zk-component/`.

## Reproducibility of the guest image
Rebuilding `zk-component/zk` from this copy with risc0 3.0.6 (`cargo build --release`,
1 min 43 s on the packaging host with the toolchain already installed) produced a guest
whose embedded image id equals the pinned `zk/image-id.txt`
(`4f1e028eacb440660d0a69e4f8ff6aa24724bc62ceaf61cb24a02d67a62e7b8b`). The host binaries
differ byte-wise from the archived ones (different target directory and build time); their
behaviour on the retained receipts is identical (oracle exit 0, 10 pairs: 7 verified, 3
rejected).

## Machine-specific content in evidence
Provenance, command-log and process-log files inside retained runs contain the absolute
workspace path of the producing machine (`/home/<user>/aisafety/swarmalign/a2a-identity`,
`…/a2a-identity-zkp`). They are published byte-identical so that their hashes match the
research trees. No credentials, private keys, tokens or e-mail addresses are present
(scanned by content, not by filename, during packaging).
