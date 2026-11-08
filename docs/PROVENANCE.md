# Provenance

`PROVENANCE_MANIFEST.json` records every distributed file except itself, including SHA-256,
size, origin and source mapping where known. `packaging/verify_manifest.py` checks listed
files and detects unexpected unlisted files. Documentation is intentionally edited for the
publication copy; raw retained evidence is unchanged.

## Final experimental identities

| Component | Primary run | Snapshot/binary identity |
|---|---|---|
| PQ identity producer and checker | `pq-identity/results/pq/20261108-153049` (rerun `…pq-integration/20261108-164204`) | Snapshot `20261108T143034Z-pqcorr-snapshot-2`; binary `15b7717f…` for the run, the rerun, the audit and the controls; final checker snapshot `20261108T154818Z-pqcorr-final-snapshot` (only a test's wording and documentation changed after the run; the rebuilt binary hashes to the same `15b7717f…`); emulator `fwtpm_server` `65ae8f1b…` (research build) / `b38b243b…` (public-copy build, identical libraries), bridge `pqtpm` `b69d5dc7…` |
| Identity | `identity/results/v3-final/20261108-004047` | Producer snapshot `20261107T234045Z-v3final-snapshot`; recorded binary `9d91bdbd…` |
| ZK producer | `zk-component/results/zk/20261108-111817` | Snapshot `20261108T111816Z-zkcorr-snapshot`; recorded binary `8405b852…` |
| ZK checker | Final oracle/control reports | Snapshot `20261108T112430Z-zkcorr-final-snapshot`; binary `48592e76…` |

The ZK final checker differs from the producer snapshot in evidence-classification code
and tests, not matrix producer behavior. The publication copy had already reverted the
later usage-string edit to the final checker snapshot. The RISC Zero verifier identity
recorded by the primary run is `c96cd581…`; the guest image ID is pinned in
`zk-component/zk/image-id.txt`. Rebuilt binaries can differ; report the actual verifier hash.

`pq-identity/` inherits `zk-component/` (identity and ZK) and adds the PQ proof format,
device signer, the shared release guard and the composite audit; its snapshot hash lists
omit the retained source tarballs and binaries, and the audit-control and reviewer
directories hold only summaries, reports and logs, not the mutated run copies. Its
records carry `producer_revision` `2026-11-08-pq-corrections` (evidence schema 2). `zk-component/` inherits the identity implementation and adds ZK application logic. Shared
code is not an independently implemented second identity system. Libraries/tools and sample
adaptations are in [TOOLS.md](TOOLS.md) and [ATTRIBUTION.md](ATTRIBUTION.md).

This curated tree is not byte-identical to an experimental snapshot: it contains selected
results, publication documents and a packaged paper. Paper TeX uses a local `fonts/` path.
Edited documentation entries retain their earlier source hashes where available. No change
to public documentation changes the identities of the original experimental evidence.

When intentionally changing distributed files, review the changes first, then run
`python3 docs/packaging/update_manifest.py`. This updates a packaging inventory, not an
experimental attestation or proof that results are true. Ordinary build/test outputs are
excluded and must not be added to the publication package accidentally.

## Publication revision: final review

After the corrected runs, publication-only changes remove the unused discovery/paid-inference CLI, improve CLI help, and let the runner test receive its real binary path through `A2AID_RUNNER_TEST_BIN`. Cryptographic, appraisal, delivery, guest, matrix and audit implementations are unchanged by this revision. The published CLI binary therefore has a different source identity from the recorded producer binary; the latter remains identified in retained provenance. Hashes for changed files keep their earlier source hash in the publication manifest.

The PQ copy was missing three Rust host source files because a generic `bin/` exclusion also matched `src/bin/`. They were restored byte-for-byte from the final research source. Both modules' Rust executable sources are now visible to Git and included in the inventory. `check_package.py` checks declared Cargo binary paths, source-map coverage and relative documentation links; its regression tests reproduce the missing-source and Git-ignore failures. A clean manifest alone never establishes source completeness.
