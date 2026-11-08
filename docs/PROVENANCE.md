# Provenance

`PROVENANCE_MANIFEST.json` records every distributed file except itself, including SHA-256,
size, origin and source mapping where known. `packaging/verify_manifest.py` checks listed
files and detects unexpected unlisted files. Documentation is intentionally edited for the
publication copy; raw retained evidence is unchanged.

## Final experimental identities

| Component | Primary run | Snapshot/binary identity |
|---|---|---|
| Identity | `identity/results/v3-final/20261108-004047` | Producer snapshot `20261107T234045Z-v3final-snapshot`; recorded binary `9d91bdbd…` |
| ZK producer | `zk-component/results/zk/20261108-111817` | Snapshot `20261108T111816Z-zkcorr-snapshot`; recorded binary `8405b852…` |
| ZK checker | Final oracle/control reports | Snapshot `20261108T112430Z-zkcorr-final-snapshot`; binary `48592e76…` |

The ZK final checker differs from the producer snapshot in evidence-classification code
and tests, not matrix producer behavior. The publication copy had already reverted the
later usage-string edit to the final checker snapshot. The RISC Zero verifier identity
recorded by the primary run is `c96cd581…`; the guest image ID is pinned in
`zk-component/zk/image-id.txt`. Rebuilt binaries can differ; report the actual verifier hash.

`zk-component/` inherits the identity implementation and adds ZK application logic. Shared
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
