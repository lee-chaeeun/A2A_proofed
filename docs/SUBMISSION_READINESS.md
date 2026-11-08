# Current paper and package status

The paper is distributed at `paper/a2a-identity-paper.pdf`, with Markdown, TeX, converter,
fonts and a self-contained source ZIP alongside it. The latest prior typesetting check
reported a 236-word abstract and eight main-text pages, with references/appendices outside
that limit. This repository cleanup did not regenerate or change the manuscript/PDF.

## Final-source publication cleanup

The public README now presents the TPM/PTV identity integration and separate RISC Zero
component, with linked tools and a conditional explanation of physical TPM benefits.
Superseded full runs, review notes, development plans and old root reports are excluded.
Selected baseline/regression evidence remains to support the research paper and runner.
The original research trees and a full pre-cleanup publication backup remain outside this
repository. Existing Git history was not rewritten.

## Checks performed after cleanup

- `go test -race -count=1 ./...` passed in both `identity/` and `zk-component/`, with local
  networking available for HTTPS tests.
- Retained evidence checked against the pre-cleanup inventory: 957 files, zero changes.
- Application source was not edited; documentation and publication tooling were updated.
- Edited documentation's local links were checked for existence.
- The refreshed publication manifest verifies file hashes, sizes, missing files and extras.
- New proof generation, physical TPM testing and networked matrix reruns were not performed.
  Default integration/receipt-dependent skips remain subject to their documented prerequisites.

The public working tree contains the cleanup changes for review. This task did not commit
or push them. A prior repository publication may already exist; this file does not claim
that nothing has ever been uploaded.

## Scientific scope

TPM integration uses swtpm and a synthetic PCR. Physical non-migratable key protection is
a design motivation under stated enrollment/device assumptions, not measured here. The
application uses classical P-256, not PQC. The ZK component measures task/input checks over
verified receipts; it is not a combined TPM/ZK experiment or a comparison with signatures.
