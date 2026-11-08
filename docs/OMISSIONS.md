# Publication scope

The public tree contains final application source, the paper and selected evidence needed
for its comparisons and regression checks. Superseded full runs, review notes, planning
files, historical root reports and the old workspace-copy builder are omitted.

Development history remains in the separate original research trees. A complete pre-cleanup
publication copy is preserved outside this repository under `publication-archives/` in the
local research workspace. This directory is not included in the public package. Local Git
history is not rewritten by this cleanup; earlier published commits may still contain files
removed from the current tree.

No runtime private keys, CA private keys, signer tokens, emulator state, sockets, caches,
local toolchains, compiled binaries or Rust targets are included. Setup regenerates disposable
lab state. Evidence bytes remain unchanged; original workspace paths inside raw provenance
and logs are retained so their hashes remain checkable.

The paper's historical discussion remains a research record. Some historical timestamp and
legacy-view supporting files are now available only in the research archive; the primary
final-run evidence is included. This package does not claim to contain the entire historical
record or every old reproduction environment.
