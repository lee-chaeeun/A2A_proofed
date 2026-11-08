# Publication scope

The public tree contains final application source, the paper and selected evidence needed
for its comparisons and regression checks. Superseded full runs, superseded review notes and planning
files, historical root reports and the old workspace-copy builder are omitted.

Development history remains in the separate original research trees. A complete pre-cleanup
publication copy is preserved outside this repository under `publication-archives/` in the
local research workspace. This directory is not included in the public package. Local Git
history is not rewritten by this cleanup; earlier published commits may still contain files
removed from the current tree.

For the PQ component the same rule applies: the `PQ_IDENTITY_PLAN.md` planning file (its
hash is retained in `results/audit/20261108T125045Z-pq-prefix/`), the development smoke
runs under `results/pq-smoke/`, the source tarballs inside the snapshot directories, the
mutated run copies of the audit controls (their reports are kept), the compiled `pqtpm`
bridge, the task-local wolfSSL/wolfTPM build, the pre-correction binary and the source
tarballs are omitted. The pre-correction PQ runs (`results/pq/20261108-142400`, `…142717`,
`results/pq-integration/20261108-142915`) and their controls and snapshots are kept in
the research tree only; the first corrected execution (`…152809`) is retained here because
the paper discusses it.

No runtime private keys, CA private keys, signer tokens, ML-DSA seeds, device authValues,
emulator state or NV journal keys, sockets, caches,
local toolchains, compiled binaries or Rust targets are included. Setup regenerates disposable
lab state. Evidence bytes remain unchanged; original workspace paths inside raw provenance
and logs are retained so their hashes remain checkable.

The paper's historical discussion remains a research record. Some historical timestamp and
legacy-view supporting files are now available only in the research archive; the primary
final-run evidence is included. This package does not claim to contain the entire historical
record or every old reproduction environment.

## Final publication cleanup

The unused Adaption/discovery command and its `internal/discover` package were removed from the publication modules. None of the paper experiments calls this feature. The CLI help now lists the available commands. The three modules remain because they are the final implementations of distinct measured studies; there are no archived code versions. Generated toolchains and binaries are outside the public tree. Rust `zk/host/src/bin/*.rs` files are application source and are explicitly included. The broad `bin/` exclusion that hid them was corrected in Git rules and the provenance inventory, with regression checks.

The frozen `pq-identity/PQ_CORRECTION_PLAN.md` is retained solely to make its recorded pre-run hash checkable. It is not a second implementation or a pending task list.
