# What this copy intentionally omits, and where it remains

The private research trees `swarmalign/a2a-identity/` and `swarmalign/a2a-identity-zkp/`
hold the complete development record. This copy was built by
`docs/packaging/build_public_copy.py` from an explicit allowlist; nothing was copied by
directory default. Omitted:

| omitted | reason | where it remains |
|---|---|---|
| `run/` (lab CA key, TLS keys, swtpm state, registry, pids) | private runtime credentials of the original runs; `scripts/setup.sh` regenerates a fresh disposable lab | research trees (never to be published) |
| `.toolchain/` (3.2 GB RISC Zero toolchain), `zk/target/`, `bin/` | regenerable, large, machine-specific | research trees / rebuilt locally |
| `zk/proof-cache/*.json` (v1 flat entries and v2 entries) | derived receipts, 12 MB; the retained runs keep every receipt that was used | `a2a-identity-zkp/zk/proof-cache/` |
| copied-run trees under the oracle control directories (`…zk-before-fix/oracle-controls-pre-edit/<case>/`, `…after-legacyview/<case>/`, `…after-schema2/<case>/`, `results/zk/20261108-002724/oracle-controls/<case>/`, `results/reviewer-zk/…/<case>/`) | each is a mutated copy of a full run (≈2 MB × 25 cases × 4 sets); the per-case `cli.log`, `oracle-summary.json`, `oracle.md`/`oracle.jsonl` and the set's `controls.json` are kept, which record the mutation and the verdict | research trees |
| source tarballs and binaries inside snapshot directories (`source-*.tar.gz`, `a2aid*`) | the sources are in this copy; the hash lists (`sha256-source.txt`, `files.txt`, `binary-sha256.txt`, `tarball-sha256.txt`) are kept so a rebuilt tree can be compared | research trees |
| identity run `results/v2/20261107-194025/cells/`, `boot/`, `process-logs/` and the full trees of the superseded first final run `…000017` and the two failed final attempts | compact: top-level matrices, provenance, audits and notes are kept (17 MB of per-cell traces omitted) | research trees |
| identity v1 run `results/full/20261106-231737`, v2 aborted/partial runs, `results/integration/`, `results/audit/20261107T180305Z/` (v1 audit) | superseded by v2/v3 evidence cited in the paper | research trees |
| earlier manuscripts (`paper/a2a-identity/v1`, `v2`, `v3-pre-review`, `v3-reviewed-md-only`, `identity-only-v3final`, `pre-finalization-*`), task prompts (`CLAUDE_*_PROMPT.md`), planning notes unrelated to the result (`DATASETS_AND_ADAPTION_PLAN*.md`) | editorial history and briefs, not evidence | paper folder |
| unrelated projects in the workspace | not part of this work | — |

Byte-identical evidence files carry the original workspace path `/home/<user>/aisafety/swarmalign/…`
inside provenance, command and log records. They were not rewritten so that their hashes
match the research trees; see `PROVENANCE.md`. If the author prefers redacted derivatives,
they must be published separately with their own hashes and a stated transformation.

Because the original lab credentials are not included, the networked runs cannot be
reproduced byte-for-byte: a new lab has new keys, nonces, challenges and timestamps. What
can be verified offline from this copy: every retained receipt against the pinned image id,
every checker verdict on the retained records, the source hashes against the snapshot lists,
and the unit/regression suites.
