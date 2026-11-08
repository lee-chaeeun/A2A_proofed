# Selected evidence

Only final source is included. These directories are evaluation evidence, not alternate
software releases. Paths are relative to the repository root.

| Path | Purpose |
|---|---|
| `identity/results/v3-final/20261108-004047` | Final focused matrix, continuity/churn, audits and test logs |
| `identity/results/v2/20261107-194025` | Broad comparison matrix used by the paper |
| `identity/results/v3-repro/20261107-202528` | Selected before/after regression evidence supporting the paper |
| `identity/results/v3/20261107-203206` | Historical-schema negative input used by the final runner |
| `identity/results/audit/20261107T225036Z-v2-continuity-historical` | Selected connection-continuity regression evidence |
| `identity/results/audit/20261107T233054Z-checker-falseclean-before` | Before-control observations referenced in the paper |
| `identity/results/audit/20261107T234220Z-checker-falseclean-after` | Final checker control observations |
| `identity/results/audit/20261107T234045Z-v3final-snapshot` | Producer hash lists; no archived source/binary |
| `zk-component/results/zk/20261108-111817` | Final schema-2 run, receipt bytes, inventory and oracle reports |
| `zk-component/results/zk-integration/20261108-112143` | Fresh integration execution with receipt bytes |
| `zk-component/results/audit/20261108T105605Z-zk-before-fix` | Selected transport/oracle regression observations |
| `zk-component/results/audit/20261108T112131Z-zk-oracle-controls-after-schema2` | Final schema-2 evidence-mutation controls |
| `zk-component/results/audit/20261108T111816Z-zkcorr-snapshot` | Producer snapshot hash lists |
| `zk-component/results/audit/20261108T112430Z-zkcorr-final-snapshot` | Final checker snapshot hash lists and test logs |

The `fixtures/` definitions support the selectable comparison matrices; versioned filenames
identify experimental protocols, not separate code installations. Some backward-compatible
legacy tests skip because superseded full run archives are intentionally omitted.

`zk-component/zk/host/testdata/` includes a genuine receipt for Rust verification tests.
ZK fixture openings are published synthetic test data, not credentials or a privacy claim.
Full development records remain in the separate research workspace. The source tarballs,
old binaries, failed attempts and superseded full matrices are not distributed here.
