# Selected evidence

Only final source is included. These directories are evaluation evidence, not alternate
software releases. Paths are relative to the repository root.

| Path | Purpose |
|---|---|
| `pq-identity/results/pq/20261108-153049` | Final 128-cell PQ matrix (corrected producer): per-cell decisions and proof bytes, appraisals, frozen manifest and predictions, enrollment registry (public keys), X4 overrides, copy manifests, provenance, retained composite `audit-pq` v2 reports |
| `pq-identity/results/pq-integration/20261108-164204` | Further execution of the same matrix (128/128, audit exit 0) |
| `pq-identity/results/pq/20261108-152809` | First corrected execution (128/128 predictions, stopped by the audit gate) with `ATTEMPT-NOTE.md`; superseded, kept as validation history |
| `pq-identity/results/audit/20261108T125045Z-pq-prefix` | Plan hash and starting source hashes recorded before the PQ work |
| `pq-identity/results/audit/20261108T141124Z-pqcorr-prefix` | Correction plan hash, pre-correction source hashes and the reproductions of the review findings (transport characterization, seven false-clean mutations, structural checker baseline); the pre-correction tarball and binary are not distributed |
| `pq-identity/results/audit/20261108T142748Z-pqcorr-snapshot`, `…143034Z-pqcorr-snapshot-2`, `…154818Z-pqcorr-final-snapshot` | Source hash lists of the corrected code (attempt 1, final run, final checker), changed-file lists, runner logs, race-test and runner-test logs; tarballs omitted |
| `pq-identity/results/audit/20261108T141020Z-public-toolchain-build` | Build of the pinned wolfSSL/wolfTPM stack and the bridge from this public copy (logs, CMake caches, commits, hashes; first attempt failed at a script defect, rerun succeeded) and the opt-in device test against that backend |
| `pq-identity/results/reviewer-pq/20261108T135205Z` | Reviewer evidence: transport characterization test, audit summaries of the seven mutations the pre-correction audit accepted, structural-checker baseline (mutated run copies not distributed) |
| `pq-identity/results/audit/20261108T130125Z-pq-gate` | Emulator gate: create/sign/restart command traces, wrong-auth and tampered-message negatives, CIRCL cross-verification, ACVP log, upstream commits and CMake options, binary hashes |
| `pq-identity/results/audit/20261108T143109Z-pq-audit-controls` | `controls.json` (seventeen cases, expected vs observed) plus each case's audit reports and CLI log (the mutated run copies themselves are not distributed) |
| `pq-identity/results/pq-bench/20261108-132255` | Sizes and timings (30 samples over a fixed 306-byte message; software and device paths) |
| `pq-identity/results/zk-pq-smoke/20261108-154419` | Genuine-receipt ZK task over the PQ-device+cb transport through the guarded send: exchanges, identity record, receipt bytes, logs |
| `pq-identity/fixtures/testdata/pq-mini-run` | Six cells copied from the pre-correction run as the fixture of the audit tests and the runner failure-injection script; not an experimental result |
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

`pq-identity/results/audit/GATE_CLOCK_START.txt` and `circl-mldsa65-acvp-test.log` are the
gate clock and the CIRCL ACVP vector log. The PQ development smoke runs (`results/pq-smoke`),
the `PQ_IDENTITY_PLAN.md` planning file (hash in the prefix record) and the pre-correction
runs `results/pq/20261108-142400`, `…142717`, `results/pq-integration/20261108-142915`
with their controls and snapshots are not distributed; they remain in the research tree
and are summarized in `pq-identity/RESULTS_PQ_CORRECTIONS.md`.

`zk-component/zk/host/testdata/` includes a genuine receipt for Rust verification tests.
ZK fixture openings are published synthetic test data, not credentials or a privacy claim.
Full development records remain in the separate research workspace. The source tarballs,
old binaries, failed attempts and superseded full matrices are not distributed here.

The publication review restored the three PQ Rust host CLI source files and made both modules' `src/bin/*.rs` files visible to Git and the inventory. These are final application sources, not generated executables. The current `pq-identity/RESULTS_PQ_IDENTITY.md` summarizes the corrected final outcomes; detailed before/after history remains in `RESULTS_PQ_CORRECTIONS.md`. All retained fixture and result bytes were preserved.
