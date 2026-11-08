# Artifact inventory

Every retained run and control set in this copy, with its role. "Full" = all files of the
directory; "top level" = the directory's files without per-cell subtrees; "summaries" = the
set's `controls.json` plus each case's CLI log and oracle summary (mutated run copies omitted).

## identity/results
| directory | role | copy |
|---|---|---|
| `v3-final/20261108-004047` | **final corrected identity run** (evidence schema 2, checker v2): matrix, continuity cells, churn, audits, negative controls, provenance, test logs | full (incl. `process-logs/`, `boot/`) |
| `v3-final/20261108-000017` | first final run (schema 1); its checker v1 passed five corruptions; superseded | top level + continuity summaries |
| `v3-final/20261107-235740`, `20261107-235908` | failed attempts (harness defects, notes) | top level |
| `v2/20261107-194025` | retained v2 coverage matrix (231 cells) | top level (no `cells/`) |
| `v3/20261107-203206` | fixed v3 matrix (24 cells, 4 prediction misses) | full |
| `v3-repro/20261107-202528` | pre-fix reproduction of the binding attacks on the archived v2 binary | full |
| `audit/20261107T225036Z-v2-continuity-historical` | pre-fix connection-swap reproduction on an isolated extraction of the archived v2 source | full except the source tarball |
| `audit/20261107T233054Z-checker-falseclean-before`, `audit/20261107T234220Z-checker-falseclean-after` | the five reviewer corruptions through checker v1 (clean) and v2 (2,2,1,1,1) | full |
| `audit/20261107T234220Z-checker-v2-over-run-20261108-000017` | checker v2 over the schema-1 run: unsupported historical schema | reports |
| `audit/20261107T233054Z-v3corr-prefix`, `audit/20261107T234045Z-v3final-snapshot` | pre-edit hashes and the producer snapshot of the final run | hash lists and notes (no tarball/binary) |
| `reviewer-v3-final/` | independent reviewer reproductions | full except tarballs |

Not included (see `OMISSIONS.md`): v1 run, aborted/partial v2 runs, v2 per-cell traces, v1 audit directory.

## zk-component/results
| directory | role | copy |
|---|---|---|
| `zk/20261108-111817` | **final ZK run** (evidence schema 2, inventory declared first, oracle v2 exit 0, 52/52) | full |
| `zk/20261108-002724` | first ZK run (schema 1; same 52 outcomes; scored by oracle v1 at the time; superseded as validation) | full except mutated copies under `oracle-controls/` (its `controls.json` kept) |
| `zk/20261108-002012`, `zk/20261108-002316` | failed attempts (HTTP timeout; oracle heuristic), with notes | top level |
| `zk/feasibility` | feasibility gate: first genuine receipt, build hashes, timings | full |
| `zk/PLAN.sha256`, `zk/zk-integration-test*.log` | pre-run plan hash; integration logs | files |
| `zk-integration/20261108-112143` | second independent execution after the corrections (52/52, oracle exit 0) | full |
| `zk-integration/20261108-003306` | second execution of the first version | top level + receipts |
| `audit/20261108T105605Z-zk-before-fix` | before-fix reproductions: unsigned-card dispatch (PASS = reproduced) and oracle v1 on four reviewer mutations (all exit 0) | logs + summaries |
| `audit/20261108T111037Z-zk-oracle-controls-after-legacyview`, `audit/20261108T112131Z-zk-oracle-controls-after-schema2` | 24 mutations + unmodified through oracle v2 (legacy view of the first run; schema-2 final run) | summaries |
| `audit/20261108T112526Z-zk-legacy-view-20261108-002724`, `…112527Z-…-003306` | legacy replay/audit views of the schema-1 runs (exit 0, limitations listed) | full |
| `audit/20261108T105409Z-zkcorr-prefix`, `…111816Z-zkcorr-snapshot`, `…112430Z-zkcorr-final-snapshot`, `…003236Z-zk-snapshot` | pre-edit, producer, final-checker and first-run snapshots | hash lists, logs, notes (no tarball/binary) |
| `reviewer-zk/20261108T103550Z` | reviewer's reproduction script, receipt re-verification, oracle checks, characterization test | files (no copied runs) |

## Fixtures (inputs)
Identity: `identity/fixtures/manifest*.json`, `predictions*.md` (frozen per version, addenda only).
ZK: `zk-component/fixtures/zk/predictions.json` (frozen), `authority.json` (public commitments),
`openings.json` (**synthetic private openings, published deliberately for reproducibility;
not credentials and not claimed private**), `legacy-inventory-v1.json` (declared 8 Nov 2026
for the schema-1 runs).

## Test data
`zk-component/zk/host/testdata/genuine-receipt-v1.b64` and `image-id.txt`: a retained genuine
receipt used by the Rust host tests (no proving in tests).
