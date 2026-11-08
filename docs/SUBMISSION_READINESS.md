# Submission readiness — 8 November 2026 (updated after the author's decisions)

## Deliverables
| item | path |
|---|---|
| final paper (PDF) | `paper/a2a-identity/output/pdf/a2a-identity-paper.pdf` (sha256 in `output/pdf/SHA256SUMS`; identical copy at `a2a-proof-binding-public/paper/a2a-identity-paper.pdf`) |
| editorial source / TeX / converter | `paper/a2a-identity/paper-draft.md`, `main.tex`, `md2tex.py` (tables and bibliography now generated from the Markdown) |
| LaTeX source ZIP (self-contained, builds standalone) | `paper/a2a-identity/a2a-identity-latex.zip` |
| publication copy | `/home/bitchae/aisafety/swarmalign/a2a-proof-binding-public/` (1,861 allowlisted files, 20.9 MB, manifest `docs/PROVENANCE_MANIFEST.json`) |
| pre-rewrite state preserved | `paper/a2a-identity/pre-finalization-20261108T113018Z/` (with hashes) |

## Format compliance (measured)
- Abstract: **236 words** (requirement 150–250).
- Main text: ends on **page 8**; references begin on page 9; appendices A–D on pages 9–12 (12 pages total). Template fonts (Old Standard TT), 11 pt, 1 in margins and spacing unchanged; no font shrinking.
- Official template preamble kept; title block carries author, event and track. The author decided to submit without an institutional affiliation (independent); no affiliation line is printed and none was invented.
- Required appendix "Limitations and dual-use / ethical considerations" present (Appendix A), stating what is and is not established and the dual-use considerations.
- Pre-sprint code marked (Appendix D; `identity/internal/cardsig` header; `docs/ATTRIBUTION.md`).
- No overfull boxes; all fonts embedded; no missing glyphs; diagram and tables inspected page by page.

## Evidence the paper rests on
- Identity: `a2a-identity/results/v3-final/20261108-004047` (checker v2, evidence schema 2), v2 matrix `results/v2/20261107-194025`, pre-fix reproductions `results/v3-repro/20261107-202528` and `results/audit/20261107T225036Z-v2-continuity-historical`, checker before/after controls.
- Computation: `a2a-identity-zkp/results/zk/20261108-111817` (schema 2, inventory first, oracle v2 exit 0, 52/52; 9 exchanges, 7 new proofs, 0 cache hits), integration rerun `results/zk-integration/20261108-112143`, before/after oracle and transport controls (`RESULTS_ZK_CORRECTIONS.md`). The first ZK run `20261108-002724` is cited only as superseded.
- Gate check for the ZK corrections: report present, final run + provenance + snapshot present, control sets present, reviewer characterization test fails to reproduce on the final snapshot, race suite and cargo tests logged in `results/audit/20261108T112430Z-zkcorr-final-snapshot/`; no producer process was running when packaging began.

## Checks performed on the publication copy (from the copy's own paths)
| check | result |
|---|---|
| `identity`: `go vet`, `go test -race -count=1 ./...` | pass (8 packages) |
| `identity`: `bin/a2aid audit-release` on a copy of the final run | exit 0, NO UNEXPECTED VIOLATION, 6/10/8 (run on the published directory first by mistake, which rewrote `release-audit.*`; those files were restored from the originals and the manifest re-verified; README now says to audit a copy) |
| `zk-component`: `go vet`, `go test -race -count=1 ./...` | pass (9 packages; oracle tests skip without `zkverify`) |
| `zk-component/zk`: `cargo build --release` from the copied sources (temporary target dir, existing local RISC Zero toolchain) | 1 min 43 s; rebuilt guest image id **equals the pinned id** `4f1e028e…` |
| `zk-component`: `zk-oracle` with the rebuilt verifier on the copied final run (output to a temp dir) | exit 0; 52 agree; 10 receipt/image pairs re-verified (7 valid, 3 rejected) |
| `zk-component`: legacy replay view of the copied first run | exit 0 |
| `zk-component`: `TestOracleV2_*` with the rebuilt verifier | pass |
| `zk-component/zk`: `cargo test --release` from the copied sources | 4 host tests pass |
| `docs/packaging/verify_manifest.py` | 1,861 entries, 0 mismatches, 0 missing, 0 unlisted |
| source files vs. hashed snapshots (`sha256sum -c`) | identity: only `README.md`, `RESULTS_V3_FINAL.md`, `SCOPE_AND_LIMITATIONS.md` differ (post-run documentation, disclosed in `RESULTS_V3_FINAL.md`); zk: only `README.md`, `RESULTS_ZK.md` differ (post-run documentation). `cmd/a2aid/main.go` of the ZK tree had a post-snapshot usage-string edit; it was reverted to the snapshot content and the rebuilt binary hash equals the snapshot's `48592e76…` |
| content scan (secrets, keys, tokens, e-mails, oversized files) | none found; only `/home/<user>/…` workspace paths inside retained run records, published byte-identical and disclosed |
| `.gitignore` rules | tested in a scratch repository: `run/`, keys, toolchains, targets, binaries, cache entries and any new run directory are ignored; the retained runs and `proof-cache/README.md` are tracked |
| documented commands/paths | every path named in `README.md`, `docs/RESULTS.md` and `docs/ARTIFACT_INVENTORY.md` exists |
| paper builds from packaged sources | `a2a-identity-latex.zip` unzipped into an empty directory compiles with LuaLaTeX to 12 pages (re-checked after the affiliation change) |
| not run | networked identity lab runs and new proof generation (not needed to verify the retained evidence; would need swtpm and ~3 min proving per matrix); fuzz budgets of `scripts/test.sh` |

## Changes from the reviewed manuscript
Complete rewrite around one question with two binding subquestions; title changed to
"Valid Proofs, Wrong Decisions: Identity and Task Binding in A2A"; abstract 332 → 236 words;
main text 9 → 8 pages; new §2 background (TLS/channel binding, TPM, zkVM defined), §3 threat
model with the Pinned/Current example, one measured-flow diagram, compact Tables 1–3 with
denominators, full v2 matrix moved to Appendix C; identity audit claim moved to checker v2 and
run `…004047`; 24/24, TLS receipt and churn accounting corrected; ZK section rebuilt on the
corrected run with the oracle v1 and transport defects disclosed; 9-exchange/7-proof counting;
timestamp disclosure; verified primary references added (TLS 1.3, RFC 5056, TPM 2.0, swtpm,
RISC Zero zkVM, JWS, FIPS 180-4); Appendix D for pre-sprint and third-party code.
Unresolved scientific limitations are stated in Appendix A (software TPM, synthetic PCR,
harness-enforced isolation, cooperative logs, no signature-only arm, coverage counts).

## Decisions taken by the author (8 Nov 2026)
1. **Affiliation:** none (independent author). The placeholder was removed; the PDF, ZIP and
   publication copy were rebuilt (PDF sha256 `f6a5b6d0…`, 12 pages, main text ends on page 8,
   abstract 236 words). If the submission form requires an affiliation string, "Independent"
   is the truthful entry.
2. **Licence:** Apache License 2.0. `LICENSE` and `NOTICE` (copyright, a2a-samples attribution
   for `internal/cardsig`) were added to the publication copy; `docs/ATTRIBUTION.md` updated.

## Remaining items (outside this work)
The submission form asks for team/member details (name, e-mail) and offers optional
video/slides; none were prepared here. The paper is otherwise ready to submit, and the
publication copy is ready to be initialized as a repository and pushed when the author
chooses; neither was done.

## Not done, by instruction
Nothing was uploaded, pushed, committed or submitted; no remote repository was created; the
publication copy is a plain directory (no `.git`). The unrelated template `paper/main.tex`
was not edited. The research trees and all retained runs are unchanged except the ZK tree's
`cmd/a2aid/main.go` usage string, which was reverted to its snapshot content.
