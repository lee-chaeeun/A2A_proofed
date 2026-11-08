# Publication readiness — 8 November 2026

## Current paper

- Editable source: `paper/paper-draft.md` and `paper/main.tex`; Markdown conversion uses pandoc, compilation uses LuaLaTeX.
- PDF: `paper/a2a-identity-paper.pdf`, **16 pages**; main text ends on **page 8**, references start on page 9; **217-word abstract**, **19 references**.
- Source package: `paper/a2a-identity-latex.zip`, with TeX, Markdown, converter, compiler setting, fonts and their OFL license. Tested from a separate source directory with LuaLaTeX twice.
- PDF SHA256: `700bd35997c8d7fa56358cc896b30cff513b6a657446a3d8fdcbda69034a5166`; file and ZIP hashes are in `paper/SHA256SUMS`.
- The main text explains the PQ identity study, separate classical/ZK results and the narrower composition smoke test. The Google CAPS technical report remains reference 19. The background/algorithm appendices are retained.

## Checks executed in this review

| Check | Result |
|---|---|
| New root reproduction entry point, all three modules | Go builds and race suites pass |
| Corrected PQ final and integration evidence | Both 128/128 agree; composite audit exit 0 |
| PQ full-run mutation controls | 17/17 classifications match |
| Runner failure injection | 9/9, including the actual built audit binary |
| Classical release audit | Exit 0; eight declared weak-policy attack successes remain listed |
| Standalone ZK oracle | 52/52 agree, seven expected weak-policy successes; genuine receipts reverified |
| Public PQ emulator with rebuilt bridge | Opt-in create/sign/negative/restart/evict test passes |
| Restored public Rust source | Clean offline build with cached dependencies and the installed RISC Zero 3.0.6 guest toolchain, separate target directory; all four Rust tests pass |
| Public-built Rust verifier on retained ZK run | Oracle exit 0, 52/52 agree; no new proofs generated |
| Package completeness | All six declared Rust CLI sources present, Git-visible and inventoried; source guide covers every application source; relative documentation links resolve |
| Packaging regression tests | 3/3 (complete source, missing source, overly broad Git ignore) |
| Retained raw evidence and fixtures | All 2467 baseline hashes unchanged |
| Paper | LuaLaTeX twice, no undefined citations, overfull boxes or missing characters; all 16 rendered pages inspected |

Fresh full matrices, new genuine proofs, a new timing benchmark and physical hardware were not run in this review. The Rust build used already installed guest tools and cached dependencies, not a fresh installation of that toolchain. The emulator libraries were the public-copy build retained from the correction pass; this review rebuilt the C bridge against them and exercised them. Default Go skips are not counted as those opt-in integrations.

## Public tree

The three directories are final implementations of distinct paper studies. Generated toolchains, binaries and live state are excluded. The unused discovery/paid-inference command was removed; no experimental security implementation changed. Rust `src/bin` source is restored and included in Git and provenance checks. `docs/CODE_MAP.md` lists every source file; `docs/REPRODUCING.md` gives the prerequisites and commands.

Selected earlier observations remain only where the paper or a regression control needs them; archived code versions and source tarballs are not shipped. Raw historical paths inside copied records are preserved, not rewritten. The pre-cleanup publication tree and generated files are preserved outside the repository in the author's research workspace.

Nothing was committed, pushed or submitted. The Git working tree is prepared for the author to review and publish. Submission-form team details and optional presentation materials remain separate from the repository.
