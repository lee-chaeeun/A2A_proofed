# Final correction and publication review

Reviewed on 8 November 2026 using public source and retained records, not only the producer's summary.

## Assessment

The earlier integration/evidence findings have focused fixes: the ZK task uses the shared delivery guard, the PQ audit composes signature checks with structural release checks, and runner failures propagate. Tests support these repairs. The experiment supports emulator-command feasibility and the declared comparisons, not physical protection or a new cryptographic primitive.

## Independently checked

| Check | Observation |
|---|---|
| Public Go race suites, all three components | Pass; repeated through the new reproduction entry point after publication changes |
| Both corrected PQ retained runs | Audit exit 0, 128/128 agree, 25 declared attacker deliveries, zero orphan receipts/duplicate ids |
| Full-run evidence mutations | 17/17 expected outcomes |
| Runner failure injection | 9/9, including the real audit/control case |
| Public emulator backend and rebuilt C bridge | Device create/sign/negative/restart/evict test passes; first invocation correctly failed because the deliberately unshipped bridge was not built |
| Retained standalone ZK evidence | Oracle exit 0, 52/52 agree, seven expected weak-policy approvals; existing genuine receipts reverified |
| ZK transport tests | HTTPS and server counters; software test key/stub receipt distinguished from actual device/proving tests |
| Related work | Both IETF drafts checked directly; MTAC has a verifier and vectors, not only requirements |

No new full PQ/ZK matrix, genuine computation proof or timing benchmark was generated. The device test creates a temporary emulator key. Public Rust-build and paper/package checks are recorded in [SUBMISSION_READINESS.md](SUBMISSION_READINESS.md).

## Publication defects repaired

- Broad `bin/` exclusions hid Rust executable source. The PQ copy lacked three `zk/host/src/bin/*.rs` files; the standalone copy had them but Git ignored them. The inventory also excluded those paths, so its clean result did not establish completeness. Sources were restored byte-for-byte; Git and manifest rules now include them. Cargo-path checks and three regression tests detect missing source and the bad Git rule.
- A 1.3 GB toolchain and generated binaries remained locally. They were moved outside the public tree. No dependency checkout, live state or executable is shipped.
- CLI help omitted PQ/ZK commands, while an unused discovery/paid-inference feature remained. Help is corrected and that unmeasured feature is removed. Cryptographic, matrix, appraisal, delivery, guest and audit implementations are unchanged by publication edits.

## Manuscript changes

The abstract, introduction and result section explain decisions before measurements. Context schemas are distinguished from identical signed bytes; emulator key use from physical protection. The identity proof authenticates the receiving connection, not the later ZK payload or the location of computation. Related work is described accurately as migration requirements and credential issuance. Background remains in appendices; AI assistance remains disclosed.

The PDF converter also left literal checkmarks in appendix tables, where the template font could not render them. The converter now emits LaTeX checkmarks for both body and appendix, and the corrected table was rendered and checked.

## Remaining scope

The signer boundary is simulated under one OS account; emulator state and authorization files are copyable. Cards, TLS and the CA are classical. Enrollment/revocation are not production protocols. The audit trusts inventory, registry and cooperative observations. Scripted scenarios are not attack-rate estimates. Full PQ-to-ZK adversarial composition remains unmeasured. These limitations stay visible in the paper.
