# Release-evidence audit of results/audit/20261107T233054Z-checker-falseclean-before/removed-appraised-event

**Verdict: NO UNEXPECTED VIOLATION** (exit 0). Inventory: 6 cells from run-inventory.json; 6 found; missing []; unexpected []; malformed [].

Decisions 7 · dispatch attempts 6 · receipts 2 · orphan receipts 0 · duplicate release tokens []

Outcomes (each decision counted once):

* verified_dispatch: 2
* verified_non_dispatch: 4
* violation: 0
* violation_expected_by_fixture: 0
* insufficient_evidence: 0
* unsupported_historical_schema: 0
* malformed: 0
* ablation_excluded: 1

Checks by trust class (failed/total; classes are reported, never summed into one score):

* recomputed: 1/56
* requester_tls_observation: 0/12
* cooperative_event: 0/4
* copied_appraisal: 0/7
* stipulated_order: 0/2

Structural audit of retained records. Authorization validity is conditional on the recorded appraisal (copied_appraisal); TLS facts are the requester's own run-time observations; receipts are cooperative events attributed by the controller; cross-process order rests on causal ids (decision id, nonce, token) and requester sequence numbers, with any remainder stipulated by the controller. Not tamper-proof evidence and not a security proof.

| cell | decision | policy | authorized | dispatch | sent | refused | unknown | receipts | outcome | failed checks |
|---|---|---|---|---|---|---|---|---|---|---|
| 1_honest_uninterrupted | 8713769894… | S-env+cb | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| 2_close_then_swap_to_B | a73bb283a9… | S-env+cb | true | true | false | true | false | 0 () | verified_non_dispatch |  |
| 3_split_connection | 2e8e79f234… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| 4_cert_swap_sealed | 41b5a99469… | S-env+cb | true | true | false | true | false | 0 () | verified_non_dispatch |  |
| 4_cert_swap_noseal_ABLATION | 14a2b63122… | S-env+cb | true | true | false | false | false | 0 () | ablation_excluded | pinned connection is the proof connection |
| 5_honest_recovery_new_decision | 8877fef79f… | S-env+cb | true | true | false | true | false | 0 () | verified_non_dispatch |  |
| 5_honest_recovery_new_decision | f5c3b27294… | S-env+cb | true | true | true | false | false | 1 (A) | verified_dispatch |  |
