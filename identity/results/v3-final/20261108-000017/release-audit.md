# Release-evidence audit of /home/bitchae/aisafety/swarmalign/a2a-identity/results/v3-final/20261108-000017

**Verdict: NO UNEXPECTED VIOLATION (8 fixture-predicted attack successes: the invariant was violated as declared)** (exit 0). Inventory: 24 cells from run-inventory.json; 24 found; missing []; unexpected []; malformed [].

Decisions 24 · dispatch attempts 14 · receipts 14 · orphan receipts 0 · duplicate release tokens []

Outcomes (each decision counted once):

* verified_dispatch: 6
* verified_non_dispatch: 10
* violation: 0
* violation_expected_by_fixture: 8
* insufficient_evidence: 0
* unsupported_historical_schema: 0
* malformed: 0
* ablation_excluded: 0

Checks by trust class (failed/total; classes are reported, never summed into one score):

* recomputed: 0/164
* requester_tls_observation: 0/22
* cooperative_event: 8/28
* copied_appraisal: 0/24
* stipulated_order: 0/14

Structural audit of retained records. Authorization validity is conditional on the recorded appraisal (copied_appraisal); TLS facts are the requester's own run-time observations; receipts are cooperative events attributed by the controller; cross-process order rests on causal ids (decision id, nonce, token) and requester sequence numbers, with any remainder stipulated by the controller. Not tamper-proof evidence and not a security proof.

| cell | decision | policy | authorized | dispatch | sent | refused | unknown | receipts | outcome | failed checks |
|---|---|---|---|---|---|---|---|---|---|---|
| V1_C+url | 5838058e42… | C+url | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_C+tls | 524b41e0ac… | C+tls | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_S-env+tls | af0432a714… | S-env+tls | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_S-env+cb | 88c42da3ff… | S-env+cb | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_T+tls | 7bcbbc0c71… | T+tls | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_T+cb | 093457d7ad… | T+cb | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V2_C+url | f7b5c693a2… | C+url | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V2_C+tls | ccc9e06ad4… | C+tls | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V2_S-env+tls | 2d0598260a… | S-env+tls | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V2_S-env+cb | 507f319286… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V2_T+tls | 11fe59ad04… | T+tls | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V2_T+cb | 0d0e20b384… | T+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_C+url | 211fd88507… | C+url | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V3_C+tls | 2082720a7a… | C+tls | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V3_S-env+tls | c56aa83a04… | S-env+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_S-env+cb | a75f4d0ed3… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_T+tls | 958cb1fe9b… | T+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_T+cb | 6fccf01ac4… | T+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_C+url | 3ce4e24957… | C+url | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V4_C+tls | b403e05780… | C+tls | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V4_S-env+tls | a0a0be7882… | S-env+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_S-env+cb | 1bffc6df5d… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_T+tls | 2bea0707eb… | T+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_T+cb | 34dab43817… | T+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
