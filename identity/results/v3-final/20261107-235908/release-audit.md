# Release-evidence audit of results/v3-final/20261107-235908

**Verdict: VIOLATION** (exit 1). Inventory: 24 cells from run-inventory.json; 24 found; missing []; unexpected []; malformed [].

Decisions 24 · dispatch attempts 14 · receipts 14 · orphan receipts 0 · duplicate release tokens []

Outcomes (each decision counted once):

* verified_dispatch: 6
* verified_non_dispatch: 10
* violation: 8
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
| V1_C+url | 7eb744ecfe… | C+url | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_C+tls | 2b87d5aea7… | C+tls | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_S-env+tls | f7a74d1356… | S-env+tls | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_S-env+cb | 2d00c15edc… | S-env+cb | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_T+tls | da2c365edc… | T+tls | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_T+cb | 6249d94947… | T+cb | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V2_C+url | 62ceb0e544… | C+url | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V2_C+tls | c30f1eb449… | C+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V2_S-env+tls | 930cd26c74… | S-env+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V2_S-env+cb | a2f209abe1… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V2_T+tls | b2274437d2… | T+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V2_T+cb | 68bf3fa697… | T+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_C+url | 361429c55a… | C+url | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V3_C+tls | 22e4e62071… | C+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V3_S-env+tls | eb3e6b9268… | S-env+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_S-env+cb | 1d9a01cddf… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_T+tls | 26b652a428… | T+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_T+cb | e27e84b143… | T+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_C+url | 0c94143536… | C+url | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V4_C+tls | ed3a8ffdf9… | C+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V4_S-env+tls | 33c2fa9396… | S-env+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_S-env+cb | 11b559c584… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_T+tls | 43c49bb791… | T+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_T+cb | 52d13fba52… | T+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
