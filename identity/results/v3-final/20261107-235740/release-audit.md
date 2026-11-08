# Release-evidence audit of results/v3-final/20261107-235740

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
| V1_C+url | 88a1f22463… | C+url | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_C+tls | cc9b151b01… | C+tls | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_S-env+tls | 5da47564d3… | S-env+tls | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_S-env+cb | 116938ed24… | S-env+cb | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_T+tls | c97cf4712f… | T+tls | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_T+cb | 1b6e235559… | T+cb | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V2_C+url | acaf685996… | C+url | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V2_C+tls | f090ae608d… | C+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V2_S-env+tls | 8717d83c5f… | S-env+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V2_S-env+cb | 9e6343950a… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V2_T+tls | 6b91c2bf9d… | T+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V2_T+cb | 3199dfa170… | T+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_C+url | b3a14b279c… | C+url | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V3_C+tls | 291955c883… | C+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V3_S-env+tls | e0fbb24339… | S-env+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_S-env+cb | eca4ca4e99… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_T+tls | d500b808b3… | T+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_T+cb | 2d8007dc8d… | T+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_C+url | 8d4c39c7c5… | C+url | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V4_C+tls | a4be2f7934… | C+tls | true | true | true | false | false | 1 (B) | violation | receipt recipient is the expected enrolled deployment |
| V4_S-env+tls | 82ff7c9cc5… | S-env+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_S-env+cb | f6c6c3227c… | S-env+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_T+tls | 5ba7d399e8… | T+tls | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_T+cb | 8023eea75c… | T+cb | false | false | false | false | false | 0 () | verified_non_dispatch |  |
