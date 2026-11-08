# Release-evidence audit of /home/bitchae/aisafety/swarmalign/a2a-identity/results/v3-final/20261108-004047 (checker version 2)

**Verdict: NO UNEXPECTED VIOLATION (8 fixture-predicted attack successes: the invariant was violated as declared)** (exit 0). Inventory: 24 cells from run-inventory.json (schema 2); 24 found; missing []; unexpected []; cardinality []; inventory errors []; malformed []; duplicate decision ids []. Producer evidence schemas seen: map[2:24].

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

* recomputed: 0/502
* requester_tls_observation: 0/22
* cooperative_event: 8/28
* copied_appraisal: 0/24
* stipulated_order: 0/14

Structural audit of retained records (checker version 2). Authorization validity is conditional on the recorded appraisal (copied_appraisal); TLS facts are the requester's own run-time observations; receipts are cooperative events attributed by the controller; cross-process order rests on causal ids (decision id, session key, token) and requester sequence numbers, with any remainder stipulated by the controller. Not tamper-proof evidence and not a security proof.

| cell | decision | schema | policy | path | authorized | dispatch | sent | refused | unknown | receipts | outcome | failed checks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| V1_C+url | ef8f0f896b… | 2 | C+url | sent/ack | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_C+tls | e91523097d… | 2 | C+tls | sent/ack | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_S-env+tls | a9879f2b7f… | 2 | S-env+tls | sent/ack | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_S-env+cb | 0aee647074… | 2 | S-env+cb | sent/ack | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_T+tls | 414d8dbf13… | 2 | T+tls | sent/ack | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V1_T+cb | a541b19e83… | 2 | T+cb | sent/ack | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| V2_C+url | c248260e90… | 2 | C+url | sent/ack | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V2_C+tls | 4c6fea6d25… | 2 | C+tls | sent/ack | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V2_S-env+tls | 882a99ad7f… | 2 | S-env+tls | sent/ack | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V2_S-env+cb | dc1a942c31… | 2 | S-env+cb | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V2_T+tls | dae9bcdb41… | 2 | T+tls | sent/ack | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V2_T+cb | a60fc45f58… | 2 | T+cb | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_C+url | e659a6a2c1… | 2 | C+url | sent/ack | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V3_C+tls | 4e4bd43656… | 2 | C+tls | sent/ack | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V3_S-env+tls | 40aa9dd72c… | 2 | S-env+tls | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_S-env+cb | 313c76a579… | 2 | S-env+cb | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_T+tls | ba17c65451… | 2 | T+tls | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V3_T+cb | 50eef671e7… | 2 | T+cb | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_C+url | ed0c414720… | 2 | C+url | sent/ack | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V4_C+tls | 9787da1d87… | 2 | C+tls | sent/ack | true | true | true | false | false | 1 (B) | violation_expected_by_fixture | receipt recipient is the expected enrolled deployment |
| V4_S-env+tls | 461825887d… | 2 | S-env+tls | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_S-env+cb | 11270b9338… | 2 | S-env+cb | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_T+tls | c1ee44cc29… | 2 | T+tls | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| V4_T+cb | aff18cb513… | 2 | T+cb | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
