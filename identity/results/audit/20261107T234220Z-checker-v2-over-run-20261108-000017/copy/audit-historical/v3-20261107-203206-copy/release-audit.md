# Release-evidence audit of /home/bitchae/aisafety/swarmalign/a2a-identity/results/v3-final/20261108-000017/audit-historical/v3-20261107-203206-copy

**Verdict: INCOMPLETE** (exit 2). Inventory: 24 cells from manifest-frozen.json (derived; historical run without a declared inventory); 24 found; missing []; unexpected []; malformed [].

Decisions 24 · dispatch attempts 0 · receipts 0 · orphan receipts 0 · duplicate release tokens []

Outcomes (each decision counted once):

* verified_dispatch: 0
* verified_non_dispatch: 0
* violation: 0
* violation_expected_by_fixture: 0
* insufficient_evidence: 0
* unsupported_historical_schema: 24
* malformed: 0
* ablation_excluded: 0

Checks by trust class (failed/total; classes are reported, never summed into one score):

* recomputed: 24/24
* requester_tls_observation: 0/0
* cooperative_event: 0/0
* copied_appraisal: 0/0
* stipulated_order: 0/0

Structural audit of retained records. Authorization validity is conditional on the recorded appraisal (copied_appraisal); TLS facts are the requester's own run-time observations; receipts are cooperative events attributed by the controller; cross-process order rests on causal ids (decision id, nonce, token) and requester sequence numbers, with any remainder stipulated by the controller. Not tamper-proof evidence and not a security proof.

| cell | decision | policy | authorized | dispatch | sent | refused | unknown | receipts | outcome | failed checks |
|---|---|---|---|---|---|---|---|---|---|---|
| V1_C+url |  | C+url | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V1_C+tls |  | C+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V1_S-env+tls |  | S-env+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V1_S-env+cb |  | S-env+cb | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V1_T+tls |  | T+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V1_T+cb |  | T+cb | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V2_C+url |  | C+url | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V2_C+tls |  | C+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V2_S-env+tls |  | S-env+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V2_S-env+cb |  | S-env+cb | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V2_T+tls |  | T+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V2_T+cb |  | T+cb | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V3_C+url |  | C+url | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V3_C+tls |  | C+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V3_S-env+tls |  | S-env+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V3_S-env+cb |  | S-env+cb | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V3_T+tls |  | T+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V3_T+cb |  | T+cb | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V4_C+url |  | C+url | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V4_C+tls |  | C+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V4_S-env+tls |  | S-env+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V4_S-env+cb |  | S-env+cb | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V4_T+tls |  | T+tls | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
| V4_T+cb |  | T+cb | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries decision_id and requester_events |
