# Release-evidence audit of /home/bitchae/aisafety/swarmalign/a2a-identity/results/v3-final/20261108-004047/audit-historical/historical-copy (checker version 2)

**Verdict: INCOMPLETE** (exit 2). Inventory: 24 cells from manifest-frozen.json (derived; historical run without a declared inventory) (schema 0); 24 found; missing []; unexpected []; cardinality [V1_C+url: inventory declares no decision count (legacy inventory) V1_C+tls: inventory declares no decision count (legacy inventory) V1_S-env+tls: inventory declares no decision count (legacy inventory) V1_S-env+cb: inventory declares no decision count (legacy inventory) V1_T+tls: inventory declares no decision count (legacy inventory) V1_T+cb: inventory declares no decision count (legacy inventory) V2_C+url: inventory declares no decision count (legacy inventory) V2_C+tls: inventory declares no decision count (legacy inventory) V2_S-env+tls: inventory declares no decision count (legacy inventory) V2_S-env+cb: inventory declares no decision count (legacy inventory) V2_T+tls: inventory declares no decision count (legacy inventory) V2_T+cb: inventory declares no decision count (legacy inventory) V3_C+url: inventory declares no decision count (legacy inventory) V3_C+tls: inventory declares no decision count (legacy inventory) V3_S-env+tls: inventory declares no decision count (legacy inventory) V3_S-env+cb: inventory declares no decision count (legacy inventory) V3_T+tls: inventory declares no decision count (legacy inventory) V3_T+cb: inventory declares no decision count (legacy inventory) V4_C+url: inventory declares no decision count (legacy inventory) V4_C+tls: inventory declares no decision count (legacy inventory) V4_S-env+tls: inventory declares no decision count (legacy inventory) V4_S-env+cb: inventory declares no decision count (legacy inventory) V4_T+tls: inventory declares no decision count (legacy inventory) V4_T+cb: inventory declares no decision count (legacy inventory)]; inventory errors []; malformed []; duplicate decision ids []. Producer evidence schemas seen: map[none:24].

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

Structural audit of retained records (checker version 2). Authorization validity is conditional on the recorded appraisal (copied_appraisal); TLS facts are the requester's own run-time observations; receipts are cooperative events attributed by the controller; cross-process order rests on causal ids (decision id, session key, token) and requester sequence numbers, with any remainder stipulated by the controller. Not tamper-proof evidence and not a security proof.

| cell | decision | schema | policy | path | authorized | dispatch | sent | refused | unknown | receipts | outcome | failed checks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| V1_C+url |  | 0 | C+url |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_C+tls |  | 0 | C+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_S-env+tls |  | 0 | S-env+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_S-env+cb |  | 0 | S-env+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_T+tls |  | 0 | T+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_T+cb |  | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_C+url |  | 0 | C+url |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_C+tls |  | 0 | C+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_S-env+tls |  | 0 | S-env+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_S-env+cb |  | 0 | S-env+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_T+tls |  | 0 | T+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_T+cb |  | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_C+url |  | 0 | C+url |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_C+tls |  | 0 | C+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_S-env+tls |  | 0 | S-env+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_S-env+cb |  | 0 | S-env+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_T+tls |  | 0 | T+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_T+cb |  | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_C+url |  | 0 | C+url |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_C+tls |  | 0 | C+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_S-env+tls |  | 0 | S-env+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_S-env+cb |  | 0 | S-env+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_T+tls |  | 0 | T+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_T+cb |  | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
