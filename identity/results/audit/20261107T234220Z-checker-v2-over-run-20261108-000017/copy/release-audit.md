# Release-evidence audit of results/audit/20261107T234220Z-checker-v2-over-run-20261108-000017/copy (checker version 2)

**Verdict: INCOMPLETE** (exit 2). Inventory: 24 cells from run-inventory.json (schema 0); 24 found; missing []; unexpected []; cardinality [V1_C+url: inventory declares no decision count (legacy inventory) V1_C+tls: inventory declares no decision count (legacy inventory) V1_S-env+tls: inventory declares no decision count (legacy inventory) V1_S-env+cb: inventory declares no decision count (legacy inventory) V1_T+tls: inventory declares no decision count (legacy inventory) V1_T+cb: inventory declares no decision count (legacy inventory) V2_C+url: inventory declares no decision count (legacy inventory) V2_C+tls: inventory declares no decision count (legacy inventory) V2_S-env+tls: inventory declares no decision count (legacy inventory) V2_S-env+cb: inventory declares no decision count (legacy inventory) V2_T+tls: inventory declares no decision count (legacy inventory) V2_T+cb: inventory declares no decision count (legacy inventory) V3_C+url: inventory declares no decision count (legacy inventory) V3_C+tls: inventory declares no decision count (legacy inventory) V3_S-env+tls: inventory declares no decision count (legacy inventory) V3_S-env+cb: inventory declares no decision count (legacy inventory) V3_T+tls: inventory declares no decision count (legacy inventory) V3_T+cb: inventory declares no decision count (legacy inventory) V4_C+url: inventory declares no decision count (legacy inventory) V4_C+tls: inventory declares no decision count (legacy inventory) V4_S-env+tls: inventory declares no decision count (legacy inventory) V4_S-env+cb: inventory declares no decision count (legacy inventory) V4_T+tls: inventory declares no decision count (legacy inventory) V4_T+cb: inventory declares no decision count (legacy inventory)]; inventory errors []; malformed []; duplicate decision ids []. Producer evidence schemas seen: map[none:24].

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
| V1_C+url | 5838058e42… | 0 | C+url |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_C+tls | 524b41e0ac… | 0 | C+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_S-env+tls | af0432a714… | 0 | S-env+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_S-env+cb | 88c42da3ff… | 0 | S-env+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_T+tls | 7bcbbc0c71… | 0 | T+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V1_T+cb | 093457d7ad… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_C+url | f7b5c693a2… | 0 | C+url |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_C+tls | ccc9e06ad4… | 0 | C+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_S-env+tls | 2d0598260a… | 0 | S-env+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_S-env+cb | 507f319286… | 0 | S-env+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_T+tls | 11fe59ad04… | 0 | T+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V2_T+cb | 0d0e20b384… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_C+url | 211fd88507… | 0 | C+url |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_C+tls | 2082720a7a… | 0 | C+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_S-env+tls | c56aa83a04… | 0 | S-env+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_S-env+cb | a75f4d0ed3… | 0 | S-env+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_T+tls | 958cb1fe9b… | 0 | T+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V3_T+cb | 6fccf01ac4… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_C+url | 3ce4e24957… | 0 | C+url |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_C+tls | b403e05780… | 0 | C+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_S-env+tls | a0a0be7882… | 0 | S-env+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_S-env+cb | 1bffc6df5d… | 0 | S-env+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_T+tls | 2bea0707eb… | 0 | T+tls |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| V4_T+cb | 34dab43817… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
