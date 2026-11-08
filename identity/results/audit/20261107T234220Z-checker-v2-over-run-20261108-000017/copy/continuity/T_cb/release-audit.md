# Release-evidence audit of results/audit/20261107T234220Z-checker-v2-over-run-20261108-000017/copy/continuity/T_cb (checker version 2)

**Verdict: INCOMPLETE** (exit 2). Inventory: 6 cells from run-inventory.json (schema 0); 6 found; missing []; unexpected []; cardinality [1_honest_uninterrupted: inventory declares no decision count (legacy inventory) 2_close_then_swap_to_B: inventory declares no decision count (legacy inventory) 3_split_connection: inventory declares no decision count (legacy inventory) 4_cert_swap_sealed: inventory declares no decision count (legacy inventory) 4_cert_swap_noseal_ABLATION: inventory declares no decision count (legacy inventory) 5_honest_recovery_new_decision: inventory declares no decision count (legacy inventory)]; inventory errors []; malformed []; duplicate decision ids []. Producer evidence schemas seen: map[none:7].

Decisions 7 · dispatch attempts 0 · receipts 0 · orphan receipts 0 · duplicate release tokens []

Outcomes (each decision counted once):

* verified_dispatch: 0
* verified_non_dispatch: 0
* violation: 0
* violation_expected_by_fixture: 0
* insufficient_evidence: 0
* unsupported_historical_schema: 6
* malformed: 0
* ablation_excluded: 1

Checks by trust class (failed/total; classes are reported, never summed into one score):

* recomputed: 7/7
* requester_tls_observation: 0/0
* cooperative_event: 0/0
* copied_appraisal: 0/0
* stipulated_order: 0/0

Structural audit of retained records (checker version 2). Authorization validity is conditional on the recorded appraisal (copied_appraisal); TLS facts are the requester's own run-time observations; receipts are cooperative events attributed by the controller; cross-process order rests on causal ids (decision id, session key, token) and requester sequence numbers, with any remainder stipulated by the controller. Not tamper-proof evidence and not a security proof.

| cell | decision | schema | policy | path | authorized | dispatch | sent | refused | unknown | receipts | outcome | failed checks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1_honest_uninterrupted | d6e4f5f80e… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| 2_close_then_swap_to_B | d6ba239dba… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| 3_split_connection | 101e74f952… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| 4_cert_swap_sealed | 9fd20d6689… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| 4_cert_swap_noseal_ABLATION | 49719d0dc2… | 0 | T+cb |  | false | false | false | false | false | 0 () | ablation_excluded | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| 5_honest_recovery_new_decision | efa11eb628… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
| 5_honest_recovery_new_decision | f29225328e… | 0 | T+cb |  | false | false | false | false | false | 0 () | unsupported_historical_schema | record carries evidence_schema>=2, decision_id, requester_events and typed context |
