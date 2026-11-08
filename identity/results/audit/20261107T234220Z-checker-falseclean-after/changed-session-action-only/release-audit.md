# Release-evidence audit of results/audit/20261107T234220Z-checker-falseclean-after/changed-session-action-only (checker version 2)

**Verdict: UNEXPECTED VIOLATION** (exit 1). Inventory: 6 cells from run-inventory.json (schema 2); 6 found; missing []; unexpected []; cardinality []; inventory errors []; malformed []; duplicate decision ids []. Producer evidence schemas seen: map[2:7].

Decisions 7 · dispatch attempts 6 · receipts 2 · orphan receipts 0 · duplicate release tokens []

Outcomes (each decision counted once):

* verified_dispatch: 1
* verified_non_dispatch: 4
* violation: 1
* violation_expected_by_fixture: 0
* insufficient_evidence: 0
* unsupported_historical_schema: 0
* malformed: 0
* ablation_excluded: 1

Checks by trust class (failed/total; classes are reported, never summed into one score):

* recomputed: 2/159
* requester_tls_observation: 0/12
* cooperative_event: 0/4
* copied_appraisal: 0/7
* stipulated_order: 0/2

Structural audit of retained records (checker version 2). Authorization validity is conditional on the recorded appraisal (copied_appraisal); TLS facts are the requester's own run-time observations; receipts are cooperative events attributed by the controller; cross-process order rests on causal ids (decision id, session key, token) and requester sequence numbers, with any remainder stipulated by the controller. Not tamper-proof evidence and not a security proof.

| cell | decision | schema | policy | path | authorized | dispatch | sent | refused | unknown | receipts | outcome | failed checks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1_honest_uninterrupted | 83007cba39… | 2 | S-env+cb | sent/ack | true | true | true | false | false | 1 (A) | violation | issued session equals the decision context (typed: expected, policy, action, audience) |
| 2_close_then_swap_to_B | 66a6070bc7… | 2 | S-env+cb | refused_reconnect | true | true | false | true | false | 0 () | verified_non_dispatch |  |
| 3_split_connection | ca4aaad30d… | 2 | S-env+cb | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| 4_cert_swap_sealed | b4b9af4005… | 2 | S-env+cb | refused_reconnect | true | true | false | true | false | 0 () | verified_non_dispatch |  |
| 4_cert_swap_noseal_ABLATION | bea15b92e6… | 2 | S-env+cb | dispatch_attempt/no-terminal | true | true | false | false | false | 0 () | ablation_excluded | exactly one dispatch terminal (sent | refused_reconnect | dispatch_error | write_failed) |
| 5_honest_recovery_new_decision | c10fce1958… | 2 | S-env+cb | refused_reconnect | true | true | false | true | false | 0 () | verified_non_dispatch |  |
| 5_honest_recovery_new_decision | cc82e82fac… | 2 | S-env+cb | sent/ack | true | true | true | false | false | 1 (A) | verified_dispatch |  |
