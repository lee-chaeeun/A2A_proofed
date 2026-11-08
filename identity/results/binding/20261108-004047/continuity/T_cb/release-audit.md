# Release-evidence audit of /home/bitchae/aisafety/swarmalign/a2a-identity/results/v3-final/20261108-004047/continuity/T_cb (checker version 2)

**Verdict: NO UNEXPECTED VIOLATION** (exit 0). Inventory: 6 cells from run-inventory.json (schema 2); 6 found; missing []; unexpected []; cardinality []; inventory errors []; malformed []; duplicate decision ids []. Producer evidence schemas seen: map[2:7].

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

* recomputed: 1/159
* requester_tls_observation: 0/12
* cooperative_event: 0/4
* copied_appraisal: 0/7
* stipulated_order: 0/2

Structural audit of retained records (checker version 2). Authorization validity is conditional on the recorded appraisal (copied_appraisal); TLS facts are the requester's own run-time observations; receipts are cooperative events attributed by the controller; cross-process order rests on causal ids (decision id, session key, token) and requester sequence numbers, with any remainder stipulated by the controller. Not tamper-proof evidence and not a security proof.

| cell | decision | schema | policy | path | authorized | dispatch | sent | refused | unknown | receipts | outcome | failed checks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1_honest_uninterrupted | 704b05d8c3… | 2 | T+cb | sent/ack | true | true | true | false | false | 1 (A) | verified_dispatch |  |
| 2_close_then_swap_to_B | 548ffc8742… | 2 | T+cb | refused_reconnect | true | true | false | true | false | 0 () | verified_non_dispatch |  |
| 3_split_connection | 48f6ef6592… | 2 | T+cb | rejected | false | false | false | false | false | 0 () | verified_non_dispatch |  |
| 4_cert_swap_sealed | e0cabe451b… | 2 | T+cb | refused_reconnect | true | true | false | true | false | 0 () | verified_non_dispatch |  |
| 4_cert_swap_noseal_ABLATION | 95841623a1… | 2 | T+cb | dispatch_attempt/no-terminal | true | true | false | false | false | 0 () | ablation_excluded | exactly one dispatch terminal (sent | refused_reconnect | dispatch_error | write_failed) |
| 5_honest_recovery_new_decision | 80525a6a6d… | 2 | T+cb | refused_reconnect | true | true | false | true | false | 0 () | verified_non_dispatch |  |
| 5_honest_recovery_new_decision | d414551ae7… | 2 | T+cb | sent/ack | true | true | true | false | false | 1 (A) | verified_dispatch |  |
