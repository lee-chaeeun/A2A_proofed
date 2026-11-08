# Offline business-decision oracle v2 for results/audit/20261108T112131Z-zk-oracle-controls-after-schema2/approval-event-duplicated-Z1-V0

Mode: schema-2 (inventory declared before execution) · declared 52 · rows read 52 · scored 0 (agree 0, disagree 0) · violations 20 · evidence mismatches 0 · incomplete 0 · malformed 51 · expected weak-policy attack successes 0 · **exit 1**

* Wrong-context receipts accepted: 0/0
* Unsafe approvals (input not authorized under the contract at the decision point): 0/0
* Legitimate approvals denied: 0/0
* Expected attack successes (deliberately incomplete policies): 
* Verifier: zk/target/release/zkverify sha256 c96cd5818b68266c5c05aa48890e692c563ced73a26784633c2c2b5bfa4472c6 (matches run provenance: true); 10 unique receipt/image pairs re-verified, 7 verified, 3 rejected, 0 failures. pinned RISC Zero verifier CLI (zkverify) re-run by the oracle per unique (receipt, declared image id); a shared component, not an independent proof-system implementation
* sums, commitments and journal decoding recomputed by the oracle's own routines (internal/zk/oracle_arith.go); production helpers and Evaluate are not called

Run-level findings:
* violation: events show 2 insertions in ledger Z1/V0 but ledgers.json records 1
* violation: ledgers.json entry 0 of Z3/V0 differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z5/V0 differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z1/VT differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z3/VI differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z6/V0 differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z7/V0 differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z3P/VT differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z4/VT differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z7/VT differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z1/VI differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z3P/V0 differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z3P/VTI differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z6/VI differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z6/VT differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z6/VTI differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z1/VTI differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z3P/VI differs from the reconstructed approval
* violation: ledgers.json entry 0 of Z4/V0 differs from the reconstructed approval

| evaluation | status | receipt | correct | semantics | prior approval | expected insert | observed insert | attack success | detail |
|---|---|---|---|---|---|---|---|---|---|
| Z1/V0 | violation | verified | false | false | false | false | false | false | 2 approval_inserted events for one evaluation |
| Z1/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z1/VT, 7) disagree with the row (Z1/VT, 6) |
| Z1/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z1/VI, 9) disagree with the row (Z1/VI, 8) |
| Z1/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z1/VTI, 11) disagree with the row (Z1/VTI, 10) |
| Z10/V0 | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z10/V0, 99) disagree with the row (Z10/V0, 98) |
| Z10/VT | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z10/VT, 100) disagree with the row (Z10/VT, 99) |
| Z10/VI | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z10/VI, 101) disagree with the row (Z10/VI, 100) |
| Z10/VTI | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z10/VTI, 102) disagree with the row (Z10/VTI, 101) |
| Z11/V0 | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z1/V0, 13) disagree with the row (Z1/V0, 12) |
| Z11/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z1/VT, 14) disagree with the row (Z1/VT, 13) |
| Z11/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z1/VI, 15) disagree with the row (Z1/VI, 14) |
| Z11/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z1/VTI, 16) disagree with the row (Z1/VTI, 15) |
| Z2/V0 | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z2/V0, 29) disagree with the row (Z2/V0, 28) |
| Z2/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z2/VT, 30) disagree with the row (Z2/VT, 29) |
| Z2/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z2/VI, 31) disagree with the row (Z2/VI, 30) |
| Z2/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z2/VTI, 32) disagree with the row (Z2/VTI, 31) |
| Z3/V0 | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z3/V0, 36) disagree with the row (Z3/V0, 35) |
| Z3/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z3/VT, 38) disagree with the row (Z3/VT, 37) |
| Z3/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z3/VI, 39) disagree with the row (Z3/VI, 38) |
| Z3/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z3/VTI, 41) disagree with the row (Z3/VTI, 40) |
| Z3P/V0 | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z3P/V0, 44) disagree with the row (Z3P/V0, 43) |
| Z3P/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z3P/VT, 46) disagree with the row (Z3P/VT, 45) |
| Z3P/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z3P/VI, 48) disagree with the row (Z3P/VI, 47) |
| Z3P/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z3P/VTI, 50) disagree with the row (Z3P/VTI, 49) |
| Z4/V0 | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z4/V0, 56) disagree with the row (Z4/V0, 55) |
| Z4/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z4/VT, 58) disagree with the row (Z4/VT, 57) |
| Z4/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z4/VI, 60) disagree with the row (Z4/VI, 59) |
| Z4/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z4/VTI, 61) disagree with the row (Z4/VTI, 60) |
| Z5/V0 | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z5/V0, 64) disagree with the row (Z5/V0, 63) |
| Z5/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z5/VT, 66) disagree with the row (Z5/VT, 65) |
| Z5/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z5/VI, 67) disagree with the row (Z5/VI, 66) |
| Z5/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z5/VTI, 68) disagree with the row (Z5/VTI, 67) |
| Z6/V0 | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z6/V0, 73) disagree with the row (Z6/V0, 72) |
| Z6/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z6/VT, 75) disagree with the row (Z6/VT, 74) |
| Z6/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z6/VI, 77) disagree with the row (Z6/VI, 76) |
| Z6/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z6/VTI, 79) disagree with the row (Z6/VTI, 78) |
| Z7/V0 | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z7/V0, 82) disagree with the row (Z7/V0, 81) |
| Z7/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z7/VT, 84) disagree with the row (Z7/VT, 83) |
| Z7/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z7/VI, 86) disagree with the row (Z7/VI, 85) |
| Z7/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z7/VTI, 87) disagree with the row (Z7/VTI, 86) |
| Z8/V0 | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z8/V0, 92) disagree with the row (Z8/V0, 91) |
| Z8/VT | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z8/VT, 93) disagree with the row (Z8/VT, 92) |
| Z8/VI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z8/VI, 94) disagree with the row (Z8/VI, 93) |
| Z8/VTI | malformed | verified | false | false | false | false | false | false | marker ledger/seq (Z8/VTI, 95) disagree with the row (Z8/VTI, 94) |
| Z9a/V0 | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z9a/V0, 17) disagree with the row (Z9a/V0, 16) |
| Z9a/VT | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z9a/VT, 18) disagree with the row (Z9a/VT, 17) |
| Z9a/VI | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z9a/VI, 19) disagree with the row (Z9a/VI, 18) |
| Z9a/VTI | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z9a/VTI, 20) disagree with the row (Z9a/VTI, 19) |
| Z9b/V0 | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z9b/V0, 21) disagree with the row (Z9b/V0, 20) |
| Z9b/VT | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z9b/VT, 22) disagree with the row (Z9b/VT, 21) |
| Z9b/VI | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z9b/VI, 23) disagree with the row (Z9b/VI, 22) |
| Z9b/VTI | malformed | rejected | false | false | false | false | false | false | marker ledger/seq (Z9b/VTI, 24) disagree with the row (Z9b/VTI, 23) |

Offline business-decision oracle v2 (completeness against the declared inventory, receipt bytes re-verified with the pinned verifier, ledgers reconstructed from ordered events, duplicate suppression derived from ledger history). Trusted: the declared inventory, the fixture authority history, the openings, the verifier binary.
