# Offline business-decision oracle v2 for results/audit/20261108T111037Z-zk-oracle-controls-after-legacyview/one-receipt-file-removed

Mode: legacy replay/audit view of a schema-1 run (declared inventory supplied afterwards) · declared 52 · rows read 52 · scored 36 (agree 36, disagree 0) · violations 0 · evidence mismatches 0 · incomplete 16 · malformed 0 · expected weak-policy attack successes 5 · **exit 2**

* Wrong-context receipts accepted: 1/4
* Unsafe approvals (input not authorized under the contract at the decision point): 5/12
* Legitimate approvals denied: 0/8
* Expected attack successes (deliberately incomplete policies): Z4/V0, Z4/VT, Z5/V0, Z7/V0, Z7/VT
* Verifier: zk/target/release/zkverify sha256 c96cd5818b68266c5c05aa48890e692c563ced73a26784633c2c2b5bfa4472c6 (matches run provenance: true); 8 unique receipt/image pairs re-verified, 6 verified, 2 rejected, 0 failures. pinned RISC Zero verifier CLI (zkverify) re-run by the oracle per unique (receipt, declared image id); a shared component, not an independent proof-system implementation
* sums, commitments and journal decoding recomputed by the oracle's own routines (internal/zk/oracle_arith.go); production helpers and Evaluate are not called

Limitations of this view:
* schema-1 rows and events carry no evaluation id: markers are joined by the declared ordinal order per (request, policy)
* schema-1 rows carry no ledger id: ledger grouping is taken from the declared legacy inventory
* schema-1 approval events carry no evaluation id: an insert is attributed to the marker it immediately follows
* schema-1 producers emitted no decision marker for verification failures: those evaluations are bound to their retained receipt bytes only
* schema-1 runs have no ledgers.json: final ledger state is reconstructed from events only

| evaluation | status | receipt | correct | semantics | prior approval | expected insert | observed insert | attack success | detail |
|---|---|---|---|---|---|---|---|---|---|
| Z1/V0 | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z1/VT | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z1/VI | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z1/VTI | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z10/V0 | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z10/VT | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z10/VI | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z10/VTI | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z11/V0 | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z11/VT | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z11/VI | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z11/VTI | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z2/V0 | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z2/VT | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z2/VI | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z2/VTI | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z3/V0 | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z3/VT | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z3/VI | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z3/VTI | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z3P/V0 | agree | verified | true | true | false | true | true | false | journal=v1 recomputed_pass=true ctx=true head=v1 input=true prior_approval=false |
| Z3P/VT | agree | verified | true | true | false | true | true | false | journal=v1 recomputed_pass=true ctx=true head=v1 input=true prior_approval=false |
| Z3P/VI | agree | verified | true | true | false | true | true | false | journal=v1 recomputed_pass=true ctx=true head=v1 input=true prior_approval=false |
| Z3P/VTI | agree | verified | true | true | false | true | true | false | journal=v1 recomputed_pass=true ctx=true head=v1 input=true prior_approval=false |
| Z4/V0 | agree | verified | false | true | false | true | true | true | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z4/VT | agree | verified | false | true | false | true | true | true | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z4/VI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z4/VTI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z5/V0 | agree | verified | false | true | false | true | true | true | journal=v1 recomputed_pass=true ctx=false head=v2 input=false prior_approval=false |
| Z5/VT | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=false head=v2 input=false prior_approval=false |
| Z5/VI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=false head=v2 input=false prior_approval=false |
| Z5/VTI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=false head=v2 input=false prior_approval=false |
| Z6/V0 | agree | verified | true | true | false | true | true | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=true prior_approval=false |
| Z6/VT | agree | verified | true | true | false | true | true | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=true prior_approval=false |
| Z6/VI | agree | verified | true | true | false | true | true | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=true prior_approval=false |
| Z6/VTI | agree | verified | true | true | false | true | true | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=true prior_approval=false |
| Z7/V0 | agree | verified | false | true | false | true | true | true | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z7/VT | agree | verified | false | true | false | true | true | true | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z7/VI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z7/VTI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z8/V0 | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z8/VT | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z8/VI | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z8/VTI | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z9a/V0 | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z9a/VT | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z9a/VI | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z9a/VTI | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z9b/V0 | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z9b/VT | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z9b/VI | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |
| Z9b/VTI | incomplete | unchecked | false | false | false | false | false | false | receipt bytes a9ce152410d0… are not retained |

Offline business-decision oracle v2 (completeness against the declared inventory, receipt bytes re-verified with the pinned verifier, ledgers reconstructed from ordered events, duplicate suppression derived from ledger history). Trusted: the declared inventory, the fixture authority history, the openings, the verifier binary.
