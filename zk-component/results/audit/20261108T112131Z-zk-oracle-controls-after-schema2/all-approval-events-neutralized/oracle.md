# Offline business-decision oracle v2 for results/audit/20261108T112131Z-zk-oracle-controls-after-schema2/all-approval-events-neutralized

Mode: schema-2 (inventory declared before execution) · declared 52 · rows read 52 · scored 29 (agree 29, disagree 0) · violations 0 · evidence mismatches 0 · incomplete 42 · malformed 0 · expected weak-policy attack successes 0 · **exit 2**

* Wrong-context receipts accepted: 0/5
* Unsafe approvals (input not authorized under the contract at the decision point): 0/7
* Legitimate approvals denied: 0/0
* Expected attack successes (deliberately incomplete policies): 
* Verifier: zk/target/release/zkverify sha256 c96cd5818b68266c5c05aa48890e692c563ced73a26784633c2c2b5bfa4472c6 (matches run provenance: true); 10 unique receipt/image pairs re-verified, 7 verified, 3 rejected, 0 failures. pinned RISC Zero verifier CLI (zkverify) re-run by the oracle per unique (receipt, declared image id); a shared component, not an independent proof-system implementation
* sums, commitments and journal decoding recomputed by the oracle's own routines (internal/zk/oracle_arith.go); production helpers and Evaluate are not called

Run-level findings:
* incomplete: ledgers.json records 1 approvals for Z3P/VT but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z3P/VTI but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z6/VI but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z3/V0 but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z3/VI but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z7/V0 but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z1/V0 but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z3P/V0 but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z3P/VI but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z5/V0 but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z6/V0 but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z7/VT but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z1/VI but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z1/VT but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z1/VTI but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z4/VT but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z6/VT but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z6/VTI but the events support only 0
* incomplete: ledgers.json records 1 approvals for Z4/V0 but the events support only 0

| evaluation | status | receipt | correct | semantics | prior approval | expected insert | observed insert | attack success | detail |
|---|---|---|---|---|---|---|---|---|---|
| Z1/V0 | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z1/VT | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z1/VI | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z1/VTI | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z10/V0 | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z10/VT | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z10/VI | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z10/VTI | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z11/V0 | incomplete | verified | false | false | false | false | false | false | row records approval_count_after=1 but the events support only 0 insertions in ledger Z1/V0 |
| Z11/VT | incomplete | verified | false | false | false | false | false | false | row records approval_count_after=1 but the events support only 0 insertions in ledger Z1/VT |
| Z11/VI | incomplete | verified | false | false | false | false | false | false | row records approval_count_after=1 but the events support only 0 insertions in ledger Z1/VI |
| Z11/VTI | incomplete | verified | false | false | false | false | false | false | row records approval_count_after=1 but the events support only 0 insertions in ledger Z1/VTI |
| Z2/V0 | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z2/VT | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z2/VI | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z2/VTI | agree | verified | false | false | false | false | false | false | journal=v2 recomputed_pass=false ctx=true head=v2 input=true prior_approval=false |
| Z3/V0 | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z3/VT | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=false head=v1 input=true prior_approval=false |
| Z3/VI | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z3/VTI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=false head=v1 input=true prior_approval=false |
| Z3P/V0 | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z3P/VT | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z3P/VI | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z3P/VTI | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z4/V0 | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z4/VT | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z4/VI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z4/VTI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=true head=v2 input=false prior_approval=false |
| Z5/V0 | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z5/VT | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=false head=v2 input=false prior_approval=false |
| Z5/VI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=false head=v2 input=false prior_approval=false |
| Z5/VTI | agree | verified | false | false | false | false | false | false | journal=v1 recomputed_pass=true ctx=false head=v2 input=false prior_approval=false |
| Z6/V0 | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z6/VT | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z6/VI | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z6/VTI | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z7/V0 | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
| Z7/VT | incomplete | verified | false | false | false | false | false | false | row claims an inserted approval but no approval_inserted event is attributed to the evaluation |
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
| Z9b/V0 | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z9b/VT | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z9b/VI | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |
| Z9b/VTI | agree | rejected | false | false | false | false | false | false | receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision |

Offline business-decision oracle v2 (completeness against the declared inventory, receipt bytes re-verified with the pinned verifier, ledgers reconstructed from ordered events, duplicate suppression derived from ledger history). Trusted: the declared inventory, the fixture authority history, the openings, the verifier binary.
