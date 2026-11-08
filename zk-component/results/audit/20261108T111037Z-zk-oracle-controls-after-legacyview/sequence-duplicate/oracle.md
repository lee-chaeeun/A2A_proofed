# Offline business-decision oracle v2 for results/audit/20261108T111037Z-zk-oracle-controls-after-legacyview/sequence-duplicate

Mode: legacy replay/audit view of a schema-1 run (declared inventory supplied afterwards) · declared 52 · rows read 52 · scored 0 (agree 0, disagree 0) · violations 0 · evidence mismatches 0 · incomplete 0 · malformed 54 · expected weak-policy attack successes 0 · **exit 2**

* Wrong-context receipts accepted: 0/0
* Unsafe approvals (input not authorized under the contract at the decision point): 0/0
* Legitimate approvals denied: 0/0
* Expected attack successes (deliberately incomplete policies): 
* Verifier: zk/target/release/zkverify sha256 c96cd5818b68266c5c05aa48890e692c563ced73a26784633c2c2b5bfa4472c6 (matches run provenance: true); 0 unique receipt/image pairs re-verified, 0 verified, 0 rejected, 0 failures. pinned RISC Zero verifier CLI (zkverify) re-run by the oracle per unique (receipt, declared image id); a shared component, not an independent proof-system implementation
* sums, commitments and journal decoding recomputed by the oracle's own routines (internal/zk/oracle_arith.go); production helpers and Evaluate are not called

Run-level findings:
* malformed: events.jsonl line 6: seq 5 after 5 (nonpositive, duplicate, gap or out of order)
* malformed: events.jsonl line 7: seq 7 after 5 (nonpositive, duplicate, gap or out of order)

Limitations of this view:
* schema-1 rows and events carry no evaluation id: markers are joined by the declared ordinal order per (request, policy)
* schema-1 rows carry no ledger id: ledger grouping is taken from the declared legacy inventory
* schema-1 approval events carry no evaluation id: an insert is attributed to the marker it immediately follows
* schema-1 producers emitted no decision marker for verification failures: those evaluations are bound to their retained receipt bytes only
* schema-1 runs have no ledgers.json: final ledger state is reconstructed from events only

| evaluation | status | receipt | correct | semantics | prior approval | expected insert | observed insert | attack success | detail |
|---|---|---|---|---|---|---|---|---|---|
| Z1/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z1/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z1/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z1/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z10/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z10/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z10/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z10/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z11/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z11/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z11/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z11/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z2/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z2/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z2/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z2/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z3/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z3/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z3/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z3/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z3P/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z3P/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z3P/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z3P/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z4/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z4/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z4/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z4/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z5/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z5/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z5/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z5/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z6/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z6/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z6/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z6/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z7/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z7/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z7/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z7/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z8/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z8/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z8/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z8/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z9a/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z9a/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z9a/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z9a/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z9b/V0 | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z9b/VT | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z9b/VI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |
| Z9b/VTI | malformed | unchecked | false | false | false | false | false | false | event stream malformed (sequence or scanner errors; see run-level findings) |

Offline business-decision oracle v2 (completeness against the declared inventory, receipt bytes re-verified with the pinned verifier, ledgers reconstructed from ordered events, duplicate suppression derived from ledger history). Trusted: the declared inventory, the fixture authority history, the openings, the verifier binary.
