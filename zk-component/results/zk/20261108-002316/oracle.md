# Offline business-decision oracle for results/zk/20261108-002316

Rows 52 · scored 52 · incomplete 0 · observed-vs-policy-semantics disagreements 1 · exit 1

* Wrong-context receipts accepted: 3/8
* Unsafe approvals (input not authorized under the contract at the decision point): 5/9
* Legitimate approvals denied: 0/12

Offline business-decision oracle: recomputes sums/commitments from the fixture openings and joins the trusted request contract with the ordered authority/approval events. Receipt validity is the pinned verifier CLI's recorded status; the oracle does not reimplement the proof system. Trusted: fixture authority history and openings.

| fixture | policy | status | correct decision | policy semantics | observed | agree | detail |
|---|---|---|---|---|---|---|---|
| Z1 | V0 | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z1 | VT | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z1 | VI | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z1 | VTI | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z10 | V0 | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z10 | VT | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z10 | VI | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z10 | VTI | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z11 | V0 | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z11 | VT | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z11 | VI | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z11 | VTI | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z2 | V0 | scored | false | false | false | true | journal=v2 recomputed_pass=false ctx=true authorized=v1 (contract current, head v1) input=false |
| Z2 | VT | scored | false | false | false | true | journal=v2 recomputed_pass=false ctx=true authorized=v1 (contract current, head v1) input=false |
| Z2 | VI | scored | false | false | false | true | journal=v2 recomputed_pass=false ctx=true authorized=v1 (contract current, head v1) input=false |
| Z2 | VTI | scored | false | false | false | true | journal=v2 recomputed_pass=false ctx=true authorized=v1 (contract current, head v1) input=false |
| Z3 | V0 | scored | false | true | true | true | journal=v1 recomputed_pass=true ctx=false authorized=v1 (contract pinned, head v1) input=true |
| Z3 | VT | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=false authorized=v1 (contract pinned, head v1) input=true |
| Z3 | VI | scored | false | true | true | true | journal=v1 recomputed_pass=true ctx=false authorized=v1 (contract pinned, head v1) input=true |
| Z3 | VTI | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=false authorized=v1 (contract pinned, head v1) input=true |
| Z3P | V0 | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z3P | VT | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z3P | VI | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z3P | VTI | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v1) input=true |
| Z4 | V0 | scored | false | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v2 (contract current, head v2) input=false |
| Z4 | VT | scored | false | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v2 (contract current, head v2) input=false |
| Z4 | VI | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=true authorized=v2 (contract current, head v2) input=false |
| Z4 | VTI | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=true authorized=v2 (contract current, head v2) input=false |
| Z5 | V0 | scored | false | true | true | true | journal=v1 recomputed_pass=true ctx=false authorized=v2 (contract current, head v2) input=false |
| Z5 | VT | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=false authorized=v1 (contract current, head v1) input=true |
| Z5 | VI | scored | false | true | false | false | journal=v1 recomputed_pass=true ctx=false authorized=v1 (contract current, head v1) input=true |
| Z5 | VTI | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=false authorized=v1 (contract current, head v1) input=true |
| Z6 | V0 | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v2) input=true |
| Z6 | VT | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v2) input=true |
| Z6 | VI | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v2) input=true |
| Z6 | VTI | scored | true | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v1 (contract pinned, head v2) input=true |
| Z7 | V0 | scored | false | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v2 (contract current, head v2) input=false |
| Z7 | VT | scored | false | true | true | true | journal=v1 recomputed_pass=true ctx=true authorized=v2 (contract current, head v2) input=false |
| Z7 | VI | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=true authorized=v2 (contract current, head v2) input=false |
| Z7 | VTI | scored | false | false | false | true | journal=v1 recomputed_pass=true ctx=true authorized=v2 (contract current, head v2) input=false |
| Z8 | V0 | scored | false | false | false | true | journal=v2 recomputed_pass=false ctx=true authorized=v1 (contract current, head v1) input=false |
| Z8 | VT | scored | false | false | false | true | journal=v2 recomputed_pass=false ctx=true authorized=v1 (contract current, head v1) input=false |
| Z8 | VI | scored | false | false | false | true | journal=v2 recomputed_pass=false ctx=true authorized=v1 (contract current, head v1) input=false |
| Z8 | VTI | scored | false | false | false | true | journal=v2 recomputed_pass=false ctx=true authorized=v1 (contract current, head v1) input=false |
| Z9a | V0 | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z9a | VT | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z9a | VI | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z9a | VTI | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z9b | V0 | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z9b | VT | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z9b | VI | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
| Z9b | VTI | scored | false | false | false | true | receipt did not verify (verifier status); deny is the only correct decision |
