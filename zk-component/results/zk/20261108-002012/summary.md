# ZK matrix summary (results/zk/20261108-002012)

Rows: 48 (fixture × policy). A2A requests dispatched: 10. New genuine proofs generated this run: 6 (others served from the proof cache or replayed). Wall time: 160.7s.

| fixture | V0 | VT | VI | VTI | proof valid | pass | notes |
|---|---|---|---|---|---|---|---|
| Z1 honest Pinned v1, below limit | –† | –† | –† | –† | false | false |  |
| Z2 honest Current at v2, above limit (proof valid, pass=false) | – | – | – | – | false | false |  |
| Z3 genuine passing receipt of request A delivered for request B | –† | – | –† | – | false | false | worker replayed Z1's genuine receipt (same authorized input v1) |
| Z3P positive control: correctly bound genuine proof for B | –† | –† | –† | –† | false | false |  |
| Z4 B's challenge, REAL proof over obsolete v1 witness, Current at v2 | –† | –† | – | – | false | false | REAL proof over the obsolete v1 opening with Z4's challenge |
| Z5 wrong challenge AND obsolete v1 witness under Current | –† | – | – | – | false | false |  |
| Z6 delayed Pinned(v1) result after authority moved to v2 | –† | –† | –† | –† | false | false | authority_update happened after receipt, before the approval decision |
| Z7 identical bytes+challenge as Z6, isolated Current contract at v2 | –† | –† | – | – | false | false | same receipt bytes and challenge as Z6 (hash recorded), Current contract |
| Z8 genuine failing journal, outer metadata claims pass | – | – | – | – | false | false |  |
| Z9b wrong expected image id (requester misconfiguration) | – | – | – | – | false | false | requester pinned a different image id |
| Z10 fake/dev receipt through the production verifier path | – | – | – | – | false | false | worker used the test-only dev-mode tool |
| Z11 duplicate accepted result after a recorded approval (second delivery) | – | – | – | – | false | false | second delivery of Z1's result into Z1's ledgers |

✓ approval inserted, – no approval, † differs from the frozen prediction.

* Cells matching the frozen prediction: 29 / 48
* Wrong-context receipts accepted (valid, passing, challenge mismatch): 0 / 0 policy-cells
* Unsafe approvals (valid, passing, input not the authorized one under the contract): 0 / 0 policy-cells
* Legitimate approvals denied (valid, passing, context and input correct): 0 / 0 policy-cells

These are coverage counts over hand-selected fixtures, not prevalence estimates. Repeated verification of cached proofs is a regression check, not independent proving trials.
