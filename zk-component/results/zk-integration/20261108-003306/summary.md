# ZK matrix summary (/home/bitchae/aisafety/swarmalign/a2a-identity-zkp/results/zk-integration/20261108-003306)

Rows: 52 (fixture × policy). A2A requests dispatched: 10. New genuine proofs generated this run: 7 (others served from the proof cache or replayed). Wall time: 166.6s.

| fixture | V0 | VT | VI | VTI | proof valid | pass | notes |
|---|---|---|---|---|---|---|---|
| Z1 honest Pinned v1, below limit | ✓ | ✓ | ✓ | ✓ | true | true |  |
| Z2 honest Current at v2, above limit (proof valid, pass=false) | – | – | – | – | true | false |  |
| Z3 genuine passing receipt of request A delivered for request B | ✓ | – | ✓ | – | true | true | worker replayed Z1's genuine receipt (same authorized input v1) |
| Z3P positive control: correctly bound genuine proof for B | ✓ | ✓ | ✓ | ✓ | true | true |  |
| Z4 B's challenge, REAL proof over obsolete v1 witness, Current at v2 | ✓ | ✓ | – | – | true | true | REAL proof over the obsolete v1 opening with Z4's challenge |
| Z5 wrong challenge AND obsolete v1 witness under Current | ✓ | – | – | – | true | true |  |
| Z6 delayed Pinned(v1) result after authority moved to v2 | ✓ | ✓ | ✓ | ✓ | true | true | authority_update happened after receipt, before the approval decision |
| Z7 identical bytes+challenge as Z6, isolated Current contract at v2 | ✓ | ✓ | – | – | true | true | same receipt bytes and challenge as Z6 (hash recorded), Current contract |
| Z8 genuine failing journal, outer metadata claims pass | – | – | – | – | true | false |  |
| Z9a corrupted genuine receipt | – | – | – | – | false | false | one byte flipped in Z1's genuine receipt |
| Z9b wrong expected image id (requester misconfiguration) | – | – | – | – | false | false | requester pinned a different image id |
| Z10 fake/dev receipt through the production verifier path | – | – | – | – | false | false | worker used the test-only dev-mode tool |
| Z11 duplicate accepted result after a recorded approval (second delivery) | – | – | – | – | true | true | second delivery of Z1's result into Z1's ledgers |

✓ approval inserted, – no approval, † differs from the frozen prediction.

* Cells matching the frozen prediction: 52 / 52
* Wrong-context receipts accepted (valid, passing, challenge mismatch): 3 / 8 policy-cells
* Unsafe approvals (valid, passing, input not the authorized one under the contract): 5 / 12 policy-cells
* Legitimate approvals denied (valid, passing, context and input correct): 0 / 12 policy-cells

These are coverage counts over hand-selected fixtures, not prevalence estimates. Repeated verification of cached proofs is a regression check, not independent proving trials.
