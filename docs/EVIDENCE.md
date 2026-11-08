# Reading the experiment outputs

A matrix cell is one scenario under one policy. A scenario may intentionally succeed against a weak policy. The important outcome is who received the task or which approval was inserted, not simply whether a signature verified.

## Identity and PQ matrices

The main retained run is `pq-identity/results/pq/20261108-153049/`. The integration rerun is `pq-identity/results/pq-integration/20261108-164204/`. Classical observations live under `identity/results/`.

| File or directory | Meaning |
|---|---|
| `run-inventory.json` | Declared cells, policies, expected record counts and expected decisions/recipients |
| `manifest-frozen.json`, `predictions-frozen.md` (where present) | Exact scenario definitions/expectations copied into the run; inspect the inventory and provenance for the recorded names |
| `enrollment-registry.json` | Public enrollment used for proof verification; not a collection of private signing keys |
| `matrix.csv`, `summary.md` | Compact cell outcomes; A/B identify the receiving deployment |
| `cells/<fixture>_<policy>/decision.json` or `decisions.json` | Requester verdict, signed proof bytes, context, connection identifiers and ordered events; concurrent cells can contain more than one decision |
| `sessions.json` at run level | Issued nonce sessions supporting freshness and authorization checks |
| `cells/.../controller-events.jsonl` | Controller/recipient observations; receipt joins identify which decision and token produced a delivery |
| `pq-audit-summary.json`, `pq-audit.jsonl`, `pq-audit.md` | Composite re-verification and structural checks, including expected attack successes |
| `release-audit*` | Classical structural release checker reports |
| `provenance.json` and snapshot hash lists | Recorded source/binary identities, run metadata and dependency versions |
| `copy-manifest*` | Which files the copy/clone attacker received; read this before interpreting key-custody outcomes |

The names above describe repeated schema roles; inspect the concrete directory for exact filenames. A = honest recipient, B = attacker recipient, R = rejected, N = appraised but refused before dispatch. `unknown` is client uncertainty after a write, not proof of non-delivery.

The corrected PQ audit reports 128 agreeing cells, 35 valid v4 proofs, 84 invalid proofs, 16 verified dispatches, 95 verified non-dispatches and 25 declared attacker deliveries. These count different things: proofs, decisions and cells are not interchangeable. A structural violation expected by a deliberately weak fixture remains listed even when the overall audit exits 0.

## ZK result matrix

The standalone run is `zk-component/results/zk/20261108-111817/`.

| Output | Meaning |
|---|---|
| `run-inventory.json` | The 52 declared evaluations and policy/ledger assignments |
| `requests.json` | Stored request challenges and Pinned/Current contracts |
| `decisions.csv`, `decisions.jsonl` | Every policy evaluation, decision id, ledger id and approval links |
| `events.jsonl` | Ordered authority updates, decision markers and approval insertions |
| `ledgers.json` | Recorded final approval state, checked against the event history |
| `exchanges.jsonl` | Nine A2A exchanges and transport verdicts; not 52 independent network interactions |
| `receipts/<hash>.bin` | Retained RISC Zero receipt bytes; the verifier recomputes their hashes and verifies the pinned image |
| `run-stats.json` | Counts of exchanges, fresh proofs and cache hits |
| `oracle-summary.json`, `oracle.jsonl`, `oracle.md` | Complete inventory/ledger/receipt checks and declared weak-policy successes |
| `fixtures/zk/openings.json` in the component | Disclosed synthetic inputs for recomputing commitments and sums |

All four policies verify ZK. V0 omits task/input checks; VT checks the challenge; VI checks the input; VTI checks both. Pinned permits the named historical input; Current requires the authority's head when approval is inserted. The same valid proof can therefore produce different correct decisions under different contracts.

## Smoke, timing and validation records

- `pq-identity/results/zk-pq-smoke/20261108-154419/`: an emulator-authenticated honest task with a genuine receipt, plus a rejected impostor. This is narrower than the standalone ZK matrix.
- `pq-identity/results/pq-bench/20261108-132255/`: software/device timing samples over a fixed 306-byte message. Matrix context sizes vary from 271 to 310 bytes.
- `results/audit/*`: mutation controls, build logs, command traces and snapshot hashes. Before-fix summaries explain why a correction was needed; they are not another implementation to run.

Audit reports are consistency checks over trusted cooperative records, using some of the same cryptographic libraries as the application. They are not tamper-proof attestations of every logged event. The inventory itself is trusted experiment input. See [the selected-artifact index](ARTIFACT_INVENTORY.md) and [the paper](../paper/paper-draft.md) for exact run selection and limitations.
