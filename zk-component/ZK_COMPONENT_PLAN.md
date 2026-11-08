# ZK component plan — proof-carrying A2A task results (RISC Zero)

Declared 2026-11-08 before any ZK result was collected; sha256 recorded in
`results/zk/PLAN.sha256` once frozen. Working tree: `a2a-identity-zkp/`, a copy of
the finalized identity repo (`a2a-identity/`, which stays untouched). Design source:
`../project brainstorm/a2a-zk-weekend-experiment.md`.

## Research question
Can an A2A requester reject a genuine proof for the wrong task or an obsolete input,
while accepting a delayed proof for a task that explicitly requested the historical
snapshot? The decisive observation: the proof stays cryptographically valid while
its authorization to trigger a dependent action changes with the task context.

## Scope and distinctions
* The identity component asks who controls the identity key and which endpoint
  receives a task. This component asks whether a returned computation is valid for
  the request's authorized inputs and decision-time contract.
* RISC Zero verification proves correct execution of the pinned guest on SOME
  witness. It does not prove which physical prover ran, a TPM-backed key, an honest
  agent, authoritative or current inputs; proving can be outsourced. Combining it
  with identity does not show the identified device computed locally. No
  whole-agent/model verification is claimed.
* Reference integration and regression suite. Task binding and commitments are
  established mechanisms; no novelty claim beyond the executable suite. No flaws are
  inferred in named external systems.
* Out of scope: extra circuits, benchmarks, standards proposal, identity × ZK cross
  product, cloud proving, blockchain, LLM calls, paid services, hardware.

## Feasibility gate (declared maximum 90 minutes for the first genuine proof)
Start time recorded in the evidence tree. Steps: task-local `rzup` (no profile
edits), `rzup install` of the pinned toolchain, one tiny guest, one authentic local
receipt with dev mode disabled, verified against the locally pinned image id. If
the gate fails, the component is retained as an explicitly labelled unexecuted plan
or mock transport prototype; no mock receipt is ever reported as a ZK result; no
remote prover is used. Elapsed time and resource limits are recorded either way.

## Computation and authority
* Guest: four private bounded u32 values (each ≤ 2^20) summed into a u64; pass ⇔
  sum ≤ 100. Old snapshot v1 `[10,20,20,30]` (80, pass); updated v2 `[20,30,30,40]`
  (120, fail). Each snapshot has a secret random 32-byte salt.
* Commitment `C = SHA-256("a2aid-zk-commit-v1" ‖ 0x00 ‖ portfolio_id (UTF-8) ‖ 0x00 ‖
  version (u32 LE) ‖ salt (32 bytes) ‖ v1..v4 (each u32 LE))`. The guest recomputes
  C and the Boolean from the private witness; it never accepts a Boolean as input.
* Public journal (canonical, little-endian fixed width): schema u32 = 1 ‖ challenge
  (16 bytes) ‖ commitment (32 bytes) ‖ limit u64 ‖ pass u8. Holdings, sum and salt
  are never published.
* One fixed guest image for ALL policies; the expected image id is pinned locally by
  the requester and never taken from the worker.
* Trusted fixture authority (requester-side, read-only to the worker) owns the
  ordered snapshot history and exposes {portfolio, version, commitment}. The worker
  and the offline oracle hold the synthetic private openings (in `fixtures/zk/`,
  disclosed for reproducibility; not claimed private).
* Challenge: 128-bit, requester-generated, stored against the local business request
  (expected worker, portfolio, contract) and associated with the server-generated
  A2A task id after dispatch.
* Contracts: **Pinned** = snapshot version authorized at dispatch; **Current** =
  authoritative version at the approval decision point, compared and inserted inside
  one serialized critical section (a single mutex over the authority head and the
  approval ledger; its linearization point is the ledger insert under that lock).

## Transport
Real a2a-go discovery and SendMessage over the existing authenticated-TLS endpoint
(`C+tls` baseline, the +cb identity policies untouched). A dedicated `zk_task`
DataPart carries portfolio, contract, challenge and requested version; the worker
answers with a `zk_result` DataPart: schema, receipt bytes (base64, bounded at 2 MiB),
receipt sha256, claimed image id (diagnostic only) and claimed pass (diagnostic
only). Verification runs in a separate verifier CLI (JSON on stdin/stdout, bounded
time and output); the requester acts only on the verified journal. Identity matrix
commands keep working without Rust installed.

## Policies (all verify the SAME receipt against the SAME pinned image and require
the verified Boolean to be true; same TLS, task association, authority and
single-use approval)
V0: proof valid ∧ pass. VT: V0 ∧ journal challenge = stored request challenge.
VI: V0 ∧ journal commitment = authority commitment under the stored contract.
VTI: VT ∧ VI. Separate fields: proof_valid, result_pass, context_match,
input_authorized, approval_allowed, approval_inserted.

## Frozen predictions (approvers among V0 / VT / VI / VTI; isolated store per cell)
| # | fixture | V0 | VT | VI | VTI |
|---|---|---|---|---|---|
| Z1 | honest Pinned, v1 below limit | ✓ | ✓ | ✓ | ✓ |
| Z2 | honest Current, authority at v2 above limit (proof valid, pass=false) | – | – | – | – |
| Z3 | genuine passing receipt of request A delivered for request B, same authorized input | ✓ | – | ✓ | – |
| Z3+ | positive control: correctly bound genuine proof for B | ✓ | ✓ | ✓ | ✓ |
| Z4 | B's challenge, REAL proof over obsolete v1 witness, Current authority at v2 | ✓ | ✓ | – | – |
| Z5 | wrong challenge AND obsolete v1 witness under Current | ✓ | – | – | – |
| Z6 | delayed matching Pinned(v1) result after the authority moved to v2 | ✓ | ✓ | ✓ | ✓ |
| Z7 | identical proof bytes + challenge as Z6, isolated Current contract after update | ✓ | ✓ | – | – |
| Z8 | genuine failing journal, outer metadata claims pass | – | – | – | – |
| Z9a/b | corrupted genuine receipt / wrong expected image id | – (verification fails) |
| Z10 | fake/dev receipt through the production verifier path | – (verification fails) |
| Z11 | duplicate accepted result after a recorded approval | no additional approval under any policy |

Z6 and Z7 reuse byte-identical receipt and challenge (hashes recorded) with different
trusted local contracts; this is a controlled comparison, not a challenge-reuse
recommendation. Genuine proofs are cached by (guest image id, all proof inputs);
unique proofs generated vs verification/replay attempts are reported.

## Scoring
Offline business-decision oracle (`a2aid zk-oracle`): recomputes sums and commitments
from the fixture history, joins the trusted request contract with the authoritative
update/approval order, and scores business authorization independently of the
production helper and of the recorded accept flag. Mutations (missing/wrong task,
wrong input, reordered events) run through its validation path; missing evidence is
incomplete, never a pass. Metrics with denominators: wrong-context acceptances,
unsafe Current approvals, denied legitimate Pinned approvals.

## Deliverables
`zk/` Rust workspace (guest, prover CLI, verifier CLI; Cargo.lock, toolchain and image
id recorded), `internal/zk` Go package, `a2aid zk-matrix` / `zk-oracle` commands,
`fixtures/zk/`, `results/zk/<run-id>/` evidence tree, `RESULTS_ZK.md`, README section,
and a separate measured paper section only after the component runs.
