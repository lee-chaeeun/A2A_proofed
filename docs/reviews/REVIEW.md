# Judge-style review: A2A identity experiment

Reviewed November 7, 2026. Author supplied: Chae Eun Lee. This review assesses the retained run and current source; it does not represent an actual hackathon judge's decision.

## Verdict

**Sound as a narrow, scripted mechanism demonstration; insufficient as a secure identity system, hardware advantage, or swarm-alignment result.** The core observations are credible under the stated permissions. The isolated software signer is a valuable control. Separating key identity from job recipient is the strongest explanatory contribution. However, five new verifier-level cases reproduce unsafe acceptance, so 59/59 expected original outcomes cannot support implementation correctness.

If judging the current evidence, I would provisionally put impact/innovation around **2–3/5** and execution around **2–3/5**. The ideas are familiar cryptographic mechanisms; the integration and artifacts add value, but missing baselines and a fail-open appraisal path prevent a strong execution score. Clear, bounded reporting can improve presentation; it cannot substitute for repairing the verifier or testing a defense. These are subjective assessments against the [published rubric](https://apartresearch.com/sprints/swarm-alignment-2026#overview), not predicted official scores.

## Confirmed implementation defects

### 1. High priority: policy P accepts a signed response without evidence appraisal

Locations: `internal/ptv/ptv.go:151` and `internal/verifier/verifier.go:294`, relative to the idea folder.

`SchemaCheck` accepts either evidence or proof when the band is routine. `Appraise` only checks a quote when `len(Evidence) > 0`. A correctly signed routine response with **proof only**, **empty evidence**, or **null evidence** reaches acceptance with `Decision.Quote == nil`. All three variants reproduced.

The tests enroll a generated software key and assume the card check passed, deliberately isolating verifier logic. They do not extract an AK or demonstrate a remote exploit. The relevant attacker is an enrolled signer, compromised attester, or party with signing access who cannot produce an approved configuration quote. Draft-01 [section 5.2](https://www.ietf.org/archive/id/draft-anandakrishnan-rats-ptv-agent-identity-01.html#section-5.2) requires evidence specifically in routine mode. This is a defect in this implementation, not evidence that the draft permits the bypass.

**Fix criterion:** every P acceptance must imply successful independent quote appraisal. Reject proof in routine mode, absent/empty/null evidence, invalid encoding, and invalid quotes. Repeat through the real TPM signing adapter with a changed PCR before claiming end-to-end coverage.

### 2. Medium priority: stored session binding is ignored

Location: `internal/verifier/verifier.go:211`.

`Store.Claim` returns the session but the caller discards it. A nonce stored for B, a different action, and P is accepted when appraised as A under S-file with a valid A signature. The present runner supplies fixed consistent parameters; the test demonstrates a missing invariant, not that a network attacker currently controls those arguments.

**Fix criterion:** compare the stored expected identity, action, policy, and expiry with the appraisal context; derive context from the session where possible. T signs the nonce rather than the software policy's explicit action binding, making correct session interpretation especially important.

### 3. Medium priority: unknown policy fails open

Location: `internal/verifier/verifier.go:227` through `:303`.

The policy switch has no rejecting default. An unknown policy accepts a valid card and matching issued nonce with no proof. Reproduced at the verifier API. Exploitation requires configuration/caller control not shown in the experiment.

**Fix criterion:** reject unsupported policy values before issuing challenges and again at appraisal.

### 4. Additional code-review concerns, not demonstrated exploits

- `VerifyQuote` checks quote type but does not explicitly check TPM attestation magic or declared signature/hash parameters. A restricted AK can sign ticketed non-attestation bytes; robust parsing must distinguish those from genuine TPM-generated attestations. Add adversarial tests before claiming this enables quote fabrication.
- Nonce issue time is recorded but the session store has no expiry enforcement. F4 tests different nonces, not expiry of a delayed unused nonce. P's signed timestamp adds a separate freshness check; S/T do not share it.
- Release is marked before the HTTP send and only in memory. “One token in this process” is not durable exactly-once execution or guaranteed receipt.

## Experimental holes that matter most

**Missing endpoint/transport controls.** All attacker-address cells have signed-card URL mismatches, yet the verifier deliberately ignores that signal. Add URL enforcement and authenticated HTTPS baselines. A2A's [production security requirements](https://a2a-protocol.org/latest/specification/) require encrypted transport and recommend server certificate verification. This experiment cannot establish that A2A itself is broken. URL equality alone is not a sufficient fix for an attacker at the expected address.

**The boundary is an assumption.** All processes share an account, excluded files remain accessible to that account, and gate administration is unauthenticated local HTTP. The controller accepts actor-reported events; emissions can fail silently. Calling it an independent observer is accurate only in the sense that it does not make verifier decisions. It is not an adversarial ground-truth oracle.

**No hardware advantage demonstrated.** The copied volume excludes the emulator state and signer credentials by design. S-iso and T matching is useful evidence for custody under that assumption. It says nothing about hardware non-exportability, full-state cloning, or compromised-host resistance. PCR 16 is a resettable synthetic value, not a verified measurement of running model or code.

**Envelope comparison is incomplete.** F8 shows that signing metadata detects metadata modification. T does not use that outer timestamp for its decision, and no matched software-signed envelope exists. Add that control and a decision-relevant tamper fixture before attributing value to PTV or TPMs specifically.

**Limited novelty and swarm relevance.** Replay protection and relayability of unbound signatures are expected properties. The project has two scripted agents and no behavior or population dynamics. Frame it as testing a prerequisite for safe delegation, not proving safe swarms. LLM agents are not necessary for this narrow question; a well-tested defense would add more value than gratuitous model calls.

**Coverage is not prevalence.** One retained full run, manually chosen attacks, and a shared implementation do not yield independent samples or meaningful attack-rate confidence intervals. Repeating deterministic cells helps reproducibility but does not solve missing coverage. Prediction freeze timing and the two deleted runs are self-reported rather than independently auditable.

## Correct the accounting

- 65 cells, 59 applicable; all 59 match the recorded expectations.
- Non-concurrency B-endpoint outcomes: C 6/7, S-file 4/8, S-iso 3/8, T 3/8, P 2/8. Total 18/39, describing this fixture set only.
- All four F13 cases deliver one job to B. The row exporter selects A's rejected decision and stores B's accepted decision separately. Therefore the summary's 12 accepted proof attack cells excludes four actual accepted proof decisions. Do not treat its signer/custody totals as all-attack totals.
- No duplicate releases were observed in those four cases. Responses finish before concurrent appraisal starts, so these are local concurrency tests, not network races. Do not infer a relay-win probability from four B wins.
- Common honest baseline: 10/10 accepted in F1/F2. The report's 13-cell definition adds F9 only for C/S and differs from the prediction document. F12 rejects a valid honest second response by design; the “zero honest rejection” phrase needs its denominator and condition.
- F4 captures the old response immediately before replay. Replace “yesterday” with “a different previously issued nonce.”

## Highest-value next work

1. Repair the three confirmed acceptance defects; turn the characterization cases into rejecting regression tests. Preserve original results and publish a new versioned matrix.
2. Add URL and TLS baselines, then implement and test channel/recipient-bound task authorization. Include legitimate proxy and authorized-replica controls so the security objective is not accidentally “reject every intermediary.”
3. Add an isolated software signer with identical envelope coverage. Separate key custody, metadata integrity, configuration appraisal, and endpoint binding in the analysis.
4. Separate actors at the OS boundary, protect the raw socket and admin interfaces, and compare application copy with emulator-state copy. Only then consider a hardware-backed experiment.
5. Publish source/binary hashes, all runs, explicit per-decision accounting, and an offline signature reappraisal script. Add randomized races, restart/delivery failure tests, and latency measurements if claiming operational usefulness.

Do not add invented measurements or claim these recommendations have been implemented. The paper reports the audit defects openly and makes no repaired-system claim.

## Validation performed

Inspected the report, predictions, manifest-related logic, source, retained CSV, and per-cell decisions. Recomputed applicable-cell and recipient counts. Added `internal/verifier/review_audit_test.go`, guarded by the `reviewaudit` build tag. All five characterization cases reproduced; `go test -race -tags reviewaudit ./...` passed. Most packages have no tests, so that command is not a comprehensive security validation. No production code was changed, and no fresh full emulator matrix was run. The seven-page PDF was compiled and all seven rendered pages visually checked.
