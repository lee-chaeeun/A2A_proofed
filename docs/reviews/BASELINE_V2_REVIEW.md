# Review of Claude's v2 experiment

## Assessment

V2 substantially improves the experiment. It directly answers the v1 criticism: signed endpoint enforcement stops the original different-address attacks, and TLS handles the illustrated address hijack without stolen credentials. The retained matrix has 231 cells, 201 applicable and 199 prediction matches, as reported. The two F19 divergences are retained rather than rewritten; F21 is a useful follow-up explaining why a restored emulator key can still impersonate A once the synthetic PCR is reconstructed.

This supports a bounded infrastructure study, not yet a general claim that the +cb implementation securely binds task delivery to the proven endpoint. Two missing adversarial tests are more urgent than more generated fixtures or model calls.

This review inspected source and retained artifacts and recomputed the matrix and reverification counts. It did not rerun the full matrix, tests, or the candidate attacks below. “Confirmed” here refers to code structure/artifact facts, not an independently executed network exploit.

## Highest priority: the binding mode is request-controlled

In internal/agent/agent.go:384, the agent applies channel binding only when ch.Binding is tls-exporter. Empty binding is permitted even when the parsed policy requests +cb. At line 394, BoundNonce returns the supplied nonce unchanged if no binding was selected.

A candidate attack is to compute the bound nonce for the requester-to-B connection, send that computed value to A as its challenge nonce while omitting binding, and return the resulting signed evidence to the requester with the original unsigned outer nonce restored. B has the necessary exporter because it terminates that connection in the existing F15 threat model. This may work for T+cb and S-env+cb without B holding A's proof key or directly accessing its signer gate.

There is a related cross-policy concern: a plain-T service that signs arbitrary nonces with the same AK may produce a quote acceptable as T+cb when given the already-computed bound nonce. Merely enforcing Binding when the request names +cb may not fix this weaker-mode oracle. A proof needs unambiguous context generated and enforced by the signer, or suitably separated keys/interfaces.

These are strong code-derived hypotheses, not executed attack results. They should be the next networked tests. F16's ignored raw cb field does not cover substitution of the nonce and omission of the binding selector.

## Highest priority: connection continuity to job delivery is unenforced

In internal/verifier/verifier.go:429, cbCandidate considers exporters from the decision's recorded connections and allows the agent's claimed value to select one that matches. At :683, Release sends the job through the general A2A client without checking that this send uses the connection that supplied the accepted proof. HTTP connection pooling can reconnect; MaxConnsPerHost=1 does not prevent sequential replacement connections. TLS identity facts are captured at discovery.

A candidate test is: genuine A answers the proof; that connection closes; the next dial reaches B with A's stolen TLS credentials but no proof signer access. Does the already-approved task reach B without fresh proof? A second test should change the peer between discovery and challenge. These require controlled networked reproductions. Do not present them as confirmed recipient compromises until those runs exist.

RFC 9266 defines connection-specific exporter data and additional lifecycle constraints. Using its exporter primitive does not establish correct binding across a sequence of application requests. Source: https://www.rfc-editor.org/rfc/rfc9266.html .

## Baseline and reporting corrections

- +tls implies +url, and +cb implies both. This is reasonable as a layered design, but the rejection stage must identify which layer helped. The report claims different-address TLS cells fail at connect-tls; retained rows include connect-url. Correct this description.
- Add S-env+tls alongside S-env+cb. T+tls versus T+cb already supplies a useful channel-binding comparison, but the software control lacks its matching transport baseline.
- State whether B is authorized to obtain fresh proofs from A. The current public challenge interface allows it. A separate requester-authentication baseline could constrain that oracle, depending on the deployment and credential separation. It is not automatically supplied by a server TLS certificate, nor is it a universal relay defense.
- S-env is not exactly metadata-matched to P. S-env signs action, audience, policy, issuance and expiry; P's payload has a different set of fields. The timestamp-tampering conclusion is supported, but exact metadata equivalence is not.
- “Identical on every custody fixture” is contradicted by F21: T/P accept the reconstructed emulator clone, while S-iso/S-env reject. This reflects different copied assets. Restrict equivalence to genuinely matched access/copy conditions.
- Of the 217 offline records, 58 classify transport/exchange-stage failure by copying the recorded stage; 10 copy nonce-consumption order. The checker also uses the production appraisal implementation. Its agreement is useful consistency evidence, not an independent proof of all 217 outcomes. Report the categories rather than using the aggregate as a security score.
- The randomized 500 trials cover five unbound proof policies, not +cb. They support the one-release observations for those cases, not connection-binding robustness.
- 0/22 honest rejections only covers F1/F2. Reconnects, credential rotation and supported production topologies need separate positive controls; unsupported proxies must remain explicit exclusions.

## How the paper's central claim should change

The evidence now supports: ordinary endpoint authentication handles the original different-address attacks; a second proof credential with channel binding rejects the specific tested stolen-TLS-key relays; synthetic measurement appraisal adds a configuration check. Whether that binding survives active protocol manipulation and connection replacement is not established yet.

Even after a repair, successful S-env+cb means the relay defense is not TPM-specific. This is a useful negative or comparative result. Do not invent a hardware advantage to preserve the original motivation. Full hardware resistance, realistic workload measurement, and OS-enforced custody remain separate questions.

## Next action

Run the targeted instructions in CLAUDE_BASELINE_V3_PROMPT.md. They preserve v2 and prioritize binding-mode substitution, cross-policy oracles and proof-to-delivery connection continuity before further model-generated discovery. No Adaption spending is needed for these tests.
