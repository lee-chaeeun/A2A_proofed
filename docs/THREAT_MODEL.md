# Threat model (summary; the paper's §3 is authoritative)

**Trusted.** The requester and its own observations of the TLS connections it opens; an
out-of-band enrollment registry (publisher key, software signing keys, TPM attestation key
and PCR reference, TLS name, authorized origins per deployment); a lab certificate
authority; for the computation component, a fixture authority holding the ordered history
of input commitments, the synthetic openings held by worker and offline scorer, the guest
build and pinned image id, the verifier binary, and the serialized approval ledger.

**Untrusted.** Everything an agent sends: Agent Cards, challenge responses, quotes,
envelopes, receipts and all unsigned metadata.

**PQ identity attacker (deployment B impersonating A), escalating capabilities.** Copy A's
card; copy A's application volume (which holds the `PQ-file` seed but no gated or device
key); take over A's network address without credentials; hold A's TLS certificate and key
(P3–P6, P8, P9, P12 and the controls); be granted A's classical signer through the gate
(P12, the classical-compromise surrogate); be granted A's PQ signer and device signer
(X1); copy A's firmware-TPM state directory including the journal key, with the authValue
(X2); generate an ML-DSA key under A's key id (X3); hold a key the registry has rotated
away from (X4). Active variants: tampered action, replayed proof, algorithm confusion and
classical fallback, binding strip, exporter injection, chosen bound nonce, cross-policy
forwarding, connection substitution before dispatch, concurrent deliveries. Trusted in
addition: the registry's per-credential pins (algorithm, key id, version, public key,
custody), the two emulator processes and their state directories, the signer directories.

**Classical identity attacker (deployment B impersonating A), escalating capabilities.** Copy A's
card; copy A's application volume (file-held keys); take over A's network address without
credentials; hold A's TLS certificate and private key; additionally use A's proof signer
(software signer or swtpm). A copied swtpm state directory is a further capability for the
TPM policies. Active variants: rewrite protocol fields (binding-mode downgrade, cross-policy
signing oracle) and force a reconnection after a valid proof.

**Computation attacker (the worker).** Replay, corrupt or substitute receipts; prove over an
obsolete snapshot; prove with a wrong challenge; lie in unsigned metadata; deliver a result
twice. The worker cannot change the requester's authority, stored contracts or pinned image
id, and its claimed image id is never used as a trust anchor.

**Out of scope / not established.** Hardware key protection (swtpm and the wolfTPM
firmware TPM are software; their state is a file), FIPS validation and the security of
ML-DSA itself, post-quantum security of Agent Card signatures, TLS 1.3, the lab CA or
the exporter (an adversary recovering TLS session keys is not the measured relay),
enrollment, rotation and revocation protocols (one rotated pin exercised), measured
boot or model integrity (PCR 16 holds an operator-set value), requester authentication,
OS-level isolation (one OS account; the signer gate is harness-enforced), durable
exactly-once execution, production enrollment and credential lifecycle, prover identity or
honesty, whether a zero-knowledge proof is necessary for the toy predicate, behaviour of
real (model-driven) agents. The attacker holding both A's TLS key and A's signer access
defeats every tested control.

**Measured outcomes.** Identity: which deployment's server logged the synthetic task
(A, B or none), the requester's decision, and for the final run the checker's per-decision
outcome. Computation: per fixture × policy, whether an approval row was inserted, with the
verified journal, the authority head at the decision and the ledger state.

**Dual use.** The fixtures implement generic copy, replay, relay, hijack, credential-reuse,
downgrade and emulator-cloning behaviour against locally controlled processes and synthetic tokens;
no third-party software is exploited and the defects are in this project's code. The same
material is what a defender needs to test channel binding and task binding, and the repairs
are published with the attacks.
