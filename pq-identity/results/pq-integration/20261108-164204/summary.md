# Matrix summary

Run results/pq-integration/20261108-164204 started 2026-11-08T15:42:04Z, 128 cells, 136 appraisals, manifest v5 frozen 2026-11-08T13:30:00Z.

## Decisions (observed → job recipient; bold = divergence from the frozen prediction)

| Fixture | C+tls | EC-env+tls | EC-env+cb | PQ-env+tls | PQ-env+cb | PQ-file+cb | PQ-device+tls | PQ-device+cb |
|---|---|---|---|---|---|---|---|---|
| P1 honest A, one delivery | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A |
| P2 recorded proof replayed against a fresh nonce | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| P3 context tamper: relay changes the action of the forwarded challenge | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| P4 wrong enrolled key: B presents its own genuine keys under A's key ids | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| P5 algorithm confusion / classical fallback | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| P6 application volume copied (incl. PQ-file seed) + A's TLS credentials, no signer access | accept → B | reject → none | reject → none | reject → none | reject → none | accept → B | reject → none | reject → none |
| P7 address hijack without TLS credentials | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| P8 relay with A's TLS credentials, untouched forwarding | accept → B | accept → B | reject → none | accept → B | reject → none | reject → none | accept → B | reject → none |
| P9 relay + binding strip, exporter injection, chosen nonce and cross-policy forward | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| P10 valid proof, then proof connection closed and A's name repointed to B before dispatch | accept → none | accept → none | accept → none | accept → none | accept → none | accept → none | accept → none | accept → none |
| P11 two concurrent deliveries for one session | one → A | one → A | one → A | one → A | one → A | one → A | one → A | one → A |
| P12 classical-compromise surrogate: A's TLS credentials + EC signer access, no PQ key | accept → B | accept → B | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none |
| X1 boundary control: A's TLS credentials + PQ software signer and device signer access | accept → B | reject → none | reject → none | accept → B | accept → B | accept → B | accept → B | accept → B |
| X2 boundary control: copy of A's emulator NV file in a third fwTPM instance + A's authValue | accept → B | reject → none | reject → none | reject → none | reject → none | accept → B | accept → B | accept → B |
| X3 boundary control: attacker-generated ML-DSA key presented under A's key ids | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| X4 boundary control: PQ-file key rotated in the registry (version 2) while the copied volume holds version 1 | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |

## Counts (denominators stated; coverage of this fixture set, not prevalence)

* Cells matching the frozen prediction: 128 / 128 applicable
* False endpoint acceptances (job to B while expecting A): 25 / 104 attacker-endpoint cells (F12/F13 excluded)
  * per policy: C+tls 11/13; EC-env+tls 2/13; EC-env+cb 1/13; PQ-env+tls 2/13; PQ-env+cb 1/13; PQ-file+cb 3/13; PQ-device+tls 3/13; PQ-device+cb 2/13
* Honest-class cells (explicit fixture class, or derived from endpoint=A for legacy manifests) not delivering to A: 0 / 16 cells; cells by class: map[honest:16 malicious:112]
* v3-final schema: decision matches 128 / 128, recipient matches 128 / 128 (predicted separately; accept is not delivery to A)
* Changed-configuration rejections (F9, reported separately, legitimate by policy): 0 cells
* Nonce burning (F12): valid second responses rejected because the nonce was consumed: 0 appraisals (availability cost of consume-on-failure)
* Concurrent valid responses (F13): 0 cells; one job to B: 0; one job to A: 0; zero jobs: 0
* Duplicate dispatch (two job_released for one nonce): 0 cells; duplicate receipt (one token received twice): 0 cells
* False signer attributions (accepted attack appraisal with no A-enrolled key used, typed): 0 / 21 accepted attack appraisals with a proof
* Custody broken (A's key used by B's process or from copied materials) among those: 11 / 21
* TOCTOU (F18): jobs delivered after the appraised configuration changed: 0 appraisals (no continuity is enforced by any policy)
* Telemetry incomplete: 0 appraisals; released tokens never observed at a recipient: 8

No divergences from the frozen predictions.

## Per-appraisal detail

| Cell | # | endpoint | eq | tls | cb | keys | invokers | job → | accept | stage | code | reason | telemetry |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1_C+tls | 1 | A | yes | yes/yes | n/a |  |  | A | true |  |  |  | complete |
| P1_EC-env+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| P1_EC-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| P1_PQ-env+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| P1_PQ-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| P1_PQ-file+cb | 1 | A | yes | yes/yes | yes | A | A(in-process) | A | true |  |  |  | complete |
| P1_PQ-device+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| P1_PQ-device+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| P2_C+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| P2_EC-env+tls | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| P2_EC-env+cb | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| P2_PQ-env+tls | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| P2_PQ-env+cb | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| P2_PQ-file+cb | 1 | A | no | yes/no | n/a | A | A(in-process) | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| P2_PQ-device+tls | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| P2_PQ-device+cb | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| P3_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| P3_EC-env+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [action]) | complete |
| P3_EC-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [action exporter]) | complete |
| P3_PQ-env+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [action]) | complete |
| P3_PQ-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [action exporter]) | complete |
| P3_PQ-file+cb | 1 | B>A | yes | yes/yes | no | A | A(in-process) | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [action exporter]) | complete |
| P3_PQ-device+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [action]) | complete |
| P3_PQ-device+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [action exporter]) | complete |
| P4_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| P4_EC-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| P4_EC-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| P4_PQ-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| P4_PQ-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| P4_PQ-file+cb | 1 | B | yes | yes/yes | no | B | B(in-process) | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqfile-k1 | complete |
| P4_PQ-device+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
| P4_PQ-device+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
| P5_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| P5_EC-env+tls | 1 | B | yes | yes/yes | n/a | B |  | none | false | proof-v4-alg |  | proof_v4: algorithm "ML-DSA-65" is not the pinned ES256 for this policy (no downgrade or confusion) | complete |
| P5_EC-env+cb | 1 | B | yes | yes/yes | no | B |  | none | false | proof-v4-alg |  | proof_v4: algorithm "ML-DSA-65" is not the pinned ES256 for this policy (no downgrade or confusion) | complete |
| P5_PQ-env+tls | 1 | B | yes | yes/yes | n/a | B |  | none | false | proof-v4-alg |  | proof_v4: algorithm "ES256" is not the pinned ML-DSA-65 for this policy (no downgrade or confusion) | complete |
| P5_PQ-env+cb | 1 | B | yes | yes/yes | no | B |  | none | false | proof-v4-alg |  | proof_v4: algorithm "ES256" is not the pinned ML-DSA-65 for this policy (no downgrade or confusion) | complete |
| P5_PQ-file+cb | 1 | B | yes | yes/yes | no | B |  | none | false | proof-v4-alg |  | proof_v4: algorithm "ES256" is not the pinned ML-DSA-65 for this policy (no downgrade or confusion) | complete |
| P5_PQ-device+tls | 1 | B | yes | yes/yes | n/a | B |  | none | false | proof-v4-alg |  | proof_v4: algorithm "ES256" is not the pinned ML-DSA-65 for this policy (no downgrade or confusion) | complete |
| P5_PQ-device+cb | 1 | B | yes | yes/yes | no | B |  | none | false | proof-v4-alg |  | proof_v4: algorithm "ES256" is not the pinned ML-DSA-65 for this policy (no downgrade or confusion) | complete |
| P6_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| P6_EC-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| P6_EC-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| P6_PQ-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| P6_PQ-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| P6_PQ-file+cb | 1 | B | yes | yes/yes | yes | A | B(in-process) | B | true |  |  |  | complete |
| P6_PQ-device+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
| P6_PQ-device+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
| P7_C+tls | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| P7_EC-env+tls | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| P7_EC-env+cb | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| P7_PQ-env+tls | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| P7_PQ-env+cb | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| P7_PQ-file+cb | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| P7_PQ-device+tls | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| P7_PQ-device+cb | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| P8_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| P8_EC-env+tls | 1 | B>A | yes | yes/yes | n/a | A | A | B | true |  |  |  | complete |
| P8_EC-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [exporter]) | complete |
| P8_PQ-env+tls | 1 | B>A | yes | yes/yes | n/a | A | A | B | true |  |  |  | complete |
| P8_PQ-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [exporter]) | complete |
| P8_PQ-file+cb | 1 | B>A | yes | yes/yes | no | A | A(in-process) | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [exporter]) | complete |
| P8_PQ-device+tls | 1 | B>A | yes | yes/yes | n/a | A | A | B | true |  |  |  | complete |
| P8_PQ-device+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [exporter]) | complete |
| P9_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| P9_EC-env+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [nonce session]) | complete |
| P9_EC-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [policy nonce session exporter]) | complete |
| P9_PQ-env+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [nonce session]) | complete |
| P9_PQ-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [policy nonce session exporter]) | complete |
| P9_PQ-file+cb | 1 | B>A | yes | yes/yes | no | A | A(in-process) | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [policy nonce session exporter]) | complete |
| P9_PQ-device+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [nonce session]) | complete |
| P9_PQ-device+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | proof-v4-context-mismatch |  | proof_v4: signed context differs from the expected context (fields: [policy nonce session exporter]) | complete |
| P10_C+tls | 1 |  | yes | yes/yes | n/a |  |  | unobserved | true |  |  |  | complete |
| P10_EC-env+tls | 1 | A | yes | yes/yes | n/a | A | A | unobserved | true |  |  |  | complete |
| P10_EC-env+cb | 1 | A | yes | yes/yes | yes | A | A | unobserved | true |  |  |  | complete |
| P10_PQ-env+tls | 1 | A | yes | yes/yes | n/a | A | A | unobserved | true |  |  |  | complete |
| P10_PQ-env+cb | 1 | A | yes | yes/yes | yes | A | A | unobserved | true |  |  |  | complete |
| P10_PQ-file+cb | 1 | A | yes | yes/yes | yes | A | A(in-process) | unobserved | true |  |  |  | complete |
| P10_PQ-device+tls | 1 | A | yes | yes/yes | n/a | A | A | unobserved | true |  |  |  | complete |
| P10_PQ-device+cb | 1 | A | yes | yes/yes | yes | A | A | unobserved | true |  |  |  | complete |
| P11_C+tls | 1 | A | yes | yes/yes | n/a |  |  | A | true |  |  |  | complete |
| P11_C+tls | 2 | A | yes | yes/no | n/a |  |  | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| P11_EC-env+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| P11_EC-env+tls | 2 | A | yes | yes/no | n/a | A | A | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| P11_EC-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| P11_EC-env+cb | 2 | A | yes | yes/no | n/a | A | A | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| P11_PQ-env+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| P11_PQ-env+tls | 2 | A | yes | yes/no | n/a | A | A | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| P11_PQ-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| P11_PQ-env+cb | 2 | A | yes | yes/no | n/a | A | A | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| P11_PQ-file+cb | 1 | A | yes | yes/yes | yes | A | A(in-process) | A | true |  |  |  | complete |
| P11_PQ-file+cb | 2 | A | yes | yes/no | n/a | A | A(in-process) | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| P11_PQ-device+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| P11_PQ-device+tls | 2 | A | yes | yes/no | n/a | A | A | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| P11_PQ-device+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| P11_PQ-device+cb | 2 | A | yes | yes/no | n/a | A | A | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| P12_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| P12_EC-env+tls | 1 | B | yes | yes/yes | n/a | A | B | B | true |  |  |  | complete |
| P12_EC-env+cb | 1 | B | yes | yes/yes | yes | A | B | B | true |  |  |  | complete |
| P12_PQ-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| P12_PQ-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| P12_PQ-file+cb | 1 | B | yes | yes/yes | no | B | B(in-process) | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqfile-k1 | complete |
| P12_PQ-device+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
| P12_PQ-device+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
| X1_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| X1_EC-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| X1_EC-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| X1_PQ-env+tls | 1 | B | yes | yes/yes | n/a | A | B | B | true |  |  |  | complete |
| X1_PQ-env+cb | 1 | B | yes | yes/yes | yes | A | B | B | true |  |  |  | complete |
| X1_PQ-file+cb | 1 | B | yes | yes/yes | yes | A | B(in-process) | B | true |  |  |  | complete |
| X1_PQ-device+tls | 1 | B | yes | yes/yes | n/a | A | B | B | true |  |  |  | complete |
| X1_PQ-device+cb | 1 | B | yes | yes/yes | yes | A | B | B | true |  |  |  | complete |
| X2_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| X2_EC-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| X2_EC-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| X2_PQ-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| X2_PQ-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| X2_PQ-file+cb | 1 | B | yes | yes/yes | yes | A | B(in-process) | B | true |  |  |  | complete |
| X2_PQ-device+tls | 1 | B | yes | yes/yes | n/a | A | B | B | true |  |  |  | complete |
| X2_PQ-device+cb | 1 | B | yes | yes/yes | yes | A | B | B | true |  |  |  | complete |
| X3_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| X3_EC-env+tls | 1 | B | yes | yes/yes | n/a | attacker-generated | B(in-process) | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| X3_EC-env+cb | 1 | B | yes | yes/yes | no | attacker-generated | B(in-process) | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| X3_PQ-env+tls | 1 | B | yes | yes/yes | n/a | attacker-generated | B(in-process) | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| X3_PQ-env+cb | 1 | B | yes | yes/yes | no | attacker-generated | B(in-process) | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| X3_PQ-file+cb | 1 | B | yes | yes/yes | no | attacker-generated | B(in-process) | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqfile-k1 | complete |
| X3_PQ-device+tls | 1 | B | yes | yes/yes | n/a | attacker-generated | B(in-process) | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
| X3_PQ-device+cb | 1 | B | yes | yes/yes | no | attacker-generated | B(in-process) | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
| X4_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| X4_EC-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| X4_EC-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ES256 signature does not verify under the pinned key A-ecenv-k1 | complete |
| X4_PQ-env+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| X4_PQ-env+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqenv-k1 | complete |
| X4_PQ-file+cb | 1 | B | yes | yes/yes | no | A | B(in-process) | none | false | proof-v4-kid |  | proof_v4: key id "A-pqfile-k1" is not the pinned "A-pqfile-k2" | complete |
| X4_PQ-device+tls | 1 | B | yes | yes/yes | n/a | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
| X4_PQ-device+cb | 1 | B | yes | yes/yes | no | B | B | none | false | proof-v4-signature |  | proof_v4: ML-DSA-65 signature does not verify under the pinned key A-pqdev-k1 | complete |
