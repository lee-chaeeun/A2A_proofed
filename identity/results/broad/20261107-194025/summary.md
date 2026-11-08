# Matrix v2 summary

Run results/v2/20261107-194025 started 2026-11-07T18:40:25Z, 231 cells, 217 appraisals, manifest v2 frozen 2026-11-07T19:30+01:00.

## Decisions (observed → job recipient; bold = divergence from the frozen prediction)

| Fixture | C | S-file | S-iso | S-env | T | P | C+url | C+tls | T+tls | S-env+cb | T+cb |
|---|---|---|---|---|---|---|---|---|---|---|---|
| F1 honest baseline | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A |
| F2 legitimate rename of A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A |
| F3 B claims A's display name with B's own key | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| F4 B serves copy of A's card and replays an old proof | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| F5 B copies A's application volume | accept → B | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| F6 B relays the live challenge to A | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none |
| F7 B granted A's signer sockets and authorizations | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none |
| F8 relay with outer timestamp edited, inner quote preserved | accept → B | accept → B | accept → B | reject → none | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| F9 A's appraised PCR changed | accept → A | accept → A | accept → A | accept → A | reject → none | reject → none | accept → A | accept → A | reject → none | accept → A | reject → none |
| F10 routine envelope with both evidence and proof, correctly signed | n/a | n/a | n/a | n/a | n/a | reject → none | n/a | n/a | n/a | n/a | n/a |
| F11 B presents a never-enrolled key claiming A | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none | reject → none |
| F12 one nonce: invalid first (B), valid second (A) | n/a | reject,reject → none | reject,reject → none | reject,reject → none | reject,reject → none | reject,reject → none | n/a | n/a | reject,accept → A | reject,accept → A | reject,accept → A |
| F13 one nonce: two simultaneous valid responses | n/a | one → A | one → B | one → B | one → B | one → B | n/a | n/a | one → A | one → A | one → A |
| F14 attacker at the expected address without A's credentials (address hijack, relay) | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | reject → none | reject → none | reject → none | reject → none |
| F15 attacker at the expected address with A's TLS credentials (relay) | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | reject → none | reject → none |
| F16 F15 plus relay injects its observed channel binding into the forwarded challenge | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | accept → B | reject → none | reject → none |
| F17 attacker at the expected address with a self-signed certificate for A's name (relay) | n/a | n/a | n/a | n/a | n/a | n/a | accept → B | reject → none | reject → none | reject → none | reject → none |
| F18 configuration changed between successful appraisal and job delivery (TOCTOU) | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A |
| F19 B runs a byte clone of A's emulator state and holds A's AK password | accept → B | accept → B | reject → none | reject → none | **reject → none (expected accept)** | **reject → none (expected accept)** | reject → none | reject → none | reject → none | reject → none | reject → none |
| F20 attacker at the expected address with A's TLS credentials AND A's signer access | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B | accept → B |
| F21 F19 plus attacker re-extends the clone's PCR 16 with the public configuration string | accept → B | accept → B | reject → none | reject → none | accept → B | accept → B | reject → none | reject → none | reject → none | reject → none | reject → none |

## Counts (denominators stated; coverage of this fixture set, not prevalence)

* Cells matching the frozen prediction: 199 / 201 applicable
* False endpoint acceptances (job to B while expecting A): 55 / 140 attacker-endpoint cells (F12/F13 excluded)
  * per policy: C 11/12; S-file 9/12; S-iso 6/12; S-env 5/12; T 7/12; P 6/12; C+url 4/13; C+tls 2/13; T+tls 3/14; S-env+cb 1/14; T+cb 1/14
* Honest baseline (F1, F2) rejections: 0 / 22 cells
* Changed-configuration rejections (F9, reported separately, legitimate by policy): 4 cells
* Nonce burning (F12): valid second responses rejected because the nonce was consumed: 5 appraisals (availability cost of consume-on-failure)
* Concurrent valid responses (F13): 8 cells; one job to B: 4; one job to A: 4; zero jobs: 0
* Duplicate dispatch (two job_released for one nonce): 0 cells; duplicate receipt (one token received twice): 0 cells
* False signer attributions (accepted attack appraisal with no A-enrolled key used, typed): 0 / 49 accepted attack appraisals with a proof
* Custody broken (A's key used by B's process or from copied materials) among those: 18 / 49
* TOCTOU (F18): jobs delivered after the appraised configuration changed: 18 appraisals (no continuity is enforced by any policy)
* Telemetry incomplete: 0 appraisals; released tokens never observed at a recipient: 0

## Divergences from frozen predictions

* F19_T: expected accept, observed reject (PCR digest != reference value)
* F19_P: expected accept, observed reject (PCR digest != reference value)

## Randomized race trials (100 per policy, seeds 20261107..20261206, delays U[0,40] ms)

Each trial: one nonce, challenge sent to A directly and to B (relay to A) concurrently; each response appraised on arrival. These trials share one deployment pair and one implementation: they measure this harness's race behaviour, not attack prevalence.

| Policy | trials | B wins | A wins | zero releases | two releases | errors | A latency p50/p90 ms | B latency p50/p90 ms |
|---|---|---|---|---|---|---|---|---|
| S-file | 100 | 0 | 100 | 0 | 0 | 0 | 19.7/39.2 | 43.0/68.6 |
| S-iso | 100 | 0 | 100 | 0 | 0 | 0 | 19.2/39.7 | 43.5/68.7 |
| S-env | 100 | 0 | 100 | 0 | 0 | 0 | 19.8/39.5 | 43.3/69.3 |
| T | 100 | 1 | 99 | 0 | 0 | 0 | 20.1/40.5 | 44.0/70.1 |
| P | 100 | 0 | 100 | 0 | 0 | 0 | 21.5/41.5 | 44.5/71.3 |

## Per-appraisal detail

| Cell | # | endpoint | eq | tls | cb | keys | invokers | job → | accept | stage | code | reason | telemetry |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F1_C | 1 | A | yes | no/no | n/a |  |  | A | true |  |  |  | complete |
| F1_S-file | 1 | A | yes | no/no | n/a | A | A(in-process) | A | true |  |  |  | complete |
| F1_S-iso | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F1_S-env | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F1_T | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F1_P | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F1_C+url | 1 | A | yes | no/no | n/a |  |  | A | true |  |  |  | complete |
| F1_C+tls | 1 | A | yes | yes/yes | n/a |  |  | A | true |  |  |  | complete |
| F1_T+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| F1_S-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F1_T+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F2_C | 1 | A | yes | no/no | n/a |  |  | A | true |  |  |  | complete |
| F2_S-file | 1 | A | yes | no/no | n/a | A | A(in-process) | A | true |  |  |  | complete |
| F2_S-iso | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F2_S-env | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F2_T | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F2_P | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F2_C+url | 1 | A | yes | no/no | n/a |  |  | A | true |  |  |  | complete |
| F2_C+tls | 1 | A | yes | yes/yes | n/a |  |  | A | true |  |  |  | complete |
| F2_T+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| F2_S-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F2_T+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F3_C | 1 |  | yes | no/no | n/a |  |  | none | false | card |  | card: kid "B-card-k1": kid is not the enrolled publisher key of A | complete |
| F3_S-file | 1 | B | yes | no/no | n/a | B | B(in-process) | none | false | card |  | card: kid "B-card-k1": kid is not the enrolled publisher key of A | complete |
| F3_S-iso | 1 | B | yes | no/no | n/a | B | B | none | false | card |  | card: kid "B-card-k1": kid is not the enrolled publisher key of A | complete |
| F3_S-env | 1 | B | yes | no/no | n/a | B | B | none | false | card |  | card: kid "B-card-k1": kid is not the enrolled publisher key of A | complete |
| F3_T | 1 | B | yes | no/no | n/a | B | B | none | false | card |  | card: kid "B-card-k1": kid is not the enrolled publisher key of A | complete |
| F3_P | 1 | B | yes | no/no | n/a | B | B | none | false | card |  | card: kid "B-card-k1": kid is not the enrolled publisher key of A | complete |
| F3_C+url | 1 |  | yes | no/no | n/a |  |  | none | false | card |  | card: kid "B-card-k1": kid is not the enrolled publisher key of A | complete |
| F3_C+tls | 1 |  | yes | yes/no | n/a |  |  | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| F3_T+tls | 1 |  | yes | yes/no | n/a |  |  | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| F3_S-env+cb | 1 |  | yes | yes/no | n/a |  |  | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| F3_T+cb | 1 |  | yes | yes/no | n/a |  |  | none | false | connect-tls |  | transport not authenticated as the enrolled deployment: authenticated peer b.a2aid.test is not the enrolled name a.a2aid.test | complete |
| F4_C | 1 | B | no | no/no | n/a |  |  | B | true |  |  |  | complete |
| F4_S-file | 1 | A>B | no | no/no | n/a | A | A(in-process) | none | false | nonce | PTV_ERR_006 | response nonce != issued nonce (stale or replayed proof) | complete |
| F4_S-iso | 1 | A>B | no | no/no | n/a | A | A | none | false | nonce | PTV_ERR_006 | response nonce != issued nonce (stale or replayed proof) | complete |
| F4_S-env | 1 | A>B | no | no/no | n/a | A | A | none | false | nonce | PTV_ERR_006 | response nonce != issued nonce (stale or replayed proof) | complete |
| F4_T | 1 | A>B | no | no/no | n/a | A | A | none | false | nonce | PTV_ERR_006 | response nonce != issued nonce (stale or replayed proof) | complete |
| F4_P | 1 | A>B | no | no/no | n/a | A | A | none | false | nonce | PTV_ERR_006 | response nonce != issued nonce (stale or replayed proof) | complete |
| F4_C+url | 1 |  | no | no/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is http://b.a2aid.test:9102 | complete |
| F4_C+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F4_T+tls | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F4_S-env+cb | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F4_T+cb | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F5_C | 1 | B | no | no/no | n/a |  |  | B | true |  |  |  | complete |
| F5_S-file | 1 | B | no | no/no | n/a | A | B(in-process) | B | true |  |  |  | complete |
| F5_S-iso | 1 | B | no | no/no | n/a | B | B | none | false | signature |  | challenge signature does not verify under enrolled key A-siso-k1 (kid presented: "B-siso-k1") | complete |
| F5_S-env | 1 | B | no | no/no | n/a | B | B | none | false | envelope-signature |  | software envelope signature invalid under the enrolled S-iso key of A | complete |
| F5_T | 1 | B | no | no/no | n/a | B | B | none | false | trust-anchor | PTV_ERR_010 | quote signature invalid under enrolled AK | complete |
| F5_P | 1 | B | no | no/no | n/a | B | B | none | false | envelope-signature | PTV_ERR_010 | COSE_Sign1 signature invalid under the enrolled AK of A | complete |
| F5_C+url | 1 |  | no | no/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is http://b.a2aid.test:9102 | complete |
| F5_C+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F5_T+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F5_S-env+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F5_T+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F6_C | 1 | B | no | no/no | n/a |  |  | B | true |  |  |  | complete |
| F6_S-file | 1 | B>A | no | no/no | n/a | A | A(in-process) | B | true |  |  |  | complete |
| F6_S-iso | 1 | B>A | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F6_S-env | 1 | B>A | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F6_T | 1 | B>A | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F6_P | 1 | B>A | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F6_C+url | 1 |  | no | no/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is http://b.a2aid.test:9102 | complete |
| F6_C+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F6_T+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F6_S-env+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F6_T+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F7_C | 1 | B | no | no/no | n/a |  |  | B | true |  |  |  | complete |
| F7_S-file | 1 | B | no | no/no | n/a | A | B(in-process) | B | true |  |  |  | complete |
| F7_S-iso | 1 | B | no | no/no | n/a | A | B | B | true |  |  |  | complete |
| F7_S-env | 1 | B | no | no/no | n/a | A | B | B | true |  |  |  | complete |
| F7_T | 1 | B | no | no/no | n/a | A | B | B | true |  |  |  | complete |
| F7_P | 1 | B | no | no/no | n/a | A | B | B | true |  |  |  | complete |
| F7_C+url | 1 |  | no | no/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is http://b.a2aid.test:9102 | complete |
| F7_C+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F7_T+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F7_S-env+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F7_T+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F8_C | 1 | B | no | no/no | n/a |  |  | B | true |  |  |  | complete |
| F8_S-file | 1 | B>A | no | no/no | n/a | A | A(in-process) | B | true |  |  |  | complete |
| F8_S-iso | 1 | B>A | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F8_S-env | 1 | B>A | no | no/no | n/a | A | A | none | false | envelope-signature |  | software envelope signature invalid under the enrolled S-iso key of A | complete |
| F8_T | 1 | B>A | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F8_P | 1 | B>A | no | no/no | n/a | A | A | none | false | envelope-signature | PTV_ERR_010 | COSE_Sign1 signature invalid under the enrolled AK of A | complete |
| F8_C+url | 1 |  | no | no/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is http://b.a2aid.test:9102 | complete |
| F8_C+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F8_T+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F8_S-env+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F8_T+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F9_C | 1 | A | yes | no/no | n/a |  |  | A | true |  |  |  | complete |
| F9_S-file | 1 | A | yes | no/no | n/a | A | A(in-process) | A | true |  |  |  | complete |
| F9_S-iso | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F9_S-env | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F9_T | 1 | A | yes | no/no | n/a | A | A | none | false | config | PTV_ERR_007 | PCR digest != reference value | complete |
| F9_P | 1 | A | yes | no/no | n/a | A | A | none | false | config | PTV_ERR_007 | PCR digest != reference value | complete |
| F9_C+url | 1 | A | yes | no/no | n/a |  |  | A | true |  |  |  | complete |
| F9_C+tls | 1 | A | yes | yes/yes | n/a |  |  | A | true |  |  |  | complete |
| F9_T+tls | 1 | A | yes | yes/yes | n/a | A | A | none | false | config | PTV_ERR_007 | PCR digest != reference value | complete |
| F9_S-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F9_T+cb | 1 | A | yes | yes/yes | no | A | A | none | false | config | PTV_ERR_007 | PCR digest != reference value | complete |
| F10_P | 1 | A | yes | no/no | n/a | A | A | none | false | schema | PTV_ERR_008 | routine band requires evidence XOR proof (both present) | complete |
| F11_C | 1 | B | no | no/no | n/a |  |  | B | true |  |  |  | complete |
| F11_S-file | 1 | B | no | no/no | n/a | unenrolled |  | none | false | signature |  | challenge signature does not verify under enrolled key A-sfile-k1 (kid presented: "unknown-sfile") | complete |
| F11_S-iso | 1 | B | no | no/no | n/a | unenrolled |  | none | false | signature |  | challenge signature does not verify under enrolled key A-siso-k1 (kid presented: "unknown-siso") | complete |
| F11_S-env | 1 | B | no | no/no | n/a | unenrolled |  | none | false | envelope-signature |  | software envelope signature invalid under the enrolled S-iso key of A | complete |
| F11_T | 1 | B | no | no/no | n/a | unenrolled | B | none | false | trust-anchor | PTV_ERR_010 | quote signature invalid under enrolled AK | complete |
| F11_P | 1 | B | no | no/no | n/a | unenrolled;B | B | none | false | envelope-signature | PTV_ERR_010 | COSE_Sign1 signature invalid under the enrolled AK of A | complete |
| F11_C+url | 1 |  | no | no/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is http://b.a2aid.test:9102 | complete |
| F11_C+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F11_T+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F11_S-env+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F11_T+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F12_S-file | 1 | B>A | no | no/no | n/a | garbage;A | A(in-process) | none | false | signature |  | challenge signature does not verify under enrolled key A-sfile-k1 (kid presented: "sfile-garbage") | complete |
| F12_S-file | 2 | B>A | yes | no/no | n/a | garbage;A | A(in-process) | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F12_S-iso | 1 | B>A | no | no/no | n/a | garbage;A | A | none | false | signature |  | challenge signature does not verify under enrolled key A-siso-k1 (kid presented: "siso-garbage") | complete |
| F12_S-iso | 2 | B>A | yes | no/no | n/a | garbage;A | A | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F12_S-env | 1 | B>A | no | no/no | n/a | unenrolled;A | A | none | false | envelope-signature |  | software envelope signature invalid under the enrolled S-iso key of A | complete |
| F12_S-env | 2 | B>A | yes | no/no | n/a | unenrolled;A | A | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F12_T | 1 | B>A | no | no/no | n/a | B;A | B;A | none | false | trust-anchor | PTV_ERR_010 | quote signature invalid under enrolled AK | complete |
| F12_T | 2 | B>A | yes | no/no | n/a | B;A | B;A | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F12_P | 1 | B>A | no | no/no | n/a | B;A | B;A | none | false | envelope-signature | PTV_ERR_010 | COSE_Sign1 signature invalid under the enrolled AK of A | complete |
| F12_P | 2 | B>A | yes | no/no | n/a | B;A | B;A | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F12_T+tls | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F12_T+tls | 2 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| F12_S-env+cb | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F12_S-env+cb | 2 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F12_T+cb | 1 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F12_T+cb | 2 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F13_S-file | 1 | B>A | yes | no/no | n/a | A | A(in-process) | A | true |  |  |  | complete |
| F13_S-file | 2 | B>A | no | no/no | n/a | A | A(in-process) | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F13_S-iso | 1 | B>A | yes | no/no | n/a | A | A | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F13_S-iso | 2 | B>A | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F13_S-env | 1 | B>A | yes | no/no | n/a | A | A | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F13_S-env | 2 | B>A | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F13_T | 1 | A>B | yes | no/no | n/a | A | A | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F13_T | 2 | A>B | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F13_P | 1 | B>A | yes | no/no | n/a | A | A | none | false | nonce | PTV_ERR_006 | nonce already consumed by an earlier appraisal | complete |
| F13_P | 2 | B>A | no | no/no | n/a | A | A | B | true |  |  |  | complete |
| F13_T+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| F13_T+tls | 2 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F13_S-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F13_S-env+cb | 2 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F13_T+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F13_T+cb | 2 | A | no | yes/no | n/a | A | A | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F14_C | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| F14_S-file | 1 | B>A | yes | no/no | n/a | A | A(in-process) | B | true |  |  |  | complete |
| F14_S-iso | 1 | B>A | yes | no/no | n/a | A | A | B | true |  |  |  | complete |
| F14_S-env | 1 | B>A | yes | no/no | n/a | A | A | B | true |  |  |  | complete |
| F14_T | 1 | B>A | yes | no/no | n/a | A | A | B | true |  |  |  | complete |
| F14_P | 1 | B>A | yes | no/no | n/a | A | A | B | true |  |  |  | complete |
| F14_C+url | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| F14_C+tls | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| F14_T+tls | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| F14_S-env+cb | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| F14_T+cb | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate is valid for b.a2aid.test, not a.a2aid.test | complete |
| F15_C | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| F15_S-file | 1 | B>A | yes | no/no | n/a | A | A(in-process) | B | true |  |  |  | complete |
| F15_S-iso | 1 | B>A | yes | no/no | n/a | A | A | B | true |  |  |  | complete |
| F15_S-env | 1 | B>A | yes | no/no | n/a | A | A | B | true |  |  |  | complete |
| F15_T | 1 | B>A | yes | no/no | n/a | A | A | B | true |  |  |  | complete |
| F15_P | 1 | B>A | yes | no/no | n/a | A | A | B | true |  |  |  | complete |
| F15_C+url | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| F15_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| F15_T+tls | 1 | B>A | yes | yes/yes | n/a | A | A | B | true |  |  |  | complete |
| F15_S-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | envelope-metadata |  | software envelope metadata: nonce != issued (bound) nonce | complete |
| F15_T+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | nonce | PTV_ERR_006 | quote extraData != issued nonce | complete |
| F16_T+tls | 1 | B>A | yes | yes/yes | n/a | A | A | B | true |  |  |  | complete |
| F16_S-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | envelope-metadata |  | software envelope metadata: nonce != issued (bound) nonce | complete |
| F16_T+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | nonce | PTV_ERR_006 | quote extraData != issued nonce | complete |
| F17_C+url | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| F17_C+tls | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate signed by unknown authority | complete |
| F17_T+tls | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate signed by unknown authority | complete |
| F17_S-env+cb | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate signed by unknown authority | complete |
| F17_T+cb | 1 |  | no | no/no | n/a |  |  | none | false | connect |  | card fetch: card request failed: Get "https://a.a2aid.test:9443/.well-known/agent-card.json": tls: failed to verify certificate: x509: certificate signed by unknown authority | complete |
| F18_C | 1 | A | yes | no/no | n/a |  |  | A | true |  |  |  | complete |
| F18_S-file | 1 | A | yes | no/no | n/a | A | A(in-process) | A | true |  |  |  | complete |
| F18_S-iso | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F18_S-env | 1 | A | yes | no/no | n/a | A | A | A | true |  |  |  | complete |
| F18_T | 1 | A | yes | no/no | n/a | A | A;operator | A | true |  |  |  | complete |
| F18_P | 1 | A | yes | no/no | n/a | A | A;operator | A | true |  |  |  | complete |
| F18_C+url | 1 | A | yes | no/no | n/a |  |  | A | true |  |  |  | complete |
| F18_C+tls | 1 | A | yes | yes/yes | n/a |  |  | A | true |  |  |  | complete |
| F18_T+tls | 1 | A | yes | yes/yes | n/a | A | A;operator | A | true |  |  |  | complete |
| F18_S-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| F18_T+cb | 1 | A | yes | yes/yes | yes | A | A;operator | A | true |  |  |  | complete |
| F19_C | 1 | B | no | no/no | n/a |  |  | B | true |  |  |  | complete |
| F19_S-file | 1 | B | no | no/no | n/a | A | B(in-process) | B | true |  |  |  | complete |
| F19_S-iso | 1 | B | no | no/no | n/a | B | B | none | false | signature |  | challenge signature does not verify under enrolled key A-siso-k1 (kid presented: "B-siso-k1") | complete |
| F19_S-env | 1 | B | no | no/no | n/a | B | B | none | false | envelope-signature |  | software envelope signature invalid under the enrolled S-iso key of A | complete |
| F19_T | 1 | B | no | no/no | n/a | A | B | none | false | config | PTV_ERR_007 | PCR digest != reference value | complete |
| F19_P | 1 | B | no | no/no | n/a | A | B | none | false | config | PTV_ERR_007 | PCR digest != reference value | complete |
| F19_C+url | 1 |  | no | no/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is http://b.a2aid.test:9102 | complete |
| F19_C+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F19_T+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F19_S-env+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F19_T+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F20_C | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| F20_S-file | 1 | B | yes | no/no | n/a | A | B(in-process) | B | true |  |  |  | complete |
| F20_S-iso | 1 | B | yes | no/no | n/a | A | B | B | true |  |  |  | complete |
| F20_S-env | 1 | B | yes | no/no | n/a | A | B | B | true |  |  |  | complete |
| F20_T | 1 | B | yes | no/no | n/a | A | B | B | true |  |  |  | complete |
| F20_P | 1 | B | yes | no/no | n/a | A | B | B | true |  |  |  | complete |
| F20_C+url | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| F20_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| F20_T+tls | 1 | B | yes | yes/yes | n/a | A | B | B | true |  |  |  | complete |
| F20_S-env+cb | 1 | B | yes | yes/yes | yes | A | B | B | true |  |  |  | complete |
| F20_T+cb | 1 | B | yes | yes/yes | yes | A | B | B | true |  |  |  | complete |
| F21_C | 1 | B | no | no/no | n/a |  |  | B | true |  |  |  | complete |
| F21_S-file | 1 | B | no | no/no | n/a | A | B(in-process) | B | true |  |  |  | complete |
| F21_S-iso | 1 | B | no | no/no | n/a | B | B | none | false | signature |  | challenge signature does not verify under enrolled key A-siso-k1 (kid presented: "B-siso-k1") | complete |
| F21_S-env | 1 | B | no | no/no | n/a | B | B | none | false | envelope-signature |  | software envelope signature invalid under the enrolled S-iso key of A | complete |
| F21_T | 1 | B | no | no/no | n/a | A | B | B | true |  |  |  | complete |
| F21_P | 1 | B | no | no/no | n/a | A | B | B | true |  |  |  | complete |
| F21_C+url | 1 |  | no | no/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is http://b.a2aid.test:9102 | complete |
| F21_C+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F21_T+tls | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F21_S-env+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
| F21_T+cb | 1 |  | no | yes/no | n/a |  |  | none | false | connect-url |  | signed card declares [http://a.a2aid.test:9101 https://a.a2aid.test:9443], discovery endpoint is https://b.a2aid.test:9444 | complete |
