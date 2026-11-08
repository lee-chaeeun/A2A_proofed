# Matrix summary

Run results/v3-final/20261108-004047 started 2026-11-07T23:40:47Z, 24 cells, 24 appraisals, manifest v4 frozen 2026-11-07T23:55:00Z.

## Decisions (observed → job recipient; bold = divergence from the frozen prediction)

| Fixture | C+url | C+tls | S-env+tls | S-env+cb | T+tls | T+cb |
|---|---|---|---|---|---|---|
| V1 honest baseline (positive control) | accept → A | accept → A | accept → A | accept → A | accept → A | accept → A |
| V2 F15 relay: stolen TLS key, untouched relay | accept → B | accept → B | accept → B | reject → none | accept → B | reject → none |
| V3 binding downgrade: chosen nonce, +cb kept but binding stripped | accept → B | accept → B | reject → none | reject → none | reject → none | reject → none |
| V4 cross-policy oracle: chosen nonce forwarded to A under a weaker mode | accept → B | accept → B | reject → none | reject → none | reject → none | reject → none |

## Counts (denominators stated; coverage of this fixture set, not prevalence)

* Cells matching the frozen prediction: 24 / 24 applicable
* False endpoint acceptances (job to B while expecting A): 8 / 18 attacker-endpoint cells (F12/F13 excluded)
  * per policy: C+url 3/3; C+tls 3/3; S-env+tls 1/3; S-env+cb 0/3; T+tls 1/3; T+cb 0/3
* Honest-class cells (explicit fixture class, or derived from endpoint=A for legacy manifests) not delivering to A: 0 / 6 cells; cells by class: map[honest:6 malicious:18]
* v3-final schema: decision matches 24 / 24, recipient matches 24 / 24 (predicted separately; accept is not delivery to A)
* Changed-configuration rejections (F9, reported separately, legitimate by policy): 0 cells
* Nonce burning (F12): valid second responses rejected because the nonce was consumed: 0 appraisals (availability cost of consume-on-failure)
* Concurrent valid responses (F13): 0 cells; one job to B: 0; one job to A: 0; zero jobs: 0
* Duplicate dispatch (two job_released for one nonce): 0 cells; duplicate receipt (one token received twice): 0 cells
* False signer attributions (accepted attack appraisal with no A-enrolled key used, typed): 0 / 2 accepted attack appraisals with a proof
* Custody broken (A's key used by B's process or from copied materials) among those: 0 / 2
* TOCTOU (F18): jobs delivered after the appraised configuration changed: 0 appraisals (no continuity is enforced by any policy)
* Telemetry incomplete: 0 appraisals; released tokens never observed at a recipient: 0

No divergences from the frozen predictions.

## Per-appraisal detail

| Cell | # | endpoint | eq | tls | cb | keys | invokers | job → | accept | stage | code | reason | telemetry |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| V1_C+url | 1 | A | yes | no/no | n/a |  |  | A | true |  |  |  | complete |
| V1_C+tls | 1 | A | yes | yes/yes | n/a |  |  | A | true |  |  |  | complete |
| V1_S-env+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| V1_S-env+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| V1_T+tls | 1 | A | yes | yes/yes | n/a | A | A | A | true |  |  |  | complete |
| V1_T+cb | 1 | A | yes | yes/yes | yes | A | A | A | true |  |  |  | complete |
| V2_C+url | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| V2_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| V2_S-env+tls | 1 | B>A | yes | yes/yes | n/a | A | A | B | true |  |  |  | complete |
| V2_S-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | envelope-metadata |  | software envelope metadata: nonce != issued (bound) nonce | complete |
| V2_T+tls | 1 | B>A | yes | yes/yes | n/a | A | A | B | true |  |  |  | complete |
| V2_T+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | nonce | PTV_ERR_006 | quote extraData != issued nonce | complete |
| V3_C+url | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| V3_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| V3_S-env+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | envelope-metadata |  | software envelope metadata: nonce != issued (bound) nonce | complete |
| V3_S-env+cb | 1 | B>A | yes | yes/yes | no |  |  | none | false | envelope |  | no software envelope in response | complete |
| V3_T+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | nonce | PTV_ERR_006 | quote extraData != issued nonce | complete |
| V3_T+cb | 1 | B>A | yes | yes/yes | no |  |  | none | false | quote | PTV_ERR_001 | no quote in response | complete |
| V4_C+url | 1 | B | yes | no/no | n/a |  |  | B | true |  |  |  | complete |
| V4_C+tls | 1 | B | yes | yes/yes | n/a |  |  | B | true |  |  |  | complete |
| V4_S-env+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | envelope-metadata |  | software envelope metadata: nonce != issued (bound) nonce | complete |
| V4_S-env+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | envelope-metadata |  | software envelope metadata: nonce != issued (bound) nonce | complete |
| V4_T+tls | 1 | B>A | yes | yes/yes | n/a | A | A | none | false | nonce | PTV_ERR_006 | quote extraData != issued nonce | complete |
| V4_T+cb | 1 | B>A | yes | yes/yes | no | A | A | none | false | nonce | PTV_ERR_006 | quote extraData != issued nonce | complete |
