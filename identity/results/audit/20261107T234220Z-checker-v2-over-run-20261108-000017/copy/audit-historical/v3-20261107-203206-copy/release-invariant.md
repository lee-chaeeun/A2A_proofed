# Independent release-invariant oracle for results/v3/20261107-203206

Protected dispatches examined: 14. Authorized (recipient = expected): 6. Unauthorized: 8. Incomplete evidence: 10.

Checks by how each was established (copied facts are reported, never summed into an independent-verification score):

* recomputed: 0
* shared_code: 14
* copied_fact: 14
* unverified: 11

Failed/flagged checks: 17 (negative control included and passing: a missing-recipient record is flagged, not agreed).

| cell | token | class | invariant | ok | detail |
|---|---|---|---|---|---|
| NEG-CONTROL | synthetic | unverified | missing-recipient record flagged incomplete | true | a record with no observed_recipient is reported incomplete, not agreed |
| V1_C+tls | 48ec0161f181… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V1_C+tls | 48ec0161f181… | copied_fact | observed recipient is the expected deployment | true |  |
| V1_C+tls | 48ec0161f181… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V1_C+url | 0b17b3d06fc0… | copied_fact | observed recipient is the expected deployment | true |  |
| V1_C+url | 0b17b3d06fc0… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V1_S-env+cb | e3ac29b05f5f… | copied_fact | observed recipient is the expected deployment | true |  |
| V1_S-env+cb | e3ac29b05f5f… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V1_S-env+cb | e3ac29b05f5f… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V1_S-env+tls | 96da73277a45… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V1_S-env+tls | 96da73277a45… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V1_S-env+tls | 96da73277a45… | copied_fact | observed recipient is the expected deployment | true |  |
| V1_T+cb | a3869c18d45c… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V1_T+cb | a3869c18d45c… | copied_fact | observed recipient is the expected deployment | true |  |
| V1_T+cb | a3869c18d45c… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V1_T+tls | a2ba8736197b… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V1_T+tls | a2ba8736197b… | copied_fact | observed recipient is the expected deployment | true |  |
| V1_T+tls | a2ba8736197b… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V2_C+tls | d4eff6e28c3b… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V2_C+tls | d4eff6e28c3b… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V2_C+tls | d4eff6e28c3b… | copied_fact | observed recipient is the expected deployment | false | job reached B |
| V2_C+url | 805af2a5b9c9… | copied_fact | observed recipient is the expected deployment | false | job reached B |
| V2_C+url | 805af2a5b9c9… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V2_S-env+tls | 10cda7c3f194… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V2_S-env+tls | 10cda7c3f194… | copied_fact | observed recipient is the expected deployment | false | job reached B |
| V2_S-env+tls | 10cda7c3f194… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V2_T+tls | 74ac3cfd4bf0… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V2_T+tls | 74ac3cfd4bf0… | copied_fact | observed recipient is the expected deployment | false | job reached B |
| V2_T+tls | 74ac3cfd4bf0… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V3_C+tls | c70387d82720… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V3_C+tls | c70387d82720… | copied_fact | observed recipient is the expected deployment | false | job reached B |
| V3_C+tls | c70387d82720… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V3_C+url | aeafea2b2659… | copied_fact | observed recipient is the expected deployment | false | job reached B |
| V3_C+url | aeafea2b2659… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V4_C+tls | e91e1cd8c78d… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V4_C+tls | e91e1cd8c78d… | copied_fact | observed recipient is the expected deployment | false | job reached B |
| V4_C+tls | e91e1cd8c78d… | unverified | job reused the proof connection (no reconnect before dispatch) | false | no connection-reuse record |
| V4_C+url | 97a63af8aa9a… | shared_code | dispatch had a preceding accepted appraisal | true |  |
| V4_C+url | 97a63af8aa9a… | copied_fact | observed recipient is the expected deployment | false | job reached B |
