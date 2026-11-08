# Offline reverification of results/v2/20261107-194025/

217 / 217 appraisals agree with the recorded decision (accept, failure stage, PTV code, card verdict).

Re-derived offline: card JWS (from the fetched card in the requester trace), nonce-session context and expiry (from the stored session with the clock fixed at the recorded appraisal time), S signatures, S-env envelope, TPM quote structure/signature/PCR digest, PTV envelope signature/schema/freshness, channel-bound nonce (from the requester's stored exporter value). Copied from the record, not re-derivable: TLS peer identity, endpoint equality, controller events.

| Cell | # | policy | recorded | offline | card | agree | note |
|---|---|---|---|---|---|---|---|
| F10_P | 1 | P | false/schema | false/schema | true/valid | true |  |
| F11_C+tls | 1 | C+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F11_C+url | 1 | C+url | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F11_C | 1 | C | true/ | true/ | true/valid | true |  |
| F11_P | 1 | P | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F11_S-env+cb | 1 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F11_S-env | 1 | S-env | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F11_S-file | 1 | S-file | false/signature | false/signature | true/valid | true |  |
| F11_S-iso | 1 | S-iso | false/signature | false/signature | true/valid | true |  |
| F11_T+cb | 1 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F11_T+tls | 1 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F11_T | 1 | T | false/trust-anchor | false/trust-anchor | true/valid | true |  |
| F12_P | 1 | P | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F12_P | 2 | P | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F12_S-env+cb | 1 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F12_S-env+cb | 2 | S-env+cb | true/ | true/ | true/valid | true |  |
| F12_S-env | 1 | S-env | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F12_S-env | 2 | S-env | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F12_S-file | 1 | S-file | false/signature | false/signature | true/valid | true |  |
| F12_S-file | 2 | S-file | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F12_S-iso | 1 | S-iso | false/signature | false/signature | true/valid | true |  |
| F12_S-iso | 2 | S-iso | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F12_T+cb | 1 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F12_T+cb | 2 | T+cb | true/ | true/ | true/valid | true |  |
| F12_T+tls | 1 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F12_T+tls | 2 | T+tls | true/ | true/ | true/valid | true |  |
| F12_T | 1 | T | false/trust-anchor | false/trust-anchor | true/valid | true |  |
| F12_T | 2 | T | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F13_P | 1 | P | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F13_P | 2 | P | true/ | true/ | true/valid | true |  |
| F13_S-env+cb | 1 | S-env+cb | true/ | true/ | true/valid | true |  |
| F13_S-env+cb | 2 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F13_S-env | 1 | S-env | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F13_S-env | 2 | S-env | true/ | true/ | true/valid | true |  |
| F13_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F13_S-file | 2 | S-file | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F13_S-iso | 1 | S-iso | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F13_S-iso | 2 | S-iso | true/ | true/ | true/valid | true |  |
| F13_T+cb | 1 | T+cb | true/ | true/ | true/valid | true |  |
| F13_T+cb | 2 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F13_T+tls | 1 | T+tls | true/ | true/ | true/valid | true |  |
| F13_T+tls | 2 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F13_T | 1 | T | false/nonce | false/nonce | true/valid | true | nonce-consumption order copied from record; crypto re-derived |
| F13_T | 2 | T | true/ | true/ | true/valid | true |  |
| F14_C+tls | 1 | C+tls | false/connect | false/connect | false/no card in trace | true | transport-stage failure: copied from record (not re-derivable offline) |
| F14_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| F14_C | 1 | C | true/ | true/ | true/valid | true |  |
| F14_P | 1 | P | true/ | true/ | true/valid | true |  |
| F14_S-env+cb | 1 | S-env+cb | false/connect | false/connect | false/no card in trace | true | transport-stage failure: copied from record (not re-derivable offline) |
| F14_S-env | 1 | S-env | true/ | true/ | true/valid | true |  |
| F14_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F14_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F14_T+cb | 1 | T+cb | false/connect | false/connect | false/no card in trace | true | transport-stage failure: copied from record (not re-derivable offline) |
| F14_T+tls | 1 | T+tls | false/connect | false/connect | false/no card in trace | true | transport-stage failure: copied from record (not re-derivable offline) |
| F14_T | 1 | T | true/ | true/ | true/valid | true |  |
| F15_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| F15_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| F15_C | 1 | C | true/ | true/ | true/valid | true |  |
| F15_P | 1 | P | true/ | true/ | true/valid | true |  |
| F15_S-env+cb | 1 | S-env+cb | false/envelope-metadata | false/envelope-metadata | true/valid | true |  |
| F15_S-env | 1 | S-env | true/ | true/ | true/valid | true |  |
| F15_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F15_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F15_T+cb | 1 | T+cb | false/nonce | false/nonce | true/valid | true |  |
| F15_T+tls | 1 | T+tls | true/ | true/ | true/valid | true |  |
| F15_T | 1 | T | true/ | true/ | true/valid | true |  |
| F16_S-env+cb | 1 | S-env+cb | false/envelope-metadata | false/envelope-metadata | true/valid | true |  |
| F16_T+cb | 1 | T+cb | false/nonce | false/nonce | true/valid | true |  |
| F16_T+tls | 1 | T+tls | true/ | true/ | true/valid | true |  |
| F17_C+tls | 1 | C+tls | false/connect | false/connect | false/no card in trace | true | transport-stage failure: copied from record (not re-derivable offline) |
| F17_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| F17_S-env+cb | 1 | S-env+cb | false/connect | false/connect | false/no card in trace | true | transport-stage failure: copied from record (not re-derivable offline) |
| F17_T+cb | 1 | T+cb | false/connect | false/connect | false/no card in trace | true | transport-stage failure: copied from record (not re-derivable offline) |
| F17_T+tls | 1 | T+tls | false/connect | false/connect | false/no card in trace | true | transport-stage failure: copied from record (not re-derivable offline) |
| F18_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| F18_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| F18_C | 1 | C | true/ | true/ | true/valid | true |  |
| F18_P | 1 | P | true/ | true/ | true/valid | true |  |
| F18_S-env+cb | 1 | S-env+cb | true/ | true/ | true/valid | true |  |
| F18_S-env | 1 | S-env | true/ | true/ | true/valid | true |  |
| F18_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F18_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F18_T+cb | 1 | T+cb | true/ | true/ | true/valid | true |  |
| F18_T+tls | 1 | T+tls | true/ | true/ | true/valid | true |  |
| F18_T | 1 | T | true/ | true/ | true/valid | true |  |
| F19_C+tls | 1 | C+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F19_C+url | 1 | C+url | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F19_C | 1 | C | true/ | true/ | true/valid | true |  |
| F19_P | 1 | P | false/config | false/config | true/valid | true |  |
| F19_S-env+cb | 1 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F19_S-env | 1 | S-env | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F19_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F19_S-iso | 1 | S-iso | false/signature | false/signature | true/valid | true |  |
| F19_T+cb | 1 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F19_T+tls | 1 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F19_T | 1 | T | false/config | false/config | true/valid | true |  |
| F1_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| F1_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| F1_C | 1 | C | true/ | true/ | true/valid | true |  |
| F1_P | 1 | P | true/ | true/ | true/valid | true |  |
| F1_S-env+cb | 1 | S-env+cb | true/ | true/ | true/valid | true |  |
| F1_S-env | 1 | S-env | true/ | true/ | true/valid | true |  |
| F1_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F1_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F1_T+cb | 1 | T+cb | true/ | true/ | true/valid | true |  |
| F1_T+tls | 1 | T+tls | true/ | true/ | true/valid | true |  |
| F1_T | 1 | T | true/ | true/ | true/valid | true |  |
| F20_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| F20_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| F20_C | 1 | C | true/ | true/ | true/valid | true |  |
| F20_P | 1 | P | true/ | true/ | true/valid | true |  |
| F20_S-env+cb | 1 | S-env+cb | true/ | true/ | true/valid | true |  |
| F20_S-env | 1 | S-env | true/ | true/ | true/valid | true |  |
| F20_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F20_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F20_T+cb | 1 | T+cb | true/ | true/ | true/valid | true |  |
| F20_T+tls | 1 | T+tls | true/ | true/ | true/valid | true |  |
| F20_T | 1 | T | true/ | true/ | true/valid | true |  |
| F21_C+tls | 1 | C+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F21_C+url | 1 | C+url | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F21_C | 1 | C | true/ | true/ | true/valid | true |  |
| F21_P | 1 | P | true/ | true/ | true/valid | true |  |
| F21_S-env+cb | 1 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F21_S-env | 1 | S-env | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F21_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F21_S-iso | 1 | S-iso | false/signature | false/signature | true/valid | true |  |
| F21_T+cb | 1 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F21_T+tls | 1 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F21_T | 1 | T | true/ | true/ | true/valid | true |  |
| F2_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| F2_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| F2_C | 1 | C | true/ | true/ | true/valid | true |  |
| F2_P | 1 | P | true/ | true/ | true/valid | true |  |
| F2_S-env+cb | 1 | S-env+cb | true/ | true/ | true/valid | true |  |
| F2_S-env | 1 | S-env | true/ | true/ | true/valid | true |  |
| F2_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F2_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F2_T+cb | 1 | T+cb | true/ | true/ | true/valid | true |  |
| F2_T+tls | 1 | T+tls | true/ | true/ | true/valid | true |  |
| F2_T | 1 | T | true/ | true/ | true/valid | true |  |
| F3_C+tls | 1 | C+tls | false/connect-tls | false/connect-tls | false/invalid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F3_C+url | 1 | C+url | false/card | false/card | false/invalid | true |  |
| F3_C | 1 | C | false/card | false/card | false/invalid | true |  |
| F3_P | 1 | P | false/card | false/card | false/invalid | true |  |
| F3_S-env+cb | 1 | S-env+cb | false/connect-tls | false/connect-tls | false/invalid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F3_S-env | 1 | S-env | false/card | false/card | false/invalid | true |  |
| F3_S-file | 1 | S-file | false/card | false/card | false/invalid | true |  |
| F3_S-iso | 1 | S-iso | false/card | false/card | false/invalid | true |  |
| F3_T+cb | 1 | T+cb | false/connect-tls | false/connect-tls | false/invalid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F3_T+tls | 1 | T+tls | false/connect-tls | false/connect-tls | false/invalid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F3_T | 1 | T | false/card | false/card | false/invalid | true |  |
| F4_C+tls | 1 | C+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F4_C+url | 1 | C+url | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F4_C | 1 | C | true/ | true/ | true/valid | true |  |
| F4_P | 1 | P | false/nonce | false/nonce | true/valid | true |  |
| F4_S-env+cb | 1 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F4_S-env | 1 | S-env | false/nonce | false/nonce | true/valid | true |  |
| F4_S-file | 1 | S-file | false/nonce | false/nonce | true/valid | true |  |
| F4_S-iso | 1 | S-iso | false/nonce | false/nonce | true/valid | true |  |
| F4_T+cb | 1 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F4_T+tls | 1 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F4_T | 1 | T | false/nonce | false/nonce | true/valid | true |  |
| F5_C+tls | 1 | C+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F5_C+url | 1 | C+url | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F5_C | 1 | C | true/ | true/ | true/valid | true |  |
| F5_P | 1 | P | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F5_S-env+cb | 1 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F5_S-env | 1 | S-env | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F5_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F5_S-iso | 1 | S-iso | false/signature | false/signature | true/valid | true |  |
| F5_T+cb | 1 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F5_T+tls | 1 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F5_T | 1 | T | false/trust-anchor | false/trust-anchor | true/valid | true |  |
| F6_C+tls | 1 | C+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F6_C+url | 1 | C+url | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F6_C | 1 | C | true/ | true/ | true/valid | true |  |
| F6_P | 1 | P | true/ | true/ | true/valid | true |  |
| F6_S-env+cb | 1 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F6_S-env | 1 | S-env | true/ | true/ | true/valid | true |  |
| F6_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F6_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F6_T+cb | 1 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F6_T+tls | 1 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F6_T | 1 | T | true/ | true/ | true/valid | true |  |
| F7_C+tls | 1 | C+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F7_C+url | 1 | C+url | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F7_C | 1 | C | true/ | true/ | true/valid | true |  |
| F7_P | 1 | P | true/ | true/ | true/valid | true |  |
| F7_S-env+cb | 1 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F7_S-env | 1 | S-env | true/ | true/ | true/valid | true |  |
| F7_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F7_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F7_T+cb | 1 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F7_T+tls | 1 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F7_T | 1 | T | true/ | true/ | true/valid | true |  |
| F8_C+tls | 1 | C+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F8_C+url | 1 | C+url | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F8_C | 1 | C | true/ | true/ | true/valid | true |  |
| F8_P | 1 | P | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F8_S-env+cb | 1 | S-env+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F8_S-env | 1 | S-env | false/envelope-signature | false/envelope-signature | true/valid | true |  |
| F8_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F8_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F8_T+cb | 1 | T+cb | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F8_T+tls | 1 | T+tls | false/connect-url | false/connect-url | true/valid | true | transport-stage failure: copied from record (not re-derivable offline) |
| F8_T | 1 | T | true/ | true/ | true/valid | true |  |
| F9_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| F9_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| F9_C | 1 | C | true/ | true/ | true/valid | true |  |
| F9_P | 1 | P | false/config | false/config | true/valid | true |  |
| F9_S-env+cb | 1 | S-env+cb | true/ | true/ | true/valid | true |  |
| F9_S-env | 1 | S-env | true/ | true/ | true/valid | true |  |
| F9_S-file | 1 | S-file | true/ | true/ | true/valid | true |  |
| F9_S-iso | 1 | S-iso | true/ | true/ | true/valid | true |  |
| F9_T+cb | 1 | T+cb | false/config | false/config | true/valid | true |  |
| F9_T+tls | 1 | T+tls | false/config | false/config | true/valid | true |  |
| F9_T | 1 | T | false/config | false/config | true/valid | true |  |
