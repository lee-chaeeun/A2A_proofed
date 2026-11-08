# Offline reverification of /home/bitchae/aisafety/swarmalign/a2a-identity/results/v3-final/20261108-000017

24 / 24 appraisals agree with the recorded decision (accept, failure stage, PTV code, card verdict).

Agreement is not one aggregate verification score. By how each verdict was established:

* independently recomputed cryptographic primitives (card JWS, signatures, quotes, envelopes, bound nonces): 24
* shared-code reappraisal that reused the production appraisal path: included in the recomputed count above (so these are consistency, not independence)
* copied transport/exchange-stage facts (not re-derivable offline): 0
* copied nonce-consumption order: 0

Copied facts are reported, never summed into an independent-verification claim.

Re-derived offline: card JWS (from the fetched card in the requester trace), nonce-session context and expiry (from the stored session with the clock fixed at the recorded appraisal time), S signatures, S-env envelope, TPM quote structure/signature/PCR digest, PTV envelope signature/schema/freshness, channel-bound nonce (from the requester's stored exporter value). Copied from the record, not re-derivable: TLS peer identity, endpoint equality, controller events.

| Cell | # | policy | recorded | offline | card | agree | note |
|---|---|---|---|---|---|---|---|
| V1_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| V1_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| V1_S-env+cb | 1 | S-env+cb | true/ | true/ | true/valid | true |  |
| V1_S-env+tls | 1 | S-env+tls | true/ | true/ | true/valid | true |  |
| V1_T+cb | 1 | T+cb | true/ | true/ | true/valid | true |  |
| V1_T+tls | 1 | T+tls | true/ | true/ | true/valid | true |  |
| V2_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| V2_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| V2_S-env+cb | 1 | S-env+cb | false/envelope-metadata | false/envelope-metadata | true/valid | true |  |
| V2_S-env+tls | 1 | S-env+tls | true/ | true/ | true/valid | true |  |
| V2_T+cb | 1 | T+cb | false/nonce | false/nonce | true/valid | true |  |
| V2_T+tls | 1 | T+tls | true/ | true/ | true/valid | true |  |
| V3_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| V3_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| V3_S-env+cb | 1 | S-env+cb | false/envelope | false/envelope | true/valid | true |  |
| V3_S-env+tls | 1 | S-env+tls | false/envelope-metadata | false/envelope-metadata | true/valid | true |  |
| V3_T+cb | 1 | T+cb | false/quote | false/quote | true/valid | true |  |
| V3_T+tls | 1 | T+tls | false/nonce | false/nonce | true/valid | true |  |
| V4_C+tls | 1 | C+tls | true/ | true/ | true/valid | true |  |
| V4_C+url | 1 | C+url | true/ | true/ | true/valid | true |  |
| V4_S-env+cb | 1 | S-env+cb | false/envelope-metadata | false/envelope-metadata | true/valid | true |  |
| V4_S-env+tls | 1 | S-env+tls | false/envelope-metadata | false/envelope-metadata | true/valid | true |  |
| V4_T+cb | 1 | T+cb | false/nonce | false/nonce | true/valid | true |  |
| V4_T+tls | 1 | T+tls | false/nonce | false/nonce | true/valid | true |  |
