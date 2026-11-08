# Frozen v3 predictions (2026-11-07 20:30 CET)

See BASELINE_V3_PLAN.md for the threat model and claim boundaries. Machine-readable
expectations: fixtures/manifest-v3.json (these are the POST-FIX predictions).

Policies: C+url (ablation), C+tls, S-env+tls, S-env+cb, T+tls, T+cb.

| Fixture | C+url | C+tls | S-env+tls | S-env+cb | T+tls | T+cb |
|---|---|---|---|---|---|---|
| V1 honest | A | A | A | A | A | A |
| V2 F15 relay (stolen TLS) | A | A | A | R | A | R |
| V3 downgrade (binding stripped) | A | A | A | R | A | R |
| V4 cross-policy oracle | A | A | A | R | A | R |

A = job to that deployment, R = reject. V2–V4 use the F15 capability set (B holds
A's TLS key, can reach A, has no signer access, holds no proof key).

Pre-fix reproduction (results/v3-repro): V3 and V4 are expected to ACCEPT the +cb
cells and deliver the job to B on the v2 binding logic — that is the defect this
follow-up repairs. The +tls cells accept to B in all of V2/V3/V4 because stolen TLS
credentials defeat transport authentication (a stated capability escalation), so
+tls is not a channel-binding control.

Connection continuity (P0-B) is covered by internal/verifier/continuity_test.go,
not by this matrix: close-then-swap, split-connection, cert-swap and an honest
reconnect positive control.

## Change log
(empty at freeze)
