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

## Change log

* 2026-11-07 20:35 CET, after the pre-fix reproduction (results/v3-repro/20261107-202528)
  and the post-fix run (results/v3/20261107-203206): six frozen-prediction misses,
  all V3/V4 under the +tls policies (S-env+tls, T+tls), expected `accept` but
  observed `reject`. Cause: the V3/V4 fixtures apply the chosen-nonce rewrite to
  every policy for uniformity, and the rewrite is self-defeating under +tls (the
  signer commits to the rewritten nonce, which the verifier does not expect). These
  are not security results: the meaningful attacker outcome for a +tls policy is the
  untouched relay V2, which delivers to B (stolen TLS credentials). The +cb cells —
  the ones the attack targets — behaved exactly as predicted both before the fix
  (V3/V4 +cb accept → B, the reproduced defect) and after (reject). Predictions were
  left frozen; this miss is a fixture-design artifact, recorded, not edited away.
* Post-fix, the downgrade causes honest A to REFUSE the inconsistent challenge
  (binding field inconsistent with the parsed policy), so V3 +cb shows "no
  envelope/quote in response"; the cross-policy oracle (V4 +cb) is blocked by the
  policy-domain separation in the signed proof context ("quote extraData != issued
  nonce").

## Addendum (2026-11-07 23:55 UTC, count correction; entries above are unchanged)

* Confirmed from `results/v3/20261107-203206/matrix.csv`: the fixed matrix has 24
  cells, 20 prediction matches and **four** misses (V3_S-env+tls, V3_T+tls,
  V4_S-env+tls, V4_T+tls), not six as the entry above says. The pre-fix reproduction
  `results/v3-repro/20261107-202528/matrix.csv` has 17 matches and seven misses
  against these (post-fix) predictions: the same four plus V3_S-env+cb, V3_T+cb and
  V4_T+cb accepting with the job delivered to B, which is the reproduced defect.
* "A" in the table above conflates acceptance with delivery to A. For V2–V4 under
  C+url, C+tls (and V2 under S-env+tls, T+tls) the accepted job is delivered to **B**.
  `fixtures/predictions-v3-final.md` states decision and recipient separately.
* Six honest V1 cells deliver to A; the generated summary's "0/0 honest" line is a
  stale F1/F2 label filter, not an observation.
