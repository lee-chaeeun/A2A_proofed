# Declared v3-final predictions (2026-11-07 23:55 UTC, before the final rerun)

Machine-readable: `fixtures/manifest-v3-final.json` (version 4). The frozen
`manifest-v3.json` / `predictions-v3.md` are unchanged; this file declares the
expectations for the single rerun of the same 24 cells against the final snapshot,
with decision and recipient stated separately.

Fixture classes: V1 honest (positive control); V2, V3, V4 malicious (F15 capability
set: B holds A's TLS certificate and key, can reach A, no signer access, no proof key;
V3 adds the chosen-nonce rewrite with the binding field stripped; V4 adds the
weaker-mode forward). Policy classes: C+url = ablation (plain HTTP); C+tls, S-env+tls,
T+tls = secured transport baseline; S-env+cb, T+cb = defended.

| Fixture | C+url | C+tls | S-env+tls | S-env+cb | T+tls | T+cb |
|---|---|---|---|---|---|---|
| V1 honest | accept→A | accept→A | accept→A | accept→A | accept→A | accept→A |
| V2 stolen-TLS relay, untouched | accept→B | accept→B | accept→B | reject→none | accept→B | reject→none |
| V3 binding downgrade | accept→B | accept→B | reject→none\* | reject→none | reject→none\* | reject→none |
| V4 cross-policy oracle | accept→B | accept→B | reject→none\* | reject→none | reject→none\* | reject→none |

\* Not protection: the chosen-nonce rewrite is self-defeating under +tls because the
signer commits to the rewritten value the verifier does not expect. The attacker's
working attack against +tls is V2, which delivers to B. The earlier frozen
`predictions-v3.md` predicted `accept` for these four cells; that was a prediction
error about the attack script, recorded there in a dated addendum and not edited.

Expected counts: 24 cells; decision matches 24/24 and recipient matches 24/24 if the
final snapshot behaves like the retained fixed run; 6 honest cells → A; 0 deliveries
to B under S-env+cb and T+cb; 8 deliveries to B (V2/V3/V4 × C+url, C+tls, and V2 ×
S-env+tls, T+tls). Any divergence is reported as such.

Continuity and churn are declared in `V3_FINALIZATION_PLAN.md` §3 and are evidenced
by `internal/verifier/continuity_final_test.go`, not by this matrix.

## Change log
(empty at declaration)
