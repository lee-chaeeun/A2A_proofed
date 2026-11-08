# Corrected-matrix attempt 1 (results/pq/20261108-152809): retained, superseded

Run by the gated runner (`scripts/pq_matrix.sh`, binary `8d047e2e…`, source snapshot
`results/audit/20261108T142748Z-pqcorr-snapshot`). The matrix itself matched all 128
frozen predictions (`summary.md`), but the composite audit (`audit-pq` v2) exited 1 with
24 structural violations and the runner stopped at that gate, as designed.

Causes (all in producer/checker consistency for the new schema-2 paths, none in the
decisions or recipients):

1. `Connect` emitted `connect_failed` only when the card fetch failed; a rejection at
   the endpoint-equality or TLS-name stage (P2 replay cells, the B leg of the P11
   concurrent cells) left the record with `connect, card_fetched` and no terminal event
   (`appraised/no-terminal`). Fixed: `connect_failed` is emitted for those stages too.
2. The checker's typed-context equality required a non-empty session key for every
   decision; an early rejection (P7, connect failure before any challenge) legitimately
   has none. Fixed in checker 2.1: the session key is required once a nonce was issued
   or a release happened.
3. The concurrent-delivery driver issued a nonce and sent a challenge even for the
   card-only `C+tls` arm, so the authorization context carried the synthetic release key
   while the decision context carried the nonce. Fixed: card-only legs are appraised and
   released without a nonce, as in `Run`.

Re-audit of this attempt with the corrected checker (`…pqcorr-snapshot/attempt-1-recheck/`):
16 violations remain (P2 and P11: producer side, items 1 and 3), confirming that the
rerun is needed. Nothing in this directory was modified after the run except this note.
