Reviewer evidence of 8 Nov 2026 (REVIEW_PQ_IDENTITY.md): the transport characterization test (overlay
onto internal/zk/transport_test.go; PASS = the undesirable delivery after connection replacement reproduced
on the pre-correction source), and the audit summaries / CLI logs of the seven evidence mutations that the
pre-correction audit-pq accepted as clean (exit 0). The mutated run copies themselves are not distributed;
the mutations are reproduced by scripts/pq_audit_controls.py (R1-R7) and internal/pqaudit/pqaudit_test.go.
