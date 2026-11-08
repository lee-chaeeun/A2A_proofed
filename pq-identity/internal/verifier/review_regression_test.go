package verifier

// Rejecting regressions converted from the 7 Nov 2026 review audit
// (results/audit/<ts>/review_audit_test.go.orig is the retained characterization
// artifact; before the fix all three cases ACCEPTED). [UNIT/software-key]

import (
	"testing"

	"a2aid/internal/wire"
)

func TestRegression_ReviewAudit_MissingQuoteRejected(t *testing.T) {
	k := newKit(t)
	for _, variant := range []string{"proof-only", "empty-evidence", "null-evidence"} {
		t.Run(variant, func(t *testing.T) {
			n, nb := k.issue(wire.PolicyP)
			p := k.basePayload(nb)
			switch variant {
			case "proof-only":
				p["proof"] = []byte("unverified")
			case "empty-evidence":
				p["evidence"] = []byte{}
			case "null-evidence":
				p["evidence"] = nil
			}
			d := k.appraise(wire.PolicyP, n, k.pResponse(p, k.coseSigner(k.ak), n))
			assertInvariant(t, d)
			if d.Accept || d.Quote != nil && d.Quote.OK() {
				t.Fatalf("review audit case %s still accepted", variant)
			}
			if d.FailureStage != "schema" {
				t.Fatalf("%s: expected schema rejection, got %s (%s)", variant, d.FailureStage, d.Reason)
			}
		})
	}
}

func TestRegression_ReviewAudit_SessionBindingEnforced(t *testing.T) {
	k := newKit(t)
	nb := wire.NewNonce()
	n := wire.B64(nb)
	k.r.Store.Issue(n, "B", "different-action", wire.PolicyP, DefaultAudience)
	d := k.appraise(wire.PolicySFile, n, k.validS(wire.PolicySFile, n, nb, k.sfile))
	if d.Accept || d.FailureStage != "session" {
		t.Fatalf("session context still ignored: %+v", d)
	}
}

func TestRegression_ReviewAudit_UnknownPolicyRejected(t *testing.T) {
	k := newKit(t)
	nb := wire.NewNonce()
	n := wire.B64(nb)
	k.r.Store.Issue(n, "A", Action, "typo", DefaultAudience)
	d := k.appraise("typo", n, map[string]any{"nonce": n})
	if d.Accept || d.FailureStage != "policy" {
		t.Fatalf("unknown policy still accepted: %+v", d)
	}
}

// Found on 2026-11-07 by the deterministic mutation baseline (internal/discover):
// a routine envelope with triage_band ABSENT or NULL decoded to band 0 and was
// accepted. Required fields must be present with the correct CBOR type.
func TestRegression_Discovery_MissingTriageBandRejected(t *testing.T) {
	k := newKit(t)
	for _, variant := range []string{"absent", "null", "text"} {
		n, nb := k.issue(wire.PolicyP)
		q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
		p := k.basePayload(nb)
		p["evidence"] = k.evidenceBytes(q, s)
		switch variant {
		case "absent":
			delete(p, "triage_band")
		case "null":
			p["triage_band"] = nil
		case "text":
			p["triage_band"] = "0"
		}
		d := k.appraise(wire.PolicyP, n, k.pResponse(p, k.coseSigner(k.ak), n))
		assertInvariant(t, d)
		if d.Accept || d.FailureStage != "schema" {
			t.Fatalf("triage_band %s: accept=%v stage=%s", variant, d.Accept, d.FailureStage)
		}
	}
	for _, f := range []string{"ptv_version", "msg_type", "nonce", "attester_id", "timestamp"} {
		n, nb := k.issue(wire.PolicyP)
		q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
		p := k.basePayload(nb)
		p["evidence"] = k.evidenceBytes(q, s)
		delete(p, f)
		if d := k.appraise(wire.PolicyP, n, k.pResponse(p, k.coseSigner(k.ak), n)); d.Accept {
			t.Fatalf("missing %s accepted", f)
		}
	}
}
