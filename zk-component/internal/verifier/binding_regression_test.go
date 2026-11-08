package verifier

// Binding regressions: a proof made under a weaker policy must not satisfy a
// stronger one, and a +cb proof must be bound to the verifier's own exporter.
// [UNIT/software-key]

import (
	"testing"

	"a2aid/internal/wire"
)

// cbKit extends the kit with an exporter so +cb paths can be exercised offline.
func (k *kit) validTCB(nonce string, nb, exporter []byte) map[string]any {
	eff := wire.ProofContext("T+cb", nb, exporter)
	q, s := k.quote(quoteOpts{nonce: eff})
	return wire.ToMap(wire.Evidence{Type: "evidence", Policy: "T+cb", DeploymentID: "dep-A", Nonce: nonce, Quote: &wire.QuoteEvidence{Quoted: wire.B64(q), Signature: wire.B64(s)}})
}

// appraiseCB appraises with a fixed verifier exporter (no live TLS needed).
func (k *kit) appraiseCB(policy, nonce string, exporter []byte, raw map[string]any) *Decision {
	d := k.decision()
	// +cb implies +url and +tls; supply those transport preconditions so the test
	// isolates the channel-binding logic.
	d.EndpointEqual = true
	d.TLS = &TLSVerdict{Used: true, Authenticated: true, NameMatch: true, PeerName: "a.a2aid.test"}
	d.CB = &CBVerdict{Requested: true, ExpectedHex: hexOf(exporter)}
	k.r.Appraise(policy, nonce, "A", raw, d)
	return d
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = h[c>>4], h[c&0xf]
	}
	return string(out)
}

func TestRegression_CrossPolicyOracleRejected(t *testing.T) {
	k := newKit(t)
	exporter := []byte("requester-B-exporter-32-bytes!!!")
	n, nb := k.issue("T+cb")
	// What a plain-T endpoint actually signs for an attacker-chosen nonce m: a quote
	// whose extraData is ProofContext("T", m, nil). To make this satisfy the T+cb
	// verifier (expecting ProofContext("T+cb", n, exporter)) the attacker would need
	// a cross-domain preimage, which SHA-256 domain separation prevents. We model the
	// best the attacker can do: pick m so the plain-T value happens to be presented.
	m := nb // the attacker can choose any plain-T nonce; none yields the +cb value
	q, s := k.quote(quoteOpts{nonce: wire.ProofContext(wire.PolicyT, m, nil)})
	plainT := wire.ToMap(wire.Evidence{Type: "evidence", Policy: wire.PolicyT, DeploymentID: "dep-A", Nonce: n, Quote: &wire.QuoteEvidence{Quoted: wire.B64(q), Signature: wire.B64(s)}})
	d := k.appraiseCB("T+cb", n, exporter, plainT)
	assertInvariant(t, d)
	if d.Accept {
		t.Fatal("cross-policy oracle: a plain-T quote was accepted under T+cb")
	}
	if d.Quote == nil || !d.Quote.SignatureValid {
		t.Fatalf("the quote signature should still be valid; rejection is the domain/nonce check: %+v", d.Quote)
	}
	// The same quote IS accepted as plain T (that is the oracle it provides), proving
	// it is cryptographically valid but domain-bound away from +cb.
	n2 := wire.B64(m)
	k.r.Store.Issue(n2, "A", Action, wire.PolicyT, DefaultAudience)
	d2 := k.appraise(wire.PolicyT, n2, wire.ToMap(wire.Evidence{Type: "evidence", Nonce: n2, Quote: &wire.QuoteEvidence{Quoted: wire.B64(q), Signature: wire.B64(s)}}))
	if !d2.Accept {
		t.Fatalf("the quote should verify in its own plain-T domain: %s", d2.Reason)
	}
}

func TestRegression_WrongExporterBindingRejected(t *testing.T) {
	k := newKit(t)
	good := []byte("the-verifiers-own-exporter-32by!")
	bad := []byte("a-different-connection-exporter!")
	n, nb := k.issue("T+cb")
	// Proof bound to a DIFFERENT exporter (the relay's connection), presented to a
	// verifier whose own exporter is `good`.
	d := k.appraiseCB("T+cb", n, good, k.validTCB(n, nb, bad))
	assertInvariant(t, d)
	if d.Accept {
		t.Fatal("a proof bound to another connection's exporter was accepted")
	}
	// Positive control: a fresh nonce, proof bound to the verifier's own exporter.
	n2, nb2 := k.issue("T+cb")
	d = k.appraiseCB("T+cb", n2, good, k.validTCB(n2, nb2, good))
	if !d.Accept {
		t.Fatalf("legitimate +cb proof rejected: %s %s", d.FailureStage, d.Reason)
	}
}

func TestRegression_DowngradeMissingBindingRejected(t *testing.T) {
	k := newKit(t)
	exporter := []byte("the-verifiers-own-exporter-32by!")
	n, nb := k.issue("T+cb")
	// Downgrade: a proof computed with NO exporter (binding stripped) but presented
	// under T+cb. The verifier mixes its own exporter, so the value cannot match.
	eff := wire.ProofContext("T+cb", nb, nil) // attacker omitted the exporter
	q, s := k.quote(quoteOpts{nonce: eff})
	raw := wire.ToMap(wire.Evidence{Type: "evidence", Policy: "T+cb", DeploymentID: "dep-A", Nonce: n, Quote: &wire.QuoteEvidence{Quoted: wire.B64(q), Signature: wire.B64(s)}})
	d := k.appraiseCB("T+cb", n, exporter, raw)
	assertInvariant(t, d)
	if d.Accept {
		t.Fatal("downgrade (binding omitted) accepted under T+cb")
	}
}
