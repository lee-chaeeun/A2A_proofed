package verifier

// Software-key unit tests of the repaired verifier. See testkit_test.go. Labels:
// [UNIT/software-key] = no emulator involved; the "AK" is an ordinary ECDSA key.

import (
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"a2aid/internal/ptv"
	"a2aid/internal/senv"
	"a2aid/internal/wire"
)

// --- Policy P -------------------------------------------------------------------

func TestP_PositiveControl(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	n, nb := k.issue(wire.PolicyP)
	d := k.appraise(wire.PolicyP, n, k.validP(n, nb))
	assertInvariant(t, d)
	if !d.Accept {
		t.Fatalf("positive control rejected: stage=%s reason=%s", d.FailureStage, d.Reason)
	}
	if d.Quote == nil || !d.Quote.OK() || !d.Envelope.SchemaOK {
		t.Fatalf("positive control without complete verdicts: %+v %+v", d.Quote, d.Envelope)
	}
}

func TestP_EvidenceVariantsRejected(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	q, s := k.quote(quoteOpts{nonce: nil}) // nonce patched per case below
	_ = q
	_ = s
	cases := map[string]func(p map[string]any, nb []byte){
		"absent":     func(p map[string]any, nb []byte) {},
		"empty":      func(p map[string]any, nb []byte) { p["evidence"] = []byte{} },
		"null":       func(p map[string]any, nb []byte) { p["evidence"] = nil },
		"proof-only": func(p map[string]any, nb []byte) { p["proof"] = []byte("unverified") },
		"both": func(p map[string]any, nb []byte) {
			q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
			p["evidence"] = k.evidenceBytes(q, s)
			p["proof"] = []byte("x")
		},
		"text-not-bstr":  func(p map[string]any, nb []byte) { p["evidence"] = "not bytes" },
		"malformed-cbor": func(p map[string]any, nb []byte) { p["evidence"] = []byte{0xff, 0x00, 0x01} },
		"unknown-format": func(p map[string]any, nb []byte) {
			b, _ := cbor.Marshal(map[string]any{"fmt": "eat", "quoted": []byte{1}})
			p["evidence"] = b
		},
		"garbage-quote": func(p map[string]any, nb []byte) {
			p["evidence"] = k.evidenceBytes([]byte("not an attest"), []byte("sig"))
		},
		"wrong-band": func(p map[string]any, nb []byte) {
			q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
			p["evidence"] = k.evidenceBytes(q, s)
			p["triage_band"] = 1
		},
		"wrong-version": func(p map[string]any, nb []byte) {
			q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
			p["evidence"] = k.evidenceBytes(q, s)
			p["ptv_version"] = "1.0"
		},
		"wrong-msg-type": func(p map[string]any, nb []byte) {
			q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
			p["evidence"] = k.evidenceBytes(q, s)
			p["msg_type"] = 1
		},
		"stale-timestamp": func(p map[string]any, nb []byte) {
			q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
			p["evidence"] = k.evidenceBytes(q, s)
			p["timestamp"] = cbor.Tag{Number: 1, Content: k.clock.Add(-10 * time.Minute).Unix()}
		},
		"wrong-attester": func(p map[string]any, nb []byte) {
			q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
			p["evidence"] = k.evidenceBytes(q, s)
			p["attester_id"] = "dep-B"
		},
		"envelope-nonce": func(p map[string]any, nb []byte) {
			q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
			p["evidence"] = k.evidenceBytes(q, s)
			p["nonce"] = wire.NewNonce()
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			n, nb := k.issue(wire.PolicyP)
			p := k.basePayload(nb)
			mut(p, nb)
			d := k.appraise(wire.PolicyP, n, k.pResponse(p, k.coseSigner(k.ak), n))
			assertInvariant(t, d)
			if d.Accept {
				t.Fatalf("%s: accepted (stage=%s)", name, d.FailureStage)
			}
			if d.Envelope == nil || !d.Envelope.SignatureValid {
				t.Fatalf("%s: outer signature should verify (it was signed by the enrolled key); the rejection must come from content", name)
			}
			t.Logf("%s -> stage=%s code=%s reason=%s", name, d.FailureStage, d.Code, d.Reason)
		})
	}
}

func TestP_QuoteNegatives(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	other := k.other
	cases := map[string]func(nb []byte) quoteOpts{
		"quote-signed-by-unenrolled-key": func(nb []byte) quoteOpts { return quoteOpts{nonce: nb, signer: other} },
		"quote-wrong-nonce":              func(nb []byte) quoteOpts { return quoteOpts{nonce: wire.NewNonce()} },
		"pcr-changed":                    func(nb []byte) quoteOpts { return quoteOpts{nonce: nb, pcr: []byte(strings.Repeat("z", 32))} },
		"qualified-signer-mismatch":      func(nb []byte) quoteOpts { return quoteOpts{nonce: nb, qname: []byte("other-name")} },
		"bad-magic":                      func(nb []byte) quoteOpts { return quoteOpts{nonce: nb, badMagic: true} },
		"wrong-attest-type":              func(nb []byte) quoteOpts { return quoteOpts{nonce: nb, badType: true} },
		"sha1-signature-scheme":          func(nb []byte) quoteOpts { return quoteOpts{nonce: nb, sha1Sig: true} },
		"pcr-selection-pcr0": func(nb []byte) quoteOpts {
			sel := pcrSel16()
			sel.PCRSelections[0].PCRSelect = []byte{0x01, 0x00, 0x00}
			return quoteOpts{nonce: nb, pcrSel: &sel}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			n, nb := k.issue(wire.PolicyP)
			q, s := k.quote(mk(k.eff(wire.PolicyP, nb)))
			p := k.basePayload(nb)
			p["evidence"] = k.evidenceBytes(q, s)
			d := k.appraise(wire.PolicyP, n, k.pResponse(p, k.coseSigner(k.ak), n))
			assertInvariant(t, d)
			if d.Accept {
				t.Fatalf("%s accepted", name)
			}
			// and under T directly
			n2, nb2 := k.issue(wire.PolicyT)
			q2, s2 := k.quote(mk(k.eff(wire.PolicyT, nb2)))
			d2 := k.appraise(wire.PolicyT, n2, wire.ToMap(wire.Evidence{Type: "evidence", Policy: wire.PolicyT, DeploymentID: "dep-A", Nonce: n2, Quote: &wire.QuoteEvidence{Quoted: wire.B64(q2), Signature: wire.B64(s2)}}))
			assertInvariant(t, d2)
			if d2.Accept {
				t.Fatalf("T %s accepted", name)
			}
			t.Logf("%s -> P %s / T %s (%s)", name, d.FailureStage, d2.FailureStage, d2.Reason)
		})
	}
}

func TestP_EnvelopeSignedByUnenrolledKey(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	n, nb := k.issue(wire.PolicyP)
	q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
	p := k.basePayload(nb)
	p["evidence"] = k.evidenceBytes(q, s)
	d := k.appraise(wire.PolicyP, n, k.pResponse(p, k.coseSigner(k.other), n))
	assertInvariant(t, d)
	if d.Accept || d.Envelope.SignatureValid {
		t.Fatalf("envelope by unenrolled key accepted: %+v", d.Envelope)
	}
	if d.Quote == nil || !d.Quote.OK() {
		t.Fatalf("inner quote should still verify independently (coverage separation): %+v", d.Quote)
	}
	if d.Code != ptv.ErrSignature {
		t.Fatalf("code %s", d.Code)
	}
}

func TestT_PositiveAndMissingQuote(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	n, nb := k.issue(wire.PolicyT)
	d := k.appraise(wire.PolicyT, n, k.validT(n, nb))
	assertInvariant(t, d)
	if !d.Accept {
		t.Fatalf("T positive rejected: %s", d.Reason)
	}
	n2, _ := k.issue(wire.PolicyT)
	d2 := k.appraise(wire.PolicyT, n2, wire.ToMap(wire.Evidence{Type: "evidence", Nonce: n2}))
	if d2.Accept || d2.FailureStage != "quote" {
		t.Fatalf("missing quote: %+v", d2)
	}
}

// --- S policies -------------------------------------------------------------------

func TestS_PositiveAndNegatives(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	n, nb := k.issue(wire.PolicySFile)
	d := k.appraise(wire.PolicySFile, n, k.validS(wire.PolicySFile, n, nb, k.sfile))
	assertInvariant(t, d)
	if !d.Accept {
		t.Fatalf("S-file positive rejected: %s", d.Reason)
	}
	n, nb = k.issue(wire.PolicySIso)
	d = k.appraise(wire.PolicySIso, n, k.validS(wire.PolicySIso, n, nb, k.siso))
	if !d.Accept {
		t.Fatalf("S-iso positive rejected: %s", d.Reason)
	}
	// wrong key per policy
	n, nb = k.issue(wire.PolicySIso)
	d = k.appraise(wire.PolicySIso, n, k.validS(wire.PolicySIso, n, nb, k.sfile))
	if d.Accept {
		t.Fatal("S-iso accepted an S-file signature")
	}
	// unenrolled key, garbage, empty
	for name, raw := range map[string]map[string]any{
		"unenrolled": k.validS(wire.PolicySFile, "", nb, k.other),
		"garbage":    wire.ToMap(wire.Evidence{Sig: wire.B64([]byte("junk"))}),
		"empty":      {},
		"nil":        nil,
	} {
		n, _ := k.issue(wire.PolicySFile)
		if raw != nil {
			raw["nonce"] = n
		}
		d := k.appraise(wire.PolicySFile, n, raw)
		assertInvariant(t, d)
		if d.Accept {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestSEnv_PositiveAndNegatives(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	n, nb := k.issue(wire.PolicySEnv)
	d := k.appraise(wire.PolicySEnv, n, k.validSEnv(n, nb, k.siso, nil))
	assertInvariant(t, d)
	if !d.Accept {
		t.Fatalf("S-env positive rejected: %s", d.Reason)
	}
	cases := map[string]struct {
		key func() interface{}
		mut func(*senv.Payload)
	}{
		"wrong-audience": {mut: func(p *senv.Payload) { p.Audience = "someone-else" }},
		"wrong-action":   {mut: func(p *senv.Payload) { p.Action = "transfer-funds" }},
		"wrong-attester": {mut: func(p *senv.Payload) { p.AttesterID = "dep-B" }},
		"wrong-policy":   {mut: func(p *senv.Payload) { p.Policy = wire.PolicySIso }},
		"expired": {mut: func(p *senv.Payload) {
			p.ExpiresAt = k.clock.Add(-2 * time.Minute)
			p.IssuedAt = k.clock.Add(-5 * time.Minute)
		}},
		"future-iat":  {mut: func(p *senv.Payload) { p.IssuedAt = k.clock.Add(10 * time.Minute) }},
		"wrong-nonce": {mut: func(p *senv.Payload) { p.Nonce = wire.NewNonce() }},
	}
	for name, c := range cases {
		n, nb := k.issue(wire.PolicySEnv)
		d := k.appraise(wire.PolicySEnv, n, k.validSEnv(n, nb, k.siso, c.mut))
		assertInvariant(t, d)
		if d.Accept {
			t.Fatalf("%s accepted", name)
		}
		if !d.SEnv.SignatureValid {
			t.Fatalf("%s: signature must verify; rejection must come from metadata", name)
		}
	}
	// S-file key must not satisfy S-env; tampered timestamp must break the signature
	n, nb = k.issue(wire.PolicySEnv)
	if d := k.appraise(wire.PolicySEnv, n, k.validSEnv(n, nb, k.sfile, nil)); d.Accept {
		t.Fatal("S-env accepted the exportable S-file key")
	}
	n, nb = k.issue(wire.PolicySEnv)
	raw := k.validSEnv(n, nb, k.siso, nil)
	b, _ := wire.UnB64(raw["cose_sign1"].(string))
	nb2, _, err := senv.RewriteTimestamp(b, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw["cose_sign1"] = wire.B64(nb2)
	d = k.appraise(wire.PolicySEnv, n, raw)
	if d.Accept || d.SEnv.SignatureValid {
		t.Fatalf("tampered S-env timestamp accepted: %+v", d.SEnv)
	}
}

// --- Session, nonce, policy, enrollment -----------------------------------------------

func TestSession_ContextMismatchRejected(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	type tc struct {
		issueExpected, issuePolicy, issueAction, issueAudience string
		appraisePolicy                                         string
	}
	cases := map[string]tc{
		"expected-identity": {"B", wire.PolicySFile, Action, DefaultAudience, wire.PolicySFile},
		"policy":            {"A", wire.PolicyP, Action, DefaultAudience, wire.PolicySFile},
		"action":            {"A", wire.PolicySFile, "different-action", DefaultAudience, wire.PolicySFile},
		"audience":          {"A", wire.PolicySFile, Action, "other-requester", wire.PolicySFile},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			nb := wire.NewNonce()
			n := wire.B64(nb)
			k.r.Store.Issue(n, c.issueExpected, c.issueAction, c.issuePolicy, c.issueAudience)
			d := k.appraise(c.appraisePolicy, n, k.validS(c.appraisePolicy, n, nb, k.sfile))
			assertInvariant(t, d)
			if d.Accept {
				t.Fatalf("%s mismatch accepted", name)
			}
			if d.FailureStage != "session" {
				t.Fatalf("%s: stage %s (%s)", name, d.FailureStage, d.Reason)
			}
			if d.SigVerdict != "ok" {
				t.Fatalf("%s: the crypto was valid; rejection must be the session check", name)
			}
		})
	}
}

func TestSession_ExpiryBoundary(t *testing.T) { // [UNIT/software-key], injected clock
	k := newKit(t)
	t0 := k.clock
	ttl := k.r.Store.TTL
	// one nanosecond before expiry: valid
	n, nb := k.issue(wire.PolicySFile)
	k.clock = t0.Add(ttl - time.Nanosecond)
	d := k.appraise(wire.PolicySFile, n, k.validS(wire.PolicySFile, n, nb, k.sfile))
	if !d.Accept {
		t.Fatalf("valid just before expiry rejected: %s", d.Reason)
	}
	// exactly at expiry: expired (valid iff now < expires_at)
	k.clock = t0
	n, nb = k.issue(wire.PolicySFile)
	k.clock = t0.Add(ttl)
	d = k.appraise(wire.PolicySFile, n, k.validS(wire.PolicySFile, n, nb, k.sfile))
	assertInvariant(t, d)
	if d.Accept || d.NonceVerdict != "expired" || d.Code != ptv.ErrExpired {
		t.Fatalf("at-expiry not rejected as expired: %+v", d)
	}
	// an expired nonce is consumed too: a second attempt reports consumed
	d = k.appraise(wire.PolicySFile, n, k.validS(wire.PolicySFile, n, nb, k.sfile))
	if d.NonceVerdict != "consumed" {
		t.Fatalf("expired nonce not consumed: %s", d.NonceVerdict)
	}
	// well after expiry
	k.clock = t0
	n, nb = k.issue(wire.PolicySFile)
	k.clock = t0.Add(time.Hour)
	if d := k.appraise(wire.PolicySFile, n, k.validS(wire.PolicySFile, n, nb, k.sfile)); d.Accept {
		t.Fatal("hour-old nonce accepted")
	}
}

func TestNonce_ConsumeOnFailureThenValid(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	n, nb := k.issue(wire.PolicyT)
	d1 := k.appraise(wire.PolicyT, n, wire.ToMap(wire.Evidence{Nonce: n, Quote: &wire.QuoteEvidence{Quoted: wire.B64([]byte("x")), Signature: wire.B64([]byte("y"))}}))
	d2 := k.appraise(wire.PolicyT, n, k.validT(n, nb))
	if d1.Accept || d2.Accept || d2.NonceVerdict != "consumed" || d2.Code != ptv.ErrNonce {
		t.Fatalf("consume-on-failure broken: %v %v %s", d1.Accept, d2.Accept, d2.NonceVerdict)
	}
	if d2.Quote == nil || !d2.Quote.OK() {
		t.Fatal("record must still show the second quote verified cryptographically")
	}
}

func TestNonce_UnknownAndReplayedProof(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	// unknown nonce
	nb := wire.NewNonce()
	n := wire.B64(nb)
	d := k.appraise(wire.PolicySFile, n, k.validS(wire.PolicySFile, n, nb, k.sfile))
	if d.Accept || d.NonceVerdict != "unknown" {
		t.Fatalf("unknown nonce: %+v", d)
	}
	// replayed proof for an older nonce presented against a fresh one
	nOld, nbOld := k.issue(wire.PolicySFile)
	old := k.validS(wire.PolicySFile, nOld, nbOld, k.sfile)
	nNew, _ := k.issue(wire.PolicySFile)
	d = k.appraise(wire.PolicySFile, nNew, old)
	if d.Accept || d.NonceVerdict != "mismatch" {
		t.Fatalf("replay: %+v", d)
	}
}

func TestUnknownPolicyRejectedEverywhere(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	for _, p := range []string{"typo", "", "T+", "T+foo", "c", "P+tls+zk", "S-file+url+"} {
		if _, err := k.r.Issue("A", p); err == nil {
			t.Fatalf("Issue accepted policy %q", p)
		}
		nb := wire.NewNonce()
		n := wire.B64(nb)
		k.r.Store.Issue(n, "A", Action, p, DefaultAudience)
		d := k.appraise(p, n, map[string]any{"nonce": n})
		if d.Accept || d.FailureStage != "policy" {
			t.Fatalf("Appraise did not reject policy %q: %+v", p, d)
		}
		d2 := &Decision{Policy: p}
		if _, err := k.r.Connect(t.Context(), "http://127.0.0.1:1", "A", d2); err == nil || d2.FailureStage != "policy" {
			t.Fatalf("Connect accepted policy %q", p)
		}
		if d3, err := k.r.Run(t.Context(), p, "http://127.0.0.1:1", "A", nil); err == nil || d3.Accept {
			t.Fatalf("Run accepted policy %q", p)
		}
	}
	// the closed vocabulary parses
	for _, p := range []string{"C", "S-file", "S-iso", "S-env", "T", "P", "C+url", "C+tls", "T+tls", "T+cb", "S-env+cb", "P+url"} {
		if _, err := wire.ParsePolicy(p); err != nil {
			t.Fatalf("%q: %v", p, err)
		}
	}
}

func TestMissingEnrollmentAndGarbage(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	nb := wire.NewNonce()
	n := wire.B64(nb)
	k.r.Store.Issue(n, "Z", Action, wire.PolicyP, DefaultAudience)
	d := &Decision{}
	k.r.Appraise(wire.PolicyP, n, "Z", k.validP(n, nb), d)
	if d.Accept || d.FailureStage != "enrollment" {
		t.Fatalf("missing enrollment: %+v", d)
	}
	// decode failures and wrong types must not panic or accept
	for name, raw := range map[string]map[string]any{
		"nonce-number":    {"nonce": 5, "quote": "x"},
		"quote-string":    {"quote": "x"},
		"cose-number":     {"cose_sign1": 12},
		"cose-not-b64":    {"cose_sign1": "!!!"},
		"cose-random":     {"cose_sign1": wire.B64([]byte{0xd2, 0x84, 0xff})},
		"sig-not-b64":     {"sig": "%%%"},
		"nested-nonsense": {"quote": map[string]any{"quoted": []any{1, 2}, "signature": true}},
	} {
		for _, p := range []string{wire.PolicySFile, wire.PolicySEnv, wire.PolicyT, wire.PolicyP} {
			n, _ := k.issue(p)
			raw["nonce"] = raw["nonce"]
			d := k.appraise(p, n, raw)
			assertInvariant(t, d)
			if d.Accept {
				t.Fatalf("%s/%s accepted garbage", p, name)
			}
			if d.FailureStage == "internal" {
				t.Fatalf("%s/%s: panic path hit: %s", p, name, d.Reason)
			}
		}
	}
	// policy C with missing card
	d = &Decision{}
	k.r.Appraise(wire.PolicyC, "", "A", nil, d)
	if d.Accept {
		t.Fatal("C accepted with an invalid card")
	}
}

func TestOfflineReappraiseAgrees(t *testing.T) { // [UNIT/software-key]
	k := newKit(t)
	n, nb := k.issue(wire.PolicyP)
	d := k.appraise(wire.PolicyP, n, k.validP(n, nb))
	if !d.Accept {
		t.Fatal(d.Reason)
	}
	sess, _ := k.r.Store.Get(n)
	r2 := New(k.r.Reg, nil, nil)
	d2 := r2.Reappraise(d, sess)
	if d2.Accept != d.Accept || d2.FailureStage != d.FailureStage {
		t.Fatalf("offline disagreement: %+v vs %+v", d2, d)
	}
	// and a rejection reproduces
	n, nb = k.issue(wire.PolicyP)
	p := k.basePayload(nb)
	p["proof"] = []byte("x")
	d = k.appraise(wire.PolicyP, n, k.pResponse(p, k.coseSigner(k.ak), n))
	sess, _ = k.r.Store.Get(n)
	d2 = New(k.r.Reg, nil, nil).Reappraise(d, sess)
	if d2.Accept || d2.FailureStage != d.FailureStage || d2.Code != d.Code {
		t.Fatalf("offline disagreement on rejection: %s/%s vs %s/%s", d2.FailureStage, d2.Code, d.FailureStage, d.Code)
	}
}

func TestNormalizeURL(t *testing.T) {
	ok := map[string]string{
		"http://A.a2aid.test:80/":    "http://a.a2aid.test",
		"HTTPS://a.a2aid.test:443":   "https://a.a2aid.test",
		"https://a.a2aid.test:9443/": "https://a.a2aid.test:9443",
		"http://127.0.0.1:9101":      "http://127.0.0.1:9101",
		"http://x/path/":             "http://x/path",
	}
	for in, want := range ok {
		got, err := wire.NormalizeURL(in)
		if err != nil || got != want {
			t.Fatalf("%s -> %s %v (want %s)", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://x", "//x", "http://u:p@x", "http://x/?q=1", "http://x/#f", "x.test", "http://"} {
		if _, err := wire.NormalizeURL(bad); err == nil {
			t.Fatalf("%q normalised", bad)
		}
	}
	// different ports and schemes are different endpoints
	a, _ := wire.NormalizeURL("http://a.a2aid.test:9101")
	b, _ := wire.NormalizeURL("http://a.a2aid.test:9102")
	c, _ := wire.NormalizeURL("https://a.a2aid.test:9101")
	if a == b || a == c {
		t.Fatal("port/scheme collapsed")
	}
}
