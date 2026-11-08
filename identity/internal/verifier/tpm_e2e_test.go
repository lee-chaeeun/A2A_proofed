package verifier

// [E2E/emulator] End-to-end tests against a real swtpm instance: the restricted AK
// lives inside the emulator and signs through TPM2_Quote and the TPM2_Hash ticket
// + TPM2_Sign path, exactly as the agents do. Skipped when swtpm is not installed.

import (
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm/tpm2"

	"a2aid/internal/cardsig"
	"a2aid/internal/ptv"
	"a2aid/internal/registry"
	"a2aid/internal/tpmsig"
	"a2aid/internal/wire"
)

type tpmKit struct {
	t    *testing.T
	sw   *tpmsig.SWTPM
	ak   *tpmsig.AKInfo
	auth []byte
	r    *Requester
	ref  []byte
}

func newTPMKit(t *testing.T) *tpmKit {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed")
	}
	dir := filepath.Join(t.TempDir(), "t")
	if len(dir) > 80 {
		t.Skip("temp dir too long for a unix socket")
	}
	sw, err := tpmsig.StartSWTPM(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sw.Stop)
	c, err := tpmsig.Open(sw.Sock)
	if err != nil {
		t.Fatal(err)
	}
	auth := []byte("e2e-ak-password")
	ak, err := c.Provision(auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ExtendPCR([]byte("deployment-A-config-v1")); err != nil {
		t.Fatal(err)
	}
	ref, _ := c.ReadPCR()
	c.Close()
	reg := &registry.Registry{Deployments: map[string]*registry.Deployment{"A": {DeploymentID: "dep-A", AttesterID: "dep-A", AKPublicPEM: ak.PublicPEM, AKName: ak.Name, AKQualified: ak.QualifiedName, PCRBank: "sha256", PCRIndex: 16, PCRReference: hex.EncodeToString(ref)}}}
	return &tpmKit{t: t, sw: sw, ak: ak, auth: auth, r: New(reg, nil, nil), ref: ref}
}

func (k *tpmKit) conn() *tpmsig.Conn {
	c, err := tpmsig.Open(k.sw.Sock)
	if err != nil {
		k.t.Fatal(err)
	}
	return c
}

func (k *tpmKit) signer(c *tpmsig.Conn) *tpmsig.COSESigner {
	return &tpmsig.COSESigner{Sock: k.sw.Sock, Handle: tpmsig.AKPersistentHandle, Auth: k.auth}
}

// envelope builds a P response whose payload map is free-form, signed by the real AK.
func (k *tpmKit) envelope(payload map[string]any, nonce string) map[string]any {
	b, err := cbor.Marshal(payload)
	if err != nil {
		k.t.Fatal(err)
	}
	sealed, err := ptv.Seal(b, "dep-A", k.signer(nil))
	if err != nil {
		k.t.Fatal(err)
	}
	return wire.ToMap(wire.Evidence{Type: "evidence", Policy: wire.PolicyP, DeploymentID: "dep-A", Nonce: nonce, COSESign1: wire.B64(sealed)})
}

func (k *tpmKit) eff(policy string, nb []byte) []byte { return wire.ProofContext(policy, nb, nil) }

func (k *tpmKit) realQuote(nb []byte) *tpmsig.QuoteResult {
	c := k.conn()
	defer c.Close()
	q, err := c.QuotePersistent(k.auth, nb)
	if err != nil {
		k.t.Fatal(err)
	}
	return q
}

func (k *tpmKit) base(nb []byte) map[string]any {
	return map[string]any{"ptv_version": "1.1", "msg_type": 2, "nonce": k.eff(wire.PolicyP, nb), "attester_id": "dep-A", "triage_band": 0, "timestamp": cbor.Tag{Number: 1, Content: time.Now().Unix()}}
}

func (k *tpmKit) evidence(q *tpmsig.QuoteResult) []byte {
	b, _ := (&ptv.TPMEvidence{Format: ptv.EvidenceFormat, Quoted: q.Quoted, Signature: q.Signature, Bank: "sha256", PCRs: map[int][]byte{16: q.PCRValue}}).Encode()
	return b
}

func (k *tpmKit) appraise(policy, n string, raw map[string]any) *Decision {
	d := &Decision{Card: cardsig.Verdict{Present: true, Valid: true}}
	k.r.Appraise(policy, n, "A", raw, d)
	return d
}

func TestE2E_TPM_PositiveControlAndMissingEvidence(t *testing.T) { // [E2E/emulator]
	k := newTPMKit(t)
	// positive control: real quote inside a real-AK-signed envelope
	n, _ := k.r.Issue("A", wire.PolicyP)
	nb, _ := wire.UnB64(n)
	p := k.base(nb)
	p["evidence"] = k.evidence(k.realQuote(k.eff(wire.PolicyP, nb)))
	d := k.appraise(wire.PolicyP, n, k.envelope(p, n))
	assertInvariant(t, d)
	if !d.Accept {
		t.Fatalf("E2E positive control rejected: %s %s", d.FailureStage, d.Reason)
	}
	// T positive control
	n, _ = k.r.Issue("A", wire.PolicyT)
	nb, _ = wire.UnB64(n)
	q := k.realQuote(k.eff(wire.PolicyT, nb))
	d = k.appraise(wire.PolicyT, n, wire.ToMap(wire.Evidence{Nonce: n, Quote: &wire.QuoteEvidence{Quoted: wire.B64(q.Quoted), Signature: wire.B64(q.Signature)}}))
	if !d.Accept {
		t.Fatalf("E2E T positive control rejected: %s", d.Reason)
	}
	// the strict-evidence variants, through the real restricted AK
	for _, variant := range []string{"absent", "empty", "null", "proof-only", "both"} {
		n, _ := k.r.Issue("A", wire.PolicyP)
		nb, _ := wire.UnB64(n)
		p := k.base(nb)
		switch variant {
		case "empty":
			p["evidence"] = []byte{}
		case "null":
			p["evidence"] = nil
		case "proof-only":
			p["proof"] = []byte("unverified")
		case "both":
			p["evidence"] = k.evidence(k.realQuote(k.eff(wire.PolicyP, nb)))
			p["proof"] = []byte("x")
		}
		d := k.appraise(wire.PolicyP, n, k.envelope(p, n))
		assertInvariant(t, d)
		if d.Accept {
			t.Fatalf("E2E %s accepted", variant)
		}
		if !d.Envelope.SignatureValid {
			t.Fatalf("E2E %s: real AK signature should verify", variant)
		}
		t.Logf("E2E %s -> %s %s", variant, d.FailureStage, d.Code)
	}
}

func TestE2E_TPM_ChangedPCR(t *testing.T) { // [E2E/emulator]
	k := newTPMKit(t)
	c := k.conn()
	if err := c.ExtendPCR([]byte("unexpected-config-drift")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	for _, pol := range []string{wire.PolicyT, wire.PolicyP} {
		n, _ := k.r.Issue("A", pol)
		nb, _ := wire.UnB64(n)
		q := k.realQuote(k.eff(pol, nb))
		var raw map[string]any
		if pol == wire.PolicyT {
			raw = wire.ToMap(wire.Evidence{Nonce: n, Quote: &wire.QuoteEvidence{Quoted: wire.B64(q.Quoted), Signature: wire.B64(q.Signature)}})
		} else {
			p := k.base(nb)
			p["evidence"] = k.evidence(q)
			raw = k.envelope(p, n)
		}
		d := k.appraise(pol, n, raw)
		assertInvariant(t, d)
		if d.Accept || d.Code != ptv.ErrConfig || !d.Quote.SignatureValid || d.Quote.PCRDigestMatch {
			t.Fatalf("%s changed PCR: accept=%v code=%s quote=%+v", pol, d.Accept, d.Code, d.Quote)
		}
	}
}

// TestE2E_TPM_TicketPathCannotForgeAttestation investigates the restricted-AK
// hash-ticket path: TPM2_Hash refuses to issue a validation ticket for data that
// begins with TPM_GENERATED, so TPM2_Sign with the restricted AK over a forged
// TPMS_ATTEST is refused by the TPM (TPM_RC_TICKET). Arbitrary bytes WITHOUT the
// magic can be signed (that is how the COSE envelope is signed) and the verifier
// rejects them structurally. This is a reproducer, not a forgery.
func TestE2E_TPM_TicketPathCannotForgeAttestation(t *testing.T) { // [E2E/emulator]
	k := newTPMKit(t)
	n, _ := k.r.Issue("A", wire.PolicyT)
	nb, _ := wire.UnB64(n)
	real := k.realQuote(nb)
	// forge: take a genuine TPMS_ATTEST and change the PCR digest, then try to get
	// the restricted AK to sign it through the ticket path.
	forged := append([]byte(nil), real.Quoted...)
	forged[len(forged)-1] ^= 0xff
	c := k.conn()
	defer c.Close()
	rp, err := tpm2.ReadPublic{ObjectHandle: tpmsig.AKPersistentHandle}.Execute(c.Transport())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SignWithTicket(tpmsig.AKPersistentHandle, rp.Name, k.auth, forged)
	if err == nil {
		t.Fatal("FORGERY: restricted AK signed a TPM_GENERATED-prefixed structure via the ticket path")
	}
	if !strings.Contains(err.Error(), "TPM_RC_TICKET") && !strings.Contains(err.Error(), "ticket") {
		t.Logf("refused with a different error (still refused): %v", err)
	}
	t.Logf("TPM refused the forged attestation: %v", err)
	// control: bytes without the magic ARE signable by the same key and ARE rejected by the verifier
	arbitrary := []byte("not-an-attestation-structure")
	sig, err := c.SignWithTicket(tpmsig.AKPersistentHandle, rp.Name, k.auth, arbitrary)
	if err != nil {
		t.Fatalf("control sign failed: %v", err)
	}
	ts := tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgECDSA, Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{Hash: tpm2.TPMAlgSHA256, SignatureR: tpm2.TPM2BECCParameter{Buffer: sig[:32]}, SignatureS: tpm2.TPM2BECCParameter{Buffer: sig[32:]}})}
	pub, _ := tpmsig.ParsePublicPEM(k.ak.PublicPEM)
	v := tpmsig.VerifyQuote(arbitrary, tpm2.Marshal(&ts), pub, k.ak.QualifiedName, nb, k.ref)
	if v.OK() || v.Parsed {
		t.Fatalf("arbitrary signed bytes parsed as a quote: %+v", v)
	}
	h := sha256.Sum256(arbitrary)
	_ = h
	// and the genuine quote still verifies (sanity)
	g := tpmsig.VerifyQuote(real.Quoted, real.Signature, pub, k.ak.QualifiedName, nb, k.ref)
	if !g.OK() {
		t.Fatalf("genuine quote failed: %+v", g)
	}
}

func TestE2E_TPM_WrongPasswordRefused(t *testing.T) { // [E2E/emulator]
	k := newTPMKit(t)
	c := k.conn()
	defer c.Close()
	if _, err := c.QuotePersistent([]byte("wrong"), wire.NewNonce()); err == nil {
		t.Fatal("quote with wrong AK password succeeded")
	}
}
