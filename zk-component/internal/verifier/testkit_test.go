package verifier

// Software-key test kit. These helpers build structurally valid TPMS_ATTEST /
// TPMT_SIGNATURE byte strings signed with an ordinary ECDSA key that the test
// registry enrolls as the "AK". They exercise the verifier's parsing and acceptance
// logic only; they say nothing about a TPM. End-to-end emulator tests live in
// tpm_e2e_test.go and are labelled as such.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm/tpm2"
	cose "github.com/veraison/go-cose"

	"a2aid/internal/cardsig"
	"a2aid/internal/ptv"
	"a2aid/internal/registry"
	"a2aid/internal/senv"
	"a2aid/internal/wire"
)

type kit struct {
	t      *testing.T
	r      *Requester
	ak     *ecdsa.PrivateKey // enrolled "AK" (software stand-in)
	sfile  *ecdsa.PrivateKey
	siso   *ecdsa.PrivateKey
	other  *ecdsa.PrivateKey // never enrolled
	card   *ecdsa.PrivateKey // enrolled publisher (card JWS) key
	qname  []byte
	pcrRef []byte
	clock  time.Time
}

func pemPub(k *ecdsa.PrivateKey) string {
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newKit(t *testing.T) *kit {
	t.Helper()
	k := &kit{t: t, ak: genKey(t), sfile: genKey(t), siso: genKey(t), other: genKey(t), card: genKey(t)}
	k.qname = make([]byte, 34)
	rand.Read(k.qname)
	k.pcrRef = make([]byte, 32)
	rand.Read(k.pcrRef)
	k.clock = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	reg := &registry.Registry{Deployments: map[string]*registry.Deployment{
		"A": {DeploymentID: "dep-A", AttesterID: "dep-A", CardKeyID: "A-card-k1", CardPublicPEM: pemPub(k.card), SFileKeyID: "A-sfile-k1", SFilePublicPEM: pemPub(k.sfile),
			SIsoKeyID: "A-siso-k1", SIsoPublicPEM: pemPub(k.siso), AKPublicPEM: pemPub(k.ak), AKQualified: hex.EncodeToString(k.qname),
			PCRBank: "sha256", PCRIndex: 16, PCRReference: hex.EncodeToString(k.pcrRef), TLSName: "a.a2aid.test"},
		"B": {DeploymentID: "dep-B", AttesterID: "dep-B", CardKeyID: "B-card-k1", SFileKeyID: "B-sfile-k1", SFilePublicPEM: pemPub(k.other),
			SIsoKeyID: "B-siso-k1", SIsoPublicPEM: pemPub(k.other), AKPublicPEM: pemPub(k.other), AKQualified: "00", PCRReference: hex.EncodeToString(k.pcrRef)},
	}}
	k.r = New(reg, nil, nil)
	k.r.Now = func() time.Time { return k.clock }
	k.r.Store.Now = k.r.Now
	return k
}

func (k *kit) issue(policy string) (string, []byte) {
	n, err := k.r.Issue("A", policy)
	if err != nil {
		k.t.Fatal(err)
	}
	nb, _ := wire.UnB64(n)
	return n, nb
}

func (k *kit) decision() *Decision {
	return &Decision{Card: cardsig.Verdict{Present: true, Valid: true}}
}

func (k *kit) appraise(policy, nonce string, raw map[string]any) *Decision {
	d := k.decision()
	k.r.Appraise(policy, nonce, "A", raw, d)
	return d
}

// quoteOpts tweaks the synthetic quote.
type quoteOpts struct {
	signer   *ecdsa.PrivateKey
	nonce    []byte
	pcr      []byte
	qname    []byte
	badMagic bool
	badType  bool
	sha1Sig  bool
	pcrSel   *tpm2.TPMLPCRSelection
}

func pcrSel16() tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(16)}}}
}

// quote builds (quoted, signature) bytes.
func (k *kit) quote(o quoteOpts) ([]byte, []byte) {
	if o.signer == nil {
		o.signer = k.ak
	}
	if o.pcr == nil {
		o.pcr = k.pcrRef
	}
	if o.qname == nil {
		o.qname = k.qname
	}
	sel := pcrSel16()
	if o.pcrSel != nil {
		sel = *o.pcrSel
	}
	dg := sha256.Sum256(o.pcr)
	att := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: o.qname},
		ExtraData:       tpm2.TPM2BData{Buffer: o.nonce},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 1000, ResetCount: 1, RestartCount: 0, Safe: true},
		FirmwareVersion: 0x20191023,
		Attested:        tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{PCRSelect: sel, PCRDigest: tpm2.TPM2BDigest{Buffer: dg[:]}}),
	}
	quoted := tpm2.Marshal(&att)
	if o.badMagic {
		quoted[0] = 0x00
	}
	if o.badType {
		quoted[4], quoted[5] = 0x80, 0x17 // TPM_ST_ATTEST_CERTIFY
	}
	h := sha256.Sum256(quoted)
	rr, ss, err := ecdsa.Sign(rand.Reader, o.signer, h[:])
	if err != nil {
		k.t.Fatal(err)
	}
	hashAlg := tpm2.TPMAlgSHA256
	if o.sha1Sig {
		hashAlg = tpm2.TPMAlgSHA1
	}
	ts := tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgECDSA, Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{Hash: hashAlg, SignatureR: tpm2.TPM2BECCParameter{Buffer: rr.Bytes()}, SignatureS: tpm2.TPM2BECCParameter{Buffer: ss.Bytes()}})}
	return quoted, tpm2.Marshal(&ts)
}

type swSigner struct{ s cose.Signer }

func (s swSigner) Algorithm() cose.Algorithm { return s.s.Algorithm() }
func (s swSigner) Sign(_ io.Reader, b []byte) ([]byte, error) {
	return s.s.Sign(rand.Reader, b)
}

func (k *kit) coseSigner(key *ecdsa.PrivateKey) cose.Signer {
	s, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		k.t.Fatal(err)
	}
	return swSigner{s}
}

// evidenceBytes encodes a routine-band evidence bstr from a quote.
func (k *kit) evidenceBytes(quoted, sig []byte) []byte {
	b, err := (&ptv.TPMEvidence{Format: ptv.EvidenceFormat, Quoted: quoted, Signature: sig, Bank: "sha256", PCRs: map[int][]byte{16: k.pcrRef}}).Encode()
	if err != nil {
		k.t.Fatal(err)
	}
	return b
}

// pResponse builds a P evidence map from a free-form payload map (so tests can
// omit, null or retype fields) signed by signer.
func (k *kit) pResponse(payload map[string]any, signer cose.Signer, nonce string) map[string]any {
	b, err := cbor.Marshal(payload)
	if err != nil {
		k.t.Fatal(err)
	}
	sealed, err := ptv.Seal(b, "dep-A", signer)
	if err != nil {
		k.t.Fatal(err)
	}
	return wire.ToMap(wire.Evidence{Type: "evidence", Policy: wire.PolicyP, DeploymentID: "dep-A", Nonce: nonce, COSESign1: wire.B64(sealed)})
}

// basePayload is a conforming routine PTV_PROVE_RESP map (without evidence).
// basePayload carries the domain-separated P proof value as the envelope nonce,
// matching what the real agent signs (finishTPM sets ProveResp.Nonce = eff).
func (k *kit) basePayload(nb []byte) map[string]any {
	return map[string]any{"ptv_version": "1.1", "msg_type": 2, "nonce": k.eff(wire.PolicyP, nb), "attester_id": "dep-A", "triage_band": 0, "timestamp": cbor.Tag{Number: 1, Content: k.clock.Unix()}}
}

// eff is the domain-separated proof value the verifier expects for a non-+cb policy
// (these software-key unit tests use no TLS, so the exporter is empty).
func (k *kit) eff(policy string, nb []byte) []byte { return wire.ProofContext(policy, nb, nil) }

func (k *kit) validP(nonce string, nb []byte) map[string]any {
	q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyP, nb)})
	p := k.basePayload(nb)
	p["evidence"] = k.evidenceBytes(q, s)
	return k.pResponse(p, k.coseSigner(k.ak), nonce)
}

func (k *kit) validT(nonce string, nb []byte) map[string]any {
	q, s := k.quote(quoteOpts{nonce: k.eff(wire.PolicyT, nb)})
	return wire.ToMap(wire.Evidence{Type: "evidence", Policy: wire.PolicyT, DeploymentID: "dep-A", Nonce: nonce, Quote: &wire.QuoteEvidence{Quoted: wire.B64(q), Signature: wire.B64(s)}})
}

func (k *kit) validS(policy, nonce string, nb []byte, key *ecdsa.PrivateKey) map[string]any {
	sig, _ := wire.SignBinding(key, wire.Binding(k.eff(policy, nb), "dep-A", Action))
	return wire.ToMap(wire.Evidence{Type: "evidence", Policy: policy, DeploymentID: "dep-A", Nonce: nonce, Sig: wire.B64(sig), SigKID: "A-sfile-k1"})
}

func (k *kit) validSEnv(nonce string, nb []byte, key *ecdsa.PrivateKey, mut func(*senv.Payload)) map[string]any {
	p := &senv.Payload{Version: senv.Version, AttesterID: "dep-A", Nonce: k.eff(wire.PolicySEnv, nb), Action: Action, Audience: DefaultAudience, Policy: wire.PolicySEnv, IssuedAt: k.clock, ExpiresAt: k.clock.Add(2 * time.Minute)}
	if mut != nil {
		mut(p)
	}
	b, err := senv.Encode(p)
	if err != nil {
		k.t.Fatal(err)
	}
	sealed, err := senv.Seal(b, "A-siso-k1", k.coseSigner(key))
	if err != nil {
		k.t.Fatal(err)
	}
	return wire.ToMap(wire.Evidence{Type: "evidence", Policy: wire.PolicySEnv, DeploymentID: "dep-A", Nonce: nonce, COSESign1: wire.B64(sealed)})
}

// assertInvariant is the acceptance invariant every test checks on every decision.
func assertInvariant(t *testing.T, d *Decision) {
	t.Helper()
	pol, err := wire.ParsePolicy(d.Policy)
	if d.Accept && err != nil {
		t.Fatalf("accepted an unparseable policy %q", d.Policy)
	}
	if d.Accept && (pol.Base == wire.PolicyT || pol.Base == wire.PolicyP) && (d.Quote == nil || !d.Quote.OK()) {
		t.Fatalf("INVARIANT: %s accepted without Quote.OK(): %+v", d.Policy, d.Quote)
	}
	if d.Accept && pol.Base == wire.PolicyP && (d.Envelope == nil || !d.Envelope.SchemaOK || !d.Envelope.SignatureValid) {
		t.Fatalf("INVARIANT: P accepted without a valid envelope")
	}
	if d.Accept && pol.HasProof() && d.NonceVerdict != "ok" {
		t.Fatalf("INVARIANT: accepted with nonce verdict %q", d.NonceVerdict)
	}
}

func big0() *big.Int { return new(big.Int) }
