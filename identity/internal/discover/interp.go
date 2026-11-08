package discover

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm/tpm2"
	cose "github.com/veraison/go-cose"

	"a2aid/internal/cardsig"
	"a2aid/internal/ptv"
	"a2aid/internal/registry"
	"a2aid/internal/verifier"
	"a2aid/internal/wire"
)

// Lab is the local protocol runner: an enrolled software stand-in AK (unit-level,
// no emulator), a verifier, and the interpreter that applies plans. Keys never
// leave the process; nothing here talks to the network.
type Lab struct {
	ak, other *ecdsa.PrivateKey
	qname     []byte
	pcrRef    []byte
	reg       *registry.Registry
	clock     time.Time
	Caps      Capabilities
}

func pemPub(k *ecdsa.PrivateKey) string {
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func NewLab(caps Capabilities) *Lab {
	ak, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	l := &Lab{ak: ak, other: other, qname: make([]byte, 34), pcrRef: make([]byte, 32), clock: time.Now().UTC(), Caps: caps}
	rand.Read(l.qname)
	rand.Read(l.pcrRef)
	l.reg = &registry.Registry{Deployments: map[string]*registry.Deployment{
		"A": {DeploymentID: "dep-A", AttesterID: "dep-A", AKPublicPEM: pemPub(ak), AKQualified: hex.EncodeToString(l.qname), PCRReference: hex.EncodeToString(l.pcrRef)},
		"B": {DeploymentID: "dep-B", AttesterID: "dep-B", AKPublicPEM: pemPub(other), AKQualified: "00", PCRReference: hex.EncodeToString(l.pcrRef)},
	}}
	return l
}

type swSigner struct{ s cose.Signer }

func (s swSigner) Algorithm() cose.Algorithm { return s.s.Algorithm() }
func (s swSigner) Sign(_ io.Reader, b []byte) ([]byte, error) {
	return s.s.Sign(rand.Reader, b)
}

// state is the mutable response under construction.
type state struct {
	payload     map[string]any
	quoteSigner *ecdsa.PrivateKey
	quoteNonce  []byte
	quotePCR    []byte
	badMagic    bool
	certify     bool
	sha1        bool
	evFormat    string
	truncateEv  int
	flips       []Mutation
	envSigner   *ecdsa.PrivateKey
	untag       bool
	alg         string
	dropEv      bool
	tsShift     int // seconds; |shift| <= 300 is an acceptable variation under the draft's window
}

// Outcome of executing one plan.
type Outcome struct {
	PlanID     string `json:"plan_id"`
	Canonical  string `json:"canonical"`
	Valid      bool   `json:"valid_plan"`
	Invalid    string `json:"invalid_reason,omitempty"`
	Identity   bool   `json:"identity_plan"` // no effective change: the oracle expects accept
	OracleSays string `json:"oracle"`        // accept | reject
	Verifier   string `json:"verifier"`      // accept | reject
	Stage      string `json:"stage,omitempty"`
	Code       string `json:"code,omitempty"`
	Finding    bool   `json:"finding"` // verifier accepted what the oracle says must be rejected
	BuildErr   string `json:"build_error,omitempty"`
}

// Execute applies a plan and appraises the result under policy P.
func (l *Lab) Execute(p Plan) Outcome {
	o := Outcome{PlanID: p.ID, Canonical: p.Canonical()}
	if err := p.Validate(l.Caps); err != nil {
		o.Invalid = err.Error()
		return o
	}
	o.Valid = true
	r := verifier.New(l.reg, nil, nil)
	r.Now = func() time.Time { return l.clock }
	r.Store.Now = r.Now
	n, _ := r.Issue("A", wire.PolicyP)
	nb, _ := wire.UnB64(n)
	eff := wire.ProofContext(wire.PolicyP, nb, nil) // domain-separated P proof value
	st := &state{payload: map[string]any{"ptv_version": "1.1", "msg_type": 2, "nonce": eff, "attester_id": "dep-A", "triage_band": 0, "timestamp": cbor.Tag{Number: 1, Content: l.clock.Unix()}},
		quoteSigner: l.ak, quoteNonce: eff, quotePCR: l.pcrRef, evFormat: ptv.EvidenceFormat, envSigner: l.ak, alg: "ES256"}
	base := snapshot(st)
	for _, m := range p.Mutations {
		l.apply(st, m, nb)
	}
	// The oracle judges the FINAL state against the valid baseline (a mutation that
	// a later one undoes is not a deviation), never the planner's description.
	o.Identity = snapshot(st) == base
	o.OracleSays = map[bool]string{true: "accept", false: "reject"}[o.Identity]
	raw, err := l.build(st)
	if err != nil {
		o.BuildErr = err.Error()
		o.Verifier = "reject"
		return o
	}
	// The outer evidence nonce is always the issued nonce; the signed structures
	// carry the domain-separated proof value. Mutations target the inner payload.
	raw["nonce"] = n
	d := &verifier.Decision{Card: cardsig.Verdict{Present: true, Valid: true}}
	r.Appraise(wire.PolicyP, n, "A", raw, d)
	o.Verifier = map[bool]string{true: "accept", false: "reject"}[d.Accept]
	o.Stage, o.Code = d.FailureStage, d.Code
	o.Finding = d.Accept && !o.Identity
	return o
}

// apply mutates state; returns whether the mutation changes the valid baseline.
func (l *Lab) apply(st *state, m Mutation, nb []byte) bool {
	switch m.Op {
	case OpDropField:
		if m.Field == "evidence" {
			st.dropEv = true
			return true
		}
		_, had := st.payload[m.Field]
		delete(st.payload, m.Field)
		return had
	case OpSetNull:
		st.payload[m.Field] = nil
		if m.Field == "evidence" {
			st.dropEv = true
		}
		return true
	case OpSetEmptyBstr:
		st.payload[m.Field] = []byte{}
		if m.Field == "evidence" {
			st.dropEv = true
		}
		return true
	case OpSetText:
		st.payload[m.Field] = m.Value
		if m.Field == "evidence" {
			st.dropEv = true
		}
		return !(m.Field == "ptv_version" && m.Value == "1.1" || m.Field == "attester_id" && m.Value == "dep-A")
	case OpSetInt:
		old := st.payload[m.Field]
		st.payload[m.Field] = m.IntValue
		return fmt.Sprint(old) != fmt.Sprint(m.IntValue)
	case OpAddProof:
		st.payload["proof"] = []byte("x")
		return true
	case OpShiftTimestamp:
		st.payload["timestamp"] = cbor.Tag{Number: 1, Content: l.clock.Add(time.Duration(m.IntValue) * time.Second).Unix()}
		st.tsShift = m.IntValue
		return m.IntValue > 300 || m.IntValue < -300
	case OpReplaceNonce:
		st.payload["nonce"] = wire.NewNonce()
		return true
	case OpTruncateEvidence:
		st.truncateEv = m.IntValue
		return true
	case OpFlipByte:
		st.flips = append(st.flips, m)
		return true
	case OpSignWith:
		if m.Value == "unenrolled" {
			st.envSigner = l.other
			return true
		}
		return false
	case OpQuoteSignWith:
		if m.Value == "unenrolled" {
			st.quoteSigner = l.other
			return true
		}
		return false
	case OpQuoteNonce:
		if m.Value == "random" {
			st.quoteNonce = wire.NewNonce()
			return true
		}
		return false
	case OpQuotePCR:
		if m.Value == "other" {
			st.quotePCR = []byte("0123456789abcdef0123456789abcdef")
			return true
		}
		return false
	case OpQuoteMagic:
		st.badMagic = m.Value == "zero"
		return st.badMagic
	case OpQuoteType:
		st.certify = m.Value == "certify"
		return st.certify
	case OpQuoteHash:
		st.sha1 = m.Value == "sha1"
		return st.sha1
	case OpEvidenceFormat:
		st.evFormat = m.Value
		return m.Value != ptv.EvidenceFormat
	case OpWrongAttester:
		st.payload["attester_id"] = map[string]string{"dep-B": "dep-B"}[m.Value]
		if st.payload["attester_id"] == "" {
			st.payload["attester_id"] = "dep-unknown"
		}
		return true
	case OpEnvelopeUntagged:
		st.untag = true
		return true
	case OpAlgHeader:
		st.alg = m.Value
		return m.Value != "ES256"
	}
	return false
}

// snapshot serialises everything that influences the built response.
var detEnc, _ = cbor.CoreDetEncOptions().EncMode()

func snapshot(st *state) string {
	pl := map[string]any{}
	for k, v := range st.payload {
		pl[k] = v
	}
	if st.tsShift != 0 && st.tsShift <= 300 && st.tsShift >= -300 {
		pl["timestamp"] = "within-window" // spec oracle: any timestamp inside the 300 s window is valid
	}
	if _, ok := pl["timestamp"].(cbor.Tag); ok && st.tsShift == 0 {
		pl["timestamp"] = "within-window"
	}
	pb, _ := detEnc.Marshal(pl)
	return fmt.Sprintf("%x|%p|%x|%x|%v|%v|%v|%s|%d|%v|%p|%v|%s|%v", pb, st.quoteSigner, st.quoteNonce, st.quotePCR, st.badMagic, st.certify, st.sha1, st.evFormat, st.truncateEv, st.flips, st.envSigner, st.untag, st.alg, st.dropEv)
}

func pcrSel16() tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(16)}}}
}

func (l *Lab) build(st *state) (map[string]any, error) {
	// quote
	dg := sha256.Sum256(st.quotePCR)
	att := tpm2.TPMSAttest{Magic: tpm2.TPMGeneratedValue, Type: tpm2.TPMSTAttestQuote, QualifiedSigner: tpm2.TPM2BName{Buffer: l.qname}, ExtraData: tpm2.TPM2BData{Buffer: st.quoteNonce},
		ClockInfo: tpm2.TPMSClockInfo{Clock: 1, ResetCount: 1, Safe: true}, FirmwareVersion: 1,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{PCRSelect: pcrSel16(), PCRDigest: tpm2.TPM2BDigest{Buffer: dg[:]}})}
	quoted := tpm2.Marshal(&att)
	if st.badMagic {
		quoted[0] = 0
	}
	if st.certify {
		quoted[4], quoted[5] = 0x80, 0x17
	}
	for _, f := range st.flips {
		if f.Target == "quote" {
			flip(quoted, f.IntValue)
		}
	}
	h := sha256.Sum256(quoted)
	rr, ss, err := ecdsa.Sign(rand.Reader, st.quoteSigner, h[:])
	if err != nil {
		return nil, err
	}
	hash := tpm2.TPMAlgSHA256
	if st.sha1 {
		hash = tpm2.TPMAlgSHA1
	}
	sig := tpm2.Marshal(&tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgECDSA, Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{Hash: hash, SignatureR: tpm2.TPM2BECCParameter{Buffer: rr.Bytes()}, SignatureS: tpm2.TPM2BECCParameter{Buffer: ss.Bytes()}})})
	for _, f := range st.flips {
		if f.Target == "quote_sig" {
			flip(sig, f.IntValue)
		}
	}
	ev, err := (&ptv.TPMEvidence{Format: st.evFormat, Quoted: quoted, Signature: sig, Bank: "sha256", PCRs: map[int][]byte{16: l.pcrRef}}).Encode()
	if err != nil {
		return nil, err
	}
	if st.truncateEv > 0 && st.truncateEv < len(ev) {
		ev = ev[:st.truncateEv]
	}
	for _, f := range st.flips {
		if f.Target == "evidence" {
			flip(ev, f.IntValue)
		}
	}
	if !st.dropEv {
		if _, explicitlySet := st.payload["evidence"]; !explicitlySet {
			st.payload["evidence"] = ev
		}
	}
	pb, err := cbor.Marshal(st.payload)
	if err != nil {
		return nil, err
	}
	msg := cose.NewSign1Message()
	switch st.alg {
	case "ES256":
		msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	case "ES384":
		msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)
	case "none":
	}
	msg.Headers.Protected[cose.HeaderLabelKeyID] = []byte("dep-A")
	msg.Payload = pb
	s, err := cose.NewSigner(cose.AlgorithmES256, st.envSigner)
	if err != nil {
		return nil, err
	}
	if st.alg == "ES256" {
		if err := msg.Sign(nil, nil, swSigner{s}); err != nil {
			return nil, err
		}
	} else {
		// sign the Sig_structure manually so header/alg mismatch cases are buildable
		msg.Signature = []byte("not-a-valid-signature-for-this-header")
	}
	b, err := msg.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	if st.untag && len(b) > 0 && b[0] == 0xd2 {
		b = b[1:]
	}
	for _, f := range st.flips {
		if f.Target == "envelope" {
			flip(b, f.IntValue)
		}
	}
	nonce := wire.B64(st.quoteNonce)
	if v, ok := st.payload["nonce"].([]byte); ok {
		nonce = wire.B64(v)
	}
	_ = big.NewInt
	return wire.ToMap(wire.Evidence{Type: "evidence", Policy: wire.PolicyP, DeploymentID: "dep-A", Nonce: nonce, COSESign1: wire.B64(b)}), nil
}

func flip(b []byte, i int) {
	if len(b) == 0 {
		return
	}
	if i < 0 {
		i = len(b) + i
	}
	if i < 0 || i >= len(b) {
		i = len(b) - 1
	}
	b[i] ^= 0xff
}
