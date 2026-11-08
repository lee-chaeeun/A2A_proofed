// Package ptv implements a direct, routine-mode slice of
// draft-anandakrishnan-rats-ptv-agent-identity-01 (29 Sep 2026): version "1.1" CBOR
// messages (§5.1), PTV_PROVE_RESP type 2 (§5.3.2) in the ROUTINE band (§5.2),
// carried as COSE_Sign1 signed by the enrolled AK (§5.4), with the error registry
// of §5.5. Evidence is NOT an EAT: it is the documented raw TPM quote alternative
// (format "a2aid-tpm2-quote-v1"), encoded as a deterministic CBOR map.
package ptv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const Version = "1.1"

// Error codes from §5.5.
const (
	ErrAttestationFailed = "PTV_ERR_001"
	ErrExpired           = "PTV_ERR_005"
	ErrNonce             = "PTV_ERR_006"
	ErrConfig            = "PTV_ERR_007"
	ErrMutex             = "PTV_ERR_008"
	ErrSignature         = "PTV_ERR_010"
)

// FreshnessWindow is the draft's suggested starting window (§7.1 / brainstorm notes).
const FreshnessWindow = 300 * time.Second

var encMode cbor.EncMode
var decMode cbor.DecMode

func init() {
	opts := cbor.CoreDetEncOptions()
	opts.Time = cbor.TimeUnix
	opts.TimeTag = cbor.EncTagRequired
	var err error
	encMode, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
	decMode, err = cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		panic(err)
	}
}

// TPMEvidence is the embedded evidence (bstr contents) for the routine band.
type TPMEvidence struct {
	Format    string         `cbor:"fmt"`
	Quoted    []byte         `cbor:"quoted"`    // TPMS_ATTEST bytes
	Signature []byte         `cbor:"signature"` // TPMT_SIGNATURE bytes
	Bank      string         `cbor:"bank"`
	PCRs      map[int][]byte `cbor:"pcrs"`
}

const EvidenceFormat = "a2aid-tpm2-quote-v1"

func (e *TPMEvidence) Encode() ([]byte, error) { return encMode.Marshal(e) }

func DecodeEvidence(b []byte) (*TPMEvidence, error) {
	var e TPMEvidence
	if err := decMode.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	if e.Format != EvidenceFormat {
		return nil, fmt.Errorf("unknown evidence format %q", e.Format)
	}
	return &e, nil
}

// ProveResp is PTV_PROVE_RESP (type 2). Proof is only set by the malformed-envelope
// fixture; a conforming routine response never carries it.
type ProveResp struct {
	Version    string    `cbor:"ptv_version"`
	Nonce      []byte    `cbor:"nonce"`
	MsgType    int       `cbor:"msg_type"`
	AttesterID string    `cbor:"attester_id"`
	TriageBand int       `cbor:"triage_band"`
	Evidence   []byte    `cbor:"evidence,omitempty"`
	Proof      []byte    `cbor:"proof,omitempty"`
	Timestamp  time.Time `cbor:"timestamp"`
}

func EncodeResp(r *ProveResp) ([]byte, error) { return encMode.Marshal(r) }

// Seal wraps payload bytes in a tagged COSE_Sign1 signed by signer (the AK).
func Seal(payload []byte, attesterID string, signer cose.Signer) ([]byte, error) {
	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Protected[cose.HeaderLabelKeyID] = []byte(attesterID)
	msg.Payload = payload
	if err := msg.Sign(nil, nil, signer); err != nil {
		return nil, err
	}
	return msg.MarshalCBOR()
}

// Envelope is a decoded COSE_Sign1 plus the raw payload map for presence checks.
type Envelope struct {
	Msg        *cose.Sign1Message
	Raw        map[string]cbor.RawMessage
	Resp       ProveResp
	AttesterID string // from payload
	TypedErr   error  // typed decode failure (wrong field types); reported by SchemaCheck
}

// Open decodes the tagged COSE_Sign1 and its payload without verifying anything.
func Open(b []byte) (*Envelope, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(b); err != nil {
		return nil, fmt.Errorf("cose decode: %w", err)
	}
	env := &Envelope{Msg: &msg, Raw: map[string]cbor.RawMessage{}}
	if err := decMode.Unmarshal(msg.Payload, &env.Raw); err != nil {
		return nil, fmt.Errorf("payload is not a CBOR map: %w", err)
	}
	if err := decMode.Unmarshal(msg.Payload, &env.Resp); err != nil {
		// Keep the envelope so the outer signature can still be recorded; the
		// schema check reports the typing failure and the verifier rejects.
		env.TypedErr = fmt.Errorf("payload field types: %w", err)
		var loose struct {
			AttesterID string `cbor:"attester_id"`
		}
		_ = decMode.Unmarshal(msg.Payload, &loose)
		env.AttesterID = loose.AttesterID
		return env, nil
	}
	env.AttesterID = env.Resp.AttesterID
	return env, nil
}

// VerifySignature checks the outer AK signature with go-cose (ES256 over Sig_structure).
func (e *Envelope) VerifySignature(pub *ecdsa.PublicKey) error {
	ver, err := cose.NewVerifier(cose.AlgorithmES256, pub)
	if err != nil {
		return err
	}
	return e.Msg.Verify(nil, ver)
}

// SchemaCheck validates §5.1–5.3 structure and the §5.2 routine-band rule: a
// routine response MUST carry evidence (a non-empty byte string) and MUST NOT carry
// proof. Returns an error code and reason, or "" when fine. It never inspects the
// evidence contents; that is the quote appraisal's job.
func (e *Envelope) SchemaCheck() (code, reason string) {
	if e.TypedErr != nil {
		return ErrAttestationFailed, e.TypedErr.Error()
	}
	// Required fields must be present with the right CBOR major type. A missing or
	// null integer field would otherwise decode to Go's zero value (triage_band 0 =
	// routine) and silently pass. Found by the deterministic mutation baseline.
	for _, f := range []struct {
		name  string
		major byte
	}{{"ptv_version", 3}, {"msg_type", 0}, {"nonce", 2}, {"attester_id", 3}, {"triage_band", 0}, {"timestamp", 6}} {
		raw, ok := e.Raw[f.name]
		if !ok || len(raw) == 0 {
			return ErrAttestationFailed, "required field " + f.name + " missing"
		}
		if raw[0]>>5 != f.major {
			return ErrAttestationFailed, "required field " + f.name + " has the wrong CBOR type"
		}
	}
	if e.Resp.Version != Version {
		return ErrAttestationFailed, "ptv_version != 1.1"
	}
	if e.Resp.MsgType != 2 {
		return ErrAttestationFailed, "msg_type != 2"
	}
	if n := len(e.Resp.Nonce); n < 16 || n > 64 {
		return ErrNonce, "nonce size outside 16..64"
	}
	if e.Resp.TriageBand != 0 {
		return ErrMutex, "triage_band != 0 (routine slice only)"
	}
	evRaw, hasEv := e.Raw["evidence"]
	_, hasPr := e.Raw["proof"]
	switch {
	case hasEv && hasPr:
		return ErrMutex, "routine band requires evidence XOR proof (both present)"
	case hasPr:
		return ErrAttestationFailed, "routine band requires evidence; proof-only response"
	case !hasEv:
		return ErrAttestationFailed, "routine band requires evidence; evidence absent"
	}
	if !isNonEmptyBstr(evRaw) {
		return ErrAttestationFailed, "evidence must be a non-empty CBOR byte string"
	}
	if e.Resp.Timestamp.IsZero() {
		return ErrAttestationFailed, "timestamp missing"
	}
	return "", ""
}

// isNonEmptyBstr reports whether raw is a CBOR byte string (major type 2) with at
// least one byte of content. Null, text strings, arrays and empty bstrs fail.
func isNonEmptyBstr(raw cbor.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	major := raw[0] >> 5
	if major != 2 {
		return false
	}
	var b []byte
	if err := decMode.Unmarshal(raw, &b); err != nil {
		return false
	}
	return len(b) > 0
}

// FreshnessCheck compares the envelope timestamp with now.
func (e *Envelope) FreshnessCheck(now time.Time) (code, reason string) {
	d := now.Sub(e.Resp.Timestamp)
	if d < 0 {
		d = -d
	}
	if d > FreshnessWindow {
		return ErrExpired, fmt.Sprintf("timestamp outside %s window (%s)", FreshnessWindow, d)
	}
	return "", ""
}

// RewritePayloadTimestamp returns a new COSE_Sign1 byte string whose payload has the
// timestamp replaced and everything else (protected header, signature) unchanged.
// Used only by the tamper fixture; the result must fail outer verification.
func RewritePayloadTimestamp(b []byte, newTS time.Time) ([]byte, time.Time, error) {
	env, err := Open(b)
	if err != nil {
		return nil, time.Time{}, err
	}
	old := env.Resp.Timestamp
	env.Resp.Timestamp = newTS
	payload, err := EncodeResp(&env.Resp)
	if err != nil {
		return nil, time.Time{}, err
	}
	env.Msg.Payload = payload
	out, err := env.Msg.MarshalCBOR()
	return out, old, err
}

// softwareSigner lets tests build envelopes with a non-TPM key; the harness uses it
// only for the "unknown software key" variant and never counts it as a P pass.
type softwareSigner struct{ s cose.Signer }

func NewSoftwareSigner(key *ecdsa.PrivateKey) (cose.Signer, error) {
	s, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		return nil, err
	}
	return &softwareSigner{s}, nil
}
func (s *softwareSigner) Algorithm() cose.Algorithm { return s.s.Algorithm() }
func (s *softwareSigner) Sign(r io.Reader, c []byte) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	return s.s.Sign(r, c)
}

var ErrNotTagged = errors.New("not a tagged COSE_Sign1")

// IsTaggedSign1 reports whether b starts with CBOR tag 18.
func IsTaggedSign1(b []byte) bool { return bytes.HasPrefix(b, []byte{0xd2}) }
