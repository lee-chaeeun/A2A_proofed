// Package senv is the matched software control for the TPM quote: a COSE_Sign1 envelope with the
// same metadata coverage as the PTV routine response (identity, nonce, action,
// audience, issued/expiry) but signed by the isolated SOFTWARE signer behind the
// gate. It carries no attestation evidence and makes no configuration claim; it
// isolates "signature coverage of the response metadata" from "key type".
package senv

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const Version = "a2aid-senv-v1"

// Payload is the signed CBOR map.
type Payload struct {
	Version    string    `cbor:"v"`
	AttesterID string    `cbor:"attester_id"`
	Nonce      []byte    `cbor:"nonce"` // the (possibly channel-bound) nonce
	Action     string    `cbor:"action"`
	Audience   string    `cbor:"audience"`
	Policy     string    `cbor:"policy"`
	IssuedAt   time.Time `cbor:"iat"`
	ExpiresAt  time.Time `cbor:"exp"`
}

var encMode cbor.EncMode
var decMode cbor.DecMode

func init() {
	opts := cbor.CoreDetEncOptions()
	opts.Time = cbor.TimeUnix
	opts.TimeTag = cbor.EncTagRequired
	var err error
	if encMode, err = opts.EncMode(); err != nil {
		panic(err)
	}
	if decMode, err = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode(); err != nil {
		panic(err)
	}
}

func Encode(p *Payload) ([]byte, error) { return encMode.Marshal(p) }

// Seal signs payload with signer (ES256) as a tagged COSE_Sign1.
func Seal(payload []byte, kid string, signer cose.Signer) ([]byte, error) {
	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Protected[cose.HeaderLabelKeyID] = []byte(kid)
	msg.Payload = payload
	if err := msg.Sign(nil, nil, signer); err != nil {
		return nil, err
	}
	return msg.MarshalCBOR()
}

// Envelope is a decoded (unverified) software envelope.
type Envelope struct {
	Msg     *cose.Sign1Message
	Payload Payload
}

func Open(b []byte) (*Envelope, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(b); err != nil {
		return nil, fmt.Errorf("cose decode: %w", err)
	}
	e := &Envelope{Msg: &msg}
	if err := decMode.Unmarshal(msg.Payload, &e.Payload); err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}
	return e, nil
}

func (e *Envelope) VerifySignature(pub *ecdsa.PublicKey) error {
	if pub == nil {
		return errors.New("no public key")
	}
	ver, err := cose.NewVerifier(cose.AlgorithmES256, pub)
	if err != nil {
		return err
	}
	return e.Msg.Verify(nil, ver)
}

// Check validates the metadata against the verifier's expectations. now is the
// verifier clock; skew is the tolerated clock difference.
func (e *Envelope) Check(attester string, nonce []byte, action, audience, policy string, now time.Time, skew time.Duration) error {
	p := e.Payload
	switch {
	case p.Version != Version:
		return fmt.Errorf("version %q", p.Version)
	case p.AttesterID != attester:
		return fmt.Errorf("attester_id %q != expected %q", p.AttesterID, attester)
	case string(p.Nonce) != string(nonce):
		return errors.New("nonce != issued (bound) nonce")
	case p.Action != action:
		return fmt.Errorf("action %q != %q", p.Action, action)
	case p.Audience != audience:
		return fmt.Errorf("audience %q != %q", p.Audience, audience)
	case p.Policy != policy:
		return fmt.Errorf("policy %q != %q", p.Policy, policy)
	case p.IssuedAt.IsZero() || p.ExpiresAt.IsZero():
		return errors.New("iat/exp missing")
	case now.Add(skew).Before(p.IssuedAt):
		return errors.New("iat in the future")
	case !now.Before(p.ExpiresAt.Add(skew)):
		return errors.New("expired")
	}
	return nil
}

// RewriteTimestamp is the tamper fixture's helper: shift iat/exp inside the payload
// while keeping the signature bytes. The result must fail verification.
func RewriteTimestamp(b []byte, delta time.Duration) ([]byte, time.Time, error) {
	e, err := Open(b)
	if err != nil {
		return nil, time.Time{}, err
	}
	old := e.Payload.IssuedAt
	e.Payload.IssuedAt = e.Payload.IssuedAt.Add(delta)
	e.Payload.ExpiresAt = e.Payload.ExpiresAt.Add(delta)
	pb, err := Encode(&e.Payload)
	if err != nil {
		return nil, time.Time{}, err
	}
	e.Msg.Payload = pb
	out, err := e.Msg.MarshalCBOR()
	return out, old, err
}
