// Package cardsig signs and verifies A2A Agent Cards with JWS (ES256), following the
// official a2a-samples sign-and-verify-agent-card Go sample (pre-sprint code,
// adapted: the verifier resolves `kid` through the operator registry and ignores
// `jku`, so a key named inside the response is never trusted).
package cardsig

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/golang-jwt/jwt/v5"
)

const ES256 = "ES256"

var (
	ErrNoSignature       = errors.New("AgentCard has no signatures to verify")
	ErrInvalidSignatures = errors.New("no valid signature found")
)

type ProtectedHeader struct {
	KeyID string `json:"kid"`
	Alg   string `json:"alg,omitempty"`
	Typ   string `json:"typ,omitempty"`
}

// KeyProvider returns the verification key for a kid, or an error.
type KeyProvider func(keyID string) (*ecdsa.PublicKey, error)

func cleanEmpty(v any) any {
	switch val := v.(type) {
	case map[string]any:
		m := make(map[string]any)
		for k, item := range val {
			if ci := cleanEmpty(item); ci != nil {
				m[k] = ci
			}
		}
		if len(m) == 0 {
			return nil
		}
		return m
	case []any:
		var l []any
		for _, item := range val {
			if ci := cleanEmpty(item); ci != nil {
				l = append(l, ci)
			}
		}
		if len(l) == 0 {
			return nil
		}
		return l
	case string:
		if val == "" {
			return nil
		}
		return val
	default:
		return val
	}
}

// Canonicalize produces the canonical JSON payload (sample's JCS approximation).
func Canonicalize(card *a2a.AgentCard) ([]byte, error) {
	data, err := json.Marshal(card)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	delete(raw, "signatures")
	c := cleanEmpty(raw)
	if c == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(c)
}

// Sign returns a copy of card with one ES256 JWS signature appended.
func Sign(card *a2a.AgentCard, key *ecdsa.PrivateKey, kid string) (*a2a.AgentCard, error) {
	method := jwt.GetSigningMethod(ES256)
	cp := *card
	cp.Signatures = nil
	payload, err := Canonicalize(&cp)
	if err != nil {
		return nil, err
	}
	hdr, _ := json.Marshal(ProtectedHeader{KeyID: kid, Alg: ES256})
	hb := base64.RawURLEncoding.EncodeToString(hdr)
	pb := base64.RawURLEncoding.EncodeToString(payload)
	sig, err := method.Sign(hb+"."+pb, key)
	if err != nil {
		return nil, err
	}
	cp.Signatures = []a2a.AgentCardSignature{{Protected: hb, Signature: base64.RawURLEncoding.EncodeToString(sig)}}
	return &cp, nil
}

// Verdict describes the card check.
type Verdict struct {
	Present bool   `json:"present"`
	KeyID   string `json:"kid"`
	Valid   bool   `json:"valid"`
	Reason  string `json:"reason,omitempty"`
}

// Verify checks every signature on the card against keys from the provider.
func Verify(card *a2a.AgentCard, kp KeyProvider) Verdict {
	v := Verdict{}
	if len(card.Signatures) == 0 {
		v.Reason = ErrNoSignature.Error()
		return v
	}
	v.Present = true
	payload, err := Canonicalize(card)
	if err != nil {
		v.Reason = err.Error()
		return v
	}
	pb := base64.RawURLEncoding.EncodeToString(payload)
	for _, s := range card.Signatures {
		hb, err := base64.RawURLEncoding.DecodeString(s.Protected)
		if err != nil {
			continue
		}
		var ph ProtectedHeader
		if json.Unmarshal(hb, &ph) != nil || ph.Alg != ES256 {
			continue
		}
		v.KeyID = ph.KeyID
		key, err := kp(ph.KeyID)
		if err != nil {
			v.Reason = fmt.Sprintf("kid %q: %v", ph.KeyID, err)
			continue
		}
		tok, err := jwt.Parse(s.Protected+"."+pb+"."+s.Signature, func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != ES256 {
				return nil, errors.New("alg mismatch")
			}
			return key, nil
		})
		if err == nil && tok.Valid {
			v.Valid = true
			v.Reason = ""
			return v
		}
		v.Reason = "signature does not verify under enrolled key for kid " + ph.KeyID
	}
	return v
}
