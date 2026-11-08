// Package pqsig is the versioned application proof format "a2aid-proof-v4": a canonical
// CBOR context signed either with ML-DSA-65 (FIPS 204, Cloudflare CIRCL) or with ECDSA
// P-256 over SHA-256 (the matched classical control). Verification needs only the
// enrolled public key. The algorithm set and the field set are closed; anything
// unknown, missing, duplicated, oversized or of the wrong type is rejected.
//
// The ML-DSA signature is produced through the library's FIPS 204 interface over the
// context bytes with the context string CtxString (no pre-hash). The ECDSA control
// signs SHA-256(context bytes) (ECDSA has no context parameter; the domain and
// version are inside the signed context).
package pqsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/fxamacker/cbor/v2"
)

const (
	Format    = "a2aid-proof-v4"
	Role      = "agent-response"
	AlgES256  = "ES256"     // ECDSA P-256 / SHA-256, raw r||s (64 bytes)
	AlgMLDSA  = "ML-DSA-65" // FIPS 204 ML-DSA-65, pure mode with CtxString
	CtxString = Format      // FIPS 204 context string for ML-DSA

	PublicKeySize = mldsa65.PublicKeySize // 1952
	SignatureSize = mldsa65.SignatureSize // 3309
	SeedSize      = mldsa65.SeedSize      // 32
	NonceSize     = 32
	ExporterSize  = 32
	MaxContextLen = 1024
	MaxSigLen     = 4096
)

var Algs = map[string]bool{AlgES256: true, AlgMLDSA: true}

// Context is the signed statement. Field order and names are fixed; encoding is CBOR
// core deterministic (fxamacker), so equal contexts have equal bytes.
type Context struct {
	V         string `cbor:"v"`
	Role      string `cbor:"role"`
	Policy    string `cbor:"policy"`
	Alg       string `cbor:"alg"`
	KID       string `cbor:"kid"`
	Expected  string `cbor:"expected"`  // deployment id the requester expects
	Requester string `cbor:"requester"` // audience (requester identity)
	Action    string `cbor:"action"`
	Nonce     []byte `cbor:"nonce"`   // the issued nonce (32 bytes)
	Expiry    int64  `cbor:"expiry"`  // unix seconds
	Session   string `cbor:"session"` // session id (the issued nonce, base64) as the requester stores it
	Exporter  []byte `cbor:"exporter"` // signer's OWN tls-exporter for +cb policies; empty otherwise
}

// Proof is the response element (JSON in the A2A DataPart).
type Proof struct {
	Format    string `json:"format"`
	Alg       string `json:"alg"`
	KID       string `json:"kid"`
	Context   []byte `json:"context"`   // canonical CBOR bytes (base64 in JSON)
	Signature []byte `json:"signature"` // raw signature bytes
}

var encMode cbor.EncMode
var decMode cbor.DecMode

func init() {
	var err error
	if encMode, err = cbor.CoreDetEncOptions().EncMode(); err != nil {
		panic(err)
	}
	if decMode, err = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField, MaxArrayElements: 64, MaxMapPairs: 64}).DecMode(); err != nil {
		panic(err)
	}
}

// Encode returns the canonical bytes of c after validating it.
func Encode(c *Context) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return encMode.Marshal(c)
}

// Decode parses canonical context bytes strictly and re-encodes to check canonicity.
func Decode(b []byte) (*Context, error) {
	if len(b) == 0 || len(b) > MaxContextLen {
		return nil, fmt.Errorf("context length %d out of bounds", len(b))
	}
	var c Context
	if err := decMode.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("context: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	re, err := encMode.Marshal(&c)
	if err != nil || !bytes.Equal(re, b) {
		return nil, errors.New("context is not in canonical encoding")
	}
	return &c, nil
}

// Validate enforces the closed field set and sizes.
func (c *Context) Validate() error {
	switch {
	case c.V != Format:
		return fmt.Errorf("context version %q", c.V)
	case c.Role != Role:
		return fmt.Errorf("context role %q", c.Role)
	case !Algs[c.Alg]:
		return fmt.Errorf("context alg %q not in the closed set", c.Alg)
	case c.Policy == "" || c.KID == "" || c.Expected == "" || c.Requester == "" || c.Action == "" || c.Session == "":
		return errors.New("context has an empty mandatory field")
	case len(c.Policy) > 64 || len(c.KID) > 64 || len(c.Expected) > 64 || len(c.Requester) > 128 || len(c.Action) > 64 || len(c.Session) > 128:
		return errors.New("context field too long")
	case len(c.Nonce) != NonceSize:
		return fmt.Errorf("context nonce is %d bytes", len(c.Nonce))
	case len(c.Exporter) != 0 && len(c.Exporter) != ExporterSize:
		return fmt.Errorf("context exporter is %d bytes", len(c.Exporter))
	case c.Expiry <= 0:
		return errors.New("context expiry missing")
	}
	return nil
}

// Equal compares two contexts field by field (byte-equal nonce/exporter).
func (c *Context) Equal(o *Context) bool {
	return c.V == o.V && c.Role == o.Role && c.Policy == o.Policy && c.Alg == o.Alg && c.KID == o.KID && c.Expected == o.Expected && c.Requester == o.Requester && c.Action == o.Action && bytes.Equal(c.Nonce, o.Nonce) && c.Expiry == o.Expiry && c.Session == o.Session && bytes.Equal(c.Exporter, o.Exporter)
}

// ---- ML-DSA-65 -----------------------------------------------------------------

// MLDSAKeyFromSeed expands a 32-byte seed (FIPS 204 ξ) into the key pair.
func MLDSAKeyFromSeed(seed []byte) (*mldsa65.PublicKey, *mldsa65.PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, nil, fmt.Errorf("seed must be %d bytes", SeedSize)
	}
	var s [SeedSize]byte
	copy(s[:], seed)
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return pk, sk, nil
}

// NewMLDSASeed returns a fresh random seed.
func NewMLDSASeed() ([]byte, error) {
	s := make([]byte, SeedSize)
	_, err := rand.Read(s)
	return s, err
}

// SignMLDSA signs canonical context bytes (pure ML-DSA, ctx = CtxString, hedged).
func SignMLDSA(sk *mldsa65.PrivateKey, context []byte) ([]byte, error) {
	sig := make([]byte, SignatureSize)
	if err := mldsa65.SignTo(sk, context, []byte(CtxString), true, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// VerifyMLDSA verifies sig over context under pk bytes (1952 bytes).
func VerifyMLDSA(pub []byte, context, sig []byte) bool {
	if len(pub) != PublicKeySize || len(sig) != SignatureSize {
		return false
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pub); err != nil {
		return false
	}
	return mldsa65.Verify(&pk, context, []byte(CtxString), sig)
}

// MLDSAPublicBytes returns the FIPS 204 public key encoding.
func MLDSAPublicBytes(pk *mldsa65.PublicKey) []byte {
	b, _ := pk.MarshalBinary()
	return b
}

// ---- ECDSA P-256 control ------------------------------------------------------------

// SignES256 signs SHA-256(context) and returns raw r||s (64 bytes).
func SignES256(sk *ecdsa.PrivateKey, context []byte) ([]byte, error) {
	if sk == nil || sk.Curve != elliptic.P256() {
		return nil, errors.New("ES256 needs a P-256 key")
	}
	h := sha256.Sum256(context)
	r, s, err := ecdsa.Sign(rand.Reader, sk, h[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// VerifyES256 verifies a raw r||s signature over SHA-256(context).
func VerifyES256(pk *ecdsa.PublicKey, context, sig []byte) bool {
	if pk == nil || pk.Curve != elliptic.P256() || len(sig) != 64 {
		return false
	}
	h := sha256.Sum256(context)
	return ecdsa.Verify(pk, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// ---- generic verification with a pinned key ----------------------------------------

// PinnedKey is the requester's trust anchor for one policy base: algorithm, key id and
// public key material from the enrollment registry (never from the response).
type PinnedKey struct {
	Alg      string
	KID      string
	Version  int
	MLDSAPub []byte           // for ML-DSA-65
	ECPub    *ecdsa.PublicKey // for ES256
}

// Verify checks the proof's closed-set fields, decodes the context strictly, compares it
// with the expected context and verifies the signature under the pinned key. It returns
// the stage that failed ("alg", "kid", "context", "context-mismatch", "signature").
func Verify(p *Proof, pin PinnedKey, expected *Context) (stage string, err error) {
	switch {
	case p == nil:
		return "proof", errors.New("no proof_v4 in response")
	case p.Format != Format:
		return "format", fmt.Errorf("proof format %q", p.Format)
	case !Algs[p.Alg]:
		return "alg", fmt.Errorf("algorithm %q not in the closed set", p.Alg)
	case p.Alg != pin.Alg:
		return "alg", fmt.Errorf("algorithm %q is not the pinned %s for this policy (no downgrade or confusion)", p.Alg, pin.Alg)
	case p.KID != pin.KID:
		return "kid", fmt.Errorf("key id %q is not the pinned %q", p.KID, pin.KID)
	case len(p.Signature) == 0 || len(p.Signature) > MaxSigLen:
		return "signature", fmt.Errorf("signature length %d out of bounds", len(p.Signature))
	}
	c, err := Decode(p.Context)
	if err != nil {
		return "context", err
	}
	if c.Alg != p.Alg || c.KID != p.KID {
		return "context-mismatch", errors.New("context alg/kid differ from the proof header")
	}
	if !c.Equal(expected) {
		return "context-mismatch", fmt.Errorf("signed context differs from the expected context (%s)", diff(c, expected))
	}
	var ok bool
	switch p.Alg {
	case AlgMLDSA:
		ok = VerifyMLDSA(pin.MLDSAPub, p.Context, p.Signature)
	case AlgES256:
		ok = VerifyES256(pin.ECPub, p.Context, p.Signature)
	}
	if !ok {
		return "signature", fmt.Errorf("%s signature does not verify under the pinned key %s", p.Alg, pin.KID)
	}
	return "", nil
}

func diff(got, want *Context) string {
	var d []string
	add := func(name string, a, b any) {
		if fmt.Sprint(a) != fmt.Sprint(b) {
			d = append(d, name)
		}
	}
	add("policy", got.Policy, want.Policy)
	add("alg", got.Alg, want.Alg)
	add("kid", got.KID, want.KID)
	add("expected", got.Expected, want.Expected)
	add("requester", got.Requester, want.Requester)
	add("action", got.Action, want.Action)
	add("nonce", got.Nonce, want.Nonce)
	add("expiry", got.Expiry, want.Expiry)
	add("session", got.Session, want.Session)
	add("exporter", got.Exporter, want.Exporter)
	if len(d) == 0 {
		return "no field differs"
	}
	return "fields: " + fmt.Sprint(d)
}
