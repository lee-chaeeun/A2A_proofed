package pqsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/fxamacker/cbor/v2"
)

func sampleCtx(alg, kid string) *Context {
	return &Context{V: Format, Role: Role, Policy: "PQ-env+cb", Alg: alg, KID: kid, Expected: "dep-A", Requester: "requester:a2aid-lab", Action: "release-synthetic-job", Nonce: make([]byte, 32), Expiry: 1_800_000_000, Session: "c2Vzc2lvbg==", Exporter: make([]byte, 32)}
}

// Independent sign/verify path through the public FIPS 204 interface: fresh key, sign,
// verify; then every negative (wrong key, changed message, changed signature, malformed
// lengths) must reject.
func TestMLDSA_SignVerifyAndNegatives(t *testing.T) {
	seed, _ := NewMLDSASeed()
	pk, sk, err := MLDSAKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub := MLDSAPublicBytes(pk)
	if len(pub) != 1952 {
		t.Fatalf("public key %d bytes", len(pub))
	}
	msg, _ := Encode(sampleCtx(AlgMLDSA, "A-pq-k1"))
	sig, err := SignMLDSA(sk, msg)
	if err != nil || len(sig) != 3309 {
		t.Fatalf("sign: %v len %d", err, len(sig))
	}
	if !VerifyMLDSA(pub, msg, sig) {
		t.Fatal("genuine signature must verify")
	}
	// determinism of key expansion from the seed (FIPS 204 ξ)
	pk2, _, _ := MLDSAKeyFromSeed(seed)
	if string(MLDSAPublicBytes(pk2)) != string(pub) {
		t.Fatal("seed expansion not deterministic")
	}
	other, _, _ := mldsa65.GenerateKey(rand.Reader)
	if VerifyMLDSA(MLDSAPublicBytes(other), msg, sig) {
		t.Fatal("wrong key accepted")
	}
	m2 := append([]byte(nil), msg...)
	m2[len(m2)/2] ^= 1
	if VerifyMLDSA(pub, m2, sig) {
		t.Fatal("changed message accepted")
	}
	s2 := append([]byte(nil), sig...)
	s2[100] ^= 1
	if VerifyMLDSA(pub, msg, s2) {
		t.Fatal("changed signature accepted")
	}
	if VerifyMLDSA(pub, msg, sig[:len(sig)-1]) || VerifyMLDSA(pub[:len(pub)-1], msg, sig) || VerifyMLDSA(pub, msg, append(sig, 0)) {
		t.Fatal("malformed lengths accepted")
	}
	// the FIPS 204 context string is part of the signed statement
	if mldsa65.Verify(pk, msg, []byte("other-ctx"), sig) {
		t.Fatal("signature verified under another context string")
	}
}

func TestES256_SignVerifyAndNegatives(t *testing.T) {
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg, _ := Encode(sampleCtx(AlgES256, "A-ec-k1"))
	sig, err := SignES256(sk, msg)
	if err != nil || len(sig) != 64 || !VerifyES256(&sk.PublicKey, msg, sig) {
		t.Fatalf("es256: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m2 := append([]byte(nil), msg...)
	m2[0] ^= 1
	s2 := append([]byte(nil), sig...)
	s2[5] ^= 1
	if VerifyES256(&other.PublicKey, msg, sig) || VerifyES256(&sk.PublicKey, m2, sig) || VerifyES256(&sk.PublicKey, msg, s2) || VerifyES256(&sk.PublicKey, msg, sig[:63]) {
		t.Fatal("negative accepted")
	}
}

// Canonical encoding: equal contexts give equal bytes; non-canonical or extended
// encodings are rejected; every mandatory field and size is enforced.
func TestContextEncodingStrict(t *testing.T) {
	c := sampleCtx(AlgMLDSA, "k")
	b1, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := Encode(sampleCtx(AlgMLDSA, "k"))
	if string(b1) != string(b2) {
		t.Fatal("encoding not deterministic")
	}
	d, err := Decode(b1)
	if err != nil || !d.Equal(c) {
		t.Fatalf("decode: %v", err)
	}
	// extra field
	var m map[string]any
	cbor.Unmarshal(b1, &m)
	m["extra"] = 1
	eb, _ := cbor.Marshal(m)
	if _, err := Decode(eb); err == nil {
		t.Fatal("unknown field accepted")
	}
	// non-canonical (indefinite-length map) encoding of the same fields
	em, _ := cbor.EncOptions{Sort: cbor.SortNone}.EncMode()
	nb, _ := em.Marshal(m2sorted(c))
	if string(nb) != string(b1) {
		if _, err := Decode(nb); err == nil {
			t.Fatal("non-canonical encoding accepted")
		}
	}
	// wrong types / sizes
	for _, mut := range []func(*Context){
		func(x *Context) { x.Nonce = x.Nonce[:31] },
		func(x *Context) { x.Exporter = []byte{1} },
		func(x *Context) { x.Alg = "Dilithium3" },
		func(x *Context) { x.V = "a2aid-proof-v3" },
		func(x *Context) { x.Action = "" },
		func(x *Context) { x.Expiry = 0 },
		func(x *Context) { x.Session = "" },
	} {
		x := *sampleCtx(AlgMLDSA, "k")
		mut(&x)
		if _, err := Encode(&x); err == nil {
			t.Fatalf("invalid context encoded: %+v", x)
		}
	}
	if _, err := Decode(nil); err == nil {
		t.Fatal("empty context accepted")
	}
	if _, err := Decode(make([]byte, MaxContextLen+1)); err == nil {
		t.Fatal("oversized context accepted")
	}
}

// m2sorted builds the same map with keys in a different (non-canonical) order.
func m2sorted(c *Context) map[string]any {
	return map[string]any{"v": c.V, "role": c.Role, "policy": c.Policy, "alg": c.Alg, "kid": c.KID, "expected": c.Expected, "requester": c.Requester, "action": c.Action, "nonce": c.Nonce, "expiry": c.Expiry, "session": c.Session, "exporter": c.Exporter}
}

// Verify: closed algorithm set, pinned alg/kid (no downgrade or confusion), context
// equality with the expected context, signature under the pinned key only.
func TestVerifyStages(t *testing.T) {
	seed, _ := NewMLDSASeed()
	pk, sk, _ := MLDSAKeyFromSeed(seed)
	pin := PinnedKey{Alg: AlgMLDSA, KID: "A-pq-k1", MLDSAPub: MLDSAPublicBytes(pk)}
	want := sampleCtx(AlgMLDSA, "A-pq-k1")
	ctxb, _ := Encode(want)
	sig, _ := SignMLDSA(sk, ctxb)
	good := &Proof{Format: Format, Alg: AlgMLDSA, KID: "A-pq-k1", Context: ctxb, Signature: sig}
	if st, err := Verify(good, pin, want); err != nil {
		t.Fatalf("good proof rejected at %s: %v", st, err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecCtx := sampleCtx(AlgES256, "A-pq-k1")
	ecb, _ := Encode(ecCtx)
	ecSig, _ := SignES256(ec, ecb)
	cases := []struct {
		name  string
		p     *Proof
		pin   PinnedKey
		want  *Context
		stage string
	}{
		{"nil", nil, pin, want, "proof"},
		{"unknown alg", &Proof{Format: Format, Alg: "ML-DSA-87", KID: "A-pq-k1", Context: ctxb, Signature: sig}, pin, want, "alg"},
		{"classical fallback for PQ policy", &Proof{Format: Format, Alg: AlgES256, KID: "A-pq-k1", Context: ecb, Signature: ecSig}, pin, want, "alg"},
		{"wrong kid", &Proof{Format: Format, Alg: AlgMLDSA, KID: "A-pq-k2", Context: ctxb, Signature: sig}, pin, want, "kid"},
		{"header alg differs from context alg", &Proof{Format: Format, Alg: AlgMLDSA, KID: "A-pq-k1", Context: ecb, Signature: sig}, pin, want, "context-mismatch"},
		{"different expected context (nonce)", good, pin, func() *Context { x := *want; x.Nonce = append([]byte{1}, make([]byte, 31)...); return &x }(), "context-mismatch"},
		{"different exporter", good, pin, func() *Context { x := *want; x.Exporter = append([]byte{9}, make([]byte, 31)...); return &x }(), "context-mismatch"},
		{"substituted public key", good, PinnedKey{Alg: AlgMLDSA, KID: "A-pq-k1", MLDSAPub: func() []byte { o, _, _ := mldsa65.GenerateKey(rand.Reader); return MLDSAPublicBytes(o) }()}, want, "signature"},
		{"oversized signature", &Proof{Format: Format, Alg: AlgMLDSA, KID: "A-pq-k1", Context: ctxb, Signature: make([]byte, MaxSigLen+1)}, pin, want, "signature"},
		{"wrong format", &Proof{Format: "a2aid-proof-v3", Alg: AlgMLDSA, KID: "A-pq-k1", Context: ctxb, Signature: sig}, pin, want, "format"},
	}
	for _, c := range cases {
		st, err := Verify(c.p, c.pin, c.want)
		if err == nil || st != c.stage {
			t.Errorf("%s: want stage %s, got %s (%v)", c.name, c.stage, st, err)
		}
	}
}
