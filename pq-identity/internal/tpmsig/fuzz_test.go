package tpmsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// FuzzVerifyQuote: the verifier must never panic and never return OK() for
// arbitrary quote/signature bytes under a random enrolled key.
func FuzzVerifyQuote(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.Add([]byte("ff544347"), []byte{0x00, 0x18})
	f.Add([]byte{0xff, 0x54, 0x43, 0x47, 0x80, 0x18, 0x00, 0x00}, []byte{0x00, 0x18, 0x00, 0x0b})
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, quoted, sig []byte) {
		v := VerifyQuote(quoted, sig, &key.PublicKey, "0022000b", []byte("nonce"), make([]byte, 32))
		if v.OK() {
			t.Fatalf("fuzz input accepted: %x / %x", quoted, sig)
		}
		if v.SignatureValid {
			t.Fatalf("signature reported valid for random bytes")
		}
	})
}
