package gate

// Unit tests of the "env" signer protocol (in-process; no TPM): algorithm pinning per
// signer, token check, ES256 and software ML-DSA-65 backends, refusal of a mismatching
// algorithm request. The device backend is covered by the pqdev opt-in test and the
// networked matrix.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"

	"a2aid/internal/ctl"
	"a2aid/internal/pqsig"
)

func startEnvSigner(t *testing.T, s *Signer) string {
	t.Helper()
	g := New(ctl.Nop())
	g.acl[s.Name] = []string{"unregistered"} // any caller in this unit test
	s.Listen = filepath.Join(t.TempDir(), s.Name+".sock")
	ln, err := net.Listen("unix", s.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go g.accept(ln, s)
	t.Cleanup(func() { ln.Close() })
	return s.Listen
}

func TestEnvSigner_ES256AndMLDSA(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	seed, _ := pqsig.NewMLDSASeed()
	pk, sk, _ := pqsig.MLDSAKeyFromSeed(seed)
	ecSock := startEnvSigner(t, &Signer{Name: "ecT", Kind: "env", Alg: pqsig.AlgES256, Custody: "gated-service", Key: ec, Token: "tok"})
	pqSock := startEnvSigner(t, &Signer{Name: "pqT", Kind: "env", Alg: pqsig.AlgMLDSA, Custody: "gated-service", MLDSA: sk, Token: "tok"})
	ctx := &pqsig.Context{V: pqsig.Format, Role: pqsig.Role, Policy: "PQ-env+cb", Alg: pqsig.AlgMLDSA, KID: "T-pqenv-k1", Expected: "dep-T", Requester: "requester:a2aid-lab", Action: "release-synthetic-job", Nonce: make([]byte, 32), Expiry: 1_800_000_000, Session: "s", Exporter: make([]byte, 32)}
	msg, _ := pqsig.Encode(ctx)
	sig, resp, err := SignV4ViaGate(pqSock, "tok", pqsig.AlgMLDSA, msg, []byte(pqsig.CtxString))
	if err != nil || !pqsig.VerifyMLDSA(pqsig.MLDSAPublicBytes(pk), msg, sig) || resp.Custody != "gated-service" {
		t.Fatalf("mldsa via gate: %v", err)
	}
	ctx.Alg = pqsig.AlgES256
	msg2, _ := pqsig.Encode(ctx)
	sig2, _, err := SignV4ViaGate(ecSock, "tok", pqsig.AlgES256, msg2, nil)
	if err != nil || !pqsig.VerifyES256(&ec.PublicKey, msg2, sig2) {
		t.Fatalf("es256 via gate: %v", err)
	}
	// algorithm confusion is refused by the signer, not silently served
	if _, _, err := SignV4ViaGate(pqSock, "tok", pqsig.AlgES256, msg, nil); err == nil {
		t.Fatal("ML-DSA signer served an ES256 request")
	}
	if _, _, err := SignV4ViaGate(ecSock, "tok", pqsig.AlgMLDSA, msg, []byte(pqsig.CtxString)); err == nil {
		t.Fatal("ES256 signer served an ML-DSA request")
	}
	// wrong token
	if _, _, err := SignV4ViaGate(pqSock, "nope", pqsig.AlgMLDSA, msg, []byte(pqsig.CtxString)); err == nil {
		t.Fatal("wrong token accepted")
	}
	// wrong FIPS 204 context string for the software ML-DSA backend
	if _, _, err := SignV4ViaGate(pqSock, "tok", pqsig.AlgMLDSA, msg, []byte("other")); err == nil {
		t.Fatal("other context string accepted")
	}
	// oversized message
	if _, _, err := SignV4ViaGate(pqSock, "tok", pqsig.AlgMLDSA, make([]byte, pqsig.MaxContextLen+1), []byte(pqsig.CtxString)); err == nil {
		t.Fatal("oversized message accepted")
	}
}
