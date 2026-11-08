package pqdev

// Opt-in device test (A2AID_PQ_DEVICE=1): needs a running fwtpm_server (default port
// 2361 to avoid the lab's instances; set A2AID_PQ_DEVICE_PORT) and the built pqtpm.
// It exercises the real command path: create a fresh ML-DSA-65 key inside the
// emulator, read its public key, sign, verify the signature OUTSIDE the emulator with
// CIRCL, reject a wrong authValue, a tampered message and a tampered signature, and
// confirm the public key survives an emulator restart. It evicts its own key at the end.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestDevice_CreateSignVerifyRestart(t *testing.T) {
	if os.Getenv("A2AID_PQ_DEVICE") == "" {
		t.Skip("set A2AID_PQ_DEVICE=1 (needs fwtpm_server and tools/pqtpm/pqtpm)")
	}
	root, _ := filepath.Abs("../..")
	port := 2361
	if p := os.Getenv("A2AID_PQ_DEVICE_PORT"); p != "" {
		port, _ = strconv.Atoi(p)
	}
	dir := t.TempDir()
	fw, err := StartFWTPM(DefaultBin(root), dir, port, true)
	if err != nil {
		t.Fatal(err)
	}
	defer fw.Stop()
	auth := filepath.Join(dir, "auth")
	os.WriteFile(auth, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("ffffffffffffffffffffffffffffffff\n"), 0o600)
	d := &Device{Bin: DefaultBridge(root), Port: port, Handle: 0x81010077, AuthFile: auth}
	ctx := context.Background()
	cr, pub, err := d.Create(ctx)
	if err != nil || len(pub) != mldsa65.PublicKeySize {
		t.Fatalf("create: %v (%d bytes)", err, len(pub))
	}
	if cr.Attributes != "0x00040472" {
		t.Fatalf("object attributes %s (expected fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|noDA|sign)", cr.Attributes)
	}
	msg := []byte("a2aid device test message")
	fctx := []byte("a2aid-proof-v4")
	sr, sig, err := d.Sign(ctx, msg, fctx)
	if err != nil || len(sig) != mldsa65.SignatureSize {
		t.Fatalf("sign: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range sr.Commands {
		seen[c.Name] = true
	}
	if !seen["TPM2_SignSequenceStart"] || !seen["TPM2_SignSequenceComplete"] {
		t.Fatalf("expected the sign-sequence commands in the trace: %+v", sr.Commands)
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pub); err != nil || !mldsa65.Verify(&pk, msg, fctx, sig) {
		t.Fatal("device signature does not verify with CIRCL")
	}
	if mldsa65.Verify(&pk, append(msg, 0), fctx, sig) || mldsa65.Verify(&pk, msg, []byte("x"), sig) {
		t.Fatal("tampered message / other context verified")
	}
	s2 := append([]byte(nil), sig...)
	s2[7] ^= 1
	if mldsa65.Verify(&pk, msg, fctx, s2) {
		t.Fatal("tampered signature verified")
	}
	// wrong authValue: the emulator refuses the command (no signature is produced)
	dbad := *d
	dbad.AuthFile = bad
	if r, _, err := dbad.Sign(ctx, msg, fctx); err == nil || r == nil || r.RCText != "TPM_RC_BAD_AUTH" {
		t.Fatalf("wrong auth: err=%v r=%+v", err, r)
	}
	// persistence across a restart
	fw.Stop()
	fw2, err := StartFWTPM(DefaultBin(root), dir, port, false)
	if err != nil {
		t.Fatal(err)
	}
	defer fw2.Stop()
	_, pub2, err := d.Public(ctx)
	if err != nil || string(pub2) != string(pub) {
		t.Fatalf("public key changed after restart: %v", err)
	}
	if err := d.Evict(ctx); err != nil {
		t.Fatal(err)
	}
}
