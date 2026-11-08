package zk

// UNIT TESTS of the proof-cache mechanics with controlled prover STUBS (no proving,
// no genuine receipts; the genuine receipts of the retained runs are the
// cryptographic controls). The test binary re-executes itself as the stub.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const stubEnvImage, stubEnvLog, stubEnvBadID, stubEnvRespImage = "A2AID_ZK_STUB_PROVER_IMAGE", "A2AID_ZK_STUB_LOG", "A2AID_ZK_STUB_BAD_ID", "A2AID_ZK_STUB_RESPONSE_IMAGE"

func TestMain(m *testing.M) {
	if img := os.Getenv(stubEnvImage); img != "" {
		stubProver(img)
		return
	}
	os.Exit(m.Run())
}

func stubProver(img string) {
	if len(os.Args) > 1 && os.Args[1] == "--image-id" {
		if os.Getenv(stubEnvBadID) != "" {
			fmt.Println("not json at all")
			os.Exit(0)
		}
		fmt.Println(`{"image_id_hex":"` + img + `"}`)
		os.Exit(0)
	}
	in, _ := io.ReadAll(os.Stdin)
	var req ProveRequest
	if err := json.Unmarshal(in, &req); err != nil {
		fmt.Println(`{"ok":false,"error":"bad request"}`)
		os.Exit(1)
	}
	if lg := os.Getenv(stubEnvLog); lg != "" {
		f, _ := os.OpenFile(lg, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		fmt.Fprintf(f, "prove %s %s\n", img, req.ChallengeHex)
		f.Close()
	}
	respImg := img
	if r := os.Getenv(stubEnvRespImage); r != "" {
		respImg = r
	}
	receipt := []byte("stub receipt for " + respImg + " " + req.ChallengeHex)
	sum := sha256.Sum256(receipt)
	j := make([]byte, JournalLen)
	binary.LittleEndian.PutUint32(j[0:4], 1)
	ch, _ := hex.DecodeString(req.ChallengeHex)
	copy(j[4:20], ch)
	binary.LittleEndian.PutUint64(j[52:60], Limit)
	j[60] = 1
	out, _ := json.Marshal(ProveResponse{OK: true, ImageIDHex: respImg, ReceiptB64: base64.StdEncoding.EncodeToString(receipt), ReceiptSHA256: hex.EncodeToString(sum[:]), JournalHex: hex.EncodeToString(j), ProveMS: 1})
	fmt.Println(string(out))
	os.Exit(0)
}

// makeStub writes a shell wrapper that re-executes this test binary as a prover stub
// with the given embedded image id.
func makeStub(t *testing.T, dir, name, img string, extraEnv ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := []string{stubEnvImage + "=" + img, stubEnvLog + "=" + filepath.Join(dir, "stub.log")}
	env = append(env, extraEnv...)
	p := filepath.Join(dir, name)
	script := "#!/bin/sh\nexec env " + strings.Join(env, " ") + " " + exe + " \"$@\"\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func proveCount(t *testing.T, dir, img string) int {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, "stub.log"))
	return strings.Count(string(b), "prove "+img+" ")
}

var (
	imgA = strings.Repeat("a", 64)
	imgB = strings.Repeat("b", 64)
)

func TestCache_TwoBuildsAreNamespacedByImageID(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	stubA := makeStub(t, dir, "proverA", imgA)
	stubB := makeStub(t, dir, "proverB", imgB)
	req := ProveRequest{Portfolio: "p", Version: 1, SaltHex: hex.EncodeToString(make([]byte, 32)), Holdings: [4]uint32{1, 2, 3, 4}, ChallengeHex: hex.EncodeToString(make([]byte, 16))}
	ctx := context.Background()
	bA := &Bridge{ProverBin: stubA, CacheDir: cache}
	r1, raw1, err := bA.Prove(ctx, req, false)
	if err != nil || r1.Cached || r1.ImageIDHex != imgA || proveCount(t, dir, imgA) != 1 || bA.ImageIDHex != imgA {
		t.Fatalf("first prove under A: %+v %v count=%d", r1, err, proveCount(t, dir, imgA))
	}
	r2, raw2, err := bA.Prove(ctx, req, false)
	if err != nil || !r2.Cached || r2.ImageIDHex != imgA || proveCount(t, dir, imgA) != 1 || string(raw1) != string(raw2) {
		t.Fatalf("second prove under A must be a cache hit: %+v %v", r2, err)
	}
	// Same inputs, different guest build: the cache MUST NOT serve A's receipt.
	bB := &Bridge{ProverBin: stubB, CacheDir: cache}
	r3, raw3, err := bB.Prove(ctx, req, false)
	if err != nil || r3.Cached || r3.ImageIDHex != imgB || proveCount(t, dir, imgB) != 1 || string(raw3) == string(raw1) {
		t.Fatalf("prove under B must not hit A's entry: %+v %v", r3, err)
	}
	r4, _, _ := bB.Prove(ctx, req, false)
	r5, _, _ := (&Bridge{ProverBin: stubA, CacheDir: cache}).Prove(ctx, req, false)
	if !r4.Cached || r4.ImageIDHex != imgB || !r5.Cached || r5.ImageIDHex != imgA || proveCount(t, dir, imgA) != 1 || proveCount(t, dir, imgB) != 1 {
		t.Fatalf("each build is served only its own entry: %+v %+v", r4, r5)
	}
	for _, img := range []string{imgA, imgB} {
		es, _ := os.ReadDir(filepath.Join(cache, CacheVersion, img))
		if len(es) != 1 {
			t.Fatalf("expected one entry under v2/%s", img[:4])
		}
	}
	if es, _ := os.ReadDir(cache); len(es) != 1 || es[0].Name() != CacheVersion {
		t.Fatalf("no flat (unqualified) entries may be written: %v", es)
	}
}

func TestCache_TamperedEntryIsReproved(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	stub := makeStub(t, dir, "prover", imgA)
	req := ProveRequest{Portfolio: "p", Version: 1, SaltHex: hex.EncodeToString(make([]byte, 32)), Holdings: [4]uint32{1, 2, 3, 4}, ChallengeHex: hex.EncodeToString(make([]byte, 16))}
	b := &Bridge{ProverBin: stub, CacheDir: cache}
	if _, _, err := b.Prove(context.Background(), req, false); err != nil {
		t.Fatal(err)
	}
	key := b.cacheKey(req)
	for _, mut := range []func(*ProveResponse){
		func(r *ProveResponse) { r.ReceiptSHA256 = strings.Repeat("0", 64) },                                // hash no longer matches the bytes
		func(r *ProveResponse) { r.ImageIDHex = imgB },                                                      // foreign image id
		func(r *ProveResponse) { r.ReceiptB64 = base64.StdEncoding.EncodeToString([]byte("x")) },            // bytes changed
		func(r *ProveResponse) { r.JournalHex = r.JournalHex[:10] },                                         // journal unparsable
		func(r *ProveResponse) { r.JournalHex = "01000000" + strings.Repeat("ff", 16) + r.JournalHex[40:] }, // other challenge
	} {
		cb, _ := os.ReadFile(key)
		var r ProveResponse
		json.Unmarshal(cb, &r)
		mut(&r)
		mb, _ := json.Marshal(r)
		os.WriteFile(key, mb, 0o644)
		before := proveCount(t, dir, imgA)
		res, _, err := b.Prove(context.Background(), req, false)
		if err != nil || res.Cached || proveCount(t, dir, imgA) != before+1 {
			t.Fatalf("tampered entry must be ignored and re-proved: %+v %v", res, err)
		}
	}
}

func TestCache_LegacyFlatEntryIsNeverRead(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	os.MkdirAll(cache, 0o755)
	stub := makeStub(t, dir, "prover", imgA)
	req := ProveRequest{Portfolio: "p", Version: 1, SaltHex: hex.EncodeToString(make([]byte, 32)), Holdings: [4]uint32{1, 2, 3, 4}, ChallengeHex: hex.EncodeToString(make([]byte, 16))}
	// an unqualified entry (no image id in the key): key = sha256("|" + inputs)
	kb, _ := json.Marshal(req)
	h := sha256.Sum256(append([]byte("|"), kb...))
	legacy := ProveResponse{OK: true, ImageIDHex: imgA, ReceiptB64: base64.StdEncoding.EncodeToString([]byte("unqualified")), ReceiptSHA256: "x", JournalHex: "00"}
	lb, _ := json.Marshal(legacy)
	os.WriteFile(filepath.Join(cache, hex.EncodeToString(h[:])+".json"), lb, 0o644)
	b := &Bridge{ProverBin: stub, CacheDir: cache}
	res, raw, err := b.Prove(context.Background(), req, false)
	if err != nil || res.Cached || string(raw) == "unqualified" || proveCount(t, dir, imgA) != 1 {
		t.Fatalf("unqualified entry must not be served: %+v %v", res, err)
	}
}

func TestCache_UnresolvableBuildIdentityFailsClosed(t *testing.T) {
	dir := t.TempDir()
	stub := makeStub(t, dir, "prover", imgA, stubEnvBadID+"=1")
	req := ProveRequest{Portfolio: "p", Version: 1, SaltHex: hex.EncodeToString(make([]byte, 32)), Holdings: [4]uint32{1, 2, 3, 4}, ChallengeHex: hex.EncodeToString(make([]byte, 16))}
	b := &Bridge{ProverBin: stub, CacheDir: filepath.Join(dir, "cache")}
	if _, _, err := b.Prove(context.Background(), req, false); err == nil || !strings.Contains(err.Error(), "build identity") || proveCount(t, dir, imgA) != 0 {
		t.Fatalf("cache with unresolvable identity must fail closed before proving: %v", err)
	}
	// Without a cache the prover still runs (no identity needed) and its output is validated.
	b2 := &Bridge{ProverBin: stub}
	if res, _, err := b2.Prove(context.Background(), req, false); err != nil || res.Cached {
		t.Fatalf("no cache: %+v %v", res, err)
	}
}

func TestCache_ProverResponseMustMatchBuildIdentity(t *testing.T) {
	dir := t.TempDir()
	stub := makeStub(t, dir, "prover", imgA, stubEnvRespImage+"="+imgB) // --image-id says A, responses claim B
	req := ProveRequest{Portfolio: "p", Version: 1, SaltHex: hex.EncodeToString(make([]byte, 32)), Holdings: [4]uint32{1, 2, 3, 4}, ChallengeHex: hex.EncodeToString(make([]byte, 16))}
	b := &Bridge{ProverBin: stub, CacheDir: filepath.Join(dir, "cache")}
	if _, _, err := b.Prove(context.Background(), req, false); err == nil || !strings.Contains(err.Error(), "build identity") {
		t.Fatalf("a response with another image id than the build must be rejected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cache", CacheVersion, imgA)); err == nil {
		if es, _ := os.ReadDir(filepath.Join(dir, "cache", CacheVersion, imgA)); len(es) != 0 {
			t.Fatal("rejected response must not be cached")
		}
	}
}
