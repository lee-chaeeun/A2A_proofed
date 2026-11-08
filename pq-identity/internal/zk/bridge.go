package zk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// Bridge calls the pinned prover/verifier CLIs with JSON on stdin and bounded JSON on
// stdout. No shell interpolation; nonzero exit, parse failure, oversized output or
// unknown schema fail closed. ProverBin/FakeBin are used only by workers; VerifyBin
// by the requester.
type Bridge struct {
	ProverBin string
	VerifyBin string
	FakeBin   string
	Timeout   time.Duration
	MaxOutput int64 // bytes of stdout accepted
	CacheDir  string
	// ImageIDHex is the guest image id EMBEDDED IN THE LOCAL PROVER BUILD, resolved
	// from `ProverBin --image-id` before any cache use (ResolveImageID). It names the
	// cache namespace and is compared with every cached and fresh prover response.
	// It is the worker's build identity, never the requester's verification anchor.
	ImageIDHex string
}

const MaxReceiptBytes = 2 << 20 // 2 MiB cap on transported receipt bytes

// CacheVersion names the image-qualified cache layout: <CacheDir>/v2/<image id>/<key>.json.
// Flat entries directly under CacheDir are the unqualified v1 layout; they are never read.
const CacheVersion = "v2"

var imageIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ProveRequest is the private witness plus the public challenge.
type ProveRequest struct {
	Portfolio    string    `json:"portfolio"`
	Version      uint32    `json:"version"`
	SaltHex      string    `json:"salt_hex"`
	Holdings     [4]uint32 `json:"holdings"`
	ChallengeHex string    `json:"challenge_hex"`
}

type ProveResponse struct {
	OK            bool   `json:"ok"`
	Fake          bool   `json:"fake,omitempty"`
	ImageIDHex    string `json:"image_id_hex"`
	ReceiptB64    string `json:"receipt_b64"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	JournalHex    string `json:"journal_hex"`
	ProveMS       uint64 `json:"prove_ms"`
	Error         string `json:"error,omitempty"`
	Cached        bool   `json:"cached,omitempty"`
}

type verifyResponse struct {
	OK            bool   `json:"ok"`
	Verified      bool   `json:"verified"`
	JournalHex    string `json:"journal_hex"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	ReceiptKind   string `json:"receipt_kind"`
	VerifyMS      uint64 `json:"verify_ms"`
	Error         string `json:"error,omitempty"`
}

func (b *Bridge) run(ctx context.Context, bin string, args []string, in any) ([]byte, int, error) {
	if b.Timeout == 0 {
		b.Timeout = 10 * time.Minute
	}
	if b.MaxOutput == 0 {
		b.MaxOutput = 8 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	payload, err := json.Marshal(in)
	if err != nil {
		return nil, -1, err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(payload)
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: b.MaxOutput}
	cmd.Stderr = &limitedWriter{w: &bytes.Buffer{}, n: 1 << 16}
	cmd.Env = append(os.Environ(), "RISC0_DEV_MODE=0") // belt and braces: both CLIs also refuse dev mode themselves
	err = cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			return out.Bytes(), -1, fmt.Errorf("%s: %w", filepath.Base(bin), err)
		}
	}
	return out.Bytes(), code, nil
}

type limitedWriter struct {
	w interface{ Write([]byte) (int, error) }
	n int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		return 0, errors.New("output limit exceeded")
	}
	l.n -= int64(len(p))
	return l.w.Write(p)
}

// ResolveImageID asks the local prover build for its embedded guest image id and
// stores it as the bridge's build identity. It fails on any malformed answer.
func (b *Bridge) ResolveImageID(ctx context.Context) (string, error) {
	out, code, err := b.run(ctx, b.ProverBin, []string{"--image-id"}, map[string]any{})
	if err != nil {
		return "", err
	}
	var r struct {
		ImageIDHex string `json:"image_id_hex"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &r) != nil || code != 0 || !imageIDRe.MatchString(r.ImageIDHex) {
		return "", fmt.Errorf("prover build identity unavailable or invalid (exit %d): %s", code, firstLine(out))
	}
	b.ImageIDHex = r.ImageIDHex
	return r.ImageIDHex, nil
}

// cacheKey is the image-qualified cache path for a request.
func (b *Bridge) cacheKey(req ProveRequest) string {
	kb, _ := json.Marshal(req)
	h := sha256.Sum256(kb)
	return filepath.Join(b.CacheDir, CacheVersion, b.ImageIDHex, hex.EncodeToString(h[:])+".json")
}

// validateProveResponse checks a fresh or cached prover response against the request
// and the build identity and returns the decoded receipt bytes.
func validateProveResponse(r *ProveResponse, req ProveRequest, imageIDHex string) ([]byte, error) {
	if !r.OK {
		return nil, errors.New("response not ok")
	}
	if imageIDHex != "" && r.ImageIDHex != imageIDHex {
		return nil, fmt.Errorf("response image id %q is not the build identity %q", r.ImageIDHex, imageIDHex)
	}
	raw, err := base64.StdEncoding.DecodeString(r.ReceiptB64)
	if err != nil || len(raw) == 0 {
		return nil, errors.New("receipt not decodable")
	}
	if len(raw) > MaxReceiptBytes {
		return nil, fmt.Errorf("receipt %d bytes exceeds the %d-byte bound", len(raw), MaxReceiptBytes)
	}
	sum := sha256.Sum256(raw)
	if r.ReceiptSHA256 != hex.EncodeToString(sum[:]) {
		return nil, errors.New("receipt hash does not match the receipt bytes")
	}
	jb, err := hex.DecodeString(r.JournalHex)
	if err != nil {
		return nil, errors.New("journal not hex")
	}
	j, err := ParseJournal(jb)
	if err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	want, err := hex.DecodeString(req.ChallengeHex)
	if err != nil || !bytes.Equal(want, j.Challenge[:]) {
		return nil, errors.New("journal challenge is not the requested challenge")
	}
	return raw, nil
}

// Prove returns a genuine receipt. With a cache directory the entry is looked up and
// stored under the prover build's embedded image id (resolved first; the call fails
// closed if that identity is unavailable) and all proof inputs; a cached entry is
// served only if it carries that image id, a receipt matching its hash and a journal
// for the requested challenge. The returned receipt bytes are the transport form.
func (b *Bridge) Prove(ctx context.Context, req ProveRequest, fake bool) (*ProveResponse, []byte, error) {
	if fake {
		return b.proveFake(ctx, req)
	}
	key := ""
	if b.CacheDir != "" {
		if b.ImageIDHex == "" {
			if _, err := b.ResolveImageID(ctx); err != nil {
				return nil, nil, fmt.Errorf("proof cache requested but the prover build identity could not be resolved: %w", err)
			}
		}
		key = b.cacheKey(req)
		if cb, err := os.ReadFile(key); err == nil {
			var r ProveResponse
			if json.Unmarshal(cb, &r) == nil {
				if raw, verr := validateProveResponse(&r, req, b.ImageIDHex); verr == nil {
					r.Cached = true
					return &r, raw, nil
				}
			}
			// invalid or foreign entry: ignored and overwritten below
		}
	}
	out, code, err := b.run(ctx, b.ProverBin, nil, req)
	if err != nil {
		return nil, nil, err
	}
	var r ProveResponse
	if json.Unmarshal(bytes.TrimSpace(out), &r) != nil || !r.OK || code != 0 {
		return nil, nil, fmt.Errorf("prover failed (exit %d): %s", code, firstLine(out))
	}
	raw, err := validateProveResponse(&r, req, b.ImageIDHex)
	if err != nil {
		return nil, nil, fmt.Errorf("prover output: %w", err)
	}
	if key != "" {
		os.MkdirAll(filepath.Dir(key), 0o755)
		os.WriteFile(key, out, 0o644)
	}
	return &r, raw, nil
}

// proveFake runs the labelled test-only dev-mode tool (never cached, never validated
// as genuine; the requester's verifier rejects its output).
func (b *Bridge) proveFake(ctx context.Context, req ProveRequest) (*ProveResponse, []byte, error) {
	out, code, err := b.run(ctx, b.FakeBin, nil, req)
	if err != nil {
		return nil, nil, err
	}
	var r ProveResponse
	if json.Unmarshal(bytes.TrimSpace(out), &r) != nil || !r.OK || code != 0 {
		return nil, nil, fmt.Errorf("fake prover failed (exit %d): %s", code, firstLine(out))
	}
	raw, err := base64.StdEncoding.DecodeString(r.ReceiptB64)
	if err != nil || len(raw) == 0 || len(raw) > MaxReceiptBytes {
		return nil, nil, errors.New("fake prover output: receipt not usable")
	}
	return &r, raw, nil
}

// Verify runs the pinned verifier with the CALLER's expected image id and returns the
// verified journal. Any failure (nonzero exit, parse error, verified=false, schema
// mismatch) is returned as an error; the journal is never read from an unverified receipt.
func (b *Bridge) Verify(ctx context.Context, receipt []byte, expectedImageIDHex string) (*Verified, error) {
	if len(receipt) == 0 || len(receipt) > MaxReceiptBytes {
		return nil, fmt.Errorf("receipt size %d out of bounds", len(receipt))
	}
	sum := sha256.Sum256(receipt)
	out, code, err := b.run(ctx, b.VerifyBin, nil, map[string]any{"receipt_b64": base64.StdEncoding.EncodeToString(receipt), "expected_image_id_hex": expectedImageIDHex})
	if err != nil {
		return nil, err
	}
	var r verifyResponse
	if json.Unmarshal(bytes.TrimSpace(out), &r) != nil {
		return nil, fmt.Errorf("verifier output unparseable (exit %d): %s", code, firstLine(out))
	}
	if !r.OK {
		return nil, fmt.Errorf("verifier rejected the input (exit %d): %s", code, r.Error)
	}
	if !r.Verified || code != 0 {
		return nil, fmt.Errorf("receipt did not verify (exit %d, kind %s): %s", code, r.ReceiptKind, r.Error)
	}
	if r.ReceiptSHA256 != hex.EncodeToString(sum[:]) {
		return nil, errors.New("verifier reported a different receipt hash")
	}
	jb, err := hex.DecodeString(r.JournalHex)
	if err != nil {
		return nil, errors.New("verifier journal not hex")
	}
	j, err := ParseJournal(jb)
	if err != nil {
		return nil, fmt.Errorf("verified journal has an unknown schema: %w", err)
	}
	return &Verified{ReceiptSHA256: r.ReceiptSHA256, Journal: j, JournalHex: r.JournalHex}, nil
}

func firstLine(b []byte) string {
	s := string(bytes.TrimSpace(b))
	if i := bytes.IndexByte([]byte(s), '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
