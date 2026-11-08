// Package pqdev drives an ML-DSA key inside a TPM 2.0 v1.85 emulator through the
// pqtpm command-line bridge (tools/pqtpm, wolfTPM client library). The private key is
// created by and stays inside the emulator; this package sees only the public key, the
// persistent handle, the authValue file path and signatures. There is no software
// fallback: when the bridge fails, Sign returns an error.
package pqdev

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// Device is one emulator instance (host:port) and one persistent key handle.
type Device struct {
	Bin      string // path to pqtpm
	Host     string // default 127.0.0.1
	Port     int    // fwtpm_server command port
	Handle   uint32 // persistent handle, e.g. 0x81010001
	AuthFile string // file holding the key's authValue (never logged)
	Timeout  time.Duration
}

// Command is one TPM command the bridge issued (code, response code, microseconds).
type Command struct {
	Name string `json:"name"`
	CC   string `json:"cc"`
	RC   string `json:"rc"`
	US   int64  `json:"us"`
}

type Result struct {
	OK           bool      `json:"ok"`
	Op           string    `json:"op"`
	Error        string    `json:"error,omitempty"`
	RC           string    `json:"rc,omitempty"`
	RCText       string    `json:"rc_text,omitempty"`
	Handle       string    `json:"handle,omitempty"`
	Alg          string    `json:"alg,omitempty"`
	ParamSet     int       `json:"param_set,omitempty"`
	ParamSetID   int       `json:"param_set_id,omitempty"`
	Attributes   string    `json:"attributes,omitempty"`
	PublicKeyHex string    `json:"public_key_hex,omitempty"`
	PublicKeyLen int       `json:"public_key_len,omitempty"`
	NameHex      string    `json:"name_hex,omitempty"`
	SignatureHex string    `json:"signature_hex,omitempty"`
	SignatureLen int       `json:"signature_len,omitempty"`
	Verified     bool      `json:"verified,omitempty"`
	Commands     []Command `json:"commands"`
	WallUS       int64     `json:"bridge_wall_us"` // measured here: process start to exit
}

func (d *Device) run(ctx context.Context, args ...string) (*Result, error) {
	to := d.Timeout
	if to == 0 {
		to = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	host := d.Host
	if host == "" {
		host = "127.0.0.1"
	}
	full := append([]string{"--host", host, "--port", strconv.Itoa(d.Port)}, args...)
	t0 := time.Now()
	cmd := exec.CommandContext(ctx, d.Bin, full...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	var r Result
	if json.Unmarshal(bytes.TrimSpace(out.Bytes()), &r) != nil {
		if runErr != nil {
			return nil, fmt.Errorf("pqtpm: %v: %s", runErr, bytes.TrimSpace(errb.Bytes()))
		}
		return nil, errors.New("pqtpm: unparseable output")
	}
	r.WallUS = time.Since(t0).Microseconds()
	if !r.OK {
		return &r, fmt.Errorf("pqtpm %s failed: %s (%s %s)", r.Op, r.Error, r.RC, r.RCText)
	}
	return &r, nil
}

// Create creates the ML-DSA-65 primary key inside the emulator and makes it persistent
// at d.Handle, with the authValue read from d.AuthFile. Returns the public key bytes.
func (d *Device) Create(ctx context.Context) (*Result, []byte, error) {
	r, err := d.run(ctx, "create", "--persist", fmt.Sprintf("0x%08x", d.Handle), "--auth-file", d.AuthFile, "--param", "65")
	if err != nil {
		return r, nil, err
	}
	pk, err := hex.DecodeString(r.PublicKeyHex)
	return r, pk, err
}

// Public reads the public key of the persistent handle.
func (d *Device) Public(ctx context.Context) (*Result, []byte, error) {
	r, err := d.run(ctx, "pub", "--handle", fmt.Sprintf("0x%08x", d.Handle))
	if err != nil {
		return r, nil, err
	}
	pk, err := hex.DecodeString(r.PublicKeyHex)
	return r, pk, err
}

// Sign produces a pure ML-DSA signature over msg with the FIPS 204 context string ctx.
func (d *Device) Sign(ctx context.Context, msg, fipsCtx []byte) (*Result, []byte, error) {
	args := []string{"sign", "--handle", fmt.Sprintf("0x%08x", d.Handle), "--auth-file", d.AuthFile, "--msg-hex", hex.EncodeToString(msg)}
	if len(fipsCtx) > 0 {
		args = append(args, "--ctx-hex", hex.EncodeToString(fipsCtx))
	}
	r, err := d.run(ctx, args...)
	if err != nil {
		return r, nil, err
	}
	sig, err := hex.DecodeString(r.SignatureHex)
	return r, sig, err
}

// VerifyInDevice asks the emulator itself to verify (diagnostic; the requester never
// relies on it).
func (d *Device) VerifyInDevice(ctx context.Context, msg, fipsCtx, sig []byte) (*Result, error) {
	args := []string{"verify", "--handle", fmt.Sprintf("0x%08x", d.Handle), "--msg-hex", hex.EncodeToString(msg), "--sig-hex", hex.EncodeToString(sig)}
	if len(fipsCtx) > 0 {
		args = append(args, "--ctx-hex", hex.EncodeToString(fipsCtx))
	}
	r, err := d.run(ctx, args...)
	if err != nil && r != nil && r.Op == "verify" {
		return r, nil // verified=false is a result, not a bridge failure
	}
	return r, err
}

// Evict deletes the persistent key (tests / re-provisioning).
func (d *Device) Evict(ctx context.Context) error {
	_, err := d.run(ctx, "evict", "--handle", fmt.Sprintf("0x%08x", d.Handle))
	return err
}
