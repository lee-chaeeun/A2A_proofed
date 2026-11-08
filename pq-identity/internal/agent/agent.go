// Package agent runs one scripted A2A deployment (honest A, or B in a configured
// attack mode) on real a2a-go v2 JSON-RPC endpoints (plain HTTP and HTTPS).
package agent

import (
	"github.com/fxamacker/cbor/v2"

	"a2aid/internal/pqsig"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"iter"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/google/go-tpm/tpm2"

	"a2aid/internal/ctl"
	"a2aid/internal/gate"
	"a2aid/internal/ptv"
	"a2aid/internal/senv"
	"a2aid/internal/tpmsig"
	"a2aid/internal/wire"
)

// AppConfig lives inside the application volume (copied in F5/F7/F19).
type AppConfig struct {
	DeploymentID string `json:"deployment_id"`
	SFileKeyID   string `json:"sfile_key_id"`
	SFileKeyFile string `json:"sfile_key_file"` // relative to app dir; exportable, inside the volume
	SIsoKeyID    string `json:"siso_key_id"`
	TPMGateSock  string `json:"tpm_gate_sock"` // socket paths are configuration, not secrets
	SIsoGateSock string `json:"siso_gate_sock"`
	// a2aid-proof-v4 credentials (PQ identity, 2026-11-08). Gate sockets are
	// configuration; the PQ-file seed is INSIDE the volume (copied with it); the
	// tokens for the env signers live in the signer dir (outside the volume).
	ECEnvGateSock    string `json:"ecenv_gate_sock,omitempty"`
	PQEnvGateSock    string `json:"pqenv_gate_sock,omitempty"`
	PQDeviceGateSock string `json:"pqdev_gate_sock,omitempty"`
	PQFileSeedFile   string `json:"pqfile_seed_file,omitempty"`
	ECEnvKeyID       string `json:"ecenv_key_id,omitempty"`
	PQEnvKeyID       string `json:"pqenv_key_id,omitempty"`
	PQFileKeyID      string `json:"pqfile_key_id,omitempty"`
	PQDeviceKeyID    string `json:"pqdev_key_id,omitempty"`
}

// Materials is everything an agent process can use to answer a challenge.
type Materials struct {
	Source       string // "own", "copied-volume", "copied-volume+secrets", "copied-volume+ak-auth"
	DeploymentID string
	SFileKey     *ecdsa.PrivateKey
	SFileKeyID   string
	SIsoKeyID    string
	TPMGate      string
	SIsoGate     string
	AKAuth       []byte // from signer dir (outside the volume)
	SIsoToken    string // from signer dir
	// a2aid-proof-v4
	V4Gates    map[string]string // base -> gate socket (EC-env, PQ-env, PQ-device)
	V4KIDs     map[string]string // base -> key id (incl. PQ-file)
	PQFileSeed []byte            // from the volume (PQ-file custody)
	EnvToken   string            // from signer dir: token for the env signers
}

func LoadMaterials(appDir, signerDir, source string, akAuthOnly bool) (*Materials, error) {
	b, err := os.ReadFile(filepath.Join(appDir, "config.json"))
	if err != nil {
		return nil, err
	}
	var cfg AppConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	m := &Materials{Source: source, DeploymentID: cfg.DeploymentID, SFileKeyID: cfg.SFileKeyID, SIsoKeyID: cfg.SIsoKeyID, TPMGate: cfg.TPMGateSock, SIsoGate: cfg.SIsoGateSock,
		V4Gates: map[string]string{wire.PolicyECEnv: cfg.ECEnvGateSock, wire.PolicyPQEnv: cfg.PQEnvGateSock, wire.PolicyPQDevice: cfg.PQDeviceGateSock},
		V4KIDs:  map[string]string{wire.PolicyECEnv: cfg.ECEnvKeyID, wire.PolicyPQEnv: cfg.PQEnvKeyID, wire.PolicyPQFile: cfg.PQFileKeyID, wire.PolicyPQDevice: cfg.PQDeviceKeyID}}
	if cfg.PQFileSeedFile != "" {
		if sb, err := os.ReadFile(filepath.Join(appDir, cfg.PQFileSeedFile)); err == nil {
			if seed, err := hex.DecodeString(strings.TrimSpace(string(sb))); err == nil && len(seed) == pqsig.SeedSize {
				m.PQFileSeed = seed
			}
		}
	}
	if kb, err := os.ReadFile(filepath.Join(appDir, cfg.SFileKeyFile)); err == nil {
		if k, err := ParseECPrivatePEM(kb); err == nil {
			m.SFileKey = k
		}
	}
	if signerDir != "" {
		if a, err := os.ReadFile(filepath.Join(signerDir, "ak_auth")); err == nil {
			m.AKAuth = []byte(strings.TrimSpace(string(a)))
		}
		if !akAuthOnly {
			if t, err := os.ReadFile(filepath.Join(signerDir, "siso_token")); err == nil {
				m.SIsoToken = strings.TrimSpace(string(t))
			}
			if t, err := os.ReadFile(filepath.Join(signerDir, "env_token")); err == nil {
				m.EnvToken = strings.TrimSpace(string(t))
			}
		}
	}
	return m, nil
}

func ParseECPrivatePEM(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM")
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

// Mode is set by the runner over the admin endpoint before each cell.
type Mode struct {
	Mode              string            `json:"mode"` // honest|replay|copied-volume|socket-access|relay|tamper|unknown-key|invalid
	CardPath          string            `json:"card_path,omitempty"`
	RelayTo           string            `json:"relay_to,omitempty"`
	RelayResolve      map[string]string `json:"relay_resolve,omitempty"` // lab name resolution for the relay client
	ReplayEvidence    map[string]any    `json:"replay_evidence,omitempty"`
	ForeignAppDir     string            `json:"foreign_app_dir,omitempty"`
	ForeignSignerDir  string            `json:"foreign_signer_dir,omitempty"`
	ForeignAKAuthOnly bool              `json:"foreign_ak_auth_only,omitempty"`
	TamperDeltaSec    int               `json:"tamper_delta_sec,omitempty"`
	TLSIdentityDir    string            `json:"tls_identity_dir,omitempty"` // present another deployment's server certificate (stolen TLS credentials)
	InjectCB          bool              `json:"inject_cb,omitempty"`        // relay: put our observed exporter value into the forwarded challenge
	DelayMs           int               `json:"delay_ms,omitempty"`         // artificial processing delay before answering a challenge
	// Binding-downgrade / chosen-nonce relay (v3 P0-A). The relay computes the bound
	// nonce for its OWN connection with the requester and sends that value to A as a
	// plain challenge nonce, turning A into a signing oracle for the exact value the
	// requester will expect. ForwardPolicy overrides the policy sent to A (e.g.
	// downgrade T+cb to plain T); StripBinding omits the binding selector.
	ChosenNonce   bool   `json:"chosen_nonce,omitempty"`
	ForwardPolicy string `json:"forward_policy,omitempty"`
	StripBinding  bool   `json:"strip_binding,omitempty"`
	// PQ identity attack modes (a2aid-proof-v4). TamperContext ("action"|"audience")
	// makes a relay change that field of the forwarded challenge, so the honest signer
	// signs a context the requester did not issue. ClaimKIDPrefix is the enrolled
	// label whose key ids an impostor presents (e.g. "A"). Modes: "impostor-own-keys"
	// (B's genuine enrolled keys under A's kid), "alg-confusion" (swap ES256 and
	// ML-DSA-65, or an unknown algorithm with AlgName), "fresh-pq-key" (an
	// attacker-generated ML-DSA key under A's kid).
	TamperContext  string `json:"tamper_context,omitempty"`
	ClaimKIDPrefix string `json:"claim_kid_prefix,omitempty"`
	AlgName        string `json:"alg_name,omitempty"`
	// Optional ZK worker configuration (proof-carrying task results; see internal/zk).
	ZK *ZKMode `json:"zk,omitempty"`
}

type Agent struct {
	Label     string
	Listen    string
	AppDir    string
	SignerDir string
	Ctl       *ctl.Client
	TLSDir    string // own cert.pem/key.pem
	CAFile    string // lab root for outbound (relay) connections

	mu      sync.Mutex
	mode    Mode
	card    *a2a.AgentCard
	own     *Materials
	foreign *Materials
	ownCert *tls.Certificate
	altCert *tls.Certificate
	tpmMu   sync.Mutex // one TPM operation at a time per process (resource-manager stand-in)
}

func New(label, listen, appDir, signerDir string, c *ctl.Client) (*Agent, error) {
	a := &Agent{Label: label, Listen: listen, AppDir: appDir, SignerDir: signerDir, Ctl: c}
	own, err := LoadMaterials(appDir, signerDir, "own", false)
	if err != nil {
		return nil, err
	}
	a.own = own
	a.mode = Mode{Mode: "honest", CardPath: filepath.Join(appDir, "card.json")}
	if err := a.reloadCard(); err != nil {
		return nil, err
	}
	return a, nil
}

// LoadTLS loads the deployment's own server certificate.
func (a *Agent) LoadTLS(dir string) error {
	c, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		return err
	}
	a.TLSDir, a.ownCert = dir, &c
	return nil
}

// TLSConfig serves the own certificate, or the foreign one when the mode holds
// stolen TLS credentials. TLS 1.3 only so that RFC 9266 exporters are defined.
func (a *Agent) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.altCert != nil {
			return a.altCert, nil
		}
		if a.ownCert == nil {
			return nil, errors.New("no certificate")
		}
		return a.ownCert, nil
	}}
}

func (a *Agent) reloadCard() error {
	b, err := os.ReadFile(a.mode.CardPath)
	if err != nil {
		return err
	}
	var card a2a.AgentCard
	if err := json.Unmarshal(b, &card); err != nil {
		return err
	}
	a.card = &card
	return nil
}

func (a *Agent) Card(ctx context.Context) (*a2a.AgentCard, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.card, nil
}

type tlsKey struct{}

// Handler mounts the A2A JSON-RPC endpoint, the well-known card, and the lab admin
// API. The outer middleware stores the request's TLS connection state in the
// context so the executor can derive the channel binding from ITS OWN connection.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewAgentCardHandler(a))
	mux.HandleFunc("POST /admin/mode", func(w http.ResponseWriter, r *http.Request) {
		var m Mode
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if m.CardPath == "" {
			m.CardPath = filepath.Join(a.AppDir, "card.json")
		}
		a.mode = m
		a.foreign = nil
		a.altCert = nil
		if m.ForeignAppDir != "" {
			src := "copied-volume"
			if m.ForeignSignerDir != "" {
				src = "copied-volume+secrets"
				if m.ForeignAKAuthOnly {
					src = "copied-volume+ak-auth"
				}
			}
			f, err := LoadMaterials(m.ForeignAppDir, m.ForeignSignerDir, src, m.ForeignAKAuthOnly)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			a.foreign = f
		}
		if m.TLSIdentityDir != "" {
			c, err := tls.LoadX509KeyPair(filepath.Join(m.TLSIdentityDir, "cert.pem"), filepath.Join(m.TLSIdentityDir, "key.pem"))
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			a.altCert = &c
		}
		if err := a.reloadCard(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.Ctl.Emit("agent_mode", map[string]any{"label": a.Label, "mode": m.Mode, "card_path": m.CardPath, "foreign_app": m.ForeignAppDir, "foreign_secrets": m.ForeignSignerDir != "", "foreign_ak_auth_only": m.ForeignAKAuthOnly, "relay_to": m.RelayTo, "tls_identity": m.TLSIdentityDir, "inject_cb": m.InjectCB, "delay_ms": m.DelayMs})
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /admin/reload-card", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if err := a.reloadCard(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.Ctl.Emit("card_reloaded", map[string]any{"label": a.Label, "name": a.card.Name, "version": a.card.Version})
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /admin/state", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"label": a.Label, "mode": a.mode.Mode, "card_name": a.card.Name, "card_path": a.mode.CardPath, "tls_identity": a.mode.TLSIdentityDir})
	})
	handler := a2asrv.NewHandler(a)
	mux.Handle("/", a2asrv.NewJSONRPCHandler(handler))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), tlsKey{}, r.TLS)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

// exporter derives the RFC 9266 channel binding from the connection state the
// server itself observed. It never reads anything the client sent.
func exporter(ctx context.Context) ([]byte, bool) {
	cs, _ := ctx.Value(tlsKey{}).(*tls.ConnectionState)
	if cs == nil || !cs.HandshakeComplete {
		return nil, false
	}
	b, err := cs.ExportKeyingMaterial(wire.CBLabel, nil, 32)
	if err != nil {
		return nil, false
	}
	return b, true
}

func dataPart(ec *a2asrv.ExecutorContext) map[string]any {
	if ec.Message == nil {
		return nil
	}
	for _, p := range ec.Message.Parts {
		if d, ok := p.Data().(map[string]any); ok {
			return d
		}
	}
	return nil
}

func (a *Agent) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		if ec.StoredTask == nil {
			if !yield(a2a.NewSubmittedTask(ec, ec.Message), nil) {
				return
			}
		}
		d := dataPart(ec)
		var out map[string]any
		switch fmt.Sprint(d["type"]) {
		case "challenge":
			var ch wire.Challenge
			_ = wire.FromMap(d, &ch)
			out = a.handleChallenge(ctx, ch, d)
		case "zk_task":
			out = a.handleZKTask(ctx, d)
		case "job":
			var job wire.Job
			_ = wire.FromMap(d, &job)
			ack := wire.JobAck{Type: "job_ack", DeploymentID: a.own.DeploymentID, Token: job.Token, ReceivedAtUTC: time.Now().UTC().Format(time.RFC3339Nano)}
			ack.PCRAtReceipt = a.pcrNow()
			rxExp, _ := exporter(ctx) // this server's OWN exporter for the connection the job arrived on
			a.Ctl.Emit("job_received", map[string]any{"recipient": a.Label, "deployment_id": a.own.DeploymentID, "decision_id": job.DecisionID, "token": job.Token, "nonce": job.Nonce, "pcr_at_receipt_hex": ack.PCRAtReceipt, "tls": ctx.Value(tlsKey{}) != nil && ctx.Value(tlsKey{}).(*tls.ConnectionState) != nil, "exporter_hex": hex.EncodeToString(rxExp)})
			out = wire.ToMap(ack)
		default:
			out = map[string]any{"type": "error", "error": "unsupported message"}
		}
		if !yield(a2a.NewArtifactEvent(ec, a2a.NewDataPart(out)), nil) {
			return
		}
		yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil), nil)
	}
}

// pcrNow reads the agent's own PCR 16 through its gate (diagnostic for the
// TOCTOU fixture: what the configuration looked like when the job landed).
func (a *Agent) pcrNow() string {
	a.tpmMu.Lock()
	defer a.tpmMu.Unlock()
	c, err := tpmsig.Open(a.own.TPMGate)
	if err != nil {
		return ""
	}
	defer c.Close()
	v, err := c.ReadPCR()
	if err != nil {
		return ""
	}
	return hex.EncodeToString(v)
}

func (a *Agent) Cancel(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		yield(nil, errors.New("cancel not supported"))
	}
}

func (a *Agent) handleChallenge(ctx context.Context, ch wire.Challenge, raw map[string]any) map[string]any {
	a.mu.Lock()
	mode := a.mode
	foreign := a.foreign
	a.mu.Unlock()
	nonce, err := wire.UnB64(ch.Nonce)
	if err != nil {
		return map[string]any{"type": "error", "error": "bad nonce"}
	}
	pol, err := wire.ParsePolicy(ch.Policy)
	if err != nil {
		return map[string]any{"type": "error", "error": "unknown policy"}
	}
	_, overTLS := ctx.Value(tlsKey{}).(*tls.ConnectionState)
	a.Ctl.Emit("exchange_served", map[string]any{"endpoint": a.Label, "mode": mode.Mode, "policy": ch.Policy, "nonce": ch.Nonce, "expected_by_requester": ch.ExpectedDeployment, "binding": ch.Binding, "over_tls": overTLS && ctx.Value(tlsKey{}).(*tls.ConnectionState) != nil})
	if mode.DelayMs > 0 {
		time.Sleep(time.Duration(mode.DelayMs) * time.Millisecond)
	}

	switch mode.Mode {
	case "replay":
		a.Ctl.Emit("replay_served", map[string]any{"endpoint": a.Label, "fresh_nonce": ch.Nonce, "replayed_nonce": mode.ReplayEvidence["nonce"]})
		return mode.ReplayEvidence
	case "relay", "tamper":
		return a.relay(ctx, mode, ch, raw)
	}

	// Binding mode is derived from the PARSED POLICY, never from the request's
	// binding field (v3 P0-A fix). A +cb policy always mixes THIS server's own TLS
	// exporter; a relay cannot omit it to turn us into a signing oracle. Any binding
	// field supplied in the challenge must be consistent with the policy, and a "cb"
	// value supplied by a relay is ignored and reported.
	var cb []byte
	if supplied, ok := raw["cb"]; ok && supplied != nil {
		a.Ctl.Emit("ignored_supplied_cb", map[string]any{"by": a.Label, "supplied": fmt.Sprint(supplied)})
	}
	if ch.Binding != "" && ch.Binding != "tls-exporter" {
		return map[string]any{"type": "error", "error": "unsupported binding " + ch.Binding}
	}
	if (ch.Binding == "tls-exporter") != pol.CB {
		a.Ctl.Emit("inconsistent_binding_field", map[string]any{"by": a.Label, "policy": ch.Policy, "binding": ch.Binding})
		return map[string]any{"type": "error", "error": "binding field inconsistent with policy", "nonce": ch.Nonce}
	}
	if pol.CB {
		b, ok := exporter(ctx)
		if !ok {
			a.Ctl.Emit("binding_unavailable", map[string]any{"by": a.Label, "reason": "policy requires channel binding but this connection has no TLS exporter"})
			return map[string]any{"type": "error", "error": "policy requires channel binding but this connection has no TLS exporter", "nonce": ch.Nonce}
		}
		cb = b
	}
	// The signed value commits to the exact policy string and (for +cb) our own
	// exporter: a proof under one policy cannot satisfy a verifier running another.
	eff := wire.ProofContext(ch.Policy, nonce, cb)

	ev := wire.Evidence{Type: "evidence", Policy: ch.Policy, DeploymentID: a.own.DeploymentID, Nonce: ch.Nonce, Timestamp: time.Now().UTC().Format(time.RFC3339), CBHex: hex.EncodeToString(cb)}
	claimed := a.own.DeploymentID
	if mode.Mode != "honest" {
		claimed = ch.ExpectedDeployment // impostor modes claim to be the expected deployment
		ev.DeploymentID = claimed
	}

	// Choose materials: copied volume first (if present), own as fallback.
	candidates := []*Materials{}
	if foreign != nil {
		candidates = append(candidates, foreign)
	}
	candidates = append(candidates, a.own)

	switch pol.Base {
	case wire.PolicyC:
		// nothing to prove
	case wire.PolicySFile:
		if mode.Mode == "unknown-key" || mode.Mode == "invalid" {
			a.fakeSoftware(&ev, eff, claimed, ch.Action, mode.Mode == "invalid", "sfile")
			break
		}
		for _, m := range candidates {
			if m.SFileKey == nil {
				continue
			}
			sig, err := wire.SignBinding(m.SFileKey, wire.Binding(eff, claimed, ch.Action))
			a.Ctl.Emit("signer_attempt", map[string]any{"by": a.Label, "signer": "sfile-key:" + m.SFileKeyID, "key_id": m.SFileKeyID, "kind": "sfile", "materials": m.Source, "ok": err == nil})
			if err == nil {
				ev.SigAlg, ev.SigKID, ev.Sig = "ES256", m.SFileKeyID, wire.B64(sig)
				break
			}
		}
	case wire.PolicySIso:
		if mode.Mode == "unknown-key" || mode.Mode == "invalid" {
			a.fakeSoftware(&ev, eff, claimed, ch.Action, mode.Mode == "invalid", "siso")
			break
		}
		for _, m := range candidates {
			sig, err := gate.SignViaGate(m.SIsoGate, m.SIsoToken, wire.Binding(eff, claimed, ch.Action))
			a.Ctl.Emit("signer_attempt", map[string]any{"by": a.Label, "signer": "siso-gate:" + filepath.Base(m.SIsoGate), "key_id": m.SIsoKeyID, "kind": "siso", "gate": strings.TrimSuffix(filepath.Base(m.SIsoGate), ".sock"), "materials": m.Source, "ok": err == nil, "err": errStr(err)})
			if err == nil {
				ev.SigAlg, ev.SigKID, ev.Sig = "ES256", m.SIsoKeyID, wire.B64(sig)
				break
			}
			ev.Error = err.Error()
		}
	case wire.PolicySEnv:
		if mode.Mode == "unknown-key" || mode.Mode == "invalid" {
			a.fakeSEnv(&ev, eff, claimed, ch, mode.Mode == "invalid")
			break
		}
		for _, m := range candidates {
			sealed, err := a.sealSEnv(m, eff, claimed, ch)
			a.Ctl.Emit("signer_attempt", map[string]any{"by": a.Label, "signer": "siso-gate:" + filepath.Base(m.SIsoGate) + " (COSE envelope)", "key_id": m.SIsoKeyID, "kind": "siso", "gate": strings.TrimSuffix(filepath.Base(m.SIsoGate), ".sock"), "materials": m.Source, "ok": err == nil, "err": errStr(err)})
			if err == nil {
				ev.COSESign1 = wire.B64(sealed)
				ev.Error = ""
				break
			}
			ev.Error = err.Error()
		}
	case wire.PolicyT, wire.PolicyP:
		a.tpmEvidence(&ev, candidates, mode, ch, eff, claimed, pol)
	case wire.PolicyECEnv, wire.PolicyPQEnv, wire.PolicyPQFile, wire.PolicyPQDevice:
		a.proofV4(&ev, candidates, mode, ch, nonce, cb, claimed, pol)
	}
	return wire.ToMap(ev)
}

// proofV4 produces the a2aid-proof-v4 credential for the parsed policy base. The
// context is built from the challenge and from THIS endpoint's own exporter (for +cb);
// the key custody is fixed by the base: EC-env and PQ-env through the gated env
// signers, PQ-device through the gated device signer (bridge → emulator), PQ-file
// from the seed inside the application volume. Attack modes are explicit and
// reported; there is no silent fallback between custodies or algorithms.
func (a *Agent) proofV4(ev *wire.Evidence, candidates []*Materials, mode Mode, ch wire.Challenge, nonce, cb []byte, claimed string, pol wire.Policy) {
	alg := wire.V4Alg(pol.Base)
	kidPrefix := mode.ClaimKIDPrefix
	if kidPrefix == "" {
		kidPrefix = a.Label
	}
	kidSuffix := map[string]string{wire.PolicyECEnv: "ecenv", wire.PolicyPQEnv: "pqenv", wire.PolicyPQFile: "pqfile", wire.PolicyPQDevice: "pqdev"}[pol.Base]
	kid := kidPrefix + "-" + kidSuffix + "-k1"
	signAlg := alg
	switch mode.Mode {
	case "alg-confusion":
		if mode.AlgName != "" {
			signAlg = mode.AlgName
		} else if alg == pqsig.AlgES256 {
			signAlg = pqsig.AlgMLDSA
		} else {
			signAlg = pqsig.AlgES256
		}
	}
	ctx := &pqsig.Context{V: pqsig.Format, Role: pqsig.Role, Policy: ch.Policy, Alg: signAlg, KID: kid, Expected: claimed, Requester: ch.Audience, Action: ch.Action, Nonce: nonce, Expiry: time.Now().Add(120 * time.Second).Unix(), Session: ch.Nonce, Exporter: cb}
	if len(cb) == 0 {
		ctx.Exporter = []byte{}
	}
	if !pqsig.Algs[signAlg] { // unknown algorithm: encode a context that names it anyway (attack mode only)
		ctx.Alg = pqsig.AlgMLDSA
	}
	msg, err := pqsig.Encode(ctx)
	if err != nil {
		ev.Error = "context: " + err.Error()
		return
	}
	if !pqsig.Algs[signAlg] {
		var raw map[string]any
		_ = json.Unmarshal(mustJSON(ctx), &raw)
		raw["alg"] = signAlg
		msg, _ = cbor.Marshal(raw) // deliberately non-canonical/unknown-alg context for the control
	}
	emit := func(signer, custody string, ok bool, err error, extra map[string]any) {
		f := map[string]any{"by": a.Label, "signer": signer, "key_id": kid, "kind": "v4", "alg": signAlg, "custody": custody, "materials": "", "ok": ok, "err": errStr(err)}
		for k, v := range extra {
			f[k] = v
		}
		a.Ctl.Emit("signer_attempt", f)
	}
	var sig []byte
	switch {
	case mode.Mode == "fresh-pq-key":
		seed, _ := pqsig.NewMLDSASeed()
		_, sk, _ := pqsig.MLDSAKeyFromSeed(seed)
		sig, err = pqsig.SignMLDSA(sk, msg)
		emit("attacker-generated-mldsa-key", "attacker-process", err == nil, err, nil)
	case signAlg != alg && mode.Mode == "alg-confusion" && pqsig.Algs[signAlg]:
		// swap: sign with THIS deployment's own enrolled key of the other algorithm
		base := wire.PolicyECEnv
		if signAlg == pqsig.AlgMLDSA {
			base = wire.PolicyPQEnv
		}
		m := a.own
		sig, _, err = gate.SignV4ViaGate(m.V4Gates[base], m.EnvToken, signAlg, msg, []byte(pqsig.CtxString))
		emit("env-gate:"+filepath.Base(m.V4Gates[base]), "gated-service", err == nil, err, map[string]any{"materials": m.Source, "confusion": true})
	case !pqsig.Algs[signAlg]:
		m := a.own
		sig, _, err = gate.SignV4ViaGate(m.V4Gates[wire.PolicyPQEnv], m.EnvToken, pqsig.AlgMLDSA, msg, []byte(pqsig.CtxString))
		emit("env-gate:unknown-alg-label", "gated-service", err == nil, err, map[string]any{"materials": m.Source, "unknown_alg": signAlg})
	case pol.Base == wire.PolicyPQFile:
		for _, m := range candidates {
			if m.PQFileSeed == nil {
				continue
			}
			_, sk, kerr := pqsig.MLDSAKeyFromSeed(m.PQFileSeed)
			if kerr != nil {
				continue
			}
			sig, err = pqsig.SignMLDSA(sk, msg)
			emit("pqfile-seed-in-volume", "application-volume", err == nil, err, map[string]any{"materials": m.Source})
			if err == nil {
				break
			}
		}
		if sig == nil && err == nil {
			err = errors.New("no PQ-file seed in any available volume")
			emit("pqfile-seed-in-volume", "application-volume", false, err, nil)
		}
	default:
		custody := "gated-service"
		if pol.Base == wire.PolicyPQDevice {
			custody = "emulated-device"
		}
		for _, m := range candidates {
			sock := m.V4Gates[pol.Base]
			if sock == "" {
				continue
			}
			var resp *gate.SWResponse
			sig, resp, err = gate.SignV4ViaGate(sock, m.EnvToken, alg, msg, []byte(pqsig.CtxString))
			extra := map[string]any{"materials": m.Source, "gate": strings.TrimSuffix(filepath.Base(sock), ".sock")}
			if resp != nil && resp.Device != nil {
				extra["device"] = resp.Device
			}
			emit("env-gate:"+filepath.Base(sock), custody, err == nil, err, extra)
			if err == nil {
				break
			}
		}
	}
	if err != nil || sig == nil {
		ev.Error = "proof_v4: " + errStr(err)
		return
	}
	ev.ProofV4 = &pqsig.Proof{Format: pqsig.Format, Alg: signAlg, KID: kid, Context: msg, Signature: sig}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// sealSEnv signs the software envelope through the isolated signer: the COSE
// Sig_structure is hashed locally and only the digest goes to the gate.
func (a *Agent) sealSEnv(m *Materials, eff []byte, claimed string, ch wire.Challenge) ([]byte, error) {
	now := time.Now().UTC().Truncate(time.Second)
	p := &senv.Payload{Version: senv.Version, AttesterID: claimed, Nonce: eff, Action: ch.Action, Audience: ch.Audience, Policy: ch.Policy, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	pb, err := senv.Encode(p)
	if err != nil {
		return nil, err
	}
	var signer coseSignerFn = func(content []byte) ([]byte, error) {
		d := sha256.Sum256(content)
		asn, err := gate.SignViaGate(m.SIsoGate, m.SIsoToken, d[:])
		if err != nil {
			return nil, err
		}
		return asn1ToRaw(asn)
	}
	return senv.Seal(pb, m.SIsoKeyID, signer)
}

func asn1ToRaw(sig []byte) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	rb, sb := rs.R.Bytes(), rs.S.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out, nil
}

func (a *Agent) fakeSEnv(ev *wire.Evidence, eff []byte, claimed string, ch wire.Challenge, invalid bool) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	pb, _ := senv.Encode(&senv.Payload{Version: senv.Version, AttesterID: claimed, Nonce: eff, Action: ch.Action, Audience: ch.Audience, Policy: ch.Policy, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)})
	s, _ := ptv.NewSoftwareSigner(k)
	sealed, _ := senv.Seal(pb, "unknown-siso", s)
	if invalid {
		sealed[len(sealed)-1] ^= 0xff
	}
	ev.COSESign1 = wire.B64(sealed)
	a.Ctl.Emit("signer_attempt", map[string]any{"by": a.Label, "signer": "unenrolled-software-key", "key_id": "unenrolled", "kind": "unenrolled", "ok": true})
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (a *Agent) fakeSoftware(ev *wire.Evidence, nonce []byte, claimed, action string, invalid bool, kid string) {
	if invalid {
		junk := make([]byte, 64)
		rand.Read(junk)
		ev.SigAlg, ev.SigKID, ev.Sig = "ES256", kid+"-garbage", wire.B64(junk)
		a.Ctl.Emit("signer_attempt", map[string]any{"by": a.Label, "signer": "none(garbage)", "key_id": "garbage", "kind": "garbage", "ok": true})
		return
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, _ := wire.SignBinding(k, wire.Binding(nonce, claimed, action))
	ev.SigAlg, ev.SigKID, ev.Sig = "ES256", "unknown-"+kid, wire.B64(sig)
	a.Ctl.Emit("signer_attempt", map[string]any{"by": a.Label, "signer": "unenrolled-software-key", "key_id": "unenrolled", "kind": "unenrolled", "ok": true})
}

// tpmEvidence produces T or P evidence with the first TPM that accepts us.
func (a *Agent) tpmEvidence(ev *wire.Evidence, candidates []*Materials, mode Mode, ch wire.Challenge, nonce []byte, claimed string, pol wire.Policy) {
	a.tpmMu.Lock()
	defer a.tpmMu.Unlock()
	if mode.Mode == "unknown-key" {
		// fresh, never-enrolled AK inside our own TPM
		c, err := tpmsig.Open(a.own.TPMGate)
		if err != nil {
			ev.Error = err.Error()
			return
		}
		defer c.Close()
		h, name, _, err := c.CreateTransientAK([]byte("rogue"))
		if err != nil {
			ev.Error = err.Error()
			return
		}
		defer c.Flush(h)
		q, err := c.Quote(h, name, []byte("rogue"), nonce)
		a.Ctl.Emit("signer_attempt", map[string]any{"by": a.Label, "signer": "tpm-gate:" + filepath.Base(a.own.TPMGate) + " (transient unenrolled AK)", "key_id": "unenrolled", "kind": "unenrolled", "gate": gateName(a.own.TPMGate), "ok": err == nil, "err": errStr(err)})
		if err != nil {
			ev.Error = err.Error()
			return
		}
		a.finishTPM(ev, pol, nonce, claimed, q, a.own.TPMGate, h, name, []byte("rogue"), mode, c, ch)
		return
	}

	for _, m := range candidates {
		c, err := tpmsig.Open(m.TPMGate)
		var q *tpmsig.QuoteResult
		if err == nil {
			q, err = c.QuotePersistent(m.AKAuth, nonce)
		}
		a.Ctl.Emit("signer_attempt", map[string]any{"by": a.Label, "signer": "tpm-gate:" + filepath.Base(m.TPMGate), "key_id": "ak@" + gateName(m.TPMGate), "kind": "tpm", "gate": gateName(m.TPMGate), "materials": m.Source, "has_ak_auth": len(m.AKAuth) > 0, "ok": err == nil, "err": errStr(err)})
		if err != nil {
			ev.Error = err.Error()
			if c != nil {
				c.Close()
			}
			continue
		}
		ev.Error = ""
		a.finishTPM(ev, pol, nonce, claimed, q, m.TPMGate, tpmsig.AKPersistentHandle, tpm2.TPM2BName{}, m.AKAuth, mode, c, ch)
		c.Close()
		return
	}
}

func gateName(sock string) string { return strings.TrimSuffix(filepath.Base(sock), ".sock") }

func (a *Agent) finishTPM(ev *wire.Evidence, pol wire.Policy, nonce []byte, claimed string, q *tpmsig.QuoteResult, sock string, handle tpm2.TPMHandle, name tpm2.TPM2BName, auth []byte, mode Mode, c *tpmsig.Conn, ch wire.Challenge) {
	if mode.Mode == "invalid" {
		// keep the quote, destroy the signature (nonce-burn fixture)
		for i := range q.Signature {
			if i >= 4 {
				q.Signature[i] = 0
			}
		}
	}
	if pol.Base == wire.PolicyT {
		ev.Quote = &wire.QuoteEvidence{Quoted: wire.B64(q.Quoted), Signature: wire.B64(q.Signature), Bank: "sha256", Index: tpmsig.RefPCR, PCRValue: hex.EncodeToString(q.PCRValue)}
		return
	}
	// P: PTV routine-mode envelope signed by the same AK through TPM2_Hash+TPM2_Sign.
	evb, err := (&ptv.TPMEvidence{Format: ptv.EvidenceFormat, Quoted: q.Quoted, Signature: q.Signature, Bank: "sha256", PCRs: map[int][]byte{tpmsig.RefPCR: q.PCRValue}}).Encode()
	if err != nil {
		ev.Error = err.Error()
		return
	}
	resp := &ptv.ProveResp{Version: ptv.Version, Nonce: nonce, MsgType: 2, AttesterID: claimed, TriageBand: 0, Evidence: evb, Timestamp: time.Now().UTC().Truncate(time.Second)}
	if ch.Hooks["ptv_malform"] == "both" && mode.Mode == "honest" {
		resp.Proof = []byte("not-a-proof")
		a.Ctl.Emit("lab_hook", map[string]any{"by": a.Label, "hook": "ptv_malform=both"})
	}
	payload, err := ptv.EncodeResp(resp)
	if err != nil {
		ev.Error = err.Error()
		return
	}
	var signer coseSignerFn = func(content []byte) ([]byte, error) {
		n := name
		if len(n.Buffer) == 0 {
			rp, err := tpm2.ReadPublic{ObjectHandle: handle}.Execute(connTransport(c))
			if err != nil {
				return nil, err
			}
			n = rp.Name
		}
		return c.SignWithTicket(handle, n, auth, content)
	}
	sealed, err := ptv.Seal(payload, claimed, signer)
	a.Ctl.Emit("signer_attempt", map[string]any{"by": a.Label, "signer": "tpm-gate:" + filepath.Base(sock) + " (tpm2_hash+tpm2_sign for COSE)", "key_id": "ak@" + gateName(sock), "kind": "tpm", "gate": gateName(sock), "ok": err == nil, "err": errStr(err)})
	if err != nil {
		ev.Error = err.Error()
		return
	}
	if mode.Mode == "invalid" {
		sealed[len(sealed)-1] ^= 0xff
	}
	ev.COSESign1 = wire.B64(sealed)
}

// relayClient builds the attacker's outbound A2A client: lab-CA-trusting HTTPS with
// the same static name resolution the requester uses.
func (a *Agent) relayClient(ctx context.Context, mode Mode) (*a2aclient.Client, error) {
	pool := x509.NewCertPool()
	if a.CAFile != "" {
		if pem, err := os.ReadFile(a.CAFile); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	resolve := func(addr string) string {
		if to, ok := mode.RelayResolve[addr]; ok {
			return to
		}
		return addr
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, resolve(addr))
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
	}
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		raw, err := dialer.DialContext(ctx, network, resolve(addr))
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS13})
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return tc, nil
	}
	hc := &http.Client{Timeout: 20 * time.Second, Transport: tr}
	return a2aclient.NewFromEndpoints(ctx, []*a2a.AgentInterface{{URL: mode.RelayTo, ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"}}, a2aclient.WithJSONRPCTransport(hc))
}

func nonceBytesOf(b64 string) []byte { b, _ := wire.UnB64(b64); return b }

// relay forwards the challenge to the real deployment and returns its answer,
// optionally editing the outer timestamp (tamper) or injecting our own observed
// channel binding into the forwarded challenge (inject_cb).
func (a *Agent) relay(ctx context.Context, mode Mode, ch wire.Challenge, raw map[string]any) map[string]any {
	client, err := a.relayClient(ctx, mode)
	if err != nil {
		return map[string]any{"type": "error", "error": err.Error()}
	}
	defer client.Destroy()
	fwd := map[string]any{}
	for k, v := range raw {
		fwd[k] = v
	}
	injected := ""
	if mode.InjectCB {
		if b, ok := exporter(ctx); ok {
			injected = hex.EncodeToString(b)
			fwd["cb"] = injected
		}
	}
	if mode.TamperContext != "" {
		switch mode.TamperContext {
		case "action":
			fwd["action"] = "release-other-job"
		case "audience":
			fwd["audience"] = "requester:attacker"
		}
		a.Ctl.Emit("relay_context_tampered", map[string]any{"relay": a.Label, "field": mode.TamperContext, "nonce": ch.Nonce})
	}
	if mode.ForwardPolicy != "" {
		fwd["policy"] = mode.ForwardPolicy
	}
	if mode.StripBinding {
		delete(fwd, "binding")
	}
	chosen := ""
	if mode.ChosenNonce {
		// Compute the bound nonce for OUR connection with the requester and make A
		// sign that exact value, so a quote/envelope over it satisfies the requester's
		// own channel-binding check without us ever holding A's proof key.
		if b, ok := exporter(ctx); ok {
			m := wire.BoundNonce(nonceBytesOf(ch.Nonce), b)
			fwd["nonce"] = wire.B64(m)
			chosen = wire.B64(m)
		}
	}
	res, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewDataPart(fwd))})
	a.Ctl.Emit("relay_leg", map[string]any{"relay": a.Label, "to": mode.RelayTo, "nonce": ch.Nonce, "policy": ch.Policy, "binding": ch.Binding, "injected_cb": injected, "ok": err == nil, "err": errStr(err)})
	if err != nil {
		return map[string]any{"type": "error", "error": err.Error()}
	}
	task, ok := res.(*a2a.Task)
	if !ok || len(task.Artifacts) == 0 || len(task.Artifacts[0].Parts) == 0 {
		return map[string]any{"type": "error", "error": "relay: no artifact"}
	}
	out, _ := task.Artifacts[0].Parts[0].Data().(map[string]any)
	if mode.ChosenNonce {
		// The signed structures (quote extraData, envelope nonce) carry m; restore the
		// outer, unsigned nonce field to the requester's original n so the cosmetic
		// check passes while the signed value stays m.
		out["nonce"] = ch.Nonce
		a.Ctl.Emit("relay_forwarded", map[string]any{"relay": a.Label, "nonce": ch.Nonce, "modified": true, "field": "chosen_nonce", "chosen_signed_nonce": chosen, "forward_policy": fmt.Sprint(fwd["policy"]), "stripped_binding": mode.StripBinding, "payload": out})
		return out
	}
	if mode.Mode != "tamper" {
		a.Ctl.Emit("relay_forwarded", map[string]any{"relay": a.Label, "nonce": ch.Nonce, "modified": false, "sha256": sha256Map(out), "payload": out})
		return out
	}
	original := map[string]any{}
	for k, v := range out {
		original[k] = v
	}
	delta := time.Duration(mode.TamperDeltaSec) * time.Second
	if delta == 0 {
		delta = 60 * time.Second
	}
	rec := map[string]any{"relay": a.Label, "nonce": ch.Nonce, "modified": true, "field": "timestamp"}
	var ev wire.Evidence
	_ = wire.FromMap(out, &ev)
	pol, _ := wire.ParsePolicy(ch.Policy)
	switch {
	case ev.COSESign1 != "" && pol.Base == wire.PolicyP:
		b, _ := wire.UnB64(ev.COSESign1)
		before := innerQuoteHash(b)
		nb, old, err := ptv.RewritePayloadTimestamp(b, time.Now().UTC().Add(delta).Truncate(time.Second))
		if err == nil {
			out["cose_sign1"] = wire.B64(nb)
			rec["old"], rec["new"] = old.UTC().Format(time.RFC3339), time.Now().UTC().Add(delta).Truncate(time.Second).Format(time.RFC3339)
			rec["inner_quote_sha256_before"], rec["inner_quote_sha256_after"] = before, innerQuoteHash(nb)
		} else {
			rec["err"] = err.Error()
		}
	case ev.COSESign1 != "" && pol.Base == wire.PolicySEnv:
		b, _ := wire.UnB64(ev.COSESign1)
		nb, old, err := senv.RewriteTimestamp(b, delta)
		if err == nil {
			out["cose_sign1"] = wire.B64(nb)
			rec["field"] = "iat/exp"
			rec["old"], rec["new"] = old.UTC().Format(time.RFC3339), old.Add(delta).UTC().Format(time.RFC3339)
		} else {
			rec["err"] = err.Error()
		}
	default:
		old := ev.Timestamp
		t, _ := time.Parse(time.RFC3339, old)
		out["timestamp"] = t.Add(delta).UTC().Format(time.RFC3339)
		rec["old"], rec["new"] = old, out["timestamp"]
		if ev.Quote != nil {
			h := sha256.Sum256([]byte(ev.Quote.Quoted))
			rec["inner_quote_sha256_before"], rec["inner_quote_sha256_after"] = hex.EncodeToString(h[:]), hex.EncodeToString(h[:])
		}
	}
	rec["original"], rec["payload"] = original, out
	a.Ctl.Emit("relay_forwarded", rec)
	return out
}

func innerQuoteHash(cose []byte) string {
	env, err := ptv.Open(cose)
	if err != nil {
		return ""
	}
	e, err := ptv.DecodeEvidence(env.Resp.Evidence)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(e.Quoted)
	return hex.EncodeToString(h[:])
}

func sha256Map(m map[string]any) string {
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
