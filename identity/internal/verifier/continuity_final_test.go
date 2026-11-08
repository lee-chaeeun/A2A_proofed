package verifier

// [NETWORKED] v3-final continuity coverage with the principal threat-model attacker.
//
// Two real HTTPS A2A servers (a2a-go JSON-RPC) and the real requester transport.
// Honest A answers challenges; the attacker B holds A's TLS certificate and key, can
// be placed at A's name by the resolver and can reach A, but has NO proof key and NO
// signer access (it refuses challenges). A third server C presents a lab-CA
// certificate for the OTHER enrolled name (b.a2aid.test).
//
// Both defended policies are exercised: S-env+cb (software envelope signed with
// A's enrolled isolated key) and T+cb (TPM2_Quote by a restricted AK inside a real
// swtpm started for the test; skipped only when swtpm is absent, and reported so).
//
// Delivery is asserted from the servers' receipt logs (token, decision id, the
// receiving connection's own exporter), never from the client's JobReleased flag.
// Barriers are the requester's synchronous lab hooks; no scheduling luck is used.
// When A2AID_EVIDENCE_DIR is set, each case writes a checker-readable record set
// (cells/<case>/decision.json, controller-events.jsonl, run-inventory.json,
// enrollment-registry.json) for `a2aid audit-release`.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"iter"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"a2aid/internal/senv"
	"a2aid/internal/wire"
)

// ---------------------------------------------------------------- lab PKI

type labPKI struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	pool  *x509.CertPool
}

func newLabPKI(t *testing.T) *labPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a2aid continuity lab CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &labPKI{ca: ca, caKey: key, pool: pool}
}

// issue returns a server certificate for name signed by the lab CA.
func (p *labPKI) issue(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	c, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	c.Leaf = leaf
	return c
}

// ---------------------------------------------------------------- servers

// receipt is one server-side job receipt, recorded by the test controller.
type receipt struct {
	Label       string `json:"label"`
	Token       string `json:"token"`
	DecisionID  string `json:"decision_id"`
	Nonce       string `json:"nonce"`
	ExporterHex string `json:"exporter_hex"` // the SERVER's own exporter for the receiving connection
	TLS         bool   `json:"tls"`
	At          string `json:"at"`
}

// labServer is a scripted A2A deployment for the continuity tests. prove is the
// deployment's proof capability; nil models an attacker without a proof key.
type labServer struct {
	label    string
	attester string
	prove    func(ch wire.Challenge, eff []byte) (map[string]any, error)
	mu       sync.Mutex
	log      []receipt
	ch       chan receipt
	chals    int
}

func (s *labServer) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		if ec.StoredTask == nil {
			if !yield(a2a.NewSubmittedTask(ec, ec.Message), nil) {
				return
			}
		}
		var d map[string]any
		if ec.Message != nil {
			for _, p := range ec.Message.Parts {
				if m, ok := p.Data().(map[string]any); ok {
					d = m
				}
			}
		}
		cs, _ := ctx.Value(contTLSKey{}).(*tls.ConnectionState)
		var cb []byte
		if cs != nil {
			cb, _ = cs.ExportKeyingMaterial(wire.CBLabel, nil, 32)
		}
		var out map[string]any
		switch d["type"] {
		case "challenge":
			s.mu.Lock()
			s.chals++
			s.mu.Unlock()
			var ch wire.Challenge
			_ = wire.FromMap(d, &ch)
			nb, _ := wire.UnB64(ch.Nonce)
			if s.prove == nil {
				out = map[string]any{"type": "error", "error": "no proof key available to this deployment", "nonce": ch.Nonce}
				break
			}
			eff := wire.ProofContext(ch.Policy, nb, cb)
			ev, err := s.prove(ch, eff)
			if err != nil {
				out = map[string]any{"type": "error", "error": err.Error(), "nonce": ch.Nonce}
				break
			}
			out = ev
		case "job":
			var job wire.Job
			_ = wire.FromMap(d, &job)
			rc := receipt{Label: s.label, Token: job.Token, DecisionID: job.DecisionID, Nonce: job.Nonce, ExporterHex: hex.EncodeToString(cb), TLS: cs != nil, At: time.Now().UTC().Format(time.RFC3339Nano)}
			s.mu.Lock()
			s.log = append(s.log, rc)
			s.mu.Unlock()
			select {
			case s.ch <- rc:
			default:
			}
			out = wire.ToMap(wire.JobAck{Type: "job_ack", DeploymentID: s.attester, Token: job.Token})
		default:
			out = map[string]any{"type": "error", "error": "unsupported"}
		}
		if !yield(a2a.NewArtifactEvent(ec, a2a.NewDataPart(out)), nil) {
			return
		}
		yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil), nil)
	}
}

func (s *labServer) Cancel(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) { yield(nil, context.Canceled) }
}

func (s *labServer) receipts() []receipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]receipt(nil), s.log...)
}

func (s *labServer) tokens() map[string]int {
	out := map[string]int{}
	for _, r := range s.receipts() {
		out[r.Token]++
	}
	return out
}

// waitReceipt waits up to d for a receipt; ok=false means none arrived.
func (s *labServer) waitReceipt(d time.Duration) (receipt, bool) {
	select {
	case r := <-s.ch:
		return r, true
	case <-time.After(d):
		return receipt{}, false
	}
}

func startLabServer(t *testing.T, srv *labServer, cardURL string, cardKey *ecdsa.PrivateKey, cardKID string, cert tls.Certificate) *httptest.Server {
	t.Helper()
	card := &a2a.AgentCard{Name: "Atlas Prime", Version: "1.0.0", DefaultInputModes: []string{"application/json"}, DefaultOutputModes: []string{"application/json"},
		SupportedInterfaces: []*a2a.AgentInterface{{ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0", URL: cardURL}},
		Skills:              []a2a.AgentSkill{{ID: "attest", Name: "attest"}}}
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewAgentCardHandler(cardProvider{signCardForTest(t, card, cardKey, cardKID)}))
	mux.Handle("/", a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(srv)))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contTLSKey{}, r.TLS)))
	})
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// ---------------------------------------------------------------- lab

const labAURL = "https://a.a2aid.test:9443"
const labAName = "a.a2aid.test:9443"

type contLab struct {
	t        *testing.T
	k        *kit
	pki      *labPKI
	policy   string
	a, b     *labServer // honest A; B = A's TLS cert/key, no proof key
	c        *labServer // C = lab-CA cert for the OTHER enrolled name, no proof key
	aAddr    string
	bAddr    string
	cAddr    string
	tpm      *tpmKit // only for T+cb
	quoteMu  sync.Mutex
	evidence string // A2AID_EVIDENCE_DIR/<policy>, "" when not recording
	cases    []map[string]any
}

func newContLab(t *testing.T, policy string) *contLab {
	t.Helper()
	k := newKit(t)
	pki := newLabPKI(t)
	k.r.Reg.Deployments["A"].TLSName = "a.a2aid.test"
	k.r.Reg.Deployments["B"].TLSName = "b.a2aid.test"
	lab := &contLab{t: t, k: k, pki: pki, policy: policy}
	mk := func(label string) *labServer {
		return &labServer{label: label, attester: "dep-" + label, ch: make(chan receipt, 256)}
	}
	lab.a, lab.b, lab.c = mk("A"), mk("B"), mk("C")
	switch policy {
	case "S-env+cb":
		lab.a.prove = func(ch wire.Challenge, eff []byte) (map[string]any, error) {
			now := time.Now().UTC().Truncate(time.Second)
			pb, err := senv.Encode(&senv.Payload{Version: senv.Version, AttesterID: "dep-A", Nonce: eff, Action: ch.Action, Audience: ch.Audience, Policy: ch.Policy, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)})
			if err != nil {
				return nil, err
			}
			sealed, err := senv.Seal(pb, "A-siso-k1", softCOSE{k.siso})
			if err != nil {
				return nil, err
			}
			return wire.ToMap(wire.Evidence{Type: "evidence", Policy: ch.Policy, DeploymentID: "dep-A", Nonce: ch.Nonce, COSESign1: wire.B64(sealed)}), nil
		}
	case "T+cb":
		tk := newTPMKit(t) // real swtpm; skips the test when swtpm is absent
		lab.tpm = tk
		depA := k.r.Reg.Deployments["A"]
		tA := tk.r.Reg.Deployments["A"]
		depA.AKPublicPEM, depA.AKName, depA.AKQualified, depA.PCRBank, depA.PCRIndex, depA.PCRReference = tA.AKPublicPEM, tA.AKName, tA.AKQualified, tA.PCRBank, tA.PCRIndex, tA.PCRReference
		lab.a.prove = func(ch wire.Challenge, eff []byte) (map[string]any, error) {
			lab.quoteMu.Lock() // one swtpm command stream at a time
			defer lab.quoteMu.Unlock()
			c := tk.conn()
			defer c.Close()
			q, err := c.QuotePersistent(tk.auth, eff)
			if err != nil {
				return nil, err
			}
			return wire.ToMap(wire.Evidence{Type: "evidence", Policy: ch.Policy, DeploymentID: "dep-A", Nonce: ch.Nonce,
				Quote: &wire.QuoteEvidence{Quoted: wire.B64(q.Quoted), Signature: wire.B64(q.Signature), Bank: "sha256", Index: 16, PCRValue: hex.EncodeToString(q.PCRValue)}}), nil
		}
	default:
		t.Fatalf("unsupported policy %s", policy)
	}
	certA := pki.issue(t, "a.a2aid.test") // ONE credential, held by A and stolen by B
	certB := pki.issue(t, "b.a2aid.test")
	lab.aAddr = startLabServer(t, lab.a, labAURL, k.cardKey(), "A-card-k1", certA).Listener.Addr().String()
	lab.bAddr = startLabServer(t, lab.b, labAURL, k.cardKey(), "A-card-k1", certA).Listener.Addr().String()
	lab.cAddr = startLabServer(t, lab.c, labAURL, k.cardKey(), "A-card-k1", certB).Listener.Addr().String()
	if dir := os.Getenv("A2AID_EVIDENCE_DIR"); dir != "" {
		lab.evidence = filepath.Join(dir, "continuity", strings.ReplaceAll(policy, "+", "_"))
		os.MkdirAll(filepath.Join(lab.evidence, "cells"), 0o755)
		if err := k.r.Reg.Save(filepath.Join(lab.evidence, "enrollment-registry.json")); err != nil {
			t.Fatal(err)
		}
		// The inventory is DECLARED here, before any case runs, from the static table
		// below: cell, class, expected decision/recipient and decision cardinality.
		var cells []map[string]any
		for _, c := range declaredContinuityCases {
			cells = append(cells, map[string]any{"cell": c.name, "fixture": c.name, "policy": policy, "class": c.class, "expected_decision": c.decision, "expected_recipient": c.recipient, "expected_decisions": c.decisions, "attacker_capabilities": c.caps})
		}
		b, _ := json.MarshalIndent(map[string]any{"run_id": time.Now().UTC().Format("20060102T150405Z"), "kind": "continuity", "policy": policy, "inventory_schema": 2, "evidence_schema": EvidenceSchemaVersion, "declared_before_execution": true, "cells": cells}, "", "  ")
		if err := os.WriteFile(filepath.Join(lab.evidence, "run-inventory.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return lab
}

// declaredContinuityCases is the fixed case table; the inventory file is written
// from it before execution and the cases below must match it exactly.
var declaredContinuityCases = []struct {
	name, class, decision, recipient string
	decisions                        int
	caps                             []string
}{
	{"1_honest_uninterrupted", "honest", "accept", "A", 1, nil},
	{"2_close_then_swap_to_B", "malicious", "accept", "none", 1, []string{"tls_credentials_A", "address_hijack"}},
	{"3_split_connection", "honest", "reject", "none", 1, nil},
	{"4_cert_swap_sealed", "malicious", "accept", "none", 1, []string{"address_hijack", "cert_for_other_enrolled_name"}},
	{"4_cert_swap_noseal_ABLATION", "ablation", "accept", "none", 1, []string{"address_hijack", "cert_for_other_enrolled_name"}},
	{"5_honest_recovery_new_decision", "honest", "accept", "A", 2, nil},
}

// requester returns a fresh production requester (real clock) with its own resolver.
func (l *contLab) requester() (*Requester, map[string]string) {
	r := New(l.k.r.Reg, nil, nil)
	r.RootCAs = l.pki.pool
	res := map[string]string{labAName: l.aAddr}
	r.Resolver = res
	return r, res
}

func closeAll(d *Decision) {
	for _, c := range d.conns.all() {
		c.Close()
	}
}

func hasEvent(d *Decision, kind string) bool {
	for _, e := range d.Events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func eventSeq(d *Decision, kind string) int {
	for _, e := range d.Events {
		if e.Kind == kind {
			return e.Seq
		}
	}
	return 0
}

// record writes one case as a checker-readable cell and remembers it for the inventory.
func (l *contLab) record(name, class, expectedDecision, expectedRecipient string, caps []string, r *Requester, ds []*Decision, note string) {
	l.cases = append(l.cases, map[string]any{"cell": name, "fixture": name, "policy": l.policy, "class": class, "expected_decision": expectedDecision, "expected_recipient": expectedRecipient, "attacker_capabilities": caps, "note": note})
	if l.evidence == "" {
		return
	}
	dir := filepath.Join(l.evidence, "cells", name)
	os.MkdirAll(dir, 0o755)
	var sessions any
	if r != nil {
		sessions = r.Store.Dump()
	}
	b, _ := json.MarshalIndent(map[string]any{"decisions": ds, "sessions": sessions, "requester_emissions_dropped": 0, "note": note}, "", "  ")
	os.WriteFile(filepath.Join(dir, "decision.json"), b, 0o644)
	f, _ := os.Create(filepath.Join(dir, "controller-events.jsonl"))
	defer f.Close()
	w := func(source, kind string, data map[string]any) {
		line, _ := json.Marshal(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "cell": name, "source": source, "kind": kind, "data": data})
		f.Write(append(line, '\n'))
	}
	// Requester events, mirrored as the controller would have received them.
	for _, d := range ds {
		for _, e := range d.Events {
			w("requester", "req_event", map[string]any{"decision_id": d.DecisionID, "seq": e.Seq, "kind": e.Kind, "conn_id": e.ConnID, "token": e.Token, "detail": e.Detail, "policy": d.Policy, "expected": d.Expected, "nonce": d.Nonce})
		}
		if d.JobToken != "" {
			if hasEvent(d, "dispatch_attempt") {
				w("requester", "job_released", map[string]any{"decision_id": d.DecisionID, "nonce": d.Nonce, "token": d.JobToken, "to_endpoint": d.Endpoint, "believed_deployment": d.Expected, "policy": d.Policy})
			}
			if hasEvent(d, "refused_reconnect") {
				w("requester", "job_reconnect_refused", map[string]any{"decision_id": d.DecisionID, "nonce": d.Nonce, "token": d.JobToken})
			}
		}
		w("requester", "decision", map[string]any{"decision_id": d.DecisionID, "policy": d.Policy, "endpoint": d.Endpoint, "expected": d.Expected, "accept": d.Accept, "stage": d.FailureStage, "code": d.Code, "reason": d.Reason, "nonce": d.Nonce, "job_token": d.JobToken, "job_sent": d.JobSent, "dispatch_conn_id": d.DispatchConnID, "pinned_conn_id": d.PinnedConnID})
	}
	// Server receipts belonging to these decisions (test-controller attribution by server).
	ids := map[string]bool{}
	for _, d := range ds {
		ids[d.DecisionID] = true
	}
	for _, s := range []*labServer{l.a, l.b, l.c} {
		for _, rc := range s.receipts() {
			if ids[rc.DecisionID] {
				w("agent-"+s.label, "job_received", map[string]any{"recipient": s.label, "deployment_id": s.attester, "decision_id": rc.DecisionID, "token": rc.Token, "nonce": rc.Nonce, "tls": rc.TLS, "exporter_hex": rc.ExporterHex})
			}
		}
	}
}

// finishInventory writes the OBSERVED case list after the run (for comparison with
// the declared run-inventory.json); it never replaces the declared inventory.
func (l *contLab) finishInventory(runID string) {
	if l.evidence == "" {
		return
	}
	b, _ := json.MarshalIndent(map[string]any{"run_id": runID, "kind": "continuity-observed", "policy": l.policy, "written_after_execution": true, "cells": l.cases}, "", "  ")
	os.WriteFile(filepath.Join(l.evidence, "observed-cases.json"), b, 0o644)
}

// ---------------------------------------------------------------- cases

func runContinuityCases(t *testing.T, policy string) {
	l := newContLab(t, policy)
	caps := []string{"tls_credentials_A", "address_hijack"}
	runID := time.Now().UTC().Format("20060102T150405Z")

	// 1. Uninterrupted honest proof and receipt at A.
	t.Run("1_honest_uninterrupted", func(t *testing.T) {
		r, _ := l.requester()
		d, err := r.Run(context.Background(), policy, labAURL, "A", nil)
		if err != nil || !d.Accept {
			t.Fatalf("honest decision not accepted: err=%v stage=%s reason=%s", err, d.FailureStage, d.Reason)
		}
		rc, ok := l.a.waitReceipt(3 * time.Second)
		if !ok || rc.Token != d.JobToken || rc.DecisionID != d.DecisionID {
			t.Fatalf("A did not log the receipt for token %s (got %+v ok=%v)", d.JobToken, rc, ok)
		}
		if !d.JobSent || !d.JobConnReused || d.DispatchConnID != d.PinnedConnID || d.PinnedConnID != d.ProofConnID || d.ProofConnID == 0 {
			t.Fatalf("dispatch not on the proof connection: sent=%v reused=%v dispatch=%d pinned=%d proof=%d", d.JobSent, d.JobConnReused, d.DispatchConnID, d.PinnedConnID, d.ProofConnID)
		}
		if len(d.Conns) != 1 || d.Conns[0].ExporterHex != rc.ExporterHex {
			t.Fatalf("server-side exporter of the receipt %s != requester's connection exporter %+v", rc.ExporterHex, d.Conns)
		}
		if !(eventSeq(d, "authorized") < eventSeq(d, "dispatch_attempt") && eventSeq(d, "dispatch_attempt") < eventSeq(d, "sent") && eventSeq(d, "sent") < eventSeq(d, "ack")) {
			t.Fatalf("event order wrong: %+v", d.Events)
		}
		if n := len(l.b.receipts()); n != 0 {
			t.Fatalf("B logged %d receipts in the honest case", n)
		}
		l.record("1_honest_uninterrupted", "honest", "accept", "A", nil, r, []*Decision{d}, "positive control")
	})

	// 2. Valid proof at A, forced close before task send, next dial mapped to B.
	t.Run("2_close_then_swap_to_B", func(t *testing.T) {
		r, res := l.requester()
		bBefore := len(l.b.receipts())
		r.Hook = func(stage string, d *Decision) {
			if stage == "after-appraise" && d.Accept {
				closeAll(d)                   // active intermediary drops the proof connection
				d.http.CloseIdleConnections() // barrier: the client has observed the drop
				res[labAName] = l.bAddr       // and A's name now resolves to B (A's cert+key, no proof key)
			}
		}
		d, err := r.Run(context.Background(), policy, labAURL, "A", nil)
		if err != nil || !d.Accept {
			t.Fatalf("proof should appraise-accept: err=%v %s %s", err, d.FailureStage, d.Reason)
		}
		if d.JobSent || d.JobReleased || !hasEvent(d, "refused_reconnect") || hasEvent(d, "sent") {
			t.Fatalf("expected refused reconnect before any bytes: sent=%v released=%v events=%+v", d.JobSent, d.JobReleased, d.Events)
		}
		if d.DialsRefused < 1 {
			t.Fatalf("expected at least one refused dial, got dials=%d refused=%d", d.Dials, d.DialsRefused)
		}
		if _, ok := l.b.waitReceipt(800 * time.Millisecond); ok || len(l.b.receipts()) != bBefore {
			t.Fatalf("SWAP SUCCEEDED: B received a job")
		}
		if l.a.tokens()[d.JobToken] != 0 {
			t.Fatalf("A received the token of a refused dispatch")
		}
		if l.b.chals != 0 {
			t.Fatalf("B was asked for a proof; it has none")
		}
		l.record("2_close_then_swap_to_B", "malicious", "accept", "none", caps, r, []*Decision{d}, "proof accepted; reconnect refused pre-send; B holds A's TLS cert/key only")
	})

	// 3. Discovery and proof on separate connections.
	t.Run("3_split_connection", func(t *testing.T) {
		r, _ := l.requester()
		r.Hook = func(stage string, d *Decision) {
			if stage == "after-connect" {
				closeAll(d) // discovery connection gone before the challenge
			}
		}
		d, _ := r.Run(context.Background(), policy, labAURL, "A", nil)
		if d.DiscoveryConnID != 1 || d.ProofConnID != 2 {
			t.Fatalf("expected discovery on conn 1 and proof on conn 2, got %d/%d", d.DiscoveryConnID, d.ProofConnID)
		}
		// Documented fail-closed outcome: a +cb decision whose connections do not all
		// authenticate the same channel is rejected at the binding stage; nothing is
		// dispatched and the first connection's evidence authorizes nothing.
		if d.Accept || d.FailureStage != "binding" || d.JobSent || d.JobToken != "" {
			t.Fatalf("expected fail-closed binding rejection, got accept=%v stage=%s sent=%v", d.Accept, d.FailureStage, d.JobSent)
		}
		if len(l.a.receipts())+len(l.b.receipts()) != 1 { // only case 1's receipt so far
			t.Fatalf("unexpected receipts: A=%d B=%d", len(l.a.receipts()), len(l.b.receipts()))
		}
		l.record("3_split_connection", "honest", "reject", "none", nil, r, []*Decision{d}, "fail-closed: two distinct exporters in one decision reject at stage=binding")
	})

	// 4. Connection replacement with a different certificate / enrolled name.
	t.Run("4_cert_swap_sealed", func(t *testing.T) {
		r, res := l.requester()
		r.Hook = func(stage string, d *Decision) {
			if stage == "after-appraise" && d.Accept {
				closeAll(d)
				res[labAName] = l.cAddr // valid lab-CA cert, but for b.a2aid.test
			}
		}
		d, _ := r.Run(context.Background(), policy, labAURL, "A", nil)
		if !d.Accept || d.JobSent || !hasEvent(d, "refused_reconnect") || d.DialsRefused != 1 {
			t.Fatalf("sealed requester should refuse before dialing: accept=%v sent=%v refused=%d events=%+v", d.Accept, d.JobSent, d.DialsRefused, d.Events)
		}
		if len(d.Conns) != 1 { // the C connection was never handshaken, so never recorded
			t.Fatalf("a second connection was recorded: %+v", d.Conns)
		}
		if n := len(l.c.receipts()); n != 0 {
			t.Fatalf("C received %d jobs", n)
		}
		l.record("4_cert_swap_sealed", "malicious", "accept", "none", []string{"address_hijack", "cert_for_other_enrolled_name"}, r, []*Decision{d}, "layer=seal (refused before dial; TLS never evaluated the replacement)")
	})
	t.Run("4_cert_swap_noseal_ABLATION", func(t *testing.T) {
		r, res := l.requester()
		r.noSealAblation = true // ABLATION of the fix, not a production mode
		r.Hook = func(stage string, d *Decision) {
			if stage == "after-appraise" && d.Accept {
				closeAll(d)
				res[labAName] = l.cAddr
			}
		}
		d, _ := r.Run(context.Background(), policy, labAURL, "A", nil)
		if !d.Accept || d.JobSent {
			t.Fatalf("ablation: accept=%v sent=%v err=%s", d.Accept, d.JobSent, d.JobError)
		}
		if d.DialsRefused != 0 || d.Dials < 2 || !strings.Contains(d.JobError, "certificate") {
			t.Fatalf("ablation should have attempted a new dial and failed TLS name validation: dials=%d refused=%d err=%s", d.Dials, d.DialsRefused, d.JobError)
		}
		if n := len(l.c.receipts()); n != 0 {
			t.Fatalf("C received %d jobs", n)
		}
		l.record("4_cert_swap_noseal_ABLATION", "ablation", "accept", "none", []string{"address_hijack", "cert_for_other_enrolled_name"}, r, []*Decision{d}, "ABLATION (seal disabled): layer=tls (hostname validation rejected the other enrolled name)")
	})

	// 5. Honest close before dispatch, then a NEW decision with a fresh proof.
	t.Run("5_honest_recovery_new_decision", func(t *testing.T) {
		aBefore := l.a.tokens()
		r, _ := l.requester()
		r.Hook = func(stage string, d *Decision) {
			if stage == "after-appraise" && d.Accept {
				closeAll(d) // honest interruption; the name still resolves to A
			}
		}
		d1, _ := r.Run(context.Background(), policy, labAURL, "A", nil)
		if !d1.Accept || d1.JobSent || !hasEvent(d1, "refused_reconnect") {
			t.Fatalf("interrupted decision should refuse pre-send: accept=%v sent=%v events=%+v", d1.Accept, d1.JobSent, d1.Events)
		}
		r.Hook = nil // explicit new decision by the requester: fresh challenge and proof
		d2, err := r.Run(context.Background(), policy, labAURL, "A", nil)
		if err != nil || !d2.Accept || !d2.JobSent {
			t.Fatalf("recovery decision failed: err=%v accept=%v sent=%v %s", err, d2.Accept, d2.JobSent, d2.JobError)
		}
		if d2.Nonce == d1.Nonce || d2.DecisionID == d1.DecisionID {
			t.Fatalf("recovery reused the nonce or decision id")
		}
		rc, ok := l.a.waitReceipt(3 * time.Second)
		if !ok || rc.Token != d2.JobToken {
			t.Fatalf("A did not log exactly the recovery token: %+v ok=%v", rc, ok)
		}
		after := l.a.tokens()
		if len(after) != len(aBefore)+1 || after[d1.JobToken] != 0 || after[d2.JobToken] != 1 {
			t.Fatalf("A receipt log wrong: before=%v after=%v d1=%s d2=%s", aBefore, after, d1.JobToken, d2.JobToken)
		}
		l.record("5_honest_recovery_new_decision", "honest", "accept", "A", nil, r, []*Decision{d1, d2}, "decision 1 refused pre-send (no receipt); decision 2 fresh proof, one receipt")
	})
	l.finishInventory(runID)
}

func TestContinuityFinal_SEnvCB(t *testing.T) { runContinuityCases(t, "S-env+cb") }
func TestContinuityFinal_TCB(t *testing.T)    { runContinuityCases(t, "T+cb") } // [E2E/emulator]

// ---------------------------------------------------------------- churn

// runChurn runs the declared budget: 60 trials, even trials close the proof
// connection and repoint the name to B before dispatch. Receipts are counted on the
// servers and matched to the tokens of the decisions that reported a send.
func runChurn(t *testing.T, policy string) {
	const trials = 60
	l := newContLab(t, policy)
	type outcome struct {
		d   *Decision
		err error
	}
	outs := make([]outcome, trials)
	var wg sync.WaitGroup
	for i := 0; i < trials; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			churn := i%2 == 0
			r, res := l.requester()
			r.Hook = func(stage string, d *Decision) {
				if stage == "after-appraise" && d.Accept && churn {
					closeAll(d)
					res[labAName] = l.bAddr
				}
			}
			d, err := r.Run(context.Background(), policy, labAURL, "A", nil)
			outs[i] = outcome{d, err}
		}(i)
	}
	wg.Wait()
	time.Sleep(300 * time.Millisecond) // let the last acks settle (receipts are already logged before the ack)
	var attempts, accepted, dispatchAttempts, sent, refused, unknown, acks, errs int
	sentTokens := map[string]bool{}
	for _, o := range outs {
		attempts++
		d := o.d
		if o.err != nil {
			errs++
			continue
		}
		if d.Accept {
			accepted++
		}
		if d.DispatchAttempted {
			dispatchAttempts++
		}
		if d.JobSent {
			sent++
			sentTokens[d.JobToken] = d.JobAckReceived
		}
		if hasEvent(d, "refused_reconnect") {
			refused++
		}
		if hasEvent(d, "unknown_outcome") {
			unknown++ // written to the dead proof connection's buffer; resolved by the server logs below
		}
		if d.JobAckReceived {
			acks++
		}
	}
	aTok, bTok := l.a.tokens(), l.b.tokens()
	aMatched := 0
	for tok, acked := range sentTokens {
		if acked && aTok[tok] == 1 {
			aMatched++
		}
	}
	report := fmt.Sprintf("churn policy=%s trials=%d attempts=%d appraisals_accepted=%d dispatch_attempts=%d written_to_transport=%d refused_reconnect=%d client_unknown_outcome=%d acks=%d errors=%d A_receipts=%d A_receipts_matching_acked_tokens=%d B_receipts=%d",
		policy, trials, attempts, accepted, dispatchAttempts, sent, refused, unknown, acks, errs, len(aTok), aMatched, len(bTok))
	t.Log(report)
	if dir := os.Getenv("A2AID_EVIDENCE_DIR"); dir != "" {
		os.MkdirAll(dir, 0o755)
		f, _ := os.OpenFile(filepath.Join(dir, "churn.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		fmt.Fprintln(f, report)
		f.Close()
	}
	if len(bTok) != 0 {
		t.Fatalf("a job reached B under churn: %s", report)
	}
	// Declared expectation: every uninterrupted trial is acked and logged once at A;
	// every interrupted trial is either refused pre-send or client-unknown with no
	// receipt anywhere (the unknown count is reported, not hidden).
	if accepted != trials || acks != trials/2 || len(aTok) != trials/2 || aMatched != trials/2 || refused+unknown != trials/2 || errs != 0 {
		t.Fatalf("churn budget outcome does not match the declared expectation: %s", report)
	}
}

func TestChurnFinal_SEnvCB(t *testing.T) { runChurn(t, "S-env+cb") }
func TestChurnFinal_TCB(t *testing.T)    { runChurn(t, "T+cb") } // [E2E/emulator]

var _ = errors.New
