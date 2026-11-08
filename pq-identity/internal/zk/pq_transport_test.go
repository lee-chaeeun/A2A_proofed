package zk

// Proof-to-delivery continuity of the bound ZK transport (PQ-device+cb) over real
// HTTPS a2a-go servers with server-side counters. These are TRANSPORT tests: the
// worker holds a software ML-DSA-65 test key enrolled under the device policy base
// (no emulator, no key custody claim) and answers the task with an explicitly
// labelled stub receipt (no computation proof; receipt verification is a separate
// stage). The assertion in every negative case is the server's own count of task
// requests, not the client's error.
//
// History: the pre-fix requester appraised the bound proof and then called
// SendMessage directly, so a server that closed the proof connection received the
// task on a replacement connection holding the same TLS credential and no signer
// (reviewer characterization, retained verbatim in
// results/reviewer-pq/20261108T135205Z/transport_test_with_review.go.txt and re-run
// against the pre-edit source in results/audit/20261108T141124Z-pqcorr-prefix/).
// TestPQTransport_ReplacementConnectionReceivesNothing is that scenario, now asserting
// zero task receipts at the replacement.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"iter"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"a2aid/internal/cardsig"
	"a2aid/internal/pqsig"
	"a2aid/internal/registry"
	"a2aid/internal/verifier"
	"a2aid/internal/wire"
)

type pqCtxKey int

const (
	pqKeyTLS pqCtxKey = iota
	pqKeyAddr
)

// pqLabWorker signs a2aid-proof-v4 contexts with a software ML-DSA-65 TEST key and
// answers zk_task with a labelled stub receipt. Behaviour knobs:
//   - closeProofConns: how many proof exchanges are answered with "Connection: close"
//     (the server drops the proof connection; a replacement connection would hold the
//     same TLS credential but no signer);
//   - maxProofs: how many proofs the signer produces (the replacement has none);
//   - hijackTask: read the task request, then close the connection without a response
//     (the client cannot know whether the task arrived; the server can).
type pqLabWorker struct {
	sk              *mldsa65.PrivateKey
	closeProofConns int32
	maxProofs       int32
	hijackTask      bool

	proofs    atomic.Int32
	tasks     atomic.Int32
	handshake atomic.Int32 // TLS connections accepted by the server
	mu        sync.Mutex
	proofAddr []string
	taskAddr  []string
}

func (w *pqLabWorker) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		if ec.StoredTask == nil {
			if !yield(a2a.NewSubmittedTask(ec, ec.Message), nil) {
				return
			}
		}
		var m map[string]any
		for _, p := range ec.Message.Parts {
			if x, ok := p.Data().(map[string]any); ok {
				m = x
			}
		}
		addr, _ := ctx.Value(pqKeyAddr).(string)
		var res map[string]any
		switch m["type"] {
		case "challenge":
			if w.proofs.Add(1) > w.maxProofs {
				yield(nil, errors.New("this connection has no proof signer"))
				return
			}
			var ch wire.Challenge
			_ = wire.FromMap(m, &ch)
			cs := ctx.Value(pqKeyTLS).(*tls.ConnectionState)
			cb, _ := cs.ExportKeyingMaterial(wire.CBLabel, nil, 32)
			nb, _ := wire.UnB64(ch.Nonce)
			pc := &pqsig.Context{V: pqsig.Format, Role: pqsig.Role, Policy: ch.Policy, Alg: pqsig.AlgMLDSA, KID: "A-pqdev-k1", Expected: "dep-A", Requester: ch.Audience, Action: ch.Action, Nonce: nb, Expiry: time.Now().Add(120 * time.Second).Unix(), Session: ch.Nonce, Exporter: cb}
			b, err := pqsig.Encode(pc)
			if err != nil {
				yield(nil, err)
				return
			}
			sig, err := pqsig.SignMLDSA(w.sk, b)
			if err != nil {
				yield(nil, err)
				return
			}
			w.mu.Lock()
			w.proofAddr = append(w.proofAddr, addr)
			w.mu.Unlock()
			res = wire.ToMap(wire.Evidence{Type: "evidence", Policy: ch.Policy, DeploymentID: "dep-A", Nonce: ch.Nonce, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), ProofV4: &pqsig.Proof{Format: pqsig.Format, Alg: pqsig.AlgMLDSA, KID: "A-pqdev-k1", Context: b, Signature: sig}})
		case "zk_task":
			w.tasks.Add(1)
			w.mu.Lock()
			w.taskAddr = append(w.taskAddr, addr)
			w.mu.Unlock()
			rid, _ := m["request_id"].(string)
			res = wire.ToMap(wire.ZKResult{Type: "zk_result", Schema: wire.ZKSchema, RequestID: rid, ReceiptB64: base64.StdEncoding.EncodeToString([]byte("stub-receipt-not-genuine")), WorkerDeployment: "dep-A"})
		default:
			yield(nil, errors.New("unexpected message"))
			return
		}
		if !yield(a2a.NewArtifactEvent(ec, a2a.NewDataPart(res)), nil) {
			return
		}
		yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil), nil)
	}
}

func (w *pqLabWorker) Cancel(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) { yield(nil, context.Canceled) }
}

type pqLab struct {
	w        *pqLabWorker
	srv      *httptest.Server
	reg      *registry.Registry
	pool     *x509.CertPool
	resolver map[string]string
}

func newPQLab(t *testing.T, w *pqLabWorker) *pqLab {
	t.Helper()
	cardKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	card, err := cardsig.Sign(baseCard(), cardKey, "A-card-k1")
	if err != nil {
		t.Fatal(err)
	}
	pk, sk, err := pqsig.MLDSAKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	w.sk = sk
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewAgentCardHandler(cardProv{card}))
	mux.Handle("/", a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(w)))
	var closed atomic.Int32
	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(b))
			if bytes.Contains(b, []byte(`"challenge"`)) && closed.Load() < w.closeProofConns {
				closed.Add(1)
				rw.Header().Set("Connection", "close")
			}
			if w.hijackTask && bytes.Contains(b, []byte(`"zk_task"`)) {
				w.tasks.Add(1)
				w.mu.Lock()
				w.taskAddr = append(w.taskAddr, r.RemoteAddr)
				w.mu.Unlock()
				if hj, ok := rw.(http.Hijacker); ok {
					c, _, err := hj.Hijack()
					if err == nil {
						c.Close() // task received, no response: the client cannot know
						return
					}
				}
				panic("test server cannot hijack")
			}
		}
		ctx := context.WithValue(r.Context(), pqKeyTLS, r.TLS)
		ctx = context.WithValue(ctx, pqKeyAddr, r.RemoteAddr)
		mux.ServeHTTP(rw, r.WithContext(ctx))
	})
	cert := certFor(t, "a.a2aid.test")
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	ts.Config.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateNew {
			w.handshake.Add(1)
		}
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	reg := &registry.Registry{Deployments: map[string]*registry.Deployment{"A": {DeploymentID: "dep-A", AttesterID: "dep-A", CardKeyID: "A-card-k1", CardPublicPEM: pubPEM(t, cardKey), TLSName: "a.a2aid.test",
		V4Keys: map[string]registry.V4Key{"PQ-device": {Alg: pqsig.AlgMLDSA, KID: "A-pqdev-k1", Version: 1, PublicB64: base64.StdEncoding.EncodeToString(pqsig.MLDSAPublicBytes(pk)), Custody: "test-fixture-software-key (transport test, not a custody test)"}}}}}
	return &pqLab{w: w, srv: ts, reg: reg, pool: pool, resolver: map[string]string{"a.a2aid.test:9443": ts.Listener.Addr().String()}}
}

func (l *pqLab) dispatch(t *testing.T, id string) (*Exchange, []byte, error) {
	t.Helper()
	rq := &Requester{Reg: l.reg, RootCAs: l.pool, Resolver: l.resolver, Policy: "PQ-device+cb"}
	return rq.Dispatch(context.Background(), tEndpoint, NewRequest(id, "p", Pinned, 1, "A"))
}

func hasEvent(ex *Exchange, kind string) bool {
	if ex == nil || ex.Identity == nil {
		return false
	}
	for _, e := range ex.Identity.Events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func TestPQTransport_HonestTaskDeliveredOnTheProofConnection(t *testing.T) {
	l := newPQLab(t, &pqLabWorker{maxProofs: 1})
	ex, raw, err := l.dispatch(t, "pq-honest")
	if err != nil || string(raw) != "stub-receipt-not-genuine" {
		t.Fatalf("honest bound dispatch: err=%v raw=%q ex=%+v", err, raw, ex)
	}
	if l.w.tasks.Load() != 1 || l.w.proofs.Load() != 1 || l.w.handshake.Load() != 1 {
		t.Fatalf("server counters: tasks=%d proofs=%d handshakes=%d (want 1/1/1)", l.w.tasks.Load(), l.w.proofs.Load(), l.w.handshake.Load())
	}
	if l.w.proofAddr[0] != l.w.taskAddr[0] {
		t.Fatalf("task arrived on another connection than the proof: proof=%s task=%s", l.w.proofAddr[0], l.w.taskAddr[0])
	}
	id := ex.Identity
	if !ex.TaskSent || ex.Delivery != string(verifier.SendDelivered) || id == nil || id.ProofConnID != 1 || id.PinnedConnID != 1 || id.DispatchConnID != 1 || id.Token == "" || id.DialsRefused != 0 || len(id.Connections) != 1 {
		t.Fatalf("delivery record: sent=%v delivery=%s identity=%+v", ex.TaskSent, ex.Delivery, id)
	}
	for _, k := range []string{"challenge_sent", "proof_received", "appraised", "authorized", "sealed", "dispatch_attempt", "got_conn", "sent"} {
		if !hasEvent(ex, k) {
			t.Fatalf("missing lifecycle event %q in %+v", k, id.Events)
		}
	}
}

// The reviewer's scenario: valid bound proof, server closes the proof connection, a
// replacement connection with the same certificate and no signer stands ready. The
// corrected requester refuses before any byte; the server's task counter is zero.
func TestPQTransport_ReplacementConnectionReceivesNothing(t *testing.T) {
	l := newPQLab(t, &pqLabWorker{maxProofs: 1, closeProofConns: 1})
	ex, raw, err := l.dispatch(t, "pq-replaced")
	if !errors.Is(err, ErrDeliveryRefused) || raw != nil {
		t.Fatalf("replacement must be refused: err=%v raw=%v ex=%+v", err, raw, ex)
	}
	if n := l.w.tasks.Load(); n != 0 {
		t.Fatalf("ZERO task receipts expected at the replacement, server counted %d", n)
	}
	if ex.TaskSent || ex.Delivery != string(verifier.SendRefused) || !ex.Transport.Accept {
		t.Fatalf("record: sent=%v delivery=%s accept=%v", ex.TaskSent, ex.Delivery, ex.Transport.Accept)
	}
	if !hasEvent(ex, "sealed") || !(hasEvent(ex, "refused_reconnect") || hasEvent(ex, "refused_dispatch")) || hasEvent(ex, "sent") {
		t.Fatalf("expected sealed + refused events and no send: %+v", ex.Identity.Events)
	}
}

// No implicit retry: after the proof connection is gone the transport's dial is refused
// by the seal (counted, no bytes), and the server saw exactly one TLS connection.
func TestPQTransport_ImplicitReconnectIsRefusedBeforeTheDial(t *testing.T) {
	l := newPQLab(t, &pqLabWorker{maxProofs: 5, closeProofConns: 5}) // the server WOULD sign again on a new connection
	ex, _, err := l.dispatch(t, "pq-no-retry")
	if !errors.Is(err, ErrDeliveryRefused) {
		t.Fatalf("expected refusal: %v", err)
	}
	if l.w.handshake.Load() != 1 || l.w.tasks.Load() != 0 || l.w.proofs.Load() != 1 {
		t.Fatalf("server saw handshakes=%d tasks=%d proofs=%d (want 1/0/1: no second connection, no task)", l.w.handshake.Load(), l.w.tasks.Load(), l.w.proofs.Load())
	}
	if ex.Identity == nil || ex.Identity.DialsRefused < 1 || len(ex.Identity.Connections) != 1 {
		t.Fatalf("the refused dial must be counted by the sealed recorder: %+v", ex.Identity)
	}
}

// Recovery is a new decision: new connection, new nonce, new proof, new authorization.
// The old decision is not reused and the task is delivered exactly once.
func TestPQTransport_FreshDecisionRecoversAfterRefusal(t *testing.T) {
	l := newPQLab(t, &pqLabWorker{maxProofs: 2, closeProofConns: 1})
	ex1, _, err := l.dispatch(t, "pq-recover")
	if !errors.Is(err, ErrDeliveryRefused) || l.w.tasks.Load() != 0 {
		t.Fatalf("first attempt must be refused without delivery: err=%v tasks=%d", err, l.w.tasks.Load())
	}
	ex2, raw, err := l.dispatch(t, "pq-recover")
	if err != nil || string(raw) != "stub-receipt-not-genuine" {
		t.Fatalf("fresh decision must deliver: err=%v ex=%+v", err, ex2)
	}
	if l.w.tasks.Load() != 1 || l.w.proofs.Load() != 2 || l.w.handshake.Load() != 2 {
		t.Fatalf("server counters after recovery: tasks=%d proofs=%d handshakes=%d (want 1/2/2)", l.w.tasks.Load(), l.w.proofs.Load(), l.w.handshake.Load())
	}
	if l.w.taskAddr[0] != l.w.proofAddr[1] || l.w.taskAddr[0] == l.w.proofAddr[0] {
		t.Fatalf("task must ride the SECOND proof connection: proofs=%v task=%v", l.w.proofAddr, l.w.taskAddr)
	}
	if ex1.Identity.DecisionID == ex2.Identity.DecisionID || ex1.Identity.Nonce == ex2.Identity.Nonce || ex1.Identity.Token == ex2.Identity.Token {
		t.Fatalf("recovery reused the old decision: %+v vs %+v", ex1.Identity, ex2.Identity)
	}
}

// Client-unknown outcome: the task bytes were written on the proof connection and the
// server closed it without a response. The requester reports "unknown" (never "not
// delivered"), does not retry on another connection, and the server's own record
// resolves it (here: the task did arrive once).
func TestPQTransport_InterruptedTaskIsUnknownNotDenied(t *testing.T) {
	l := newPQLab(t, &pqLabWorker{maxProofs: 1, hijackTask: true})
	ex, raw, err := l.dispatch(t, "pq-unknown")
	if !errors.Is(err, ErrDeliveryUnknown) || raw != nil {
		t.Fatalf("expected unknown outcome: err=%v raw=%v ex=%+v", err, raw, ex)
	}
	if !ex.TaskSent || ex.Delivery != string(verifier.SendUnknown) || !hasEvent(ex, "sent") || !hasEvent(ex, "unknown_outcome") {
		t.Fatalf("record must say sent + unknown: sent=%v delivery=%s events=%+v", ex.TaskSent, ex.Delivery, ex.Identity.Events)
	}
	if l.w.tasks.Load() != 1 || l.w.handshake.Load() != 1 {
		t.Fatalf("server record: tasks=%d handshakes=%d (want 1/1: delivered once on the proof connection, no replacement)", l.w.tasks.Load(), l.w.handshake.Load())
	}
}

// An invalid bound proof (wrong key under the enrolled key id) never reaches the task
// stage: zero task requests, no authorization event.
func TestPQTransport_InvalidProofSendsNoTask(t *testing.T) {
	l := newPQLab(t, &pqLabWorker{maxProofs: 1})
	other, _, _ := pqsig.MLDSAKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	l.reg.Deployments["A"].V4Keys["PQ-device"] = registry.V4Key{Alg: pqsig.AlgMLDSA, KID: "A-pqdev-k1", Version: 1, PublicB64: base64.StdEncoding.EncodeToString(pqsig.MLDSAPublicBytes(other)), Custody: "test-fixture"}
	ex, raw, err := l.dispatch(t, "pq-invalid")
	if !errors.Is(err, ErrTransportRejected) || raw != nil || ex.TaskSent || l.w.tasks.Load() != 0 || hasEvent(ex, "authorized") {
		t.Fatalf("invalid proof must not reach the task: err=%v tasks=%d ex=%+v", err, l.w.tasks.Load(), ex)
	}
}
