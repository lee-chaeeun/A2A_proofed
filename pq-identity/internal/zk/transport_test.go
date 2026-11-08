package zk

// Transport policy enforcement before task delivery: real HTTPS A2A servers (a2a-go
// JSON-RPC, served card) with server-side request counters. The assertion in every
// negative case is the ABSENCE of a task POST, not merely a Dispatch error.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"iter"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"a2aid/internal/cardsig"
	"a2aid/internal/registry"
	"a2aid/internal/wire"
)

const tEndpoint = "https://a.a2aid.test:9443"

type cardProv struct{ card *a2a.AgentCard }

func (c cardProv) Card(ctx context.Context) (*a2a.AgentCard, error) { return c.card, nil }

// zkStubWorker answers zk_task with a small NON-genuine receipt (delivery test only;
// verification is a separate stage) or with a configurable broken artifact.
type zkStubWorker struct {
	mode string // ok | wrong_request_id | wrong_type | worker_error | bad_b64
}

func (s *zkStubWorker) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		if ec.StoredTask == nil {
			if !yield(a2a.NewSubmittedTask(ec, ec.Message), nil) {
				return
			}
		}
		var d map[string]any
		for _, p := range ec.Message.Parts {
			if m, ok := p.Data().(map[string]any); ok {
				d = m
			}
		}
		var task wire.ZKTask
		_ = wire.FromMap(d, &task)
		res := wire.ZKResult{Type: "zk_result", Schema: wire.ZKSchema, RequestID: task.RequestID, ReceiptB64: base64.StdEncoding.EncodeToString([]byte("stub-receipt-not-genuine")), WorkerDeployment: "dep-A"}
		switch s.mode {
		case "wrong_request_id":
			res.RequestID = "someone-else"
		case "wrong_type":
			res.Type = "zk_other"
		case "worker_error":
			res.Error, res.ReceiptB64 = "stub failure", ""
		case "bad_b64":
			res.ReceiptB64 = "%%%"
		}
		if !yield(a2a.NewArtifactEvent(ec, a2a.NewDataPart(wire.ToMap(res))), nil) {
			return
		}
		yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil), nil)
	}
}

func (s *zkStubWorker) Cancel(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) { yield(nil, context.Canceled) }
}

func certFor(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
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

func pubPEM(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

type tLab struct {
	srv       *httptest.Server
	cardGETs  atomic.Int32
	taskPOSTs atomic.Int32
	reg       *registry.Registry
	pool      *x509.CertPool
	resolver  map[string]string
}

// newLab serves the given (possibly unsigned/tampered) card and the stub worker over
// TLS with cert; the registry enrolls publisher key pub under kid and TLS name tlsName.
func newLab(t *testing.T, card *a2a.AgentCard, cert tls.Certificate, trust bool, pubPEMStr, kid, tlsName string, worker *zkStubWorker) *tLab {
	t.Helper()
	l := &tLab{resolver: map[string]string{}}
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewAgentCardHandler(cardProv{card}))
	mux.Handle("/", a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(worker)))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			l.cardGETs.Add(1)
		} else {
			l.taskPOSTs.Add(1)
		}
		mux.ServeHTTP(w, r)
	})
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	l.srv = ts
	l.pool = x509.NewCertPool()
	if trust {
		l.pool.AddCert(cert.Leaf)
	}
	l.resolver["a.a2aid.test:9443"] = ts.Listener.Addr().String()
	l.reg = &registry.Registry{Deployments: map[string]*registry.Deployment{"A": {DeploymentID: "dep-A", AttesterID: "dep-A", CardKeyID: kid, CardPublicPEM: pubPEMStr, TLSName: tlsName}}}
	return l
}

func baseCard() *a2a.AgentCard {
	return &a2a.AgentCard{Name: "ZK worker", Version: "1.0.0", DefaultInputModes: []string{"application/json"}, DefaultOutputModes: []string{"application/json"},
		SupportedInterfaces: []*a2a.AgentInterface{{ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0", URL: tEndpoint}},
		Skills:              []a2a.AgentSkill{{ID: "zk", Name: "zk"}}}
}

func (l *tLab) dispatch(t *testing.T, policy string) (*Exchange, []byte, error) {
	t.Helper()
	r := &Requester{Reg: l.reg, RootCAs: l.pool, Resolver: l.resolver, Policy: policy}
	return r.Dispatch(context.Background(), tEndpoint, NewRequest("req-1", "p", Pinned, 1, "A"))
}

func TestTransport_ValidSignedCardDelivers(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signed, err := cardsig.Sign(baseCard(), key, "A-card-k1")
	if err != nil {
		t.Fatal(err)
	}
	l := newLab(t, signed, certFor(t, "a.a2aid.test"), true, pubPEM(t, key), "A-card-k1", "a.a2aid.test", &zkStubWorker{mode: "ok"})
	ex, raw, err := l.dispatch(t, "")
	if err != nil || raw == nil || string(raw) != "stub-receipt-not-genuine" {
		t.Fatalf("valid card must deliver: err=%v raw=%q ex=%+v", err, raw, ex)
	}
	if l.taskPOSTs.Load() != 1 || l.cardGETs.Load() != 1 || !ex.TaskSent || !ex.Transport.Accept || !ex.Transport.CardValid || !ex.Transport.TLSNameMatch || ex.TaskID == "" || ex.TransportPolicy != TransportPolicy {
		t.Fatalf("delivery record: posts=%d gets=%d ex=%+v", l.taskPOSTs.Load(), l.cardGETs.Load(), ex)
	}
}

func TestTransport_UnsignedCardNeverReceivesTask(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	l := newLab(t, baseCard(), certFor(t, "a.a2aid.test"), true, pubPEM(t, key), "A-card-k1", "a.a2aid.test", &zkStubWorker{mode: "ok"})
	ex, raw, err := l.dispatch(t, "")
	if err == nil || raw != nil || !errors.Is(err, ErrTransportRejected) || !strings.Contains(err.Error(), "card") {
		t.Fatalf("unsigned card must be rejected before delivery: err=%v raw=%v", err, raw)
	}
	if l.taskPOSTs.Load() != 0 || l.cardGETs.Load() != 1 || ex.TaskSent || ex.Transport.Accept || ex.Transport.CardPresent || !ex.Transport.TLSNameMatch {
		t.Fatalf("task was disclosed or verdict wrong: posts=%d ex=%+v", l.taskPOSTs.Load(), ex.Transport)
	}
}

func TestTransport_TamperedSignedCardNeverReceivesTask(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signed, _ := cardsig.Sign(baseCard(), key, "A-card-k1")
	signed.Name = "ZK worker (modified after signing)"
	l := newLab(t, signed, certFor(t, "a.a2aid.test"), true, pubPEM(t, key), "A-card-k1", "a.a2aid.test", &zkStubWorker{mode: "ok"})
	_, raw, err := l.dispatch(t, "")
	if err == nil || raw != nil || l.taskPOSTs.Load() != 0 || !errors.Is(err, ErrTransportRejected) {
		t.Fatalf("tampered card: err=%v posts=%d", err, l.taskPOSTs.Load())
	}
}

func TestTransport_UnenrolledPublisherNeverReceivesTask(t *testing.T) {
	enrolled, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// signed by another key, once under an unknown kid and once impersonating the enrolled kid
	for _, kid := range []string{"X-card-k9", "A-card-k1"} {
		signed, _ := cardsig.Sign(baseCard(), other, kid)
		l := newLab(t, signed, certFor(t, "a.a2aid.test"), true, pubPEM(t, enrolled), "A-card-k1", "a.a2aid.test", &zkStubWorker{mode: "ok"})
		ex, raw, err := l.dispatch(t, "")
		if err == nil || raw != nil || l.taskPOSTs.Load() != 0 || ex.Transport.CardValid {
			t.Fatalf("kid %s: unenrolled publisher must not receive the task: err=%v posts=%d", kid, err, l.taskPOSTs.Load())
		}
	}
}

func TestTransport_WrongTLSNameRejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signed, _ := cardsig.Sign(baseCard(), key, "A-card-k1")
	// trusted certificate, but the enrolled name is different: rejected at connect-tls
	l := newLab(t, signed, certFor(t, "a.a2aid.test"), true, pubPEM(t, key), "A-card-k1", "other.a2aid.test", &zkStubWorker{mode: "ok"})
	ex, raw, err := l.dispatch(t, "")
	if err == nil || raw != nil || l.taskPOSTs.Load() != 0 || ex.Transport.TLSNameMatch || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("enrolled-name mismatch: err=%v posts=%d ex=%+v", err, l.taskPOSTs.Load(), ex.Transport)
	}
	// certificate not trusted at all: the handshake fails, not even the card is fetched
	l2 := newLab(t, signed, certFor(t, "a.a2aid.test"), false, pubPEM(t, key), "A-card-k1", "a.a2aid.test", &zkStubWorker{mode: "ok"})
	_, raw, err = l2.dispatch(t, "")
	if err == nil || raw != nil || l2.taskPOSTs.Load() != 0 || l2.cardGETs.Load() != 0 {
		t.Fatalf("untrusted certificate: err=%v posts=%d gets=%d", err, l2.taskPOSTs.Load(), l2.cardGETs.Load())
	}
}

func TestTransport_UnsupportedPoliciesRefusedWithoutNetwork(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signed, _ := cardsig.Sign(baseCard(), key, "A-card-k1")
	l := newLab(t, signed, certFor(t, "a.a2aid.test"), true, pubPEM(t, key), "A-card-k1", "a.a2aid.test", &zkStubWorker{mode: "ok"})
	for _, pol := range []string{"T+cb", "S-env+cb", "S-env", "T", "P+cb", "C", "C+url", "bogus"} {
		ex, raw, err := l.dispatch(t, pol)
		if !errors.Is(err, ErrUnsupportedTransportPolicy) || raw != nil || ex.Transport.Supported || ex.TaskSent {
			t.Fatalf("policy %q must be refused explicitly: err=%v ex=%+v", pol, err, ex)
		}
	}
	if l.taskPOSTs.Load() != 0 || l.cardGETs.Load() != 0 {
		t.Fatalf("unsupported policies caused network activity: posts=%d gets=%d", l.taskPOSTs.Load(), l.cardGETs.Load())
	}
}

func TestTransport_MalformedArtifactsAreErrorsWithoutBytes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signed, _ := cardsig.Sign(baseCard(), key, "A-card-k1")
	for _, mode := range []string{"wrong_request_id", "wrong_type", "worker_error", "bad_b64"} {
		l := newLab(t, signed, certFor(t, "a.a2aid.test"), true, pubPEM(t, key), "A-card-k1", "a.a2aid.test", &zkStubWorker{mode: mode})
		ex, raw, err := l.dispatch(t, "")
		if err == nil || raw != nil || ex.Error == "" {
			t.Fatalf("%s: must return an error and no bytes: err=%v raw=%v ex=%+v", mode, err, raw, ex)
		}
	}
}
