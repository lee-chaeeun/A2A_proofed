package verifier

// [NETWORKED] Proof-to-delivery connection continuity. Two real HTTPS A2A
// servers (honest A, swap-target B with A's stolen certificate) speak the a2a-go
// JSON-RPC protocol through the real requester transport. The requester runs a real
// S-env+cb decision (software-signed envelope bound to the server's own TLS
// exporter, no TPM needed for the connection property), then before dispatch the
// proof connection is closed and the resolver is flipped to B. The job must NOT
// reach B: the sealed transport refuses the reconnect.
//
// White-box (package verifier) so the test can close the recorded proof connection,
// which is what an active intermediary does to force a reconnection.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"iter"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	cose "github.com/veraison/go-cose"

	"a2aid/internal/cardsig"
	"a2aid/internal/senv"
	"a2aid/internal/wire"
)

type contTLSKey struct{}

func (k *kit) cardKey() *ecdsa.PrivateKey { return k.card }

// softCOSE adapts an ECDSA key to a cose.Signer that tolerates a nil reader.
type softCOSE struct{ key *ecdsa.PrivateKey }

func (s softCOSE) Algorithm() cose.Algorithm { return cose.AlgorithmES256 }
func (s softCOSE) Sign(_ io.Reader, content []byte) ([]byte, error) {
	cs, err := cose.NewSigner(cose.AlgorithmES256, s.key)
	if err != nil {
		return nil, err
	}
	return cs.Sign(rand.Reader, content)
}

// cardProvider serves a fixed, pre-signed agent card.
type cardProvider struct{ card *a2a.AgentCard }

func (c cardProvider) Card(ctx context.Context) (*a2a.AgentCard, error) { return c.card, nil }

func signCardForTest(t *testing.T, card *a2a.AgentCard, key *ecdsa.PrivateKey, kid string) *a2a.AgentCard {
	t.Helper()
	signed, err := cardsig.Sign(card, key, kid)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// testCertFor issues a self-contained server certificate for name (its own root).
func testCertFor(t *testing.T, name string) tls.Certificate {
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

// senvServer is a minimal honest S-env+cb responder: it signs the challenge with the
// given key, binding the proof to ITS OWN connection exporter, and acknowledges jobs.
type senvServer struct {
	label    string
	sisoKey  *ecdsa.PrivateKey
	sisoKID  string
	attester string
	audience string
	received chan string // tokens received
}

func (s *senvServer) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
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
		var out map[string]any
		switch d["type"] {
		case "challenge":
			var ch wire.Challenge
			_ = wire.FromMap(d, &ch)
			nb, _ := wire.UnB64(ch.Nonce)
			var cb []byte
			if cs, _ := ctx.Value(contTLSKey{}).(*tls.ConnectionState); cs != nil {
				cb, _ = cs.ExportKeyingMaterial(wire.CBLabel, nil, 32)
			}
			eff := wire.ProofContext(ch.Policy, nb, cb)
			now := time.Now().UTC().Truncate(time.Second)
			pb, _ := senv.Encode(&senv.Payload{Version: senv.Version, AttesterID: s.attester, Nonce: eff, Action: ch.Action, Audience: ch.Audience, Policy: ch.Policy, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)})
			sealed, _ := senv.Seal(pb, s.sisoKID, softCOSE{s.sisoKey})
			out = wire.ToMap(wire.Evidence{Type: "evidence", Policy: ch.Policy, DeploymentID: s.attester, Nonce: ch.Nonce, COSESign1: wire.B64(sealed)})
		case "job":
			var job wire.Job
			_ = wire.FromMap(d, &job)
			select {
			case s.received <- s.label + ":" + job.Token:
			default:
			}
			out = wire.ToMap(wire.JobAck{Type: "job_ack", DeploymentID: s.attester, Token: job.Token})
		default:
			out = map[string]any{"type": "error"}
		}
		if !yield(a2a.NewArtifactEvent(ec, a2a.NewDataPart(out)), nil) {
			return
		}
		yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil), nil)
	}
}

func (s *senvServer) Cancel(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) { yield(nil, context.Canceled) }
}

func startTLSA2A(t *testing.T, srv *senvServer, cardURL string, cardKey *ecdsa.PrivateKey, cardKID string) *httptest.Server {
	t.Helper()
	card := &a2a.AgentCard{Name: srv.label, Version: "1.0.0", DefaultInputModes: []string{"application/json"}, DefaultOutputModes: []string{"application/json"},
		SupportedInterfaces: []*a2a.AgentInterface{{ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0", URL: cardURL}},
		Skills:              []a2a.AgentSkill{{ID: "attest", Name: "attest"}}}
	// a minimal card provider implementing a2asrv.AgentCardProvider
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewAgentCardHandler(cardProvider{signCardForTest(t, card, cardKey, cardKID)}))
	mux.Handle("/", a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(srv)))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), contTLSKey{}, r.TLS)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	return ts
}

func TestContinuity_ProofConnectionPinned(t *testing.T) {
	k := newKit(t) // reuse its keys/registry for A (dep-A), S-iso key is the S-env signer
	// Build honest A and swap-target B, both serving A's card and signing with A's
	// enrolled S-iso key (B has A's stolen TLS cert AND, to make the swap maximally
	// favourable to the attacker, the same signer — the ONLY thing stopping delivery
	// is the connection pin).
	aURL := "https://a.a2aid.test:9443"
	mk := func(label string) *senvServer {
		return &senvServer{label: label, sisoKey: k.siso, sisoKID: "A-siso-k1", attester: "dep-A", audience: DefaultAudience, received: make(chan string, 4)}
	}
	aSrv, bSrv := mk("A"), mk("B")
	aTS := startTLSA2A(t, aSrv, aURL, k.cardKey(), "A-card-k1")
	bTS := startTLSA2A(t, bSrv, aURL, k.cardKey(), "A-card-k1")
	// One shared certificate (A's), so TLS authenticates "a.a2aid.test" for both.
	cert := testCertFor(t, "a.a2aid.test")
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	aTS.TLS.Certificates = []tls.Certificate{cert}
	bTS.TLS.Certificates = []tls.Certificate{cert}
	aTS.StartTLS()
	bTS.StartTLS()
	defer aTS.Close()
	defer bTS.Close()
	aAddr := aTS.Listener.Addr().String()
	bAddr := bTS.Listener.Addr().String()
	k.r.Reg.Deployments["A"].TLSName = "a.a2aid.test"

	run := func(flip bool) *Decision {
		r := New(k.r.Reg, nil, nil) // real clock: the servers sign with real timestamps
		r.RootCAs = pool
		var mu sync.Mutex
		resolver := map[string]string{"a.a2aid.test:9443": aAddr}
		r.Resolver = resolver
		// the SDK dials the card URL's host:port (":0"); map it to A, later to B.
		r.Hook = func(stage string, d *Decision) {
			if stage != "after-appraise" || !d.Accept || !flip {
				return
			}
			// Active intermediary: close the proof connection and repoint the name to B.
			for _, c := range d.conns.all() {
				c.Close()
			}
			mu.Lock()
			resolver["a.a2aid.test:9443"] = bAddr
			mu.Unlock()
		}
		d, _ := r.Run(context.Background(), "S-env+cb", "https://a.a2aid.test:9443", "A", nil)
		return d
	}

	// Positive control: no flip. The job reuses the proof connection and reaches A.
	d := run(false)
	if !d.Accept {
		t.Fatalf("positive control not accepted: %s %s", d.FailureStage, d.Reason)
	}
	if !d.JobReleased || !d.JobConnReused {
		t.Fatalf("positive control did not deliver on the proof connection: released=%v reused=%v err=%s", d.JobReleased, d.JobConnReused, d.JobError)
	}
	select {
	case got := <-aSrv.received:
		if got != "A:"+d.JobToken {
			t.Fatalf("A received %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("A did not receive the job in the positive control")
	}

	// Attack: proof accepted, then the connection is closed and the name points to B.
	d = run(true)
	if !d.Accept {
		t.Fatalf("attack decision should still appraise-accept (the proof was valid): %s", d.Reason)
	}
	if d.JobReleased {
		t.Fatalf("job was released after a reconnect; expected refusal. conn_reused=%v err=%s", d.JobConnReused, d.JobError)
	}
	select {
	case got := <-bSrv.received:
		t.Fatalf("SWAP SUCCEEDED: B received the job %q (connection pin failed)", got)
	case <-time.After(1200 * time.Millisecond):
		// good: B never received it
	}
}
