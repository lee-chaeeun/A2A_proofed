// Package verifier is the requester/relying party plus co-located verifier. It sees
// only protocol evidence: the card fetched from the discovery endpoint, the
// response to its own fresh nonce, the TLS connection it terminated itself, and the
// operator's enrollment registry.
//
// v2 acceptance invariants (enforced in finalize, tested in verifier_test.go):
//   - the policy string must be in the closed vocabulary (wire.ParsePolicy);
//   - the stored nonce session must match expected identity, action, policy and
//     audience, and must not be expired or already consumed (consume-on-failure);
//   - T and P accept only with Decision.Quote != nil && Quote.OK();
//   - P additionally requires a decoded, enrolled-AK-signed, schema-valid, fresh
//     envelope whose routine band carries evidence and no proof;
//   - S-* accept only with a signature that verifies under the enrolled key;
//   - +url requires endpoint equality, +tls requires an authenticated peer whose
//     certificate carries the enrolled name, +cb requires the proof to be bound to
//     an exporter value the requester derived from its own connection.
package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"

	"a2aid/internal/cardsig"
	"a2aid/internal/ctl"
	"a2aid/internal/pqsig"
	"a2aid/internal/ptv"
	"a2aid/internal/registry"
	"a2aid/internal/senv"
	"a2aid/internal/tpmsig"
	"a2aid/internal/wire"
)

const Action = "release-synthetic-job"

// DefaultAudience identifies this requester in S-env envelopes.
const DefaultAudience = "requester:a2aid-lab"

// SEnvSkew is the clock tolerance applied to S-env iat/exp.
const SEnvSkew = 60 * time.Second

// EnvelopeVerdict is the P-policy outer appraisal.
type EnvelopeVerdict struct {
	Decoded        bool   `json:"decoded"`
	Tagged         bool   `json:"tagged_cose_sign1"`
	AttesterID     string `json:"attester_id"`
	AttesterKnown  bool   `json:"attester_known"`
	AttesterMatch  bool   `json:"attester_matches_expected"`
	SignatureValid bool   `json:"signature_valid_under_enrolled_ak"`
	SchemaCode     string `json:"schema_code,omitempty"`
	SchemaOK       bool   `json:"schema_ok"`
	NonceMatch     bool   `json:"nonce_match"`
	FreshCode      string `json:"freshness_code,omitempty"`
	Timestamp      string `json:"timestamp"`
	Reason         string `json:"reason,omitempty"`
}

// SEnvVerdict is the S-env software-envelope appraisal.
type SEnvVerdict struct {
	Decoded        bool   `json:"decoded"`
	SignatureValid bool   `json:"signature_valid_under_enrolled_siso_key"`
	MetadataOK     bool   `json:"metadata_ok"`
	IssuedAt       string `json:"iat,omitempty"`
	ExpiresAt      string `json:"exp,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// TLSVerdict describes the authenticated transport of one decision.
type TLSVerdict struct {
	Used           bool   `json:"used"`
	Authenticated  bool   `json:"authenticated"` // chain verified under the lab root for the URL host
	Version        string `json:"version,omitempty"`
	PeerName       string `json:"peer_name,omitempty"`
	PeerCertSHA256 string `json:"peer_cert_sha256,omitempty"`
	ExpectedName   string `json:"expected_name"`
	NameMatch      bool   `json:"name_match"` // authenticated peer carries the ENROLLED name
	Conns          int    `json:"connections"`
	Reason         string `json:"reason,omitempty"`
}

// CBVerdict describes the channel-binding check.
type CBVerdict struct {
	Requested        bool   `json:"requested"`
	Available        bool   `json:"requester_exporter_available"`
	ExpectedHex      string `json:"requester_exporter_hex,omitempty"` // the requester's OWN value (safe to log after the session)
	AgentProvidedHex string `json:"agent_claimed_hex,omitempty"`      // diagnostic only, never trusted
	Matched          bool   `json:"proof_bound_to_requester_connection"`
}

// SessionVerdict reports the stored nonce-session context check.
type SessionVerdict struct {
	Found        bool      `json:"found"`
	Expected     string    `json:"expected_deployment,omitempty"`
	Policy       string    `json:"policy,omitempty"`
	Action       string    `json:"action,omitempty"`
	Audience     string    `json:"audience,omitempty"`
	IssuedAt     time.Time `json:"issued_at,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Expired      bool      `json:"expired"`
	ContextMatch bool      `json:"context_match"`
	Reason       string    `json:"reason,omitempty"`
}

// ProofV4Verdict is the appraisal of an a2aid-proof-v4 credential (EC-env, PQ-env,
// PQ-file, PQ-device): the algorithm and key id are pinned from the registry, the
// signed context must equal the context the requester issued, the signature must
// verify under the pinned public key. Shared-library verification (CIRCL / Go ECDSA).
type ProofV4Verdict struct {
	Present        bool   `json:"present"`
	Alg            string `json:"alg,omitempty"`
	KID            string `json:"kid,omitempty"`
	PinnedAlg      string `json:"pinned_alg"`
	PinnedKID      string `json:"pinned_kid"`
	Custody        string `json:"pinned_custody,omitempty"`
	ContextOK      bool   `json:"context_matches_expected"`
	ExpiryOK       bool   `json:"expiry_ok"`
	SignatureValid bool   `json:"signature_valid_under_pinned_key"`
	ContextLen     int    `json:"context_bytes"`
	SignatureLen   int    `json:"signature_bytes"`
	Stage          string `json:"failure_stage,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// Decision is everything the requester concluded for one appraisal.
type Decision struct {
	Policy            string               `json:"policy"`
	Expected          string               `json:"expected_deployment"`
	Endpoint          string               `json:"endpoint_url"`
	CardName          string               `json:"card_name"`
	CardURL           string               `json:"card_url"`
	CardURLs          []string             `json:"card_urls,omitempty"`
	EndpointEqual     bool                 `json:"endpoint_equal"` // card interface URL == discovery endpoint (normalized); enforced only with +url
	Card              cardsig.Verdict      `json:"card"`
	TLS               *TLSVerdict          `json:"tls,omitempty"`
	ProofV4           *ProofV4Verdict      `json:"proof_v4,omitempty"`
	CB                *CBVerdict           `json:"channel_binding,omitempty"`
	Session           *SessionVerdict      `json:"session,omitempty"`
	Nonce             string               `json:"nonce,omitempty"`
	NonceVerdict      string               `json:"nonce_verdict"` // n/a | ok | unknown | consumed | expired | mismatch
	ClaimedDeployment string               `json:"claimed_deployment,omitempty"`
	OuterTimestamp    string               `json:"outer_timestamp,omitempty"` // UNAUTHENTICATED for C/S/T
	SigVerdict        string               `json:"sig_verdict"`               // n/a | ok | invalid
	Quote             *tpmsig.QuoteVerdict `json:"quote,omitempty"`
	Envelope          *EnvelopeVerdict     `json:"envelope,omitempty"`
	SEnv              *SEnvVerdict         `json:"senv,omitempty"`
	Accept            bool                 `json:"accept"`
	Code              string               `json:"code,omitempty"` // PTV error code where defined
	FailureStage      string               `json:"failure_stage,omitempty"`
	Reason            string               `json:"reason,omitempty"`
	Invariant         string               `json:"invariant_violation,omitempty"` // set if a stage passed but finalize refused
	AppraisedAt       time.Time            `json:"appraised_at"`
	DispatchAttempted bool                 `json:"dispatch_attempted"`
	JobReleased       bool                 `json:"job_released"`
	JobConnReused     bool                 `json:"job_reused_proof_connection"` // the job reused the proof connection; false means a reconnect was refused
	JobToken          string               `json:"job_token,omitempty"`
	JobAckReceived    bool                 `json:"job_ack_received"`
	JobAckDeployment  string               `json:"job_ack_claimed_deployment,omitempty"`
	JobAckPCR         string               `json:"job_ack_pcr_at_receipt_hex,omitempty"`
	JobError          string               `json:"job_error,omitempty"`
	AgentError        string               `json:"agent_error,omitempty"`
	RawEvidence       map[string]any       `json:"raw_evidence,omitempty"` // public protocol evidence, kept for offline reverification

	// Release evidence (requester-observed; nothing below comes from the agent).
	DecisionID      string       `json:"decision_id"`
	ExpectedDepID   string       `json:"expected_deployment_id,omitempty"` // enrolled id of Expected, from the registry
	Conns           []ConnRecord `json:"connections,omitempty"`
	DiscoveryConnID int          `json:"discovery_conn_id,omitempty"` // connection that fetched the card (httptrace GotConn)
	ProofConnID     int          `json:"proof_conn_id,omitempty"`     // connection that carried the challenge/proof exchange
	PinnedConnID    int          `json:"pinned_conn_id,omitempty"`    // the one connection dispatch was allowed on
	DispatchConnID  int          `json:"dispatch_conn_id,omitempty"`  // connection the job request was written to; 0 = never written
	JobSent         bool         `json:"job_sent"`                    // request bytes were written (httptrace WroteRequest without error)
	Dials           int          `json:"tls_dials"`
	DialsRefused    int          `json:"tls_dials_refused"`
	Events          []ReqEvent   `json:"requester_events,omitempty"`
	// evidence schema 2: typed request context carried through the decision, the
	// authorization and the dispatch attempt (exact-equality checks, no substrings).
	EvidenceSchema   int         `json:"evidence_schema"`
	ProducerRevision string      `json:"producer_revision,omitempty"`
	Context          *ReqContext `json:"context,omitempty"`
	AuthContext      *ReqContext `json:"authorization_context,omitempty"`
	DispatchCtx      *ReqContext `json:"dispatch_context,omitempty"`

	conns *connRecorder
	http  *http.Client
	seq   int
}

// ReqContext is the typed request context. SessionKey is the issued nonce for proof
// policies and the synthetic release key for card-only policies (which issue no
// nonce); both appear in the session dump under that key.
type ReqContext struct {
	DecisionID    string `json:"decision_id"`
	ExpectedLabel string `json:"expected_label"`
	ExpectedDepID string `json:"expected_deployment_id"`
	Policy        string `json:"policy"`
	Action        string `json:"action"`
	Audience      string `json:"audience"`
	SessionKey    string `json:"session_key"`
	Token         string `json:"token,omitempty"`
}

// EvidenceSchemaVersion is the current evidence schema the requester produces.
const EvidenceSchemaVersion = 2

// ProducerRevision names the producer code line that wrote a record. With this
// revision every path, including early rejections and the concurrent/nonce-burn
// drivers, writes the full schema-2 record, and the ZK task goes through GuardedSend.
// Records without a revision are read as they are.
const ProducerRevision = "2026-11-08-pq-corrections"

func (r *Requester) ctxOf(d *Decision, sessionKey, token string) *ReqContext {
	return &ReqContext{DecisionID: d.DecisionID, ExpectedLabel: d.Expected, ExpectedDepID: d.ExpectedDepID, Policy: d.Policy, Action: Action, Audience: r.Audience, SessionKey: sessionKey, Token: token}
}

// ReqEvent is one requester-local, sequence-numbered lifecycle event. The sequence
// number is the order proof inside one decision; cross-process order is established
// only by causal ids (decision id, nonce, token), never by comparing clocks.
type ReqEvent struct {
	Seq    int    `json:"seq"`
	Kind   string `json:"kind"`
	ConnID int    `json:"conn_id,omitempty"`
	Token  string `json:"token,omitempty"`
	Detail string `json:"detail,omitempty"`
	At     string `json:"at"`
}

// Requester holds the trust anchors and the per-cell session store.
type Requester struct {
	Reg      *registry.Registry
	Ctl      *ctl.Client
	Store    *Store
	Trace    io.Writer
	Now      func() time.Time
	Audience string
	RootCAs  *x509.CertPool
	Resolver map[string]string // lab name resolution: "host:port" -> "ip:port"
	// HTTPTimeout bounds each A2A request (default 20s). The ZK component raises it
	// because a worker proves inside the request; identity decisions keep the default.
	HTTPTimeout time.Duration
	// Hook, when set, is called at the lab barriers "after-connect", "after-appraise"
	// and "before-dispatch" (TOCTOU and continuity fixtures). Nil in production.
	Hook func(stage string, d *Decision)
	mu   sync.Mutex
	// noSealAblation disables the transport seal. Unexported: only white-box tests
	// can set it, and only to label an ABLATION of the transport seal; it is never a mode of
	// the production requester.
	noSealAblation bool
}

// ev appends a sequence-numbered requester event to the decision and mirrors it to
// the controller with the decision id, so the independent record can be joined
// without trusting wall clocks.
func (r *Requester) ev(d *Decision, kind string, connID int, token, detail string) {
	d.seq++
	e := ReqEvent{Seq: d.seq, Kind: kind, ConnID: connID, Token: token, Detail: detail, At: time.Now().UTC().Format(time.RFC3339Nano)}
	d.Events = append(d.Events, e)
	data := map[string]any{"decision_id": d.DecisionID, "seq": e.Seq, "kind": kind, "conn_id": connID, "token": token, "detail": detail, "policy": d.Policy, "expected": d.Expected, "nonce": d.Nonce, "evidence_schema": EvidenceSchemaVersion}
	if kind == "authorized" && d.AuthContext != nil {
		data["context"] = d.AuthContext
	}
	if kind == "dispatch_attempt" && d.DispatchCtx != nil {
		data["context"] = d.DispatchCtx
	}
	r.Ctl.Emit("req_event", data)
}

// traceCtx attaches an httptrace that reports which of OUR recorded connections the
// transport used for the request (GotConn) and whether the request bytes were
// written (WroteRequest). It is observation for the evidence record; the control
// is the sealed recorder in the transport.
func (r *Requester) traceCtx(ctx context.Context, d *Decision, got func(id int), wrote func(err error)) context.Context {
	tr := &httptrace.ClientTrace{}
	if got != nil {
		tr.GotConn = func(info httptrace.GotConnInfo) {
			if d.conns != nil {
				got(d.conns.idOf(info.Conn))
			}
		}
	}
	if wrote != nil {
		tr.WroteRequest = func(info httptrace.WroteRequestInfo) { wrote(info.Err) }
	}
	return httptrace.WithClientTrace(ctx, tr)
}

func newDecisionID() string {
	b := wire.NewNonce()
	return hex.EncodeToString(b[:8])
}

// ChallengeContext returns a context that records the connection carrying the proof
// exchange in d.ProofConnID, for lab drivers that call SendChallenge themselves (the
// concurrent-delivery fixture). Run uses the same mechanism internally.
func (r *Requester) ChallengeContext(ctx context.Context, d *Decision) context.Context {
	return r.traceCtx(ctx, d, func(id int) { d.ProofConnID = id }, nil)
}

// LabCloseConns closes every TLS connection recorded for this decision. Lab hook only
// (continuity fixtures): it simulates an active intermediary dropping the proof
// connection after appraisal so that any dispatch would need a new dial.
func (d *Decision) LabCloseConns() {
	if d.conns == nil {
		return
	}
	for _, c := range d.conns.all() {
		c.Close()
	}
}

func (d *Decision) snapshotConns() {
	if d.conns == nil {
		return
	}
	d.Conns = d.conns.records()
	d.Dials, d.DialsRefused = d.conns.counters()
}

func New(reg *registry.Registry, c *ctl.Client, trace io.Writer) *Requester {
	if c == nil {
		c = ctl.Nop()
	}
	return &Requester{Reg: reg, Ctl: c, Store: NewStore(), Trace: trace, Now: time.Now, Audience: DefaultAudience}
}

func (r *Requester) now() time.Time {
	if r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now().UTC()
}

func (r *Requester) trace(kind string, v any) {
	if r.Trace == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "kind": kind, "data": v})
	r.Trace.Write(append(b, '\n'))
}

type traceInterceptor struct{ r *Requester }

func (t traceInterceptor) Before(ctx context.Context, req *a2aclient.Request) (context.Context, any, error) {
	t.r.trace("a2a_request", map[string]any{"method": req.Method, "base_url": req.BaseURL, "payload": req.Payload})
	return ctx, nil, nil
}
func (t traceInterceptor) After(ctx context.Context, resp *a2aclient.Response) error {
	var e any
	if resp.Err != nil {
		e = resp.Err.Error()
	}
	t.r.trace("a2a_response", map[string]any{"method": resp.Method, "base_url": resp.BaseURL, "payload": resp.Payload, "err": e})
	return nil
}

func (r *Requester) expectedKey(expected string) (*registry.Deployment, error) {
	if r.Reg == nil {
		return nil, errors.New("no registry")
	}
	d := r.Reg.Deployments[expected]
	if d == nil {
		return nil, fmt.Errorf("no enrollment for %q", expected)
	}
	return d, nil
}

// Connect fetches and appraises the card at the discovery endpoint, records
// endpoint equality and the authenticated transport, enforces +url / +tls
// fail-closed BEFORE any nonce is issued, and opens an A2A client to that same
// endpoint (routing policy constant across all variants).
func (r *Requester) Connect(ctx context.Context, endpoint, expected string, d *Decision) (*a2aclient.Client, error) {
	d.Endpoint, d.Expected = endpoint, expected
	if d.DecisionID == "" {
		d.DecisionID = newDecisionID()
	}
	if d.EvidenceSchema == 0 {
		d.EvidenceSchema = EvidenceSchemaVersion
	}
	d.ProducerRevision = ProducerRevision
	pol, err := wire.ParsePolicy(d.Policy)
	if err != nil {
		d.FailureStage, d.Reason = "policy", err.Error()
		return nil, err
	}
	dep, err := r.expectedKey(expected)
	if err != nil {
		d.FailureStage, d.Reason = "enrollment", err.Error()
		if d.Context == nil {
			d.Context = r.ctxOf(d, "", "")
		}
		return nil, err
	}
	d.ExpectedDepID = dep.DeploymentID
	// The typed decision context exists from the first event on, so that an early
	// rejection (connect failure) is auditable as such and not as an unsupported record.
	if d.Context == nil {
		d.Context = r.ctxOf(d, "", "")
	}
	d.conns = &connRecorder{}
	d.http = r.newHTTP(d.conns)
	r.ev(d, "connect", 0, "", endpoint)
	cctx := r.traceCtx(ctx, d, func(id int) { d.DiscoveryConnID = id }, nil)
	card, err := agentcard.NewResolver(d.http).Resolve(cctx, endpoint)
	d.snapshotConns()
	if err != nil {
		d.Card.Reason = "card fetch: " + err.Error()
		d.TLS = tlsVerdictFrom(d.conns, dep.TLSName)
		d.FailureStage, d.Reason = "connect", d.Card.Reason
		r.ev(d, "connect_failed", d.DiscoveryConnID, "", err.Error())
		return nil, err
	}
	r.ev(d, "card_fetched", d.DiscoveryConnID, "", "")
	r.trace("agent_card", card)
	d.CardName = card.Name
	normEP, epErr := wire.NormalizeURL(endpoint)
	for _, in := range card.SupportedInterfaces {
		if in == nil {
			continue
		}
		d.CardURLs = append(d.CardURLs, in.URL)
		if in.ProtocolBinding != a2a.TransportProtocolJSONRPC {
			continue
		}
		if n, err := wire.NormalizeURL(in.URL); err == nil && epErr == nil && n == normEP {
			d.EndpointEqual = true
			d.CardURL = in.URL
		}
	}
	if d.CardURL == "" && len(d.CardURLs) > 0 {
		d.CardURL = d.CardURLs[0]
	}
	d.Card = cardsig.Verify(card, func(kid string) (*ecdsa.PublicKey, error) {
		if kid != dep.CardKeyID {
			return nil, fmt.Errorf("kid is not the enrolled publisher key of %s", expected)
		}
		return tpmsig.ParsePublicPEM(dep.CardPublicPEM)
	})
	d.TLS = tlsVerdictFrom(d.conns, dep.TLSName)
	if pol.URL && !d.EndpointEqual {
		d.FailureStage, d.Reason = "connect-url", fmt.Sprintf("signed card declares %v, discovery endpoint is %s", d.CardURLs, endpoint)
		r.ev(d, "connect_failed", d.DiscoveryConnID, "", d.FailureStage+": "+d.Reason)
		return nil, errors.New(d.Reason)
	}
	if pol.TLS && (!d.TLS.Authenticated || !d.TLS.NameMatch) {
		d.FailureStage, d.Reason = "connect-tls", "transport not authenticated as the enrolled deployment: "+d.TLS.Reason
		r.ev(d, "connect_failed", d.DiscoveryConnID, "", d.FailureStage+": "+d.Reason)
		return nil, errors.New(d.Reason)
	}
	client, err := a2aclient.NewFromEndpoints(ctx, []*a2a.AgentInterface{{URL: endpoint, ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"}},
		a2aclient.WithJSONRPCTransport(d.http), a2aclient.WithCallInterceptors(traceInterceptor{r}))
	if err != nil {
		d.FailureStage, d.Reason = "connect", err.Error()
		return nil, err
	}
	return client, nil
}

// Issue creates a fresh 32-byte nonce bound to the expected deployment, action,
// policy and audience. Unknown policies are refused here as well.
func (r *Requester) Issue(expected, policy string) (string, error) {
	if _, err := wire.ParsePolicy(policy); err != nil {
		return "", err
	}
	n := wire.B64(wire.NewNonce())
	r.Store.Issue(n, expected, Action, policy, r.Audience)
	r.Ctl.Emit("nonce_issued", map[string]any{"nonce": n, "expected": expected, "policy": policy})
	return n, nil
}

// SendChallenge sends the challenge over A2A and returns the evidence map.
func (r *Requester) SendChallenge(ctx context.Context, client *a2aclient.Client, policy, nonce, expected string, hooks map[string]string) (map[string]any, error) {
	pol, err := wire.ParsePolicy(policy)
	if err != nil {
		return nil, err
	}
	dep, err := r.expectedKey(expected)
	if err != nil {
		return nil, err
	}
	ch := wire.Challenge{Type: "challenge", Policy: policy, Nonce: nonce, ExpectedDeployment: dep.DeploymentID, Action: Action, Audience: r.Audience, Hooks: hooks}
	if pol.CB {
		ch.Binding = "tls-exporter"
	}
	res, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewDataPart(wire.ToMap(ch)))})
	if err != nil {
		return nil, err
	}
	task, ok := res.(*a2a.Task)
	if !ok || len(task.Artifacts) == 0 || len(task.Artifacts[0].Parts) == 0 {
		return nil, errors.New("no artifact in response")
	}
	m, _ := task.Artifacts[0].Parts[0].Data().(map[string]any)
	if m == nil {
		return nil, errors.New("artifact is not a data part")
	}
	return m, nil
}

// Appraise consumes the nonce, then runs every applicable check so the record is
// complete even when an early stage already fails. The decision is accept only when
// every applicable check passes AND the finalize invariants hold.
func (r *Requester) Appraise(policy, nonce, expected string, raw map[string]any, d *Decision) {
	d.Policy, d.Expected, d.Nonce, d.RawEvidence = policy, expected, nonce, raw
	d.NonceVerdict, d.SigVerdict = "n/a", "n/a"
	d.AppraisedAt = r.now()
	defer func() {
		if rec := recover(); rec != nil {
			d.Accept = false
			d.FailureStage, d.Reason = "internal", fmt.Sprintf("panic during appraisal: %v", rec)
		}
	}()
	fail := func(stage, code, reason string) {
		if d.FailureStage == "" {
			d.FailureStage, d.Code, d.Reason = stage, code, reason
		}
	}
	pol, err := wire.ParsePolicy(policy)
	if err != nil {
		fail("policy", "", err.Error())
		d.Accept = false
		return
	}
	dep, err := r.expectedKey(expected)
	if err != nil {
		fail("enrollment", "", err.Error())
		d.Accept = false
		return
	}
	if !d.Card.Valid {
		fail("card", "", "card: "+d.Card.Reason)
	}
	if pol.URL && !d.EndpointEqual {
		fail("url", "", "signed card URL != discovery endpoint")
	}
	if pol.TLS && (d.TLS == nil || !d.TLS.Authenticated || !d.TLS.NameMatch) {
		fail("tls", "", "transport not authenticated as the enrolled deployment")
	}
	if !pol.HasProof() {
		r.finalize(pol, d)
		return
	}

	// Nonce session: consumed on first appraisal including failure (§4.2), then the
	// stored context is compared with the appraisal context.
	var sess Session
	se, err := r.Store.Claim(nonce)
	switch {
	case errors.Is(err, ErrUnknownNonce):
		d.NonceVerdict = "unknown"
		fail("nonce", ptv.ErrNonce, "nonce not issued by this verifier")
	case errors.Is(err, ErrConsumedNonce):
		d.NonceVerdict = "consumed"
		fail("nonce", ptv.ErrNonce, "nonce already consumed by an earlier appraisal")
	case errors.Is(err, ErrExpiredNonce):
		d.NonceVerdict = "expired"
		fail("nonce", ptv.ErrExpired, "nonce session expired before appraisal")
	default:
		d.NonceVerdict = "ok"
	}
	if se != nil {
		sess = *se
	}
	d.Session = sessionVerdict(sess, se != nil, expected, policy, r.Audience)
	if se != nil && !d.Session.ContextMatch {
		fail("session", "", "nonce session context mismatch: "+d.Session.Reason)
	}
	r.appraiseProof(pol, dep, nonce, d, fail)
	r.finalize(pol, d)
}

func sessionVerdict(s Session, found bool, expected, policy, audience string) *SessionVerdict {
	v := &SessionVerdict{Found: found}
	if !found {
		v.Reason = "no session"
		return v
	}
	v.Expected, v.Policy, v.Action, v.Audience, v.IssuedAt, v.ExpiresAt = s.Expected, s.Policy, s.Action, s.Audience, s.IssuedAt, s.ExpiresAt
	v.Expired = s.Consumed && !s.ConsumedAt.Before(s.ExpiresAt)
	switch {
	case s.Expected != expected:
		v.Reason = fmt.Sprintf("session issued for %q, appraised as %q", s.Expected, expected)
	case s.Policy != policy:
		v.Reason = fmt.Sprintf("session issued for policy %q, appraised under %q", s.Policy, policy)
	case s.Action != Action:
		v.Reason = fmt.Sprintf("session action %q != %q", s.Action, Action)
	case s.Audience != audience:
		v.Reason = fmt.Sprintf("session audience %q != %q", s.Audience, audience)
	default:
		v.ContextMatch = true
	}
	return v
}

// ownExporter returns the verifier's OWN RFC 9266 exporter for the connection that
// carried this decision's proof, and whether every recorded connection authenticated
// the same exporter. The agent's claimed value is never consulted:
// a relay cannot steer the verifier to a connection it did not terminate.
func (r *Requester) ownExporter(d *Decision) (hexVal string, consistent bool) {
	if d.conns == nil {
		return "", false
	}
	ekms := d.conns.ekms() // hex -> bytes, deduplicated
	switch len(ekms) {
	case 0:
		return "", false
	case 1:
		for h := range ekms {
			return h, true
		}
	}
	// More than one distinct exporter means the connection changed mid-decision; the
	// proof connection is the most recent one, but we flag the inconsistency.
	conns := d.conns.all()
	cs := conns[len(conns)-1].ConnectionState()
	b, err := cs.ExportKeyingMaterial(wire.CBLabel, nil, 32)
	if err != nil {
		return "", false
	}
	return hex.EncodeToString(b), false
}

// appraiseProof runs the base-policy proof checks against the domain-separated proof
// context the signer must have committed to. It is shared by the online path and
// offline reverification.
func (r *Requester) appraiseProof(pol wire.Policy, dep *registry.Deployment, nonce string, d *Decision, fail func(stage, code, reason string)) {
	var ev wire.Evidence
	_ = wire.FromMap(d.RawEvidence, &ev)
	d.ClaimedDeployment, d.OuterTimestamp, d.AgentError = ev.DeploymentID, ev.Timestamp, ev.Error
	nonceBytes, _ := wire.UnB64(nonce)
	if ev.Nonce != nonce && d.NonceVerdict == "ok" {
		d.NonceVerdict = "mismatch"
		fail("nonce", ptv.ErrNonce, "response nonce != issued nonce (stale or replayed proof)")
	}
	// The expected proof value binds the exact policy string and, for +cb, the
	// verifier's own exporter. It is never derived from anything in the response.
	var exporterSelf []byte
	if pol.CB {
		stored := ""
		if d.CB != nil {
			stored = d.CB.ExpectedHex // offline path: the verifier's own exporter, recorded at online appraisal
		}
		d.CB = &CBVerdict{Requested: true, AgentProvidedHex: ev.CBHex, ExpectedHex: stored}
		hexVal, consistent := "", false
		if stored != "" {
			hexVal, consistent = stored, true
		} else {
			hexVal, consistent = r.ownExporter(d)
		}
		if hexVal == "" {
			fail("binding", "", "policy requires channel binding but the verifier has no exporter for this decision's connection")
		} else {
			d.CB.Available = true
			d.CB.ExpectedHex = hexVal
			exporterSelf, _ = hex.DecodeString(hexVal)
			if !consistent {
				fail("binding", "", "the connections of this decision did not all authenticate the same TLS channel")
			}
		}
	}
	effNonce := wire.ProofContext(pol.String(), nonceBytes, exporterSelf)
	now := r.now()

	switch pol.Base {
	case wire.PolicySFile, wire.PolicySIso:
		pem, kid := dep.SFilePublicPEM, dep.SFileKeyID
		if pol.Base == wire.PolicySIso {
			pem, kid = dep.SIsoPublicPEM, dep.SIsoKeyID
		}
		pub, _ := tpmsig.ParsePublicPEM(pem)
		sig, _ := wire.UnB64(ev.Sig)
		ok := ev.Sig != "" && len(effNonce) > 0 && wire.VerifyBinding(pub, wire.Binding(effNonce, dep.DeploymentID, Action), sig)
		if ok {
			d.SigVerdict = "ok"
		} else {
			d.SigVerdict = "invalid"
			fail("signature", "", fmt.Sprintf("challenge signature does not verify under enrolled key %s (kid presented: %q)", kid, ev.SigKID))
		}
	case wire.PolicySEnv:
		d.SEnv = &SEnvVerdict{}
		b, _ := wire.UnB64(ev.COSESign1)
		if len(b) == 0 {
			fail("envelope", "", "no software envelope in response")
			return
		}
		env, err := senv.Open(b)
		if err != nil {
			fail("envelope", "", "envelope: "+err.Error())
			return
		}
		d.SEnv.Decoded = true
		d.SEnv.IssuedAt, d.SEnv.ExpiresAt = env.Payload.IssuedAt.UTC().Format(time.RFC3339), env.Payload.ExpiresAt.UTC().Format(time.RFC3339)
		pub, _ := tpmsig.ParsePublicPEM(dep.SIsoPublicPEM)
		d.SEnv.SignatureValid = env.VerifySignature(pub) == nil
		if !d.SEnv.SignatureValid {
			fail("envelope-signature", "", "software envelope signature invalid under the enrolled S-iso key of "+d.Expected)
		}
		if err := env.Check(dep.DeploymentID, effNonce, Action, r.Audience, pol.String(), now, SEnvSkew); err != nil {
			d.SEnv.Reason = err.Error()
			fail("envelope-metadata", "", "software envelope metadata: "+err.Error())
		} else {
			d.SEnv.MetadataOK = true
		}
		if d.SEnv.SignatureValid && d.SEnv.MetadataOK {
			d.SigVerdict = "ok"
		} else {
			d.SigVerdict = "invalid"
		}
	case wire.PolicyECEnv, wire.PolicyPQEnv, wire.PolicyPQFile, wire.PolicyPQDevice:
		r.appraiseV4(pol, dep, nonceBytes, nonce, exporterSelf, now, d, fail)
	case wire.PolicyT:
		if ev.Quote == nil {
			fail("quote", ptv.ErrAttestationFailed, "no quote in response")
			return
		}
		quoted, _ := wire.UnB64(ev.Quote.Quoted)
		sig, _ := wire.UnB64(ev.Quote.Signature)
		d.Quote = r.appraiseQuote(dep, quoted, sig, effNonce, fail)
	case wire.PolicyP:
		d.Envelope = &EnvelopeVerdict{}
		cose, _ := wire.UnB64(ev.COSESign1)
		if len(cose) == 0 {
			fail("envelope", ptv.ErrAttestationFailed, "no COSE_Sign1 in response")
			return
		}
		d.Envelope.Tagged = ptv.IsTaggedSign1(cose)
		env, err := ptv.Open(cose)
		if err != nil {
			fail("envelope", ptv.ErrAttestationFailed, "envelope: "+err.Error())
			return
		}
		d.Envelope.Decoded = true
		d.Envelope.AttesterID = env.AttesterID
		d.Envelope.Timestamp = env.Resp.Timestamp.UTC().Format(time.RFC3339)
		d.ClaimedDeployment = env.AttesterID
		// Trust anchor: attester_id must resolve, through enrollment, to the expected deployment.
		label, _ := r.Reg.ByAttesterID(env.AttesterID)
		d.Envelope.AttesterKnown = label != ""
		d.Envelope.AttesterMatch = label == d.Expected
		akPub, _ := tpmsig.ParsePublicPEM(dep.AKPublicPEM)
		d.Envelope.SignatureValid = akPub != nil && env.VerifySignature(akPub) == nil
		if !d.Envelope.AttesterKnown {
			fail("trust-anchor", ptv.ErrSignature, "attester_id is not enrolled")
		} else if !d.Envelope.AttesterMatch {
			fail("trust-anchor", ptv.ErrSignature, "attester_id resolves to another enrolled deployment (misbinding)")
		}
		if !d.Envelope.SignatureValid {
			fail("envelope-signature", ptv.ErrSignature, "COSE_Sign1 signature invalid under the enrolled AK of "+d.Expected)
		}
		if code, reason := env.SchemaCheck(); code != "" {
			d.Envelope.SchemaCode = code
			fail("schema", code, reason)
		} else {
			d.Envelope.SchemaOK = true
		}
		d.Envelope.NonceMatch = len(effNonce) > 0 && string(env.Resp.Nonce) == string(effNonce)
		if !d.Envelope.NonceMatch {
			fail("nonce", ptv.ErrNonce, "envelope nonce != issued (bound) nonce")
		}
		if code, reason := env.FreshnessCheck(now); code != "" {
			d.Envelope.FreshCode = code
			fail("freshness", code, reason)
		}
		// Embedded evidence is MANDATORY in the routine band and is verified
		// independently of the outer signature. Absent/empty/null evidence already
		// failed SchemaCheck; the quote appraisal still runs on whatever is there so
		// the record is complete, and finalize refuses acceptance without Quote.OK().
		te, err := ptv.DecodeEvidence(env.Resp.Evidence)
		if err != nil {
			fail("evidence", ptv.ErrAttestationFailed, "evidence decode: "+err.Error())
			return
		}
		d.Quote = r.appraiseQuote(dep, te.Quoted, te.Signature, effNonce, fail)
	}
}

// appraiseV4 checks an a2aid-proof-v4 credential against the requester's OWN expected
// context (policy string, pinned algorithm/key id, expected deployment id, audience,
// action, issued nonce, session id and own exporter) and the pinned public key. The
// expiry inside the signed context must lie in (now, now+V4MaxValidity]. Nothing in
// the response selects the algorithm, the key or the exporter.
func (r *Requester) appraiseV4(pol wire.Policy, dep *registry.Deployment, nonceBytes []byte, nonce string, exporterSelf []byte, now time.Time, d *Decision, fail func(stage, code, reason string)) {
	var ev wire.Evidence
	_ = wire.FromMap(d.RawEvidence, &ev)
	v := &ProofV4Verdict{PinnedAlg: wire.V4Alg(pol.Base)}
	d.ProofV4 = v
	d.SigVerdict = "invalid"
	pinRec, ok := dep.V4Keys[pol.Base]
	if !ok {
		fail("enrollment", "", "no "+pol.Base+" credential enrolled for "+d.Expected)
		return
	}
	v.PinnedKID, v.Custody = pinRec.KID, pinRec.Custody
	if pinRec.Alg != v.PinnedAlg {
		fail("enrollment", "", "registry algorithm for "+pol.Base+" is not the policy's algorithm")
		return
	}
	pin := pqsig.PinnedKey{Alg: pinRec.Alg, KID: pinRec.KID, Version: pinRec.Version}
	switch pinRec.Alg {
	case pqsig.AlgES256:
		pub, err := tpmsig.ParsePublicPEM(pinRec.PublicPEM)
		if err != nil {
			fail("enrollment", "", "pinned ES256 key unparseable")
			return
		}
		pin.ECPub = pub
	case pqsig.AlgMLDSA:
		pub, err := wire.UnB64(pinRec.PublicB64)
		if err != nil || len(pub) != pqsig.PublicKeySize {
			fail("enrollment", "", "pinned ML-DSA-65 key is not 1952 bytes")
			return
		}
		pin.MLDSAPub = pub
	}
	if ev.ProofV4 == nil {
		fail("proof", "", "no proof_v4 in response")
		return
	}
	v.Present, v.Alg, v.KID, v.ContextLen, v.SignatureLen = true, ev.ProofV4.Alg, ev.ProofV4.KID, len(ev.ProofV4.Context), len(ev.ProofV4.Signature)
	// Expiry is read from the presented context only to be checked; the comparison
	// below uses the presented expiry inside the expected context after that check.
	expected := &pqsig.Context{V: pqsig.Format, Role: pqsig.Role, Policy: pol.String(), Alg: pinRec.Alg, KID: pinRec.KID, Expected: dep.DeploymentID, Requester: r.Audience, Action: Action, Nonce: nonceBytes, Session: nonce, Exporter: exporterSelf}
	if len(exporterSelf) == 0 {
		expected.Exporter = []byte{}
	}
	if got, err := pqsig.Decode(ev.ProofV4.Context); err == nil {
		exp := time.Unix(got.Expiry, 0)
		if exp.After(now) && !exp.After(now.Add(V4MaxValidity)) {
			v.ExpiryOK = true
			expected.Expiry = got.Expiry
		} else {
			v.Reason = fmt.Sprintf("context expiry %s outside (now, now+%s]", exp.UTC().Format(time.RFC3339), V4MaxValidity)
		}
	}
	stage, err := pqsig.Verify(ev.ProofV4, pin, expected)
	if err != nil {
		v.Stage, v.Reason = stage, err.Error()
		if stage == "context-mismatch" && !v.ExpiryOK && v.Reason != "" {
			v.Stage = "expiry"
		}
		fail("proof-v4-"+v.Stage, "", "proof_v4: "+v.Reason)
		return
	}
	if !v.ExpiryOK {
		fail("proof-v4-expiry", "", "proof_v4: "+v.Reason)
		return
	}
	v.ContextOK, v.SignatureValid = true, true
	d.SigVerdict = "ok"
}

// V4MaxValidity bounds the signed expiry of an a2aid-proof-v4 context.
const V4MaxValidity = 300 * time.Second

func (r *Requester) appraiseQuote(dep *registry.Deployment, quoted, sig, nonce []byte, fail func(stage, code, reason string)) *tpmsig.QuoteVerdict {
	akPub, _ := tpmsig.ParsePublicPEM(dep.AKPublicPEM)
	ref, _ := hex.DecodeString(dep.PCRReference)
	v := tpmsig.VerifyQuote(quoted, sig, akPub, dep.AKQualified, nonce, ref)
	switch {
	case !v.Parsed || !v.MagicOK || !v.TypeOK || !v.SigAlgOK:
		fail("quote", ptv.ErrAttestationFailed, v.Reason)
	case !v.SignatureValid || !v.SignerMatch:
		fail("trust-anchor", ptv.ErrSignature, v.Reason)
	case !v.NonceMatch:
		fail("nonce", ptv.ErrNonce, v.Reason)
	case !v.PCRSelectionOK || !v.PCRDigestMatch:
		fail("config", ptv.ErrConfig, v.Reason)
	}
	return &v
}

// finalize computes Accept from the complete record. A stage may have passed
// silently (e.g. a code path that forgot to call fail); the invariants below refuse
// acceptance regardless and record the violation.
func (r *Requester) finalize(pol wire.Policy, d *Decision) {
	if d.FailureStage != "" {
		d.Accept = false
		return
	}
	viol := func(s string) {
		d.Accept = false
		d.Invariant = s
		d.FailureStage, d.Reason = "invariant", s
	}
	if !d.Card.Valid {
		viol("card not valid")
		return
	}
	if pol.URL && !d.EndpointEqual {
		viol("+url without endpoint equality")
		return
	}
	if pol.TLS && (d.TLS == nil || !d.TLS.Authenticated || !d.TLS.NameMatch) {
		viol("+tls without authenticated enrolled peer")
		return
	}
	if pol.HasProof() {
		if d.NonceVerdict != "ok" {
			viol("proof policy without a consumed, matching nonce")
			return
		}
		if d.Session == nil || !d.Session.ContextMatch || d.Session.Expired {
			viol("proof policy without matching session context")
			return
		}
		if pol.CB && (d.CB == nil || !d.CB.Available) {
			viol("+cb without a requester-derived exporter value")
			return
		}
	}
	switch pol.Base {
	case wire.PolicySFile, wire.PolicySIso:
		if d.SigVerdict != "ok" {
			viol("S policy without a valid signature")
			return
		}
	case wire.PolicyECEnv, wire.PolicyPQEnv, wire.PolicyPQFile, wire.PolicyPQDevice:
		if d.ProofV4 == nil || !d.ProofV4.ContextOK || !d.ProofV4.SignatureValid || !d.ProofV4.ExpiryOK || d.SigVerdict != "ok" {
			viol(pol.Base + " without a verified proof_v4 over the expected context")
			return
		}
	case wire.PolicySEnv:
		if d.SEnv == nil || !d.SEnv.Decoded || !d.SEnv.SignatureValid || !d.SEnv.MetadataOK {
			viol("S-env without a valid, metadata-checked envelope")
			return
		}
	case wire.PolicyT:
		if d.Quote == nil || !d.Quote.OK() {
			viol("T without a fully valid quote")
			return
		}
	case wire.PolicyP:
		e := d.Envelope
		if e == nil || !e.Decoded || !e.SignatureValid || !e.AttesterMatch || !e.SchemaOK || !e.NonceMatch || e.FreshCode != "" {
			viol("P without a valid envelope")
			return
		}
		if d.Quote == nil || !d.Quote.OK() {
			viol("P without a fully valid embedded quote")
			return
		}
	}
	if pol.CB {
		d.CB.Matched = true // every signed proof verified under the requester-derived bound nonce
	}
	d.Accept = true
}

// SendOutcome classifies a guarded send from the requester's own observations.
type SendOutcome string

const (
	SendNotAuthorized SendOutcome = "not_authorized" // appraisal rejected; nothing sent
	SendSuppressed    SendOutcome = "suppressed"     // a release for this session already happened
	SendRefused       SendOutcome = "refused"        // refused before any byte (no unique proof connection, or a reconnect was needed)
	SendDelivered     SendOutcome = "delivered"      // request written on the pinned connection and a response was received
	SendUnknown       SendOutcome = "unknown"        // request bytes were written but the client cannot tell whether they arrived
	SendError         SendOutcome = "error"          // transport error before any byte was written
)

var (
	ErrNotAuthorized     = errors.New("decision not accepted; nothing sent")
	ErrReleaseSuppressed = errors.New("a release for this session already happened; nothing sent")
	ErrDispatchRefused   = errors.New("dispatch refused before any task byte: the proof connection is not available (a fresh connection needs a fresh proof and a fresh decision)")
	ErrOutcomeUnknown    = errors.New("request bytes were written to the proof connection but no response was received; delivery is unknown to the client (resolve from the recipient's record)")
)

// GuardedSend is the single release guard for any authorized A2A message. It is used
// by Release for the synthetic job and by the ZK requester for the computation task;
// there is no second, weaker send path for bound policies.
//
// The release flag is set in memory BEFORE the send (idempotent within one verifier
// process, not durable exactly-once execution). Dispatch is pinned to the proof
// connection: the transport is sealed (no new dial), and before any task bytes are
// written the requester checks that exactly one TLS connection exists for this
// decision and that it is the connection the proof was verified on. Every SDK or
// transport retry needs a connection, every connection comes through the sealed
// recorder, so no retry path can reach a connection the proof did not use. A request
// that was written before the connection failed is reported as unknown, never as
// "not delivered": only the recipient's record can settle it.
func (r *Requester) GuardedSend(ctx context.Context, client *a2aclient.Client, nonce string, d *Decision, kind string, build func(token string) *a2a.SendMessageRequest) (a2a.SendMessageResult, SendOutcome, error) {
	if !d.Accept {
		r.ev(d, "not_authorized", 0, "", d.FailureStage)
		return nil, SendNotAuthorized, ErrNotAuthorized
	}
	key := nonce
	pol, _ := wire.ParsePolicy(d.Policy)
	if !pol.HasProof() {
		key = "C:" + d.Endpoint + ":" + fmt.Sprint(time.Now().UnixNano())
		r.Store.Issue(key, d.Expected, Action, d.Policy, r.Audience)
		r.Store.Claim(key)
	}
	token, first := r.Store.TryRelease(key)
	if !first {
		r.Ctl.Emit("release_suppressed", map[string]any{"nonce": nonce, "token": token})
		r.ev(d, "release_suppressed", 0, token, "a release for this nonce already happened")
		return nil, SendSuppressed, ErrReleaseSuppressed
	}
	d.JobToken = token
	if d.Context != nil && d.Context.SessionKey == "" {
		d.Context.SessionKey = key // card-only policies: the synthetic release key
	}
	d.AuthContext = r.ctxOf(d, key, token)
	r.ev(d, "authorized", d.ProofConnID, token, "policy="+d.Policy+" expected="+d.Expected+" nonce="+nonce+" kind="+kind)

	// Pin dispatch to the proof connection.
	pinned := d.ProofConnID
	if !pol.HasProof() {
		pinned = d.DiscoveryConnID // C policies: the authenticated connection the card came over
	}
	if d.conns != nil && !r.noSealAblation {
		d.conns.seal()
		r.ev(d, "sealed", pinned, token, "")
	} else if r.noSealAblation {
		r.ev(d, "seal_disabled_ablation", pinned, token, "ABLATION: transport not sealed")
	}
	if r.Hook != nil {
		r.Hook("before-dispatch", d)
	}
	d.snapshotConns()
	if pol.TLS && !r.noSealAblation {
		// Structural pre-send check: exactly one authenticated connection, and it is
		// the one that carried the proof (or the card for C policies).
		if pinned == 0 || len(d.Conns) != 1 || d.Conns[0].ID != pinned {
			d.DispatchAttempted, d.JobReleased, d.JobConnReused = false, false, false
			d.JobError = fmt.Sprintf("dispatch refused before send: proof connection not uniquely identified (pinned=%d, connections=%d)", pinned, len(d.Conns))
			r.ev(d, "refused_dispatch", pinned, token, d.JobError)
			r.Ctl.Emit("job_dispatch_refused", map[string]any{"decision_id": d.DecisionID, "nonce": nonce, "token": token, "reason": d.JobError, "kind": kind})
			return nil, SendRefused, ErrDispatchRefused
		}
		d.PinnedConnID = pinned
	}
	dialsBefore, refusedBefore := 0, 0
	if d.conns != nil {
		dialsBefore, refusedBefore = d.conns.counters()
	}
	d.DispatchAttempted, d.JobReleased = true, true
	d.DispatchCtx = r.ctxOf(d, key, token)
	r.ev(d, "dispatch_attempt", pinned, token, "kind="+kind)
	r.Ctl.Emit("job_released", map[string]any{"decision_id": d.DecisionID, "nonce": nonce, "token": token, "to_endpoint": d.Endpoint, "believed_deployment": d.Expected, "policy": d.Policy, "kind": kind})
	sctx := r.traceCtx(ctx, d,
		func(id int) { d.DispatchConnID = id; r.ev(d, "got_conn", id, token, "") },
		func(err error) {
			if err == nil {
				d.JobSent = true
				r.ev(d, "sent", d.DispatchConnID, token, "request written to the transport (wire delivery is established by the recipient's receipt, not by this event)")
			} else {
				r.ev(d, "write_failed", d.DispatchConnID, token, err.Error())
			}
		})
	res, err := client.SendMessage(sctx, build(token))
	d.snapshotConns()
	if d.conns != nil {
		dials, refused := d.conns.counters()
		if dials-dialsBefore > 0 || refused-refusedBefore > 0 {
			if r.noSealAblation {
				// ABLATION only: the seal was off, so the transport really dialed. Record
				// which layer decided (here the TLS handshake / name validation error).
				d.JobConnReused = false
				d.JobReleased = d.JobSent
				d.JobError = "ABLATION (seal disabled): new connection attempted after the proof"
				if err != nil {
					d.JobError += ": " + err.Error()
				}
				r.ev(d, "ablation_reconnect", d.DispatchConnID, token, d.JobError)
				return res, SendError, errors.New(d.JobError)
			}
			if d.JobSent {
				// The request was handed to the transport buffer of the proof connection,
				// the flush to that (dead) connection failed, and the transport's retry
				// dial was refused. The client cannot prove by itself that no byte left on
				// the proof connection; only the recipient's log can. Recorded as unknown,
				// never retried on another connection.
				d.JobConnReused = false
				d.JobReleased = false
				d.JobError = "unknown outcome: request written to the proof connection's transport buffer, flush failed, retry dial refused (no delivery on any other connection; see recipient log)"
				r.Ctl.Emit("job_outcome_unknown", map[string]any{"decision_id": d.DecisionID, "nonce": nonce, "token": token, "kind": kind})
				r.ev(d, "unknown_outcome", d.DispatchConnID, token, d.JobError)
				return nil, SendUnknown, ErrOutcomeUnknown
			}
			d.JobConnReused = false
			d.JobError = "job dispatch required a NEW connection after the proof; refused before any task bytes were sent (fresh proof required before dispatch)"
			r.Ctl.Emit("job_reconnect_refused", map[string]any{"decision_id": d.DecisionID, "nonce": nonce, "token": token, "new_dials": dials - dialsBefore, "refused": refused - refusedBefore, "kind": kind})
			r.ev(d, "refused_reconnect", 0, token, fmt.Sprintf("new_dials=%d refused=%d", dials-dialsBefore, refused-refusedBefore))
			d.JobReleased = false // nothing reached a recipient
			return nil, SendRefused, ErrDispatchRefused
		}
		d.JobConnReused = d.JobSent && (d.PinnedConnID == 0 || d.DispatchConnID == d.PinnedConnID)
		if d.JobSent && d.PinnedConnID != 0 && d.DispatchConnID != d.PinnedConnID {
			d.JobError = fmt.Sprintf("INVARIANT: job written to connection %d, proof connection is %d", d.DispatchConnID, d.PinnedConnID)
			r.ev(d, "unknown_outcome", d.DispatchConnID, token, d.JobError)
			return nil, SendUnknown, ErrOutcomeUnknown
		}
	}
	if err != nil {
		d.JobError = "job delivery error: " + err.Error()
		if d.JobSent {
			r.ev(d, "unknown_outcome", d.DispatchConnID, token, d.JobError)
			return nil, SendUnknown, fmt.Errorf("%w: %v", ErrOutcomeUnknown, err)
		}
		d.JobReleased = false
		r.ev(d, "dispatch_error", d.DispatchConnID, token, d.JobError)
		return nil, SendError, err
	}
	return res, SendDelivered, nil
}

// Release delivers the synthetic job through GuardedSend at most once per nonce and
// records the recipient's acknowledgement.
func (r *Requester) Release(ctx context.Context, client *a2aclient.Client, nonce string, d *Decision) {
	res, outcome, _ := r.GuardedSend(ctx, client, nonce, d, "job", func(token string) *a2a.SendMessageRequest {
		return &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewDataPart(wire.ToMap(wire.Job{Type: "job", Token: token, Nonce: nonce, DecisionID: d.DecisionID})))}
	})
	if outcome != SendDelivered {
		return
	}
	token := d.JobToken
	if task, ok := res.(*a2a.Task); ok && len(task.Artifacts) > 0 && len(task.Artifacts[0].Parts) > 0 {
		var ack wire.JobAck
		_ = wire.FromMap(task.Artifacts[0].Parts[0].Data(), &ack)
		d.JobAckReceived = ack.Type == "job_ack" && ack.Token == token
		d.JobAckDeployment, d.JobAckPCR = ack.DeploymentID, ack.PCRAtReceipt
	}
	if d.JobAckReceived {
		r.ev(d, "ack", d.DispatchConnID, token, "claimed="+d.JobAckDeployment)
	} else {
		r.ev(d, "no_ack", d.DispatchConnID, token, "response carried no matching job_ack")
	}
}

// Challenge sends the challenge for an issued nonce over client, recording the
// connection that carried the exchange (ProofConnID) and the lifecycle events. On a
// failed exchange the nonce is burned and the decision is finalized as rejected. Lab
// drivers that share one nonce between decisions (concurrent delivery, nonce burn)
// use this and AppraiseRecord so that every decision carries the same record shape
// as Run.
func (r *Requester) Challenge(ctx context.Context, client *a2aclient.Client, d *Decision, nonce string, hooks map[string]string) (map[string]any, error) {
	d.Nonce = nonce
	if d.Context != nil {
		d.Context.SessionKey = nonce
	}
	r.ev(d, "challenge_sent", 0, "", "nonce="+nonce)
	pctx := r.traceCtx(ctx, d, func(id int) { d.ProofConnID = id }, nil)
	raw, err := r.SendChallenge(pctx, client, d.Policy, nonce, d.Expected, hooks)
	d.snapshotConns()
	if err != nil {
		r.Store.Claim(nonce) // a failed exchange still burns the nonce
		d.FailureStage, d.Reason = "exchange", err.Error()
		r.ev(d, "exchange_failed", d.ProofConnID, "", err.Error())
		return nil, err
	}
	r.ev(d, "proof_received", d.ProofConnID, "", "")
	return raw, nil
}

// AppraiseRecordNoNonce records the appraisal event of a card-only decision that was
// appraised without a nonce session (mirrors Run's non-proof branch).
func (r *Requester) AppraiseRecordNoNonce(d *Decision) {
	r.ev(d, "appraised", d.DiscoveryConnID, "", fmt.Sprintf("accept=%v stage=%s", d.Accept, d.FailureStage))
}

// AppraiseRecord appraises the returned evidence, stores the session result and
// records the appraisal event.
func (r *Requester) AppraiseRecord(d *Decision, nonce string, raw map[string]any) {
	r.Appraise(d.Policy, nonce, d.Expected, raw, d)
	r.Store.SetResult(nonce, map[bool]string{true: "accept", false: "reject:" + d.FailureStage}[d.Accept])
	r.ev(d, "appraised", d.ProofConnID, "", fmt.Sprintf("accept=%v stage=%s", d.Accept, d.FailureStage))
}

// Run performs one complete decision: connect, challenge, appraisal, release.
func (r *Requester) Run(ctx context.Context, policy, endpoint, expected string, hooks map[string]string) (*Decision, error) {
	d := &Decision{Policy: policy, Expected: expected, Endpoint: endpoint, DecisionID: newDecisionID(), EvidenceSchema: EvidenceSchemaVersion}
	pol, err := wire.ParsePolicy(policy)
	if err != nil {
		d.FailureStage, d.Reason = "policy", err.Error()
		r.record(d)
		return d, err
	}
	client, err := r.Connect(ctx, endpoint, expected, d)
	if err != nil {
		if d.FailureStage == "" {
			d.FailureStage, d.Reason = "connect", err.Error()
		}
		r.record(d)
		return d, err
	}
	defer client.Destroy()
	if r.Hook != nil {
		r.Hook("after-connect", d)
	}
	if !pol.HasProof() {
		r.Appraise(policy, "", expected, map[string]any{}, d)
		r.ev(d, "appraised", d.DiscoveryConnID, "", fmt.Sprintf("accept=%v stage=%s", d.Accept, d.FailureStage))
		if r.Hook != nil {
			r.Hook("after-appraise", d)
		}
		r.Release(ctx, client, "", d)
		r.record(d)
		return d, nil
	}
	nonce, err := r.Issue(expected, policy)
	if err != nil {
		d.FailureStage, d.Reason = "policy", err.Error()
		r.record(d)
		return d, err
	}
	raw, err := r.Challenge(ctx, client, d, nonce, hooks)
	if err != nil {
		r.record(d)
		return d, nil
	}
	r.AppraiseRecord(d, nonce, raw)
	if r.Hook != nil {
		r.Hook("after-appraise", d)
	}
	r.Release(ctx, client, nonce, d)
	r.record(d)
	return d, nil
}

func (r *Requester) record(d *Decision) {
	r.trace("decision", d)
	d.snapshotConns()
	r.Ctl.Emit("decision", map[string]any{"decision_id": d.DecisionID, "policy": d.Policy, "endpoint": d.Endpoint, "expected": d.Expected, "accept": d.Accept, "stage": d.FailureStage, "code": d.Code, "reason": d.Reason, "nonce": d.Nonce, "job_token": d.JobToken, "job_sent": d.JobSent, "dispatch_conn_id": d.DispatchConnID, "pinned_conn_id": d.PinnedConnID})
}

// Reappraise is the OFFLINE path: given a stored session (as issued), the stored raw
// evidence and the stored connection facts, recompute the cryptographic verdicts
// with the clock fixed at the original appraisal time. Transport facts (card
// verdict, endpoint equality, TLS peer) cannot be re-derived offline and are copied
// from the record; they are reported separately by the caller.
func (r *Requester) Reappraise(stored *Decision, sess Session) *Decision {
	d := &Decision{Policy: stored.Policy, Expected: stored.Expected, Endpoint: stored.Endpoint, Card: stored.Card, EndpointEqual: stored.EndpointEqual, TLS: stored.TLS, DecisionID: stored.DecisionID}
	if stored.CB != nil {
		d.CB = &CBVerdict{Requested: stored.CB.Requested, ExpectedHex: stored.CB.ExpectedHex, AgentProvidedHex: stored.CB.AgentProvidedHex}
	}
	r.Store = NewStore()
	r.Store.Now = func() time.Time { return stored.AppraisedAt }
	r.Now = func() time.Time { return stored.AppraisedAt }
	if sess.Nonce != "" {
		r.Store.Issue(sess.Nonce, sess.Expected, sess.Action, sess.Policy, sess.Audience)
		if se, ok := r.Store.sess[sess.Nonce]; ok {
			se.IssuedAt, se.ExpiresAt = sess.IssuedAt, sess.ExpiresAt
		}
		// Ordering fact copied from the record: if this appraisal found the nonce
		// already consumed by an earlier one, reproduce that state. The crypto is
		// still re-derived; only the consumption order comes from the record.
		if stored.NonceVerdict == "consumed" {
			r.Store.Claim(sess.Nonce)
		}
	}
	r.Appraise(stored.Policy, stored.Nonce, stored.Expected, stored.RawEvidence, d)
	return d
}
