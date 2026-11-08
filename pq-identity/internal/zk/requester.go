package zk

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"a2aid/internal/registry"
	"a2aid/internal/verifier"
	"a2aid/internal/wire"
)

// TransportPolicy is the default identity policy for task delivery: signed Agent Card
// by the enrolled publisher, endpoint equality and an authenticated TLS peer carrying
// the enrolled name. The closed set SupportedTransportPolicies also admits
// "PQ-device+cb": the identity component's own nonce challenge, a2aid-proof-v4
// appraisal (ML-DSA-65 key resident in the emulated device, context bound to the
// requester's own exporter) and acceptance invariants run BEFORE the task is sent, on
// the same connection, and the task itself goes through the identity requester's
// GuardedSend: single-use authorization for the issued session, sealed transport,
// dispatch pinned to the proof connection, no implicit reconnect or retry; a server
// that closes the proof connection after a valid proof receives nothing on a
// replacement connection, and recovery is a new Dispatch (new connection, nonce, proof
// and decision). The C+tls baseline keeps its documented semantics (appraisal before
// the task, no nonce session, no seal). Every other policy is refused before any
// network activity.
const TransportPolicy = "C+tls"

// SupportedTransportPolicies is the closed set the ZK requester implements.
var SupportedTransportPolicies = map[string]bool{"C+tls": true, "PQ-device+cb": true}

// ErrUnsupportedTransportPolicy is returned for any policy other than TransportPolicy.
var ErrUnsupportedTransportPolicy = errors.New("transport policy not implemented by the ZK component")

// ErrTransportRejected is wrapped when the full appraisal of the declared transport
// policy fails; no task bytes were sent.
var ErrTransportRejected = errors.New("transport appraisal rejected; task not sent")

// ErrDeliveryRefused wraps verifier.ErrDispatchRefused for bound transports: the proof
// connection was no longer the unique connection of the decision (closed, replaced or
// a reconnect was needed), so the task was refused before any byte. ErrDeliveryUnknown
// wraps verifier.ErrOutcomeUnknown: task bytes were written to the proof connection
// but the client cannot tell whether they arrived; only the worker's record can.
var (
	ErrDeliveryRefused = errors.New("task delivery refused before any byte: proof connection not available for dispatch (fresh connection, proof and decision required)")
	ErrDeliveryUnknown = errors.New("task delivery outcome unknown to the client (request written, no response); resolve from the worker's record")
)

// IdentityRecord is the bounded, requester-observed record of the identity decision
// that gated a bound-transport dispatch (nothing in it comes from the worker).
type IdentityRecord struct {
	DecisionID     string                `json:"decision_id"`
	Nonce          string                `json:"nonce,omitempty"`
	ProofConnID    int                   `json:"proof_conn_id"`
	PinnedConnID   int                   `json:"pinned_conn_id"`
	DispatchConnID int                   `json:"dispatch_conn_id"`
	Token          string                `json:"authorization_token,omitempty"`
	Dials          int                   `json:"tls_dials"`
	DialsRefused   int                   `json:"tls_dials_refused"`
	Events         []verifier.ReqEvent   `json:"requester_events"`
	Connections    []verifier.ConnRecord `json:"connections"`
}

// Requester runs the two-stage flow: (1) deliver a computation task over real A2A
// (discovery, full non-proof appraisal, SendMessage) on the authenticated-TLS
// identity baseline and receive the proof artifact; (2) verify with the pinned image
// id and gate the downstream approval under one policy at a time, with isolated
// ledgers.
type Requester struct {
	Reg        *registry.Registry
	RootCAs    interface{} // *x509.CertPool, passed through to the identity requester
	Resolver   map[string]string
	Bridge     *Bridge
	ImageIDHex string // pinned locally from the build output; never from the worker
	Auth       *Authority
	Trace      io.Writer // bounded exchange trace (no receipt bytes, no openings)
	Policy     string    // identity policy for the transport; must be TransportPolicy (default)
}

// TransportVerdict is the requester's own record of the transport appraisal that
// gated the task delivery (all fields observed by the requester, none from the worker).
type TransportVerdict struct {
	Policy           string `json:"policy"`
	Supported        bool   `json:"supported"`
	CardPresent      bool   `json:"card_signature_present"`
	CardValid        bool   `json:"card_valid_under_enrolled_publisher"`
	CardKID          string `json:"card_kid,omitempty"`
	CardReason       string `json:"card_reason,omitempty"`
	EndpointEqual    bool   `json:"endpoint_equal"`
	TLSAuthenticated bool   `json:"tls_authenticated"`
	TLSNameMatch     bool   `json:"tls_enrolled_name_match"`
	TLSPeer          string `json:"tls_peer_name,omitempty"`
	TLSExpected      string `json:"tls_expected_name,omitempty"`
	Accept           bool   `json:"accept"`
	FailureStage     string `json:"failure_stage,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

// Exchange is the bounded record of one A2A task exchange.
type Exchange struct {
	RequestID       string           `json:"request_id"`
	TaskID          string           `json:"a2a_task_id"`
	Endpoint        string           `json:"endpoint"`
	TransportPolicy string           `json:"transport_policy"`
	Transport       TransportVerdict `json:"transport"`
	TaskSent        bool             `json:"task_sent"`        // true once the zk_task was written to the transport
	Delivery        string           `json:"delivery_outcome"` // not_sent | delivered | refused | unknown | error (bound transports: from GuardedSend)
	Identity        *IdentityRecord  `json:"identity,omitempty"`
	TLSPeer         string           `json:"tls_peer_name"`
	Task            wire.ZKTask      `json:"task_sent_payload"`
	Result          wire.ZKResult    `json:"result_received"` // receipt bytes stripped below
	ReceiptBytes    int              `json:"receipt_bytes"`
	ReceiptSHA256   string           `json:"receipt_sha256"`
	RoundTripMS     int64            `json:"round_trip_ms"`
	Error           string           `json:"error,omitempty"`
}

// NewRequest creates the local business request BEFORE dispatch (challenge, contract,
// authorized version, expected worker). The A2A task id is filled in after dispatch.
func NewRequest(id, portfolio string, contract Contract, version uint32, worker string) *Request {
	c := NewChallenge()
	return &Request{ID: id, Challenge: c, ChallengeHex: hex.EncodeToString(c[:]), Portfolio: portfolio, Contract: contract, PinnedVersion: version, ExpectedWorker: worker}
}

func transportVerdict(d *verifier.Decision, pol string) TransportVerdict {
	v := TransportVerdict{Policy: pol, Supported: true, CardPresent: d.Card.Present, CardValid: d.Card.Valid, CardKID: d.Card.KeyID, CardReason: d.Card.Reason, EndpointEqual: d.EndpointEqual, Accept: d.Accept, FailureStage: d.FailureStage, Reason: d.Reason}
	if d.TLS != nil {
		v.TLSAuthenticated, v.TLSNameMatch, v.TLSPeer, v.TLSExpected = d.TLS.Authenticated, d.TLS.NameMatch, d.TLS.PeerName, d.TLS.ExpectedName
	}
	return v
}

// Dispatch sends the zk_task and returns the exchange and the raw receipt bytes.
// Order: policy check (closed set) → identity Connect (card fetch, TLS) → full
// non-proof appraisal (signed card by the enrolled publisher, endpoint equality,
// enrolled TLS name) → only then SendMessage. A failed appraisal returns before any
// task bytes exist. No nonce session is issued or consumed and the identity
// component's Release (synthetic job) is never called. Any malformed or mismatched
// artifact is an error with NO receipt bytes.
func (r *Requester) Dispatch(ctx context.Context, endpoint string, req *Request) (*Exchange, []byte, error) {
	pol := r.Policy
	if pol == "" {
		pol = TransportPolicy
	}
	ex := &Exchange{RequestID: req.ID, Endpoint: endpoint, TransportPolicy: pol, Transport: TransportVerdict{Policy: pol}, Delivery: "not_sent"}
	fail := func(msg string) (*Exchange, []byte, error) {
		ex.Error = msg
		r.trace(ex)
		return ex, nil, errors.New(msg)
	}
	failErr := func(err error) (*Exchange, []byte, error) { // keeps the error chain (errors.Is)
		ex.Error = err.Error()
		r.trace(ex)
		return ex, nil, err
	}
	if !SupportedTransportPolicies[pol] {
		err := fmt.Errorf("%w: %q (supported: C+tls, PQ-device+cb)", ErrUnsupportedTransportPolicy, pol)
		ex.Error, ex.Transport.Reason = err.Error(), err.Error()
		r.trace(ex)
		return ex, nil, err
	}
	ex.Transport.Supported = true
	idr := verifier.New(r.Reg, nil, nil)
	setRoot(idr, r.RootCAs)
	idr.Resolver = r.Resolver
	idr.HTTPTimeout = 15 * time.Minute // the worker proves inside the request
	d := &verifier.Decision{Policy: pol}
	client, err := idr.Connect(ctx, endpoint, req.ExpectedWorker, d)
	if err != nil {
		ex.Transport = transportVerdict(d, pol)
		return fail("connect: " + err.Error())
	}
	defer client.Destroy()
	// Full appraisal of the declared transport policy BEFORE any task bytes. For a
	// non-proof policy this is the identity component's own card/url/tls check and
	// invariant finalization (empty nonce: no session is claimed). For PQ-device+cb the
	// identity component issues its nonce, sends the challenge over the same
	// connection, and appraises the returned a2aid-proof-v4 credential.
	parsed, _ := wire.ParsePolicy(pol)
	identity := func() {
		ex.Identity = &IdentityRecord{DecisionID: d.DecisionID, Nonce: d.Nonce, ProofConnID: d.ProofConnID, PinnedConnID: d.PinnedConnID, DispatchConnID: d.DispatchConnID, Token: d.JobToken, Dials: d.Dials, DialsRefused: d.DialsRefused, Events: d.Events, Connections: d.Conns}
	}
	var nonce string
	if parsed.HasProof() {
		n, err := idr.Issue(req.ExpectedWorker, pol)
		if err != nil {
			return fail("issue: " + err.Error())
		}
		nonce = n
		raw, err := idr.Challenge(ctx, client, d, nonce, nil)
		if err != nil {
			ex.Transport = transportVerdict(d, pol)
			identity()
			return fail("challenge exchange: " + err.Error())
		}
		idr.AppraiseRecord(d, nonce, raw)
	} else {
		idr.Appraise(pol, "", req.ExpectedWorker, map[string]any{}, d)
	}
	ex.Transport = transportVerdict(d, pol)
	ex.TLSPeer = ex.Transport.TLSPeer
	if !d.Accept {
		err := fmt.Errorf("%w (stage %s): %s", ErrTransportRejected, d.FailureStage, d.Reason)
		ex.Error = err.Error()
		if parsed.HasProof() {
			identity()
		}
		r.trace(ex)
		return ex, nil, err
	}
	task := wire.ZKTask{Type: "zk_task", Schema: wire.ZKSchema, RequestID: req.ID, Portfolio: req.Portfolio, ChallengeHex: req.ChallengeHex, Contract: string(req.Contract), Version: req.PinnedVersion}
	ex.Task = task
	msg := &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewDataPart(wire.ToMap(task)))}
	t0 := time.Now()
	var res a2a.SendMessageResult
	if parsed.HasProof() {
		// Bound transport: the task is the authorized message of the identity decision
		// and goes through the single release guard (seal, pinned connection, no
		// implicit reconnect). The synthetic job is never sent.
		var outcome verifier.SendOutcome
		res, outcome, err = idr.GuardedSend(ctx, client, nonce, d, "zk_task", func(string) *a2a.SendMessageRequest { return msg })
		ex.RoundTripMS = time.Since(t0).Milliseconds()
		ex.TaskSent = d.JobSent
		ex.Delivery = string(outcome)
		identity()
		switch {
		case errors.Is(err, verifier.ErrDispatchRefused):
			return failErr(fmt.Errorf("%w: %v", ErrDeliveryRefused, d.JobError))
		case errors.Is(err, verifier.ErrOutcomeUnknown):
			return failErr(fmt.Errorf("%w: %v", ErrDeliveryUnknown, d.JobError))
		case err != nil:
			return fail("send: " + err.Error())
		}
	} else {
		ex.TaskSent = true
		res, err = client.SendMessage(ctx, msg)
		ex.RoundTripMS = time.Since(t0).Milliseconds()
		if err != nil {
			ex.Delivery = "error"
			return fail("send: " + err.Error())
		}
		ex.Delivery = "delivered"
	}
	tk, ok := res.(*a2a.Task)
	if !ok || len(tk.Artifacts) == 0 || len(tk.Artifacts[0].Parts) == 0 {
		return fail("no artifact in response")
	}
	ex.TaskID = string(tk.ID)
	req.TaskID = ex.TaskID
	m, ok := tk.Artifacts[0].Parts[0].Data().(map[string]any)
	if !ok {
		return fail("artifact part is not a data part")
	}
	var zr wire.ZKResult
	if err := wire.FromMap(m, &zr); err != nil {
		return fail("artifact not decodable as zk_result: " + err.Error())
	}
	if zr.Type != "zk_result" || zr.Schema != wire.ZKSchema {
		return fail(fmt.Sprintf("unexpected artifact type %q schema %d", zr.Type, zr.Schema))
	}
	if zr.RequestID != req.ID {
		zr.ReceiptB64 = ""
		ex.Result = zr
		return fail(fmt.Sprintf("artifact request id %q does not match the request %q", zr.RequestID, req.ID))
	}
	if zr.Error != "" {
		zr.ReceiptB64 = ""
		ex.Result = zr
		return fail("worker error: " + zr.Error)
	}
	raw, derr := base64.StdEncoding.DecodeString(zr.ReceiptB64)
	if derr != nil || len(raw) == 0 || len(raw) > MaxReceiptBytes {
		zr.ReceiptB64 = ""
		ex.Result = zr
		return fail(fmt.Sprintf("receipt bytes unusable (len %d, err %v)", len(raw), derr))
	}
	sum := sha256.Sum256(raw)
	ex.ReceiptBytes, ex.ReceiptSHA256 = len(raw), hex.EncodeToString(sum[:])
	zr.ReceiptB64 = "" // bounded trace: bytes are kept as a separate receipt file by hash
	ex.Result = zr
	r.trace(ex)
	return ex, raw, nil
}

// Judge verifies once and evaluates every policy with its own isolated ledger. The
// evaluation ids are "<fixture>/<policy>".
func (r *Requester) Judge(ctx context.Context, fixture string, req *Request, receipt []byte, ledgers map[string]*Ledger, imageIDHex string) (*Verified, error, []Decision) {
	var v *Verified
	var verr error
	if receipt == nil {
		verr = errors.New("no receipt delivered")
	} else {
		v, verr = r.Bridge.Verify(ctx, receipt, imageIDHex)
	}
	var out []Decision
	for _, p := range Policies {
		led := ledgers[p]
		if led == nil {
			led = NewLedgerID(fixture + "/" + p)
			ledgers[p] = led
		}
		d, err := EvaluateWithID(fixture+"/"+p, p, req, v, verr, imageIDHex, r.Auth, led)
		if err != nil { // cannot happen for the closed Policies list; never evaluate as V0
			panic(err)
		}
		if v == nil && receipt != nil {
			sum := sha256.Sum256(receipt)
			d.ReceiptSHA256 = hex.EncodeToString(sum[:])
		}
		out = append(out, d)
	}
	return v, verr, out
}

func (r *Requester) trace(ex *Exchange) {
	if r.Trace == nil {
		return
	}
	b, _ := json.Marshal(ex)
	r.Trace.Write(append(b, '\n'))
}
