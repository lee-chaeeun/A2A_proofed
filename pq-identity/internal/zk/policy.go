package zk

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// Contract is the trusted requester-side snapshot contract of a business request.
type Contract string

const (
	Pinned  Contract = "pinned"  // evaluate the snapshot authorized at dispatch
	Current Contract = "current" // evaluate the authoritative snapshot at the approval decision point
)

// EvidenceSchema is the producer schema of decision rows and events. Schema 2 adds
// evaluation ids, ledger ids, decision/approval sequence links, a decision marker for
// EVERY evaluation (including verification failures) and the pre-declared inventory.
const EvidenceSchema = 2

// Policies. All verify the same receipt against the same pinned image and require
// the verified Boolean to be true; they differ only in the declared context checks.
const (
	PolicyV0  = "V0"  // proof valid ∧ pass
	PolicyVT  = "VT"  // V0 ∧ challenge/task context
	PolicyVI  = "VI"  // V0 ∧ authorized input commitment under the stored contract
	PolicyVTI = "VTI" // VT ∧ VI
)

var Policies = []string{PolicyV0, PolicyVT, PolicyVI, PolicyVTI}

// ErrUnknownPolicy is returned for any policy string outside the closed vocabulary;
// an unknown policy is never evaluated with V0 semantics.
var ErrUnknownPolicy = errors.New("unknown ZK policy")

// KnownPolicy reports whether p is one of the four declared policies.
func KnownPolicy(p string) bool {
	for _, q := range Policies {
		if p == q {
			return true
		}
	}
	return false
}

// Request is the requester's local business request, created BEFORE dispatch. The
// A2A task id is associated after the server returns it (never chosen by us).
type Request struct {
	ID             string   `json:"request_id"`
	Challenge      [16]byte `json:"-"`
	ChallengeHex   string   `json:"challenge_hex"`
	Portfolio      string   `json:"portfolio"`
	Contract       Contract `json:"contract"`
	PinnedVersion  uint32   `json:"pinned_version"` // version authorized at dispatch (also recorded for Current, diagnostic)
	ExpectedWorker string   `json:"expected_worker"`
	TaskID         string   `json:"a2a_task_id,omitempty"`
}

// Decision is one policy evaluation of one delivered result. The fields are kept
// separate on purpose: a denial for application policy is not a verification failure.
type Decision struct {
	EvidenceSchema   int      `json:"evidence_schema"`
	EvaluationID     string   `json:"evaluation_id"`
	LedgerID         string   `json:"ledger_id"`
	RequestID        string   `json:"request_id"`
	Policy           string   `json:"policy"`
	Contract         Contract `json:"contract"`
	ReceiptSHA256    string   `json:"receipt_sha256"`
	ExpectedImageID  string   `json:"expected_image_id_hex"`
	ProofValid       bool     `json:"proof_valid"`
	VerifyError      string   `json:"verify_error,omitempty"`
	JournalHex       string   `json:"verified_journal_hex,omitempty"`
	ResultPass       bool     `json:"result_pass"`
	ContextMatch     bool     `json:"context_match"`
	ContextChecked   bool     `json:"context_checked"`
	InputAuthorized  bool     `json:"input_authorized"`
	InputChecked     bool     `json:"input_checked"`
	AuthorityVersion uint32   `json:"authority_version_at_decision"`
	ApprovalAllowed  bool     `json:"approval_allowed"`
	ApprovalInserted bool     `json:"approval_inserted"`
	DecisionSeq      int      `json:"decision_seq"`           // seq of this evaluation's zk_decision marker
	ApprovalSeq      int      `json:"approval_seq,omitempty"` // seq of its approval_inserted event (0 = none)
	Reason           string   `json:"reason"`
}

// Verified is the verifier CLI's successful output: the journal is trustworthy only
// because the pinned image id matched and the receipt verified.
type Verified struct {
	ReceiptSHA256 string
	Journal       Journal
	JournalHex    string
}

// Ledger holds the single-use business approvals of one isolated run. The Current
// contract's head comparison and the insert happen under the authority's mutex, so
// no authority update can interleave between the read and the write.
type Ledger struct {
	ID        string
	mu        sync.Mutex
	approvals map[string]Approval
	order     []string
}

type Approval struct {
	EvaluationID string `json:"evaluation_id"`
	RequestID    string `json:"request_id"`
	Policy       string `json:"policy"`
	Receipt      string `json:"receipt_sha256"`
	Version      uint32 `json:"authority_version"`
	Seq          int    `json:"event_seq"`
}

func NewLedger() *Ledger { return &Ledger{approvals: map[string]Approval{}} }

// NewLedgerID creates an isolated ledger with a stable id (recorded in rows/events).
func NewLedgerID(id string) *Ledger { return &Ledger{ID: id, approvals: map[string]Approval{}} }

func (l *Ledger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.approvals)
}

// Approvals returns the approvals in insertion order.
func (l *Ledger) Approvals() []Approval {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []Approval{}
	for _, id := range l.order {
		out = append(out, l.approvals[id])
	}
	return out
}

// Evaluate applies one policy with the default evaluation id "<request>/<policy>".
func Evaluate(policy string, req *Request, v *Verified, verr error, imageIDHex string, auth *Authority, led *Ledger) (Decision, error) {
	return EvaluateWithID(req.ID+"/"+policy, policy, req, v, verr, imageIDHex, auth, led)
}

// EvaluateWithID applies one policy to a verification outcome for a request and
// inserts at most one approval per request id in the ledger. verr != nil means the
// receipt did not verify (or was malformed); nothing is interpreted from it. Every
// evaluation records exactly one zk_decision marker; an approval records one
// approval_inserted event immediately after it, inside the same critical section.
// Unknown policies are refused before anything is recorded.
func EvaluateWithID(evalID, policy string, req *Request, v *Verified, verr error, imageIDHex string, auth *Authority, led *Ledger) (Decision, error) {
	d := Decision{EvidenceSchema: EvidenceSchema, EvaluationID: evalID, LedgerID: led.ID, RequestID: req.ID, Policy: policy, Contract: req.Contract, ExpectedImageID: imageIDHex}
	if !KnownPolicy(policy) {
		return d, fmt.Errorf("%w: %q", ErrUnknownPolicy, policy)
	}
	if v != nil {
		d.ReceiptSHA256 = v.ReceiptSHA256
	}
	marker := func(headV uint32, valid bool) map[string]any {
		return map[string]any{"evaluation_id": evalID, "ledger_id": led.ID, "request_id": req.ID, "policy": policy, "contract": string(req.Contract), "head_version": headV, "proof_valid": valid}
	}
	if verr != nil {
		d.ProofValid = false
		d.VerifyError = verr.Error()
		d.Reason = "verification failed: " + verr.Error()
		auth.mu.Lock()
		headV, _ := auth.headLocked()
		d.AuthorityVersion = headV
		d.DecisionSeq = auth.event("zk_decision", marker(headV, false))
		auth.mu.Unlock()
		return d, nil
	}
	d.ProofValid, d.JournalHex, d.ResultPass = true, v.JournalHex, v.Journal.Pass
	wantCtx := policy == PolicyVT || policy == PolicyVTI
	wantInput := policy == PolicyVI || policy == PolicyVTI
	d.ContextChecked, d.InputChecked = wantCtx, wantInput
	d.ContextMatch = bytes.Equal(v.Journal.Challenge[:], req.Challenge[:])

	// Serialized critical section: authority head read, input check and approval
	// insert cannot be interleaved by an authority update.
	auth.mu.Lock()
	defer auth.mu.Unlock()
	headV, headC := auth.headLocked()
	d.AuthorityVersion = headV
	// Explicit decision marker at the linearization point (same critical section as
	// the head read and the insert). The oracle joins on this marker's ORDER and
	// evaluation id, not on the head_version field, which is recorded for diagnostics.
	d.DecisionSeq = auth.event("zk_decision", marker(headV, true))
	switch req.Contract {
	case Pinned:
		c, ok := auth.commitmentLocked(req.PinnedVersion)
		d.InputAuthorized = ok && bytes.Equal(c[:], v.Journal.Commitment[:])
	case Current:
		d.InputAuthorized = bytes.Equal(headC[:], v.Journal.Commitment[:])
	}
	switch {
	case !d.ResultPass:
		d.Reason = "verified result is fail (sum above limit)"
	case wantCtx && !d.ContextMatch:
		d.Reason = "journal challenge does not match the stored request challenge"
	case wantInput && !d.InputAuthorized:
		d.Reason = fmt.Sprintf("journal commitment is not the authorized input under the %s contract (authority head v%d)", req.Contract, headV)
	default:
		d.ApprovalAllowed = true
	}
	if !d.ApprovalAllowed {
		return d, nil
	}
	l := led
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, dup := l.approvals[req.ID]; dup {
		d.Reason = "approval already recorded for this request; no additional approval"
		return d, nil
	}
	seq := auth.event("approval_inserted", map[string]any{"evaluation_id": evalID, "ledger_id": led.ID, "request_id": req.ID, "policy": policy, "receipt_sha256": v.ReceiptSHA256, "head_version": headV, "commitment_hex": hex.EncodeToString(v.Journal.Commitment[:])})
	l.approvals[req.ID] = Approval{EvaluationID: evalID, RequestID: req.ID, Policy: policy, Receipt: v.ReceiptSHA256, Version: headV, Seq: seq}
	l.order = append(l.order, req.ID)
	d.ApprovalInserted, d.ApprovalSeq = true, seq
	d.Reason = "approved"
	return d, nil
}
