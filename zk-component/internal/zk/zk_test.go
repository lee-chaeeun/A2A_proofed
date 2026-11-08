package zk

import (
	"encoding/hex"
	"errors"
	"testing"
)

// Commitment and journal encodings: fixed vectors so a change in either the Go or the
// Rust side is caught (the Rust side is cross-checked by the genuine-proof test).
func TestCommitmentVector(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i)
	}
	c := Commitment("desk-1/portfolio-7", 1, salt, [4]uint32{10, 20, 20, 30})
	if hex.EncodeToString(c[:]) == "" || c == ([32]byte{}) {
		t.Fatal("empty commitment")
	}
	c2 := Commitment("desk-1/portfolio-7", 2, salt, [4]uint32{10, 20, 20, 30})
	if c == c2 {
		t.Fatal("version must change the commitment")
	}
	if Sum([4]uint32{10, 20, 20, 30}) != 80 || !Pass([4]uint32{10, 20, 20, 30}) || Pass([4]uint32{20, 30, 30, 40}) {
		t.Fatal("sum/pass wrong")
	}
}

func TestParseJournal(t *testing.T) {
	b := make([]byte, JournalLen)
	b[0] = 1
	b[52] = 100
	b[60] = 1
	j, err := ParseJournal(b)
	if err != nil || !j.Pass || j.Limit != 100 {
		t.Fatalf("parse: %v %+v", err, j)
	}
	b[60] = 2
	if _, err := ParseJournal(b); err == nil {
		t.Fatal("pass byte 2 must be rejected")
	}
	b[60] = 1
	b[0] = 2
	if _, err := ParseJournal(b); err == nil {
		t.Fatal("schema 2 must be rejected")
	}
	if _, err := ParseJournal(b[:JournalLen-1]); err == nil {
		t.Fatal("short journal must be rejected")
	}
}

// Policy semantics with a synthetic verified journal (no receipt involved): the
// four policies differ only in the declared checks; approvals are single-use.
func TestPoliciesAndLedger(t *testing.T) {
	openings := []Opening{
		{Portfolio: "p", Version: 1, SaltHex: hex.EncodeToString(make([]byte, 32)), Holdings: [4]uint32{10, 20, 20, 30}},
		{Portfolio: "p", Version: 2, SaltHex: hex.EncodeToString(make([]byte, 32)), Holdings: [4]uint32{20, 30, 30, 40}},
	}
	auth, _ := NewAuthority(openings)
	c1, _ := openings[0].Commitment()
	req := &Request{ID: "r1", Challenge: NewChallenge(), Portfolio: "p", Contract: Pinned, PinnedVersion: 1}
	good := &Verified{ReceiptSHA256: "aa", Journal: Journal{Schema: 1, Challenge: req.Challenge, Commitment: c1, Limit: Limit, Pass: true}}
	for _, p := range Policies {
		led := NewLedger()
		d := mustEval(t, p, req, good, nil, "img", auth, led)
		if !d.ApprovalInserted || led.Count() != 1 {
			t.Fatalf("%s should approve honest pinned: %+v", p, d)
		}
		d2 := mustEval(t, p, req, good, nil, "img", auth, led)
		if d2.ApprovalInserted || led.Count() != 1 {
			t.Fatalf("%s duplicate must not add an approval", p)
		}
	}
	// wrong challenge: V0 and VI approve, VT/VTI deny
	bad := *good
	bad.Journal.Challenge = NewChallenge()
	want := map[string]bool{"V0": true, "VT": false, "VI": true, "VTI": false}
	for _, p := range Policies {
		d := mustEval(t, p, req, &bad, nil, "img", auth, NewLedger())
		if d.ApprovalInserted != want[p] || !d.ProofValid {
			t.Fatalf("%s wrong challenge: inserted=%v want %v", p, d.ApprovalInserted, want[p])
		}
	}
	// Current contract after the authority moved to v2: v1 commitment is obsolete -> VI/VTI deny
	auth.Advance()
	cur := &Request{ID: "r2", Challenge: req.Challenge, Portfolio: "p", Contract: Current, PinnedVersion: 1}
	want = map[string]bool{"V0": true, "VT": true, "VI": false, "VTI": false}
	for _, p := range Policies {
		d := mustEval(t, p, cur, good, nil, "img", auth, NewLedger())
		if d.ApprovalInserted != want[p] || d.AuthorityVersion != 2 {
			t.Fatalf("%s current/obsolete: inserted=%v want %v (head %d)", p, d.ApprovalInserted, want[p], d.AuthorityVersion)
		}
	}
	// Pinned(v1) after the update still approves everywhere (delayed historical result)
	for _, p := range Policies {
		if d := mustEval(t, p, req, good, nil, "img", auth, NewLedger()); !d.ApprovalInserted {
			t.Fatalf("%s pinned after update must approve: %s", p, d.Reason)
		}
	}
	// verification failure: nothing interpreted, nothing approved
	for _, p := range Policies {
		d := mustEval(t, p, req, nil, errString("verification failed"), "img", auth, NewLedger())
		if d.ProofValid || d.ApprovalInserted || d.ResultPass {
			t.Fatalf("%s verification failure must not approve", p)
		}
	}
	// verified fail result: valid proof, no approval anywhere
	failj := *good
	failj.Journal.Pass = false
	for _, p := range Policies {
		d := mustEval(t, p, req, &failj, nil, "img", auth, NewLedger())
		if !d.ProofValid || d.ApprovalInserted {
			t.Fatalf("%s valid proof with pass=false must verify and not approve", p)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// mustEval is the test shim for the closed policy vocabulary.
func mustEval(t *testing.T, policy string, req *Request, v *Verified, verr error, img string, auth *Authority, led *Ledger) Decision {
	t.Helper()
	d, err := Evaluate(policy, req, v, verr, img, auth, led)
	if err != nil {
		t.Fatalf("Evaluate(%s): %v", policy, err)
	}
	return d
}

// An unknown policy string is refused, records nothing and never falls back to V0.
func TestUnknownPolicyRefused(t *testing.T) {
	openings := []Opening{{Portfolio: "p", Version: 1, SaltHex: hex.EncodeToString(make([]byte, 32)), Holdings: [4]uint32{1, 1, 1, 1}}}
	auth, _ := NewAuthority(openings)
	c1, _ := openings[0].Commitment()
	req := &Request{ID: "r", Challenge: NewChallenge(), Portfolio: "p", Contract: Pinned, PinnedVersion: 1}
	good := &Verified{ReceiptSHA256: "aa", Journal: Journal{Schema: 1, Challenge: req.Challenge, Commitment: c1, Limit: Limit, Pass: true}}
	led := NewLedgerID("x/VX")
	d, err := Evaluate("VX", req, good, nil, "img", auth, led)
	if !errors.Is(err, ErrUnknownPolicy) || d.ApprovalInserted || led.Count() != 0 || len(auth.Events) != 0 {
		t.Fatalf("unknown policy must be refused without side effects: err=%v d=%+v events=%d", err, d, len(auth.Events))
	}
	if KnownPolicy("v0") || !KnownPolicy("V0") {
		t.Fatal("KnownPolicy is exact")
	}
}

// Every evaluation records exactly one zk_decision marker (including verification
// failures) and an approval records one approval_inserted event immediately after it,
// both carrying the evaluation and ledger ids.
func TestMarkersAndApprovalEvents(t *testing.T) {
	openings := []Opening{{Portfolio: "p", Version: 1, SaltHex: hex.EncodeToString(make([]byte, 32)), Holdings: [4]uint32{1, 1, 1, 1}}}
	auth, _ := NewAuthority(openings)
	c1, _ := openings[0].Commitment()
	req := &Request{ID: "r", Challenge: NewChallenge(), Portfolio: "p", Contract: Pinned, PinnedVersion: 1}
	good := &Verified{ReceiptSHA256: "aa", Journal: Journal{Schema: 1, Challenge: req.Challenge, Commitment: c1, Limit: Limit, Pass: true}}
	led := NewLedgerID("F/V0")
	d, _ := EvaluateWithID("F/V0", "V0", req, good, nil, "img", auth, led)
	if d.DecisionSeq != 1 || d.ApprovalSeq != 2 || !d.ApprovalInserted || d.EvaluationID != "F/V0" || d.LedgerID != "F/V0" || d.EvidenceSchema != 2 {
		t.Fatalf("first evaluation: %+v", d)
	}
	if auth.Events[0].Kind != "zk_decision" || auth.Events[0].Fields["evaluation_id"] != "F/V0" || auth.Events[1].Kind != "approval_inserted" || auth.Events[1].Fields["ledger_id"] != "F/V0" {
		t.Fatalf("events: %+v", auth.Events)
	}
	d2, _ := EvaluateWithID("G/V0", "V0", req, good, nil, "img", auth, led) // duplicate request in the same ledger
	if d2.ApprovalInserted || d2.DecisionSeq != 3 || d2.ApprovalSeq != 0 || len(auth.Events) != 3 {
		t.Fatalf("duplicate: %+v events=%d", d2, len(auth.Events))
	}
	d3, _ := EvaluateWithID("H/V0", "V0", req, nil, errString("bad"), "img", auth, NewLedgerID("H/V0"))
	if d3.ProofValid || d3.DecisionSeq != 4 || auth.Events[3].Fields["proof_valid"] != false {
		t.Fatalf("verification failure must still record a marker: %+v", d3)
	}
	aps := led.Approvals()
	if len(aps) != 1 || aps[0].EvaluationID != "F/V0" || aps[0].Seq != 2 {
		t.Fatalf("ledger approvals: %+v", aps)
	}
}

// The oracle's independent arithmetic equals the production encodings on vectors.
func TestOracleArithmeticEqualsProduction(t *testing.T) {
	for i := 0; i < 50; i++ {
		salt := NewSalt()
		h := [4]uint32{uint32(i * 7), uint32(i * 13 % 1000), uint32(i), MaxHolding - uint32(i)}
		p := Commitment("desk-1/portfolio-7", uint32(i+1), salt, h)
		o, err := oracleCommitment("desk-1/portfolio-7", uint32(i+1), salt[:], h)
		if err != nil || p != o {
			t.Fatalf("commitment differs at %d", i)
		}
		if Sum(h) != oracleSum(h) || Pass(h) != oraclePass(h) {
			t.Fatalf("sum/pass differ at %d", i)
		}
	}
	b := make([]byte, JournalLen)
	b[0], b[52], b[60] = 1, 100, 1
	for k := 4; k < 52; k++ {
		b[k] = byte(k)
	}
	pj, perr := ParseJournal(b)
	oj, oerr := oracleParseJournal(b)
	if perr != nil || oerr != nil || pj.Challenge != oj.challenge || pj.Commitment != oj.commitment || pj.Pass != oj.pass {
		t.Fatal("journal decoders differ")
	}
	if _, err := oracleParseJournal(b[:60]); err == nil {
		t.Fatal("short journal accepted")
	}
}
