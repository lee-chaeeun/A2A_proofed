// Package audit is the structural release-evidence checker (checker version 2).
// It reads a retained run directory and decides, from the retained records alone,
// whether every protected dispatch had a preceding authorization for the same
// request context on the same proven connection, and whether every receipt belongs
// to the expected enrolled recipient. It never calls the production appraisal code.
//
// What it is: a structural audit of cooperative, requester-observed and
// controller-attributed records, joined by explicit ids (decision id, session key,
// token), ordered by requester-local sequence numbers and compared as typed values.
// Every check is labelled by its trust source.
//
// What it is not: tamper-proof evidence, an independent cryptographic appraisal (the
// recorded accept flag is reported as copied_appraisal and never upgraded), proof
// that every context field was signed by every policy, or a formal security proof.
// Cross-process order beyond causal ids is stipulated by the trusted controller.
//
// Inventory and evidence schema 2 (see RESULTS_V3_CORRECTIONS.md): every inventory
// cell declares its policy and expected decision count; every decision record
// carries evidence_schema >= 2, a decision id, contiguous requester events and typed
// context/authorization_context/dispatch_context. Older records are reported as
// unsupported_historical_schema, never as complete.
//
// Exit codes: 0 no unexpected violation and complete; 1 any unexpected violation,
// orphan receipt or duplicate decision id; 2 incomplete, malformed, unsupported
// schema, inventory mismatch (missing/unexpected cells, cardinality) or empty run.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"a2aid/internal/wire"
)

// CheckerVersion 2.1 (8 Nov 2026): exported per-decision entry points for the
// composite PQ audit; session checks apply only once a nonce was issued (a connect
// failure cannot have a session), so an early rejection is classified as such.
const CheckerVersion = "2.1"

// Trust classes.
const (
	ClassRecomputed   = "recomputed"
	ClassRequesterTLS = "requester_tls_observation"
	ClassCooperative  = "cooperative_event"
	ClassCopied       = "copied_appraisal"
	ClassStipulated   = "stipulated_order"
)

// Outcomes per decision.
const (
	OutViolation      = "violation"
	OutExpectedAttack = "violation_expected_by_fixture"
	OutDispatch       = "verified_dispatch"
	OutNonDispatch    = "verified_non_dispatch"
	OutInsufficient   = "insufficient_evidence"
	OutUnsupported    = "unsupported_historical_schema"
	OutMalformed      = "malformed"
	OutAblation       = "ablation_excluded"
)

const (
	ExitClean      = 0
	ExitViolation  = 1
	ExitIncomplete = 2
)

type Check struct {
	Name   string `json:"check"`
	Class  string `json:"class"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type DecisionResult struct {
	Cell            string  `json:"cell"`
	Unexpected      bool    `json:"cell_not_in_inventory,omitempty"`
	DecisionID      string  `json:"decision_id"`
	Schema          int     `json:"evidence_schema"`
	Policy          string  `json:"policy"`
	InventoryPolicy string  `json:"inventory_policy,omitempty"`
	Protected       bool    `json:"protected_transport"`
	Expected        string  `json:"expected_label"`
	ExpectedDepID   string  `json:"expected_deployment_id"`
	Token           string  `json:"job_token,omitempty"`
	Path            string  `json:"event_path"`
	Authorized      bool    `json:"authorized_event"`
	Dispatched      bool    `json:"dispatch_attempt_event"`
	Sent            bool    `json:"sent_event"`
	Refused         bool    `json:"refused_event"`
	Unknown         bool    `json:"unknown_outcome_event"`
	Acked           bool    `json:"ack_event"`
	Receipts        int     `json:"receipts"`
	ReceiptLabels   string  `json:"receipt_labels,omitempty"`
	Outcome         string  `json:"outcome"`
	Checks          []Check `json:"checks"`
}

type Summary struct {
	CheckerVersion     string         `json:"checker_version"`
	RunDir             string         `json:"run_dir"`
	InventorySource    string         `json:"inventory_source"`
	InventorySchema    int            `json:"inventory_schema"`
	ProducerSchemas    map[string]int `json:"producer_evidence_schemas_seen"`
	InventoryCells     int            `json:"inventory_cells"`
	InventoryErrors    []string       `json:"inventory_errors,omitempty"`
	CellsFound         int            `json:"cells_found"`
	MissingCells       []string       `json:"missing_cells,omitempty"`
	UnexpectedCells    []string       `json:"unexpected_cells,omitempty"`
	CardinalityErrors  []string       `json:"cardinality_errors,omitempty"`
	MalformedFiles     []string       `json:"malformed_files,omitempty"`
	DuplicateDecisions []string       `json:"duplicate_decision_ids,omitempty"`
	Decisions          int            `json:"decisions"`
	Dispatches         int            `json:"dispatch_attempts"`
	Receipts           int            `json:"receipts"`
	Outcomes           map[string]int `json:"outcomes"`
	ChecksByClass      map[string]int `json:"checks_by_class"`
	FailedByClass      map[string]int `json:"failed_checks_by_class"`
	DuplicateTokens    []string       `json:"duplicate_release_tokens,omitempty"`
	OrphanReceipts     int            `json:"orphan_receipts"`
	ExitCode           int            `json:"exit_code"`
	Verdict            string         `json:"verdict"`
	ConditionalNote    string         `json:"conditional_note"`
}

type event struct {
	TS     string         `json:"ts"`
	Cell   string         `json:"cell"`
	Source string         `json:"source"`
	Kind   string         `json:"kind"`
	Data   map[string]any `json:"data"`
}

type invCell struct {
	Cell              string
	Policy            string
	Class             string
	ExpectedRecipient string
	ExpectedDecisions int // 0 = undeclared (legacy inventories)
}

var cellIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+.-]*$`)

// Run audits dir and writes release-audit.{jsonl,md} and release-audit-summary.json.
func Run(dir string) (*Summary, []DecisionResult, error) {
	sum := &Summary{CheckerVersion: CheckerVersion, RunDir: dir, Outcomes: map[string]int{}, ChecksByClass: map[string]int{}, FailedByClass: map[string]int{}, ProducerSchemas: map[string]int{}}
	inventory, src, schema, invErrs, err := loadInventory(dir)
	if err != nil {
		return nil, nil, err
	}
	sum.InventorySource, sum.InventorySchema, sum.InventoryErrors, sum.InventoryCells = src, schema, invErrs, len(inventory)
	labelToDep, err := loadRegistry(filepath.Join(dir, "enrollment-registry.json"))
	if err != nil {
		return nil, nil, err
	}
	cellDirs, _ := filepath.Glob(filepath.Join(dir, "cells", "*"))
	found := map[string]bool{}
	for _, cd := range cellDirs {
		if st, err := os.Stat(cd); err == nil && st.IsDir() {
			found[filepath.Base(cd)] = true
		}
	}
	sum.CellsFound = len(found)
	invByCell := map[string]invCell{}
	for _, ic := range inventory {
		invByCell[ic.Cell] = ic
		if !found[ic.Cell] {
			sum.MissingCells = append(sum.MissingCells, ic.Cell)
		}
	}
	for c := range found {
		if _, ok := invByCell[c]; !ok {
			sum.UnexpectedCells = append(sum.UnexpectedCells, c)
		}
	}
	sort.Strings(sum.MissingCells)
	sort.Strings(sum.UnexpectedCells)

	var results []DecisionResult
	tokens := map[string][]string{}
	idSeen := map[string][]int{}
	auditCell := func(cellName string, ic invCell, unexpected bool) {
		cd := filepath.Join(dir, "cells", cellName)
		decisions, sessions, derr := loadDecisions(filepath.Join(cd, "decision.json"))
		if derr != nil {
			if errors.Is(derr, errNoDecisions) {
				sum.CardinalityErrors = append(sum.CardinalityErrors, fmt.Sprintf("%s: %v", cellName, derr))
			} else {
				sum.MalformedFiles = append(sum.MalformedFiles, cellName+"/decision.json: "+derr.Error())
			}
			return
		}
		events, eerr := loadEvents(filepath.Join(cd, "controller-events.jsonl"))
		if eerr != nil {
			sum.MalformedFiles = append(sum.MalformedFiles, cellName+"/controller-events.jsonl: "+eerr.Error())
			return
		}
		if !unexpected {
			switch {
			case ic.ExpectedDecisions == 0:
				sum.CardinalityErrors = append(sum.CardinalityErrors, fmt.Sprintf("%s: inventory declares no decision count (legacy inventory)", cellName))
			case len(decisions) != ic.ExpectedDecisions:
				sum.CardinalityErrors = append(sum.CardinalityErrors, fmt.Sprintf("%s: declared %d decisions, found %d", cellName, ic.ExpectedDecisions, len(decisions)))
			}
		}
		joined := map[string]bool{}
		for _, d := range decisions {
			r := auditDecision(cellName, ic, unexpected, d, sessions, events, labelToDep)
			if r.Schema > 0 {
				sum.ProducerSchemas[fmt.Sprint(r.Schema)]++
			} else {
				sum.ProducerSchemas["none"]++
			}
			if ic.Class == "ablation" && !unexpected {
				r.Outcome = OutAblation
			}
			if r.Outcome == OutViolation && !unexpected && ic.Class == "malicious" && ic.ExpectedRecipient != "" && ic.ExpectedRecipient != r.Expected && r.ReceiptLabels == ic.ExpectedRecipient && onlyRecipientChecksFailed(r) {
				r.Outcome = OutExpectedAttack
			}
			if r.Token != "" && r.Dispatched {
				tokens[r.Token] = append(tokens[r.Token], r.DecisionID)
			}
			if r.DecisionID != "" {
				joined[r.DecisionID] = true
				idSeen[r.DecisionID] = append(idSeen[r.DecisionID], len(results))
			}
			if r.Token != "" {
				joined["tok:"+r.Token] = true
			}
			results = append(results, r)
		}
		for _, e := range events {
			if e.Kind != "job_received" {
				continue
			}
			did, _ := e.Data["decision_id"].(string)
			tok, _ := e.Data["token"].(string)
			if !joined[did] && !joined["tok:"+tok] {
				sum.OrphanReceipts++
			}
		}
	}
	for _, ic := range inventory {
		if found[ic.Cell] {
			auditCell(ic.Cell, ic, false)
		}
	}
	for _, c := range sum.UnexpectedCells { // contents of undeclared cells are inspected, never ignored
		auditCell(c, invCell{Cell: c}, true)
	}
	for id, idx := range idSeen {
		if len(idx) > 1 {
			sum.DuplicateDecisions = append(sum.DuplicateDecisions, id)
			for _, i := range idx {
				results[i].Checks = append(results[i].Checks, Check{Name: "decision id unique across the run", Class: ClassRecomputed, OK: false, Detail: fmt.Sprintf("id appears %d times", len(idx))})
				results[i].Outcome = OutViolation
			}
		}
	}
	sort.Strings(sum.DuplicateDecisions)
	for tok, ids := range tokens {
		if len(ids) > 1 {
			sum.DuplicateTokens = append(sum.DuplicateTokens, tok)
			for i := range results {
				if results[i].Token == tok {
					results[i].Checks = append(results[i].Checks, Check{Name: "one business release per token", Class: ClassRecomputed, OK: false, Detail: fmt.Sprintf("token released by %d decisions", len(ids))})
					results[i].Outcome = OutViolation
				}
			}
		}
	}
	sort.Strings(sum.DuplicateTokens)
	for _, r := range results {
		sum.Decisions++
		if r.Dispatched {
			sum.Dispatches++
		}
		sum.Receipts += r.Receipts
		sum.Outcomes[r.Outcome]++
		for _, c := range r.Checks {
			sum.ChecksByClass[c.Class]++
			if !c.OK {
				sum.FailedByClass[c.Class]++
			}
		}
	}
	incomplete := len(sum.MissingCells) > 0 || len(sum.UnexpectedCells) > 0 || len(sum.CardinalityErrors) > 0 || len(sum.MalformedFiles) > 0 || len(sum.InventoryErrors) > 0 ||
		sum.Outcomes[OutInsufficient] > 0 || sum.Outcomes[OutUnsupported] > 0 || sum.Outcomes[OutMalformed] > 0 || sum.Decisions == 0 || len(inventory) == 0
	switch {
	case sum.Outcomes[OutViolation] > 0 || sum.OrphanReceipts > 0 || len(sum.DuplicateDecisions) > 0:
		sum.ExitCode, sum.Verdict = ExitViolation, "UNEXPECTED VIOLATION"
	case incomplete:
		sum.ExitCode, sum.Verdict = ExitIncomplete, "INCOMPLETE"
	default:
		sum.ExitCode, sum.Verdict = ExitClean, "NO UNEXPECTED VIOLATION"
		if n := sum.Outcomes[OutExpectedAttack]; n > 0 {
			sum.Verdict += fmt.Sprintf(" (%d fixture-predicted attack successes: the invariant was violated as declared)", n)
		}
	}
	if sum.OrphanReceipts > 0 {
		sum.Verdict += " (receipts that join no decision)"
	}
	if len(sum.UnexpectedCells) > 0 {
		sum.Verdict += " (cells not in the declared inventory)"
	}
	sum.ConditionalNote = "Structural audit of retained records (checker version " + CheckerVersion + "). Authorization validity is conditional on the recorded appraisal (copied_appraisal); " +
		"TLS facts are the requester's own run-time observations; receipts are cooperative events attributed by the controller; " +
		"cross-process order rests on causal ids (decision id, session key, token) and requester sequence numbers, with any remainder stipulated by the controller. " +
		"Not tamper-proof evidence and not a security proof."
	writeOutputs(dir, sum, results)
	return sum, results, nil
}

type rev struct {
	seq    int
	kind   string
	conn   int
	token  string
	detail string
}

// Critical event kinds: each may appear at most once per decision.
var critical = map[string]bool{"connect": true, "connect_failed": true, "card_fetched": true, "challenge_sent": true, "proof_received": true, "exchange_failed": true,
	"appraised": true, "not_authorized": true, "release_suppressed": true, "authorized": true, "sealed": true, "seal_disabled_ablation": true, "refused_dispatch": true,
	"dispatch_attempt": true, "got_conn": true, "sent": true, "write_failed": true, "ack": true, "no_ack": true, "refused_reconnect": true, "unknown_outcome": true, "dispatch_error": true, "ablation_reconnect": true}

func auditDecision(cell string, ic invCell, unexpected bool, d map[string]any, sessions []map[string]any, events []event, labelToDep map[string]string) DecisionResult {
	r := DecisionResult{Cell: cell, Unexpected: unexpected, Checks: []Check{}, InventoryPolicy: ic.Policy}
	r.DecisionID, _ = d["decision_id"].(string)
	r.Policy, _ = d["policy"].(string)
	r.Expected, _ = d["expected_deployment"].(string)
	r.Token, _ = d["job_token"].(string)
	r.Schema = toInt(d["evidence_schema"])
	r.ExpectedDepID = labelToDep[r.Expected]
	add := func(name, class string, ok bool, detail string) {
		r.Checks = append(r.Checks, Check{Name: name, Class: class, OK: ok, Detail: detail})
	}
	pol, perr := wire.ParsePolicy(r.Policy)
	if perr != nil {
		add("policy string parses", ClassRecomputed, false, perr.Error())
		r.Outcome = OutMalformed
		return r
	}
	r.Protected = pol.TLS
	evsRaw, _ := d["requester_events"].([]any)
	ctx, _ := d["context"].(map[string]any)
	if r.Schema < 2 || r.DecisionID == "" || len(evsRaw) == 0 || ctx == nil {
		add("record carries evidence_schema>=2, decision_id, requester_events and typed context", ClassRecomputed, false, fmt.Sprintf("schema=%d id=%q events=%d typed_context=%v (historical schema: not auditable as complete)", r.Schema, r.DecisionID, len(evsRaw), ctx != nil))
		r.Outcome = OutUnsupported
		return r
	}
	if r.ExpectedDepID == "" {
		add("expected label is enrolled", ClassRecomputed, false, "label "+r.Expected+" not in enrollment registry")
		r.Outcome = OutMalformed
		return r
	}
	if !unexpected {
		add("inventory policy equals decision policy", ClassRecomputed, ic.Policy == r.Policy, fmt.Sprintf("inventory=%q decision=%q", ic.Policy, r.Policy))
	}
	// ---- events ---------------------------------------------------------------
	var evs []rev
	for _, x := range evsRaw {
		m, _ := x.(map[string]any)
		evs = append(evs, rev{seq: toInt(m["seq"]), kind: str(m["kind"]), conn: toInt(m["conn_id"]), token: str(m["token"]), detail: str(m["detail"])})
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].seq < evs[j].seq })
	seqOK := true
	for i, e := range evs {
		if e.seq != i+1 {
			seqOK = false
		}
	}
	add("requester sequence numbers contiguous and increasing from 1", ClassRecomputed, seqOK, "")
	count := map[string]int{}
	first := map[string]rev{}
	for _, e := range evs {
		count[e.kind]++
		if _, ok := first[e.kind]; !ok {
			first[e.kind] = e
		}
	}
	dup := []string{}
	for k, n := range count {
		if critical[k] && n > 1 {
			dup = append(dup, k)
		}
	}
	sort.Strings(dup)
	add("no duplicate critical event", ClassRecomputed, len(dup) == 0, strings.Join(dup, ","))
	has := func(k string) bool { return count[k] > 0 }
	seq := func(k string) int { return first[k].seq }
	ordered := func(name string, ks ...string) { // each kind exactly once, positive, strictly increasing
		ok := true
		var det []string
		last := 0
		for _, k := range ks {
			if count[k] != 1 || seq(k) <= 0 || seq(k) <= last {
				ok = false
			}
			det = append(det, fmt.Sprintf("%s=%d", k, seq(k)))
			last = seq(k)
		}
		add(name, ClassRecomputed, ok, strings.Join(det, " "))
	}
	absent := func(name string, ks ...string) {
		var present []string
		for _, k := range ks {
			if has(k) {
				present = append(present, k)
			}
		}
		add(name, ClassRecomputed, len(present) == 0, strings.Join(present, ","))
	}
	r.Authorized, r.Dispatched, r.Sent, r.Acked, r.Unknown = has("authorized"), has("dispatch_attempt"), has("sent"), has("ack"), has("unknown_outcome")
	r.Refused = has("refused_reconnect") || has("refused_dispatch")
	accept, _ := d["accept"].(bool)
	add("recorded appraisal accept flag", ClassCopied, true, fmt.Sprintf("accept=%v (copied; not re-derived here)", accept))
	add("connect is the first event", ClassRecomputed, count["connect"] == 1 && seq("connect") == 1, "")

	// ---- valid paths ----------------------------------------------------------
	dispatchKinds := []string{"authorized", "sealed", "seal_disabled_ablation", "refused_dispatch", "dispatch_attempt", "got_conn", "sent", "write_failed", "ack", "no_ack", "refused_reconnect", "unknown_outcome", "dispatch_error", "ablation_reconnect"}
	switch {
	case has("connect_failed"):
		r.Path = "connect_failed"
		absent("connect_failed path has no appraisal or dispatch events", append([]string{"appraised", "not_authorized"}, dispatchKinds...)...)
		add("connect_failed decision is not accepted and has no token", ClassRecomputed, !accept && r.Token == "", "")
	case has("exchange_failed"):
		r.Path = "exchange_failed"
		ordered("challenge before failed exchange", "challenge_sent", "exchange_failed")
		absent("exchange_failed path has no appraisal or dispatch events", append([]string{"appraised", "proof_received", "not_authorized"}, dispatchKinds...)...)
		add("exchange_failed decision is not accepted and has no token", ClassRecomputed, !accept && r.Token == "", "")
	default:
		if pol.HasProof() {
			ordered("challenge_sent < proof_received < appraised", "challenge_sent", "proof_received", "appraised")
		} else {
			ordered("card_fetched < appraised", "card_fetched", "appraised")
		}
		switch {
		case has("not_authorized"):
			r.Path = "rejected"
			ordered("appraised < not_authorized", "appraised", "not_authorized")
			add("rejected decision has accept=false", ClassRecomputed, !accept, "")
			absent("rejected decision has no authorization or dispatch events", dispatchKinds...)
			add("rejected decision has no token", ClassRecomputed, r.Token == "", r.Token)
		case has("release_suppressed"):
			r.Path = "release_suppressed"
			ordered("appraised < release_suppressed", "appraised", "release_suppressed")
			add("suppressed release follows an accepted appraisal", ClassRecomputed, accept, "")
			absent("suppressed release has no authorization or dispatch events", "authorized", "sealed", "dispatch_attempt", "sent", "ack", "refused_reconnect", "unknown_outcome")
		case has("authorized"):
			ordered("appraised < authorized", "appraised", "authorized")
			add("authorization only after an accepted appraisal", ClassRecomputed, accept, "")
			add("authorized event carries the decision token", ClassRecomputed, first["authorized"].token == r.Token && r.Token != "", "")
			sealKind := "sealed"
			if has("seal_disabled_ablation") {
				sealKind = "seal_disabled_ablation"
			}
			ordered("authorized < "+sealKind, "authorized", sealKind)
			switch {
			case has("refused_dispatch"):
				r.Path = "refused_dispatch"
				ordered(sealKind+" < refused_dispatch", sealKind, "refused_dispatch")
				absent("refused_dispatch path has no dispatch attempt", "dispatch_attempt", "got_conn", "sent", "ack", "no_ack", "refused_reconnect", "unknown_outcome")
			case has("dispatch_attempt"):
				ordered(sealKind+" < dispatch_attempt", sealKind, "dispatch_attempt")
				add("dispatch_attempt carries the decision token", ClassRecomputed, first["dispatch_attempt"].token == r.Token, "")
				terminals := 0
				for _, k := range []string{"sent", "refused_reconnect", "dispatch_error", "write_failed"} {
					if has(k) {
						terminals++
					}
				}
				add("exactly one dispatch terminal (sent | refused_reconnect | dispatch_error | write_failed)", ClassRecomputed, terminals == 1, fmt.Sprintf("sent=%v refused=%v error=%v write_failed=%v", has("sent"), has("refused_reconnect"), has("dispatch_error"), has("write_failed")))
				switch {
				case has("sent"):
					ordered("dispatch_attempt < got_conn < sent", "dispatch_attempt", "got_conn", "sent")
					add("sent event carries the decision token", ClassRecomputed, first["sent"].token == r.Token, "")
					outcomes := 0
					for _, k := range []string{"ack", "no_ack", "unknown_outcome", "ablation_reconnect"} {
						if has(k) {
							outcomes++
						}
					}
					add("exactly one post-send outcome (ack | no_ack | unknown_outcome)", ClassRecomputed, outcomes == 1, "")
					for _, k := range []string{"ack", "no_ack", "unknown_outcome"} {
						if has(k) {
							ordered("sent < "+k, "sent", k)
							add(k+" carries the decision token", ClassRecomputed, first[k].token == r.Token, "")
						}
					}
					switch {
					case has("ack"):
						r.Path = "sent/ack"
					case has("unknown_outcome"):
						r.Path = "sent/unknown"
					default:
						r.Path = "sent/no_ack"
					}
				case has("write_failed"):
					r.Path = "write_failed"
					ordered("dispatch_attempt < write_failed", "dispatch_attempt", "write_failed")
					n := 0
					for _, k := range []string{"refused_reconnect", "unknown_outcome", "dispatch_error", "ablation_reconnect"} {
						if has(k) {
							n++
							ordered("write_failed < "+k, "write_failed", k)
						}
					}
					add("failed write has exactly one resolution", ClassRecomputed, n == 1, "")
					absent("failed write has no ack", "ack", "no_ack")
				case has("refused_reconnect"):
					r.Path = "refused_reconnect"
					ordered("dispatch_attempt < refused_reconnect", "dispatch_attempt", "refused_reconnect")
					add("refused_reconnect carries the decision token", ClassRecomputed, first["refused_reconnect"].token == r.Token, "")
					absent("refused reconnect has no send or ack", "sent", "ack", "no_ack", "unknown_outcome")
				case has("dispatch_error"):
					r.Path = "dispatch_error"
					ordered("dispatch_attempt < dispatch_error", "dispatch_attempt", "dispatch_error")
					absent("dispatch error has no send or ack", "sent", "ack", "no_ack")
				default:
					r.Path = "dispatch_attempt/no-terminal"
				}
			default:
				r.Path = "authorized/no-dispatch"
				add("authorized decision reaches a dispatch attempt or a refusal", ClassRecomputed, false, "neither dispatch_attempt nor refused_dispatch present")
			}
		default:
			r.Path = "appraised/no-terminal"
			add("appraised decision has a terminal event (not_authorized | release_suppressed | authorized)", ClassRecomputed, false, "")
		}
	}
	// ---- typed context ----------------------------------------------------------
	nonceIssued := has("challenge_sent")
	cmpCtx := func(name string, c map[string]any, withToken bool) {
		if c == nil {
			add(name+" present", ClassRecomputed, false, "typed context missing")
			return
		}
		// The session key is required once a nonce was issued or a release happened;
		// an early rejection (connect failure before any challenge) has none.
		needSession := withToken || nonceIssued || r.Authorized
		ok := str(c["decision_id"]) == r.DecisionID && str(c["expected_label"]) == r.Expected && str(c["expected_deployment_id"]) == r.ExpectedDepID &&
			str(c["policy"]) == r.Policy && str(c["action"]) != "" && str(c["audience"]) != "" && (str(c["session_key"]) != "" || !needSession) &&
			str(c["action"]) == str(ctx["action"]) && str(c["audience"]) == str(ctx["audience"]) && str(c["session_key"]) == str(ctx["session_key"])
		if withToken {
			ok = ok && str(c["token"]) == r.Token && r.Token != ""
		}
		add(name+" equals the decision context (typed: id, expected, enrolled id, policy, action, audience, session key"+map[bool]string{true: ", token", false: ""}[withToken]+")", ClassRecomputed, ok, "")
	}
	cmpCtx("decision context", ctx, false)
	if pol.HasProof() && nonceIssued {
		add("decision context session key is the issued nonce", ClassRecomputed, str(ctx["session_key"]) == str(d["nonce"]) && str(d["nonce"]) != "", "")
	}
	if pol.HasProof() && !nonceIssued {
		add("early rejection without an issued nonce has no session key and no token", ClassRecomputed, str(ctx["session_key"]) == "" && str(d["nonce"]) == "" && r.Token == "", fmt.Sprintf("session_key=%q nonce=%q token=%q", str(ctx["session_key"]), str(d["nonce"]), r.Token))
	}
	if r.Authorized {
		ac, _ := d["authorization_context"].(map[string]any)
		cmpCtx("authorization context", ac, true)
	}
	if r.Dispatched {
		dc, _ := d["dispatch_context"].(map[string]any)
		cmpCtx("dispatch context", dc, true)
	}
	if r.Authorized || (pol.HasProof() && nonceIssued) {
		sess := findSession(sessions, str(ctx["session_key"]))
		if sess == nil {
			add("issued session exists for the context's session key", ClassRecomputed, false, "no session for key")
		} else {
			ok := str(sess["expected_deployment"]) == r.Expected && str(sess["policy"]) == r.Policy && str(sess["action"]) == str(ctx["action"]) && str(sess["audience"]) == str(ctx["audience"])
			add("issued session equals the decision context (typed: expected, policy, action, audience)", ClassRecomputed, ok, fmt.Sprintf("session expected=%s policy=%s action=%s audience=%s", str(sess["expected_deployment"]), str(sess["policy"]), str(sess["action"]), str(sess["audience"])))
			if r.Authorized {
				add("issued session records this release token", ClassRecomputed, str(sess["job_token"]) == r.Token, "")
			}
		}
	}
	// ---- connections -------------------------------------------------------------
	conns, _ := d["connections"].([]any)
	connByID := map[int]map[string]any{}
	for _, c := range conns {
		m, _ := c.(map[string]any)
		connByID[toInt(m["conn_id"])] = m
	}
	pinned, proof, disc, disp := toInt(d["pinned_conn_id"]), toInt(d["proof_conn_id"]), toInt(d["discovery_conn_id"]), toInt(d["dispatch_conn_id"])
	var pinnedExporter string
	if r.Protected && r.Dispatched && !has("seal_disabled_ablation") {
		want := proof
		if !pol.HasProof() {
			want = disc
		}
		add("pinned connection is the proof connection", ClassRecomputed, pinned != 0 && pinned == want, fmt.Sprintf("pinned=%d proof=%d discovery=%d", pinned, proof, disc))
		add("exactly one TLS connection recorded for the decision", ClassRecomputed, len(conns) == 1, fmt.Sprintf("connections=%d", len(conns)))
		if r.Sent {
			add("job written to the pinned connection", ClassRecomputed, disp == pinned && disp != 0 && first["sent"].conn == pinned, fmt.Sprintf("dispatch=%d sent.conn=%d pinned=%d", disp, first["sent"].conn, pinned))
		}
		if pc, ok := connByID[pinned]; ok {
			pinnedExporter = str(pc["exporter_hex"])
			tlsv, _ := d["tls"].(map[string]any)
			add("pinned connection's peer certificate is the authenticated peer of the decision", ClassRequesterTLS, tlsv != nil && str(tlsv["peer_cert_sha256"]) == str(pc["peer_cert_sha256"]) && str(pc["peer_cert_sha256"]) != "", str(pc["peer_cert_sha256"]))
			if pol.CB {
				cb, _ := d["channel_binding"].(map[string]any)
				add("proof was checked against the pinned connection's exporter", ClassRequesterTLS, cb != nil && str(cb["requester_exporter_hex"]) == pinnedExporter && pinnedExporter != "", "")
			}
		} else if pinned != 0 {
			add("pinned connection has a record", ClassRecomputed, false, fmt.Sprintf("conn %d missing from connections", pinned))
		}
	}
	// ---- receipts (cooperative, controller-attributed) --------------------------
	var labels []string
	for _, e := range events {
		if e.Kind != "job_received" {
			continue
		}
		did, tok := str(e.Data["decision_id"]), str(e.Data["token"])
		joinedByID := did != "" && did == r.DecisionID
		joinedByTok := r.Token != "" && tok == r.Token
		if !joinedByID && !joinedByTok {
			continue
		}
		r.Receipts++
		label := strings.TrimPrefix(e.Source, "agent-")
		labels = append(labels, label)
		add("receipt joins by decision id (not only by token)", ClassRecomputed, joinedByID, fmt.Sprintf("decision_id=%q token=%q", did, tok))
		add("receipt token is this decision's token", ClassRecomputed, tok == r.Token, "")
		add("receipt recipient is the expected enrolled deployment", ClassCooperative, label == r.Expected, fmt.Sprintf("receipt source=%s expected=%s (%s)", label, r.Expected, r.ExpectedDepID))
		add("receipt's claimed deployment id matches the recipient's enrollment", ClassCooperative, str(e.Data["deployment_id"]) == labelToDep[label], fmt.Sprintf("claimed=%s enrolled=%s", str(e.Data["deployment_id"]), labelToDep[label]))
		if r.Protected {
			rx := str(e.Data["exporter_hex"])
			add("receipt's server-side exporter equals the requester's pinned connection exporter", ClassRequesterTLS, rx != "" && rx == pinnedExporter, "")
		}
		add("receipt follows a dispatch_attempt (causal: token exists only after authorization)", ClassStipulated, r.Dispatched, "order across processes via the token created at authorization; arrival order stipulated by the controller")
	}
	sort.Strings(labels)
	r.ReceiptLabels = strings.Join(labels, ",")
	if r.Refused || !r.Authorized {
		add("no receipt for a refused or rejected decision", ClassRecomputed, r.Receipts == 0, fmt.Sprintf("receipts=%d", r.Receipts))
	}
	// ---- outcome ---------------------------------------------------------------
	failed := false
	for _, c := range r.Checks {
		if !c.OK {
			failed = true
		}
	}
	switch {
	case failed:
		r.Outcome = OutViolation
	case !r.Authorized:
		r.Outcome = OutNonDispatch
	case r.Refused && r.Receipts == 0:
		r.Outcome = OutNonDispatch
	case has("dispatch_error") && r.Receipts == 0:
		r.Outcome = OutNonDispatch
	case r.Unknown && r.Receipts == 0:
		r.Outcome = OutInsufficient
		add("client-unknown outcome resolved by recipient logs", ClassCooperative, true, "no receipt logged at any recipient; delivery cannot be proven absent from the client alone")
	case r.Sent && r.Receipts == 1 && r.Acked:
		r.Outcome = OutDispatch
	case r.Sent && r.Receipts == 0:
		r.Outcome = OutInsufficient
		add("confirmed send has a receipt", ClassCooperative, false, "missing receipt for a sent dispatch")
	case r.Sent && r.Receipts > 1:
		r.Outcome = OutViolation
		add("one receipt per dispatch", ClassRecomputed, false, fmt.Sprintf("receipts=%d", r.Receipts))
	default:
		r.Outcome = OutInsufficient
		add("decision state is one the checker can classify", ClassRecomputed, false, fmt.Sprintf("path=%s receipts=%d acked=%v", r.Path, r.Receipts, r.Acked))
	}
	return r
}

// onlyRecipientChecksFailed reports whether every failed check of r is a recipient
// check (the job reached a deployment other than the expected one) and the dispatch
// itself was otherwise well-formed (authorized, sent, one receipt).
func onlyRecipientChecksFailed(r DecisionResult) bool {
	if !r.Authorized || !r.Sent || r.Receipts != 1 {
		return false
	}
	for _, c := range r.Checks {
		if !c.OK && !strings.HasPrefix(c.Name, "receipt recipient is the expected") && !strings.HasPrefix(c.Name, "receipt's server-side exporter") {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------ loaders

var errNoDecisions = errors.New("no decisions in record (missing, null or empty array)")

func loadInventory(dir string) ([]invCell, string, int, []string, error) {
	var errs []string
	b, err := os.ReadFile(filepath.Join(dir, "run-inventory.json"))
	if err == nil {
		var doc struct {
			Schema int `json:"inventory_schema"`
			Cells  []struct {
				Cell, Policy, Class, ExpectedRecipient string
				ExpectedDecisions                      int
				LCell                                  string `json:"cell"`
				LPolicy                                string `json:"policy"`
				LClass                                 string `json:"class"`
				LExpectedRecipient                     string `json:"expected_recipient"`
				LExpectedDecisions                     int    `json:"expected_decisions"`
			} `json:"cells"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, "", 0, nil, fmt.Errorf("run-inventory.json: %w", err)
		}
		var out []invCell
		seen := map[string]bool{}
		for _, c := range doc.Cells {
			ic := invCell{Cell: or(c.Cell, c.LCell), Policy: or(c.Policy, c.LPolicy), Class: or(c.Class, c.LClass), ExpectedRecipient: or(c.ExpectedRecipient, c.LExpectedRecipient), ExpectedDecisions: c.ExpectedDecisions}
			if ic.ExpectedDecisions == 0 {
				ic.ExpectedDecisions = c.LExpectedDecisions
			}
			if !cellIDRe.MatchString(ic.Cell) {
				errs = append(errs, fmt.Sprintf("invalid cell id %q", ic.Cell))
				continue
			}
			if seen[ic.Cell] {
				errs = append(errs, "duplicate inventory entry "+ic.Cell)
				continue
			}
			seen[ic.Cell] = true
			if _, perr := wire.ParsePolicy(ic.Policy); perr != nil {
				errs = append(errs, fmt.Sprintf("%s: inventory policy %q does not parse", ic.Cell, ic.Policy))
			}
			if doc.Schema >= 2 && ic.ExpectedDecisions < 1 {
				errs = append(errs, ic.Cell+": inventory schema 2 requires expected_decisions >= 1")
			}
			out = append(out, ic)
		}
		if len(out) == 0 {
			errs = append(errs, "run-inventory.json declares no valid cells")
		}
		return out, "run-inventory.json", doc.Schema, errs, nil
	}
	mb, merr := os.ReadFile(filepath.Join(dir, "manifest-frozen.json"))
	if merr != nil {
		return nil, "", 0, nil, fmt.Errorf("no run-inventory.json and no manifest-frozen.json: %v / %v", err, merr)
	}
	var man struct {
		Policies []string `json:"policies"`
		Fixtures []struct {
			ID       string            `json:"id"`
			Expected map[string]string `json:"expected"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(mb, &man); err != nil {
		return nil, "", 0, nil, fmt.Errorf("manifest-frozen.json: %w", err)
	}
	var out []invCell
	for _, fx := range man.Fixtures {
		for _, p := range man.Policies {
			if fx.Expected[p] == "n/a" {
				continue
			}
			out = append(out, invCell{Cell: fx.ID + "_" + p, Policy: p})
		}
	}
	return out, "manifest-frozen.json (derived; historical run without a declared inventory)", 0, errs, nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func loadRegistry(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var reg struct {
		Deployments map[string]struct {
			DeploymentID string `json:"deployment_id"`
		} `json:"deployments"`
	}
	if err := json.Unmarshal(b, &reg); err != nil {
		return nil, fmt.Errorf("enrollment-registry.json: %w", err)
	}
	out := map[string]string{}
	for label, d := range reg.Deployments {
		out[label] = d.DeploymentID
	}
	return out, nil
}

func loadDecisions(path string) ([]map[string]any, []map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc struct {
		Decisions *[]map[string]any `json:"decisions"`
		Sessions  []map[string]any  `json:"sessions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, nil, err
	}
	if doc.Decisions == nil || len(*doc.Decisions) == 0 {
		return nil, nil, errNoDecisions
	}
	for _, d := range *doc.Decisions {
		if d == nil {
			return nil, nil, errors.New("null decision in record")
		}
	}
	return *doc.Decisions, doc.Sessions, nil
}

func loadEvents(path string) ([]event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(t), &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func findSession(sessions []map[string]any, key string) map[string]any {
	if key == "" {
		return nil
	}
	for _, s := range sessions {
		if str(s["nonce"]) == key {
			return s
		}
	}
	return nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	}
	return 0
}

// ------------------------------------------------------------------ outputs

func writeOutputs(dir string, sum *Summary, results []DecisionResult) {
	jf, _ := os.Create(filepath.Join(dir, "release-audit.jsonl"))
	for _, r := range results {
		b, _ := json.Marshal(r)
		jf.Write(append(b, '\n'))
	}
	jf.Close()
	sb, _ := json.MarshalIndent(sum, "", "  ")
	os.WriteFile(filepath.Join(dir, "release-audit-summary.json"), sb, 0o644)
	var md strings.Builder
	fmt.Fprintf(&md, "# Release-evidence audit of %s (checker version %s)\n\n", dir, CheckerVersion)
	fmt.Fprintf(&md, "**Verdict: %s** (exit %d). Inventory: %d cells from %s (schema %d); %d found; missing %v; unexpected %v; cardinality %v; inventory errors %v; malformed %v; duplicate decision ids %v. Producer evidence schemas seen: %v.\n\n",
		sum.Verdict, sum.ExitCode, sum.InventoryCells, sum.InventorySource, sum.InventorySchema, sum.CellsFound, sum.MissingCells, sum.UnexpectedCells, sum.CardinalityErrors, sum.InventoryErrors, sum.MalformedFiles, sum.DuplicateDecisions, sum.ProducerSchemas)
	fmt.Fprintf(&md, "Decisions %d · dispatch attempts %d · receipts %d · orphan receipts %d · duplicate release tokens %v\n\n", sum.Decisions, sum.Dispatches, sum.Receipts, sum.OrphanReceipts, sum.DuplicateTokens)
	md.WriteString("Outcomes (each decision counted once):\n\n")
	for _, k := range []string{OutDispatch, OutNonDispatch, OutViolation, OutExpectedAttack, OutInsufficient, OutUnsupported, OutMalformed, OutAblation} {
		fmt.Fprintf(&md, "* %s: %d\n", k, sum.Outcomes[k])
	}
	md.WriteString("\nChecks by trust class (failed/total; classes are reported, never summed into one score):\n\n")
	for _, k := range []string{ClassRecomputed, ClassRequesterTLS, ClassCooperative, ClassCopied, ClassStipulated} {
		fmt.Fprintf(&md, "* %s: %d/%d\n", k, sum.FailedByClass[k], sum.ChecksByClass[k])
	}
	fmt.Fprintf(&md, "\n%s\n\n", sum.ConditionalNote)
	md.WriteString("| cell | decision | schema | policy | path | authorized | dispatch | sent | refused | unknown | receipts | outcome | failed checks |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range results {
		var fails []string
		for _, c := range r.Checks {
			if !c.OK {
				fails = append(fails, c.Name)
			}
		}
		cell := r.Cell
		if r.Unexpected {
			cell += " (NOT IN INVENTORY)"
		}
		fmt.Fprintf(&md, "| %s | %s | %d | %s | %s | %v | %v | %v | %v | %v | %d (%s) | %s | %s |\n", cell, short(r.DecisionID), r.Schema, r.Policy, r.Path, r.Authorized, r.Dispatched, r.Sent, r.Refused, r.Unknown, r.Receipts, r.ReceiptLabels, r.Outcome, strings.Join(fails, "; "))
	}
	os.WriteFile(filepath.Join(dir, "release-audit.md"), []byte(md.String()), 0o644)
}

func short(s string) string {
	if len(s) > 10 {
		return s[:10] + "…"
	}
	return s
}

// Main is the CLI entry point (`a2aid audit-release --results <dir>`); it exits
// with the audit's exit code.
func Main(args []string) {
	dir := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--results" && i+1 < len(args) {
			dir = args[i+1]
		}
	}
	if dir == "" {
		fmt.Fprintln(os.Stderr, "usage: a2aid audit-release --results <run dir>")
		os.Exit(2)
	}
	sum, _, err := Run(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit-release:", err)
		os.Exit(ExitIncomplete)
	}
	fmt.Printf("audit-release v%s: %s exit=%d decisions=%d dispatches=%d receipts=%d outcomes=%v missing_cells=%d unexpected_cells=%d cardinality_errors=%d malformed=%d; wrote %s\n",
		CheckerVersion, sum.Verdict, sum.ExitCode, sum.Decisions, sum.Dispatches, sum.Receipts, sum.Outcomes, len(sum.MissingCells), len(sum.UnexpectedCells), len(sum.CardinalityErrors), len(sum.MalformedFiles), filepath.Join(dir, "release-audit.md"))
	os.Exit(sum.ExitCode)
}

// ---- exported entry points for composite audits ---------------------------------

// InvCell is the declared inventory entry of one cell.
type InvCell = invCell

// Event is one controller event.
type Event = event

// LoadInventory returns the declared cells, the inventory source, its schema and any
// inventory errors (an unreadable inventory is an error).
func LoadInventory(dir string) ([]InvCell, string, int, []string, error) { return loadInventory(dir) }

// LoadDecisions loads decision.json strictly (parse errors, null and empty decision
// lists are errors).
func LoadDecisions(path string) ([]map[string]any, []map[string]any, error) {
	return loadDecisions(path)
}

// LoadEvents loads controller-events.jsonl strictly (any unparseable line is an error).
func LoadEvents(path string) ([]Event, error) { return loadEvents(path) }

// LoadRegistryLabels maps enrollment labels to deployment ids.
func LoadRegistryLabels(path string) (map[string]string, error) { return loadRegistry(path) }

// AuditDecision runs the structural release invariants of checker version 2.1 on one
// decision record and returns the typed result (never calls the appraisal code).
func AuditDecision(cell string, ic InvCell, unexpected bool, d map[string]any, sessions []map[string]any, events []Event, labelToDep map[string]string) DecisionResult {
	return auditDecision(cell, ic, unexpected, d, sessions, events, labelToDep)
}

// OnlyRecipientChecksFailed reports whether r is a well-formed dispatch whose only
// failed checks are recipient checks (a fixture-declared attacker delivery).
func OnlyRecipientChecksFailed(r DecisionResult) bool { return onlyRecipientChecksFailed(r) }
