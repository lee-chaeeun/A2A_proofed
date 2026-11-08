package audit

// Negative controls for the release-evidence checker. Every control mutates a COPY
// of real retained records (testdata/base: the S-env+cb continuity cases written by
// internal/verifier/continuity_final_test.go) and runs it through Run, the same
// entry point the CLI uses. A clean verdict must become non-clean under each
// corruption, with the expected classification and exit code.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	if err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	}); err != nil {
		t.Fatal(err)
	}
}

func base(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "run")
	copyDir(t, "testdata/base", dst)
	return dst
}

const honest = "1_honest_uninterrupted"
const swap = "2_close_then_swap_to_B"

func mutateDecision(t *testing.T, dir, cell string, f func(d map[string]any)) {
	t.Helper()
	p := filepath.Join(dir, "cells", cell, "decision.json")
	b, _ := os.ReadFile(p)
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	ds := doc["decisions"].([]any)
	f(ds[0].(map[string]any))
	out, _ := json.MarshalIndent(doc, "", "  ")
	os.WriteFile(p, out, 0o644)
}

func filterEvents(t *testing.T, dir, cell string, keep func(line string) bool) {
	t.Helper()
	p := filepath.Join(dir, "cells", cell, "controller-events.jsonl")
	b, _ := os.ReadFile(p)
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" && keep(l) {
			out = append(out, l)
		}
	}
	os.WriteFile(p, []byte(strings.Join(out, "\n")+"\n"), 0o644)
}

func run(t *testing.T, dir string) (*Summary, map[string]DecisionResult) {
	t.Helper()
	sum, res, err := Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]DecisionResult{}
	for _, r := range res {
		by[r.Cell+"#"+r.DecisionID] = r
		if _, ok := by[r.Cell]; !ok {
			by[r.Cell] = r
		}
	}
	return sum, by
}

func TestAudit_BaseIsClean(t *testing.T) {
	sum, by := run(t, base(t))
	if sum.ExitCode != ExitClean || !strings.HasPrefix(sum.Verdict, "NO UNEXPECTED VIOLATION") {
		t.Fatalf("base should be clean: %+v", sum)
	}
	if by[honest].Outcome != OutDispatch || by[swap].Outcome != OutNonDispatch || by["3_split_connection"].Outcome != OutNonDispatch {
		t.Fatalf("unexpected outcomes: honest=%s swap=%s split=%s", by[honest].Outcome, by[swap].Outcome, by["3_split_connection"].Outcome)
	}
	if by["4_cert_swap_noseal_ABLATION"].Outcome != OutAblation {
		t.Fatalf("ablation cell must be reported as ablation_excluded, got %s", by["4_cert_swap_noseal_ABLATION"].Outcome)
	}
	if sum.ChecksByClass[ClassCopied] == 0 || sum.ChecksByClass[ClassRecomputed] == 0 || sum.ChecksByClass[ClassRequesterTLS] == 0 || sum.ChecksByClass[ClassCooperative] == 0 {
		t.Fatalf("every trust class must be represented: %+v", sum.ChecksByClass)
	}
}

// A legitimate rejected attempt with no dispatch is a positive audit case.
func TestAudit_LegitimateRejectionIsVerifiedNonDispatch(t *testing.T) {
	_, by := run(t, base(t))
	r := by["3_split_connection"]
	if r.Authorized || r.Dispatched || r.Receipts != 0 || r.Outcome != OutNonDispatch {
		t.Fatalf("rejected attempt misclassified: %+v", r)
	}
}

func TestAudit_MissingReceiptForSentDispatch(t *testing.T) {
	d := base(t)
	filterEvents(t, d, honest, func(l string) bool { return !strings.Contains(l, `"kind":"job_received"`) })
	sum, by := run(t, d)
	if by[honest].Outcome != OutInsufficient || sum.ExitCode != ExitIncomplete {
		t.Fatalf("expected insufficient_evidence/exit 2, got %s exit=%d", by[honest].Outcome, sum.ExitCode)
	}
}

func TestAudit_MissingConnectionEvidence(t *testing.T) {
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) { delete(m, "connections") })
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("missing connection records must fail the connection checks: %s exit=%d", by[honest].Outcome, sum.ExitCode)
	}
}

func TestAudit_WrongRecipient(t *testing.T) {
	d := base(t)
	filterEvents(t, d, honest, func(l string) bool { return true })
	p := filepath.Join(d, "cells", honest, "controller-events.jsonl")
	b, _ := os.ReadFile(p)
	s := strings.ReplaceAll(string(b), `"source":"agent-A"`, `"source":"agent-B"`)
	s = strings.ReplaceAll(s, `"recipient":"A"`, `"recipient":"B"`)
	os.WriteFile(p, []byte(s), 0o644)
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("receipt at B must be a violation: %s exit=%d", by[honest].Outcome, sum.ExitCode)
	}
}

func TestAudit_DispatchOnAnotherConnection(t *testing.T) {
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) { m["dispatch_conn_id"] = 2 })
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("dispatch on a different connection must be a violation: %s", by[honest].Outcome)
	}
}

func TestAudit_ChangedContext(t *testing.T) {
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) { m["policy"] = "T+cb" }) // authorization said S-env+cb
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("changed context must be a violation: %s", by[honest].Outcome)
	}
}

func TestAudit_RemovedAuthorization(t *testing.T) {
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) {
		var keep []any
		for _, e := range m["requester_events"].([]any) {
			if e.(map[string]any)["kind"] != "authorized" {
				keep = append(keep, e)
			}
		}
		m["requester_events"] = keep
	})
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("dispatch without authorization must be a violation: %s", by[honest].Outcome)
	}
}

func TestAudit_ReorderedRequesterEvents(t *testing.T) {
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) {
		evs := m["requester_events"].([]any)
		var a, b map[string]any
		for _, e := range evs {
			em := e.(map[string]any)
			if em["kind"] == "authorized" {
				a = em
			}
			if em["kind"] == "dispatch_attempt" {
				b = em
			}
		}
		a["seq"], b["seq"] = b["seq"], a["seq"] // swap the order numbers
	})
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("reordered events must be a violation: %s", by[honest].Outcome)
	}
}

func TestAudit_DuplicateBusinessRelease(t *testing.T) {
	d := base(t)
	// Make the recovery cell's second decision reuse the honest cell's token.
	hb, _ := os.ReadFile(filepath.Join(d, "cells", honest, "decision.json"))
	var hdoc map[string]any
	json.Unmarshal(hb, &hdoc)
	tok := hdoc["decisions"].([]any)[0].(map[string]any)["job_token"].(string)
	p := filepath.Join(d, "cells", "5_honest_recovery_new_decision", "decision.json")
	b, _ := os.ReadFile(p)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	d2 := doc["decisions"].([]any)[1].(map[string]any)
	old := d2["job_token"].(string)
	out, _ := json.Marshal(doc)
	os.WriteFile(p, []byte(strings.ReplaceAll(string(out), old, tok)), 0o644)
	ep := filepath.Join(d, "cells", "5_honest_recovery_new_decision", "controller-events.jsonl")
	eb, _ := os.ReadFile(ep)
	os.WriteFile(ep, []byte(strings.ReplaceAll(string(eb), old, tok)), 0o644)
	sum, _ := run(t, d)
	if len(sum.DuplicateTokens) != 1 || sum.ExitCode != ExitViolation {
		t.Fatalf("duplicate business release must be a violation: dup=%v exit=%d", sum.DuplicateTokens, sum.ExitCode)
	}
}

func TestAudit_MalformedInput(t *testing.T) {
	d := base(t)
	p := filepath.Join(d, "cells", honest, "decision.json")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, b[:len(b)/2], 0o644) // truncated JSON
	sum, _ := run(t, d)
	if len(sum.MalformedFiles) != 1 || sum.ExitCode != ExitIncomplete {
		t.Fatalf("truncated record must be reported as malformed/exit 2: %+v", sum.MalformedFiles)
	}
	d = base(t)
	ep := filepath.Join(d, "cells", honest, "controller-events.jsonl")
	eb, _ := os.ReadFile(ep)
	os.WriteFile(ep, append(eb, []byte("{not json\n")...), 0o644)
	sum, _ = run(t, d)
	if len(sum.MalformedFiles) != 1 || sum.ExitCode != ExitIncomplete {
		t.Fatalf("malformed event line must be reported: %+v", sum.MalformedFiles)
	}
}

func TestAudit_MissingCellAgainstInventory(t *testing.T) {
	d := base(t)
	os.RemoveAll(filepath.Join(d, "cells", swap))
	sum, _ := run(t, d)
	if len(sum.MissingCells) != 1 || sum.MissingCells[0] != swap || sum.ExitCode != ExitIncomplete {
		t.Fatalf("missing cell must make the audit incomplete: %+v exit=%d", sum.MissingCells, sum.ExitCode)
	}
	// An empty cells directory can never audit clean.
	d = base(t)
	os.RemoveAll(filepath.Join(d, "cells"))
	os.MkdirAll(filepath.Join(d, "cells"), 0o755)
	sum, _ = run(t, d)
	if sum.ExitCode == ExitClean || sum.Decisions != 0 {
		t.Fatalf("empty run audited clean: %+v", sum)
	}
}

func TestAudit_UnknownPolicyAndUnsupportedSchema(t *testing.T) {
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) { m["policy"] = "Z+zz" })
	sum, by := run(t, d)
	if by[honest].Outcome != OutMalformed || sum.ExitCode != ExitIncomplete {
		t.Fatalf("unknown policy must be malformed/exit 2: %s exit=%d", by[honest].Outcome, sum.ExitCode)
	}
	d = base(t)
	mutateDecision(t, d, honest, func(m map[string]any) { delete(m, "decision_id"); delete(m, "requester_events") })
	sum, by = run(t, d)
	if by[honest].Outcome != OutUnsupported || sum.ExitCode != ExitIncomplete {
		t.Fatalf("historical schema must be unsupported/exit 2: %s exit=%d", by[honest].Outcome, sum.ExitCode)
	}
}

func TestAudit_OrphanReceiptAndReceiptExporterMismatch(t *testing.T) {
	d := base(t)
	ep := filepath.Join(d, "cells", honest, "controller-events.jsonl")
	eb, _ := os.ReadFile(ep)
	os.WriteFile(ep, append(eb, []byte(`{"ts":"x","cell":"`+honest+`","source":"agent-B","kind":"job_received","data":{"recipient":"B","deployment_id":"dep-B","decision_id":"nope","token":"nope"}}`+"\n")...), 0o644)
	sum, _ := run(t, d)
	if sum.OrphanReceipts != 1 || sum.ExitCode != ExitViolation {
		t.Fatalf("a receipt that joins no decision must be a violation: orphan=%d exit=%d", sum.OrphanReceipts, sum.ExitCode)
	}
	d = base(t)
	ep = filepath.Join(d, "cells", honest, "controller-events.jsonl")
	eb, _ = os.ReadFile(ep)
	s := string(eb)
	i := strings.Index(s, `"exporter_hex":"`)
	s = s[:i+len(`"exporter_hex":"`)] + "00" + s[i+len(`"exporter_hex":"`)+2:]
	os.WriteFile(ep, []byte(s), 0o644)
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("receipt on a different TLS connection must be a violation: %s", by[honest].Outcome)
	}
}

// ---------------------------------------------------------------------------
// Reviewer controls (REVIEW_V3_FINAL.md): five corruptions the version-1 checker
// passed as clean (before-fix evidence retained under
// results/audit/*-checker-falseclean-before/). Each must now be non-clean with the
// declared classification and exit status, through the same Run the CLI calls.

const split = "3_split_connection"
const recovery = "5_honest_recovery_new_decision"

func TestReviewer1_EmptyDecisionsInInventoriedRejectedCell(t *testing.T) {
	d := base(t)
	p := filepath.Join(d, "cells", split, "decision.json")
	b, _ := os.ReadFile(p)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	doc["decisions"] = []any{}
	out, _ := json.Marshal(doc)
	os.WriteFile(p, out, 0o644)
	sum, _ := run(t, d)
	if sum.ExitCode != ExitIncomplete || len(sum.CardinalityErrors) != 1 || !strings.Contains(sum.CardinalityErrors[0], split) {
		t.Fatalf("empty decisions array must be incomplete/exit 2: exit=%d card=%v", sum.ExitCode, sum.CardinalityErrors)
	}
	// null and missing arrays likewise
	for _, variant := range []string{"null", "missing"} {
		d := base(t)
		b, _ := os.ReadFile(filepath.Join(d, "cells", split, "decision.json"))
		var doc map[string]any
		json.Unmarshal(b, &doc)
		if variant == "null" {
			doc["decisions"] = nil
		} else {
			delete(doc, "decisions")
		}
		out, _ := json.Marshal(doc)
		os.WriteFile(filepath.Join(d, "cells", split, "decision.json"), out, 0o644)
		sum, _ := run(t, d)
		if sum.ExitCode != ExitIncomplete || len(sum.CardinalityErrors) != 1 {
			t.Fatalf("%s decisions must be incomplete: exit=%d card=%v", variant, sum.ExitCode, sum.CardinalityErrors)
		}
	}
}

func TestReviewer2_UndeclaredMalformedCell(t *testing.T) {
	d := base(t)
	os.MkdirAll(filepath.Join(d, "cells", "UNDECLARED"), 0o755)
	os.WriteFile(filepath.Join(d, "cells", "UNDECLARED", "decision.json"), []byte("{not-json\n"), 0o644)
	sum, _ := run(t, d)
	if sum.ExitCode == ExitClean || len(sum.UnexpectedCells) != 1 || len(sum.MalformedFiles) != 1 {
		t.Fatalf("undeclared malformed cell must be non-clean and reported: exit=%d unexpected=%v malformed=%v", sum.ExitCode, sum.UnexpectedCells, sum.MalformedFiles)
	}
	// an undeclared cell with VALID, distinct contents is still an inventory mismatch
	// (exit 2), and its decisions are audited
	d = base(t)
	copyDir(t, filepath.Join(d, "cells", honest), filepath.Join(d, "cells", "EXTRA_VALID"))
	hb, _ := os.ReadFile(filepath.Join(d, "cells", honest, "decision.json"))
	var hdoc map[string]any
	json.Unmarshal(hb, &hdoc)
	hd := hdoc["decisions"].([]any)[0].(map[string]any)
	oldID, oldTok := hd["decision_id"].(string), hd["job_token"].(string)
	for _, f := range []string{"decision.json", "controller-events.jsonl"} {
		fp := filepath.Join(d, "cells", "EXTRA_VALID", f)
		fb, _ := os.ReadFile(fp)
		fs := strings.ReplaceAll(strings.ReplaceAll(string(fb), oldID, "ffffffffffffffff"), oldTok, "eeeeeeeeeeeeeeeeeeeeeeee")
		os.WriteFile(fp, []byte(fs), 0o644)
	}
	sum, by := run(t, d)
	if sum.ExitCode != ExitIncomplete || len(sum.UnexpectedCells) != 1 || by["EXTRA_VALID"].Cell == "" || !by["EXTRA_VALID"].Unexpected {
		t.Fatalf("undeclared valid cell must be exit 2 and audited: exit=%d unexpected=%v", sum.ExitCode, sum.UnexpectedCells)
	}
	// a verbatim copy shares the decision id and token: duplicate id -> violation
	d = base(t)
	copyDir(t, filepath.Join(d, "cells", honest), filepath.Join(d, "cells", "EXTRA_COPY"))
	sum, _ = run(t, d)
	if sum.ExitCode != ExitViolation || len(sum.DuplicateDecisions) != 1 {
		t.Fatalf("copied cell must produce a duplicate decision id violation: exit=%d dup=%v", sum.ExitCode, sum.DuplicateDecisions)
	}
}

func TestReviewer3_MissingAppraisedEventRenumbered(t *testing.T) {
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) {
		var keep []any
		for _, e := range m["requester_events"].([]any) {
			if e.(map[string]any)["kind"] != "appraised" {
				keep = append(keep, e)
			}
		}
		for i, e := range keep {
			e.(map[string]any)["seq"] = i + 1 // contiguous renumbering, as the reviewer did
		}
		m["requester_events"] = keep
	})
	filterEvents(t, d, honest, func(l string) bool { return !strings.Contains(l, `"kind":"appraised"`) })
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("missing appraised event must be a violation: %s exit=%d", by[honest].Outcome, sum.ExitCode)
	}
}

func TestReviewer4_ChangedSessionActionAndAudience(t *testing.T) {
	for _, variant := range []string{"both", "action", "audience"} {
		d := base(t)
		mutateSessions(t, d, honest, func(s map[string]any) {
			if variant != "audience" {
				s["action"] = "DIFFERENT-ACTION"
			}
			if variant != "action" {
				s["audience"] = "DIFFERENT-AUDIENCE"
			}
		})
		sum, by := run(t, d)
		if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
			t.Fatalf("changed session %s must be a violation: %s exit=%d", variant, by[honest].Outcome, sum.ExitCode)
		}
	}
}

func TestReviewer5_InventoryPolicyDiffersFromDecision(t *testing.T) {
	d := base(t)
	p := filepath.Join(d, "run-inventory.json")
	b, _ := os.ReadFile(p)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	for _, c := range doc["cells"].([]any) {
		cm := c.(map[string]any)
		if cm["cell"] == honest {
			cm["policy"] = "T+cb"
		}
	}
	out, _ := json.Marshal(doc)
	os.WriteFile(p, out, 0o644)
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("inventory/decision policy mismatch must be a violation: %s exit=%d", by[honest].Outcome, sum.ExitCode)
	}
}

// ---------------------------------------------------------------- new rules

func mutateSessions(t *testing.T, dir, cell string, f func(s map[string]any)) {
	t.Helper()
	p := filepath.Join(dir, "cells", cell, "decision.json")
	b, _ := os.ReadFile(p)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	for _, s := range doc["sessions"].([]any) {
		f(s.(map[string]any))
	}
	out, _ := json.Marshal(doc)
	os.WriteFile(p, out, 0o644)
}

func TestRule_DuplicateCriticalEventAndContradiction(t *testing.T) {
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) {
		evs := m["requester_events"].([]any)
		var dup map[string]any
		for _, e := range evs {
			if e.(map[string]any)["kind"] == "authorized" {
				dup = map[string]any{}
				for k, v := range e.(map[string]any) {
					dup[k] = v
				}
			}
		}
		dup["seq"] = len(evs) + 1 // a second authorization appended at the end
		m["requester_events"] = append(evs, dup)
	})
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("duplicate authorized event must be a violation: %s", by[honest].Outcome)
	}
	// contradictory terminals: a refused_reconnect added to a sent/acked decision
	d = base(t)
	mutateDecision(t, d, honest, func(m map[string]any) {
		evs := m["requester_events"].([]any)
		m["requester_events"] = append(evs, map[string]any{"seq": len(evs) + 1, "kind": "refused_reconnect", "token": m["job_token"], "at": "x"})
	})
	sum, by = run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("contradictory terminals must be a violation: %s", by[honest].Outcome)
	}
}

func TestRule_EventTokenAndConnectionMismatch(t *testing.T) {
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) {
		for _, e := range m["requester_events"].([]any) {
			if e.(map[string]any)["kind"] == "sent" {
				e.(map[string]any)["token"] = "other-token"
			}
		}
	})
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("sent event with another token must be a violation: %s", by[honest].Outcome)
	}
	d = base(t)
	mutateDecision(t, d, honest, func(m map[string]any) {
		for _, e := range m["requester_events"].([]any) {
			if e.(map[string]any)["kind"] == "sent" {
				e.(map[string]any)["conn_id"] = 7
			}
		}
	})
	sum, by = run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("sent event on another connection id must be a violation: %s", by[honest].Outcome)
	}
}

func TestRule_ExtraDecisionAndDuplicateIDs(t *testing.T) {
	d := base(t)
	p := filepath.Join(d, "cells", honest, "decision.json")
	b, _ := os.ReadFile(p)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	ds := doc["decisions"].([]any)
	doc["decisions"] = append(ds, ds[0]) // the same decision twice: extra decision AND duplicate id
	out, _ := json.Marshal(doc)
	os.WriteFile(p, out, 0o644)
	sum, _ := run(t, d)
	if sum.ExitCode != ExitViolation || len(sum.DuplicateDecisions) != 1 || len(sum.CardinalityErrors) != 1 {
		t.Fatalf("extra duplicate decision must be flagged: exit=%d dup=%v card=%v", sum.ExitCode, sum.DuplicateDecisions, sum.CardinalityErrors)
	}
	// the two-decision recovery cell declares 2: removing the second decision (and its
	// receipt, so no orphan remains) is a cardinality error
	d = base(t)
	p = filepath.Join(d, "cells", recovery, "decision.json")
	b, _ = os.ReadFile(p)
	json.Unmarshal(b, &doc)
	d2 := doc["decisions"].([]any)[1].(map[string]any)
	tok2 := d2["job_token"].(string)
	doc["decisions"] = doc["decisions"].([]any)[:1]
	out, _ = json.Marshal(doc)
	os.WriteFile(p, out, 0o644)
	filterEvents(t, d, recovery, func(l string) bool { return !strings.Contains(l, tok2) })
	sum, _ = run(t, d)
	if sum.ExitCode != ExitIncomplete || len(sum.CardinalityErrors) != 1 {
		t.Fatalf("recovery cell with one of two decisions must be incomplete: exit=%d card=%v", sum.ExitCode, sum.CardinalityErrors)
	}
	// removing the second decision but leaving its receipt is an orphan receipt -> violation
	d = base(t)
	p = filepath.Join(d, "cells", recovery, "decision.json")
	b, _ = os.ReadFile(p)
	json.Unmarshal(b, &doc)
	doc["decisions"] = doc["decisions"].([]any)[:1]
	out, _ = json.Marshal(doc)
	os.WriteFile(p, out, 0o644)
	sum, _ = run(t, d)
	if sum.ExitCode != ExitViolation || sum.OrphanReceipts != 1 {
		t.Fatalf("orphaned receipt must be a violation: exit=%d orphans=%d", sum.ExitCode, sum.OrphanReceipts)
	}
}

func TestRule_AbsentTypedContextIsUnsupportedNotClean(t *testing.T) {
	for _, field := range []string{"context", "authorization_context", "dispatch_context"} {
		d := base(t)
		mutateDecision(t, d, honest, func(m map[string]any) { delete(m, field) })
		sum, by := run(t, d)
		if sum.ExitCode == ExitClean {
			t.Fatalf("absent %s must not audit clean", field)
		}
		if field == "context" && by[honest].Outcome != OutUnsupported {
			t.Fatalf("absent decision context must be unsupported schema, got %s", by[honest].Outcome)
		}
		if field != "context" && by[honest].Outcome != OutViolation {
			t.Fatalf("absent %s must be a violation, got %s", field, by[honest].Outcome)
		}
	}
	// a typed field that disagrees (authorization policy) is a violation
	d := base(t)
	mutateDecision(t, d, honest, func(m map[string]any) { m["authorization_context"].(map[string]any)["policy"] = "T+cb" })
	sum, by := run(t, d)
	if by[honest].Outcome != OutViolation || sum.ExitCode != ExitViolation {
		t.Fatalf("authorization context policy mismatch must be a violation: %s", by[honest].Outcome)
	}
}

func TestRule_InventoryIntegrity(t *testing.T) {
	// duplicate inventory entry, invalid id, missing expected_decisions
	d := base(t)
	p := filepath.Join(d, "run-inventory.json")
	b, _ := os.ReadFile(p)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	cells := doc["cells"].([]any)
	first := cells[0].(map[string]any)
	dupe := map[string]any{}
	for k, v := range first {
		dupe[k] = v
	}
	bad := map[string]any{"cell": "../escape", "policy": "S-env+cb", "class": "honest", "expected_decisions": 1}
	nocount := map[string]any{"cell": "NOCOUNT", "policy": "S-env+cb", "class": "honest"}
	doc["cells"] = append(cells, dupe, bad, nocount)
	out, _ := json.Marshal(doc)
	os.WriteFile(p, out, 0o644)
	sum, _ := run(t, d)
	if sum.ExitCode != ExitIncomplete || len(sum.InventoryErrors) < 3 {
		t.Fatalf("inventory integrity errors must be reported: exit=%d errs=%v", sum.ExitCode, sum.InventoryErrors)
	}
}

func TestRule_ExpectedAttackSuccessStaysVisible(t *testing.T) {
	// Turn the honest cell into a declared attack success: the receipt is at B and
	// the inventory predicts B. It must be reported as an invariant violation
	// expected by the fixture, with exit 0, never dropped from the report.
	d := base(t)
	ep := filepath.Join(d, "cells", honest, "controller-events.jsonl")
	eb, _ := os.ReadFile(ep)
	s := strings.ReplaceAll(string(eb), `"source":"agent-A"`, `"source":"agent-B"`)
	s = strings.ReplaceAll(s, `"recipient":"A"`, `"recipient":"B"`)
	s = strings.ReplaceAll(s, `"deployment_id":"dep-A"`, `"deployment_id":"dep-B"`)
	os.WriteFile(ep, []byte(s), 0o644)
	p := filepath.Join(d, "run-inventory.json")
	b, _ := os.ReadFile(p)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	for _, c := range doc["cells"].([]any) {
		cm := c.(map[string]any)
		if cm["cell"] == honest {
			cm["class"], cm["expected_recipient"] = "malicious", "B"
		}
	}
	out, _ := json.Marshal(doc)
	os.WriteFile(p, out, 0o644)
	sum, by := run(t, d)
	if by[honest].Outcome != OutExpectedAttack || sum.ExitCode != ExitClean || sum.Outcomes[OutExpectedAttack] != 1 {
		t.Fatalf("declared attack success must stay visible as violation_expected_by_fixture with exit 0: %s exit=%d outcomes=%v", by[honest].Outcome, sum.ExitCode, sum.Outcomes)
	}
	md, _ := os.ReadFile(filepath.Join(d, "release-audit.md"))
	if !strings.Contains(string(md), "violation_expected_by_fixture: 1") {
		t.Fatalf("report must list the expected attack success")
	}
}

func TestRule_RefusedCaseStaysClean(t *testing.T) {
	_, by := run(t, base(t))
	if by["2_close_then_swap_to_B"].Outcome != OutNonDispatch || by["2_close_then_swap_to_B"].Path != "refused_reconnect" {
		t.Fatalf("refused reconnect must be verified_non_dispatch on path refused_reconnect: %+v", by["2_close_then_swap_to_B"].Outcome)
	}
	if by[recovery].Cell == "" {
		t.Fatalf("recovery cell missing")
	}
}
