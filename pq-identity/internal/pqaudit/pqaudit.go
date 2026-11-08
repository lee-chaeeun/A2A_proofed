// Package pqaudit is the composite evidence audit of a PQ identity matrix run
// (audit-pq version 2). For every declared cell it composes
//
//   - the structural release invariants of the identity checker (internal/audit,
//     checker 2.1): strict loading of inventory, decision records, sessions and
//     controller events; requester event multiplicity and order; typed context
//     equality across decision, authorization and dispatch; issued-session join;
//     proof/pinned/dispatch connection continuity; receipt joins by decision id, token
//     and exporter with multiplicity; release cardinality; duplicate decision ids and
//     orphan receipts across the run;
//   - re-verification of every retained a2aid-proof-v4 credential under the trusted
//     registry (algorithm and key-id pin, strict context decode, expected context
//     rebuilt from the decision's own issued session, expiry window relative to a
//     parsed appraisal time that lies inside the session's validity, signature);
//   - agreement of the recorded decision and the receipt-derived recipient with the
//     declared inventory (expected weak-policy attack successes are declared and
//     listed, never hidden).
//
// Trust: every recomputed property is labelled by the structural checker's classes;
// signature verification uses the same CIRCL / Go ECDSA libraries as the requester (a
// shared-library re-verification, not an independent implementation). The audit
// validates the consistency of trusted, cooperative observations; it does not
// cryptographically establish that the logs describe reality.
//
// Outcomes per cell: agree | disagree | violation | incomplete | malformed |
// unsupported. Exit codes: 0 complete and clean; 1 any disagreement, violation,
// orphan receipt or duplicate decision id; 2 incomplete, malformed or unsupported
// evidence (1 wins when both occur). Records that lack the schema-2 fields are
// unsupported; they are never upgraded or inferred.
package pqaudit

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"a2aid/internal/audit"
	"a2aid/internal/pqsig"
	"a2aid/internal/registry"
	"a2aid/internal/tpmsig"
	"a2aid/internal/wire"
)

const Action = "release-synthetic-job"

// Version of this audit (reported in every summary).
const Version = "2"

type Options struct {
	Run      string
	Registry string // defaults to <run>/enrollment-registry.json
	OutDir   string // defaults to Run
}

type DecisionAudit struct {
	DecisionID        string        `json:"decision_id"`
	StructuralOutcome string        `json:"structural_outcome"`
	Path              string        `json:"event_path"`
	Receipts          int           `json:"receipts"`
	ReceiptLabels     string        `json:"receipt_labels,omitempty"`
	RecordedAccept    bool          `json:"recorded_accept"`
	Proof             string        `json:"recomputed_proof"` // valid | invalid:<stage> | n/a
	FailedChecks      []string      `json:"failed_checks,omitempty"`
	Checks            []audit.Check `json:"checks"`
}

type CellResult struct {
	Cell              string          `json:"cell"`
	Policy            string          `json:"policy"`
	Status            string          `json:"status"`
	Decisions         int             `json:"decisions"`
	ExpectedDecision  string          `json:"expected_decision"`
	ExpectedRecipient string          `json:"expected_recipient"`
	ObservedDecision  string          `json:"observed_decision"`
	ObservedRecipient string          `json:"observed_recipient"`
	Releases          int             `json:"releases"`
	AttackSuccess     bool            `json:"expected_attacker_delivery"`
	Alg               string          `json:"alg,omitempty"`
	KID               string          `json:"kid,omitempty"`
	Detail            string          `json:"detail"`
	Audits            []DecisionAudit `json:"decisions_audited"`
}

type Summary struct {
	Version            string         `json:"audit_version"`
	StructuralChecker  string         `json:"structural_checker_version"`
	RunDir             string         `json:"run_dir"`
	Registry           string         `json:"registry"`
	Expected           int            `json:"cells_declared"`
	Found              int            `json:"cells_found"`
	Agree              int            `json:"agree"`
	Disagree           int            `json:"disagree"`
	Violations         int            `json:"violations"`
	Incomplete         int            `json:"incomplete"`
	Malformed          int            `json:"malformed"`
	Unsupported        int            `json:"unsupported"`
	ProofsVerified     int            `json:"proof_v4_signatures_reverified"`
	ProofsInvalid      int            `json:"proof_v4_signatures_invalid"`
	AttackSuccess      int            `json:"expected_attacker_deliveries"`
	StructuralOutcomes map[string]int `json:"structural_outcomes"`
	ChecksByClass      map[string]int `json:"checks_by_class"`
	FailedByClass      map[string]int `json:"failed_checks_by_class"`
	DuplicateDecisions []string       `json:"duplicate_decision_ids,omitempty"`
	OrphanReceipts     int            `json:"orphan_receipts"`
	RunErrors          []string       `json:"run_level_errors"`
	ExitCode           int            `json:"exit_code"`
	Note               string         `json:"note"`
}

type invCell struct {
	Cell, Fixture, Policy, Class, ExpectedDecision, ExpectedRecipient string
	ExpectedDecisions                                                 int
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// Run audits one matrix run directory.
func Run(o Options) (*Summary, []CellResult, error) {
	if o.Registry == "" {
		o.Registry = filepath.Join(o.Run, "enrollment-registry.json")
	}
	if o.OutDir == "" {
		o.OutDir = o.Run
	}
	sum := &Summary{Version: Version, StructuralChecker: audit.CheckerVersion, RunDir: o.Run, Registry: o.Registry, RunErrors: []string{}, StructuralOutcomes: map[string]int{}, ChecksByClass: map[string]int{}, FailedByClass: map[string]int{}}
	runErr := func(class, f string, a ...any) {
		sum.RunErrors = append(sum.RunErrors, class+": "+fmt.Sprintf(f, a...))
		switch class {
		case "incomplete":
			sum.Incomplete++
		case "malformed":
			sum.Malformed++
		case "violation":
			sum.Violations++
		}
	}
	finish := func(res []CellResult) (*Summary, []CellResult, error) {
		switch {
		case sum.Disagree+sum.Violations > 0 || sum.OrphanReceipts > 0 || len(sum.DuplicateDecisions) > 0:
			sum.ExitCode = 1
		case sum.Incomplete+sum.Malformed+sum.Unsupported > 0 || sum.Expected == 0:
			sum.ExitCode = 2
		}
		sum.Note = "audit-pq v" + Version + ": structural release invariants (checker " + audit.CheckerVersion + ": strict loading, event order and multiplicity, typed contexts, session join, connection continuity, receipt joins by decision id/token/exporter, release cardinality, duplicate ids, orphan receipts) composed with re-verification of every retained ES256 / ML-DSA-65 proof under the trusted registry (shared libraries; expected context rebuilt from the issued session; parsed appraisal time inside the session validity) and with the declared inventory. Consistency of cooperative observations, not tamper-proof evidence."
		write(o.OutDir, sum, res)
		return sum, res, nil
	}
	reg, err := registry.Load(o.Registry)
	if err != nil {
		runErr("incomplete", "registry: %v", err)
		return finish(nil)
	}
	labelToDep, err := audit.LoadRegistryLabels(o.Registry)
	if err != nil {
		runErr("malformed", "registry labels: %v", err)
		return finish(nil)
	}
	// Declared per-fixture trust-anchor overrides (e.g. a rotated key pin), recorded by
	// the producer at fixture setup; applied only to that fixture's cells. A present
	// but unparseable file is malformed; a missing file means no overrides.
	overrides := map[string]map[string]map[string]registry.V4Key{}
	if b, err := os.ReadFile(filepath.Join(o.Run, "registry-overrides.json")); err == nil {
		if json.Unmarshal(b, &overrides) != nil {
			runErr("malformed", "registry-overrides.json unparseable")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		runErr("malformed", "registry-overrides.json unreadable: %v", err)
	}
	regFor := func(fixture string) *registry.Registry {
		ov := overrides[fixture]
		if ov == nil {
			return reg
		}
		cp := &registry.Registry{Frozen: reg.Frozen, Deployments: map[string]*registry.Deployment{}}
		for l, d := range reg.Deployments {
			dd := *d
			dd.V4Keys = map[string]registry.V4Key{}
			for k, v := range d.V4Keys {
				dd.V4Keys[k] = v
			}
			for base, v := range ov[l] {
				dd.V4Keys[base] = v
			}
			cp.Deployments[l] = &dd
		}
		return cp
	}
	inv, errs := loadInventory(o.Run)
	for _, e := range errs {
		runErr("malformed", "%s", e)
	}
	sum.Expected = len(inv)
	if len(inv) == 0 {
		runErr("incomplete", "no declared inventory")
		return finish(nil)
	}
	cellsDir := filepath.Join(o.Run, "cells")
	present := map[string]bool{}
	if es, err := os.ReadDir(cellsDir); err == nil {
		for _, e := range es {
			if e.IsDir() {
				present[e.Name()] = true
			}
		}
	}
	declared := map[string]bool{}
	idSeen := map[string][]string{}
	var out []CellResult
	for _, ic := range inv {
		declared[ic.Cell] = true
		cr := CellResult{Cell: ic.Cell, Policy: ic.Policy, ExpectedDecision: ic.ExpectedDecision, ExpectedRecipient: ic.ExpectedRecipient}
		fail := func(status, detail string) {
			if cr.Status == "" {
				cr.Status, cr.Detail = status, detail
			}
		}
		pol, perr := wire.ParsePolicy(ic.Policy)
		if perr != nil {
			fail("malformed", "inventory policy does not parse")
		}
		cd := filepath.Join(cellsDir, ic.Cell)
		var decisions, sessions []map[string]any
		var events []audit.Event
		if cr.Status == "" {
			var derr error
			decisions, sessions, derr = audit.LoadDecisions(filepath.Join(cd, "decision.json"))
			switch {
			case derr != nil && errors.Is(derr, os.ErrNotExist):
				fail("incomplete", "no decision record for the declared cell")
			case derr != nil:
				fail("malformed", "decision.json: "+derr.Error())
			default:
				sum.Found++
				// Decision ids are registered before any other gate so that a duplicated
				// record is a run-level violation even when the cell's declared count
				// already fails (the count alone is malformed).
				for _, d := range decisions {
					if id := str(d["decision_id"]); id != "" {
						idSeen[id] = append(idSeen[id], ic.Cell)
					}
				}
				if n := max(ic.ExpectedDecisions, 1); len(decisions) != n {
					fail("malformed", fmt.Sprintf("%d decisions recorded, %d declared", len(decisions), n))
				}
			}
		}
		if cr.Status == "" {
			var eerr error
			events, eerr = audit.LoadEvents(filepath.Join(cd, "controller-events.jsonl"))
			if eerr != nil { // never ignored: receipts and recipients come from this file
				fail("malformed", "controller-events.jsonl: "+eerr.Error())
			}
		}
		if cr.Status == "" && sessions == nil && pol.HasProof() {
			// The issued-session dump is part of the record for proof policies.
			fail("incomplete", "decision.json carries no issued-session record (sessions missing)")
		}
		if cr.Status == "" {
			cr.Decisions = len(decisions)
			aic := audit.InvCell{Cell: ic.Cell, Policy: ic.Policy, Class: ic.Class, ExpectedRecipient: ic.ExpectedRecipient, ExpectedDecisions: ic.ExpectedDecisions}
			anyAccept, released, receipts := false, 0, 0
			var labels []string
			for _, d := range decisions {
				if str(d["policy"]) != ic.Policy {
					fail("violation", fmt.Sprintf("decision policy %q differs from the inventory policy %q (policy downgrade or substitution)", str(d["policy"]), ic.Policy))
				}
				// ---- structural invariants (checker 2.1) ----
				sr := audit.AuditDecision(ic.Cell, aic, false, d, sessions, events, labelToDep)
				if sr.Outcome == audit.OutViolation && ic.Class == "malicious" && ic.ExpectedRecipient != "" && ic.ExpectedRecipient != sr.Expected && sr.ReceiptLabels == ic.ExpectedRecipient && audit.OnlyRecipientChecksFailed(sr) {
					sr.Outcome = audit.OutExpectedAttack
				}
				da := DecisionAudit{DecisionID: sr.DecisionID, StructuralOutcome: sr.Outcome, Path: sr.Path, Receipts: sr.Receipts, ReceiptLabels: sr.ReceiptLabels, RecordedAccept: d["accept"] == true, Checks: sr.Checks}
				for _, c := range sr.Checks {
					sum.ChecksByClass[c.Class]++
					if !c.OK {
						sum.FailedByClass[c.Class]++
						da.FailedChecks = append(da.FailedChecks, c.Name)
					}
				}
				sum.StructuralOutcomes[sr.Outcome]++
				switch sr.Outcome {
				case audit.OutMalformed:
					fail("malformed", "structural: "+strings.Join(da.FailedChecks, "; "))
				case audit.OutUnsupported:
					fail("unsupported", "record lacks the schema-2 fields (evidence_schema, decision_id, requester_events, typed context); not upgraded")
				case audit.OutInsufficient:
					fail("incomplete", "structural: "+strings.Join(da.FailedChecks, "; ")+" (path "+sr.Path+")")
				case audit.OutViolation:
					fail("violation", "structural: "+strings.Join(da.FailedChecks, "; "))
				}
				anyAccept = anyAccept || da.RecordedAccept
				if sr.Dispatched {
					released++
				}
				receipts += sr.Receipts
				if sr.ReceiptLabels != "" {
					labels = append(labels, strings.Split(sr.ReceiptLabels, ",")...)
				}
				// ---- proof re-verification ----
				if !wire.IsV4(pol.Base) {
					da.Proof = "n/a"
				} else {
					v, stage, alg, kid := reverify(pol, d, sessions, regFor(ic.Fixture))
					cr.Alg, cr.KID = alg, kid
					if v {
						sum.ProofsVerified++
						da.Proof = "valid"
					} else {
						sum.ProofsInvalid++
						da.Proof = "invalid:" + stage
					}
					recValid := false
					if pv, ok := d["proof_v4"].(map[string]any); ok {
						recValid = pv["signature_valid_under_pinned_key"] == true && pv["context_matches_expected"] == true && pv["expiry_ok"] == true
					}
					switch {
					case stage == "malformed":
						fail("malformed", "appraisal timestamp or session record not typed (appraised_at unparseable or outside the session validity)")
					case stage == "unsupported":
						fail("unsupported", "proof algorithm or key outside the closed set: "+alg)
					case da.RecordedAccept && !v:
						fail("violation", "decision ACCEPTED but the retained proof does not re-verify ("+stage+")")
					case !da.RecordedAccept && v && recValid:
						// accepted proof but rejected decision for another reason (nonce, card, tls): fine
					case recValid != v:
						fail("disagree", fmt.Sprintf("recorded proof verdict %v, recomputed %v (%s)", recValid, v, stage))
					}
				}
				cr.Audits = append(cr.Audits, da)
			}
			// ---- recipients and declared outcome (receipts joined per decision) ----
			sort.Strings(labels)
			uniq := []string{}
			for i, l := range labels {
				if i == 0 || labels[i-1] != l {
					uniq = append(uniq, l)
				}
			}
			cr.ObservedRecipient = strings.Join(uniq, "+")
			if cr.ObservedRecipient == "" {
				cr.ObservedRecipient = "none"
			}
			cr.Releases = released
			cr.ObservedDecision = map[bool]string{true: "accept", false: "reject"}[anyAccept]
			expDecision := ic.ExpectedDecision
			if expDecision == "one" { // concurrent-delivery cells: accept with exactly one dispatch
				expDecision = "accept"
				if anyAccept && released != 1 {
					fail("violation", fmt.Sprintf("declared exactly one release, observed %d dispatch attempts", released))
				}
			}
			switch {
			case cr.Status != "":
			case released > 1:
				fail("violation", fmt.Sprintf("%d dispatch attempts for one cell", released))
			case receipts > released:
				fail("violation", fmt.Sprintf("%d receipts for %d dispatch attempts", receipts, released))
			case expDecision != "" && cr.ObservedDecision != expDecision:
				fail("disagree", fmt.Sprintf("decision %s, declared %s", cr.ObservedDecision, ic.ExpectedDecision))
			case ic.ExpectedRecipient != "" && cr.ObservedRecipient != ic.ExpectedRecipient:
				fail("disagree", fmt.Sprintf("recipient %s, declared %s", cr.ObservedRecipient, ic.ExpectedRecipient))
			case ic.ExpectedRecipient == "B":
				cr.AttackSuccess = true
				sum.AttackSuccess++
			}
			// orphan receipts: a job_received in this cell that joins no decision of the cell
			joined := map[string]bool{}
			for _, d := range decisions {
				joined[str(d["decision_id"])] = true
				if t := str(d["job_token"]); t != "" {
					joined["tok:"+t] = true
				}
			}
			for _, e := range events {
				if e.Kind != "job_received" {
					continue
				}
				if !joined[str(e.Data["decision_id"])] && !joined["tok:"+str(e.Data["token"])] {
					sum.OrphanReceipts++
					fail("violation", "receipt in the cell joins no decision (orphan receipt)")
				}
			}
		}
		if cr.Status == "" {
			cr.Status = "agree"
		}
		switch cr.Status {
		case "agree":
			sum.Agree++
		case "disagree":
			sum.Disagree++
		case "violation":
			sum.Violations++
		case "incomplete":
			sum.Incomplete++
		case "malformed":
			sum.Malformed++
		case "unsupported":
			sum.Unsupported++
		}
		out = append(out, cr)
	}
	for c := range present {
		if !declared[c] {
			runErr("malformed", "undeclared cell directory %s", c)
		}
	}
	for id, cells := range idSeen {
		if len(cells) > 1 {
			sum.DuplicateDecisions = append(sum.DuplicateDecisions, id)
			runErr("violation", "decision id %s appears %d times (%s)", id, len(cells), strings.Join(cells, ","))
		}
	}
	sort.Strings(sum.DuplicateDecisions)
	return finish(out)
}

// reverify rebuilds the expected context from the decision's own issued session and
// verifies the retained proof under the registry key for the policy base. The stage
// "malformed" means the record's appraisal time or session is not typed/consistent;
// freshness is never skipped.
func reverify(pol wire.Policy, d map[string]any, sessions []map[string]any, reg *registry.Registry) (ok bool, stage, alg, kid string) {
	expectedLabel := str(d["expected_deployment"])
	dep := reg.Deployments[expectedLabel]
	if dep == nil {
		return false, "unsupported", "", ""
	}
	pin, exists := dep.V4Keys[pol.Base]
	if !exists {
		return false, "unsupported", "", ""
	}
	raw, _ := d["raw_evidence"].(map[string]any)
	pv, _ := raw["proof_v4"].(map[string]any)
	if pv == nil {
		return false, "no-proof", "", pin.KID
	}
	alg, kid = str(pv["alg"]), str(pv["kid"])
	if !pqsig.Algs[alg] {
		return false, "unsupported", alg, kid
	}
	// Typed appraisal time: required, and inside the issued session's validity.
	at, err := time.Parse(time.RFC3339Nano, str(d["appraised_at"]))
	if err != nil {
		return false, "malformed", alg, kid
	}
	nonceB64 := str(d["nonce"])
	var sess map[string]any
	for _, s := range sessions {
		if str(s["nonce"]) == nonceB64 && nonceB64 != "" {
			sess = s
		}
	}
	audience := ""
	if sess != nil {
		issued, e1 := time.Parse(time.RFC3339Nano, str(sess["issued_at"]))
		expires, e2 := time.Parse(time.RFC3339Nano, str(sess["expires_at"]))
		if e1 != nil || e2 != nil || at.Before(issued) || at.After(expires) {
			return false, "malformed", alg, kid
		}
		audience = str(sess["audience"])
	}
	if audience == "" {
		if c, ok := d["context"].(map[string]any); ok {
			audience = str(c["audience"])
		}
	}
	ctxb, _ := wire.UnB64(str(pv["context"]))
	sig, _ := wire.UnB64(str(pv["signature"]))
	p := &pqsig.Proof{Format: str(pv["format"]), Alg: alg, KID: kid, Context: ctxb, Signature: sig}
	pk := pqsig.PinnedKey{Alg: pin.Alg, KID: pin.KID, Version: pin.Version}
	switch pin.Alg {
	case pqsig.AlgES256:
		pub, err := tpmsig.ParsePublicPEM(pin.PublicPEM)
		if err != nil {
			return false, "unsupported", alg, kid
		}
		pk.ECPub = pub
	case pqsig.AlgMLDSA:
		pub, _ := wire.UnB64(pin.PublicB64)
		pk.MLDSAPub = pub
	}
	nonce, _ := wire.UnB64(nonceB64)
	var exporter []byte
	if cb, ok := d["channel_binding"].(map[string]any); ok && pol.CB {
		exporter, _ = hex.DecodeString(str(cb["requester_exporter_hex"]))
	}
	if exporter == nil {
		exporter = []byte{}
	}
	exp := &pqsig.Context{V: pqsig.Format, Role: pqsig.Role, Policy: pol.String(), Alg: pin.Alg, KID: pin.KID, Expected: dep.DeploymentID, Requester: audience, Action: Action, Nonce: nonce, Session: nonceB64, Exporter: exporter}
	got, err := pqsig.Decode(ctxb)
	if err != nil {
		return false, "context", alg, kid
	}
	exp.Expiry = got.Expiry
	e := time.Unix(got.Expiry, 0)
	if !e.After(at) || e.After(at.Add(300*time.Second)) {
		return false, "expiry", alg, kid
	}
	st, verr := pqsig.Verify(p, pk, exp)
	if verr != nil {
		return false, st, alg, kid
	}
	return true, "", alg, kid
}

func loadInventory(run string) ([]invCell, []string) {
	var errs []string
	b, err := os.ReadFile(filepath.Join(run, "run-inventory.json"))
	if err != nil {
		return nil, []string{"run-inventory.json missing"}
	}
	var doc struct {
		Cells []struct {
			Cell, Fixture, Policy, Class, ExpectedDecision, ExpectedRecipient string
			ExpectedDecisions                                                 int
		} `json:"cells"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil, []string{"run-inventory.json unparseable"}
	}
	seen := map[string]bool{}
	var out []invCell
	for _, c := range doc.Cells {
		if c.Cell == "" || strings.ContainsAny(c.Cell, "/\\") {
			errs = append(errs, "invalid inventory cell id")
			continue
		}
		if seen[c.Cell] {
			errs = append(errs, "duplicate inventory entry "+c.Cell)
			continue
		}
		seen[c.Cell] = true
		if c.ExpectedDecisions < 1 {
			errs = append(errs, c.Cell+": inventory must declare expected_decisions >= 1")
		}
		out = append(out, invCell{Cell: c.Cell, Fixture: c.Fixture, Policy: c.Policy, Class: c.Class, ExpectedDecision: c.ExpectedDecision, ExpectedRecipient: c.ExpectedRecipient, ExpectedDecisions: c.ExpectedDecisions})
	}
	return out, errs
}

func write(dir string, sum *Summary, res []CellResult) {
	os.MkdirAll(dir, 0o755)
	f, _ := os.Create(filepath.Join(dir, "pq-audit.jsonl"))
	for _, r := range res {
		b, _ := json.Marshal(r)
		f.Write(append(b, '\n'))
	}
	f.Close()
	sb, _ := json.MarshalIndent(sum, "", "  ")
	os.WriteFile(filepath.Join(dir, "pq-audit-summary.json"), sb, 0o644)
	var md strings.Builder
	fmt.Fprintf(&md, "# PQ composite audit (audit-pq v%s, structural checker %s) for %s\n\nDeclared %d · found %d · agree %d · disagree %d · violations %d · incomplete %d · malformed %d · unsupported %d · proofs re-verified valid %d / invalid %d · expected attacker deliveries %d · orphan receipts %d · duplicate decision ids %v · **exit %d**\n\n", sum.Version, sum.StructuralChecker, sum.RunDir, sum.Expected, sum.Found, sum.Agree, sum.Disagree, sum.Violations, sum.Incomplete, sum.Malformed, sum.Unsupported, sum.ProofsVerified, sum.ProofsInvalid, sum.AttackSuccess, sum.OrphanReceipts, sum.DuplicateDecisions, sum.ExitCode)
	fmt.Fprintf(&md, "Structural outcomes per decision: %v. Checks by trust class (failed/total): ", sum.StructuralOutcomes)
	for _, k := range []string{audit.ClassRecomputed, audit.ClassRequesterTLS, audit.ClassCooperative, audit.ClassCopied, audit.ClassStipulated} {
		fmt.Fprintf(&md, "%s %d/%d; ", k, sum.FailedByClass[k], sum.ChecksByClass[k])
	}
	md.WriteString("\n\n")
	for _, e := range sum.RunErrors {
		fmt.Fprintf(&md, "* %s\n", e)
	}
	md.WriteString("\n| cell | status | decision (declared) | recipient (declared) | releases | structural | proof | detail |\n|---|---|---|---|---|---|---|---|\n")
	for _, r := range res {
		var so, pr []string
		for _, a := range r.Audits {
			so = append(so, a.StructuralOutcome)
			pr = append(pr, a.Proof)
		}
		fmt.Fprintf(&md, "| %s | %s | %s (%s) | %s (%s) | %d | %s | %s | %s |\n", r.Cell, r.Status, r.ObservedDecision, r.ExpectedDecision, r.ObservedRecipient, r.ExpectedRecipient, r.Releases, strings.Join(so, ","), strings.Join(pr, ","), r.Detail)
	}
	fmt.Fprintf(&md, "\n%s\n", sum.Note)
	os.WriteFile(filepath.Join(dir, "pq-audit.md"), []byte(md.String()), 0o644)
}
