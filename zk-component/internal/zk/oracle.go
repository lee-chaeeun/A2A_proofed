package zk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The oracle is the offline scorer of a ZK run. It validates that the run is COMPLETE
// and UNIQUE against the inventory declared before execution, binds every scored row
// to the retained receipt bytes by re-running the pinned verifier CLI (a shared
// component, recorded by hash; not an independent proof-system implementation),
// recomputes sums and commitments with its own small routines (oracle_arith.go),
// reconstructs every ledger from the ordered approval events and derives the correct
// business decision (including duplicate suppression) without calling Evaluate or
// reading the recorded accept flag as its expectation.
//
// Outcome classes per evaluation: agree | disagree | violation | evidence_mismatch |
// incomplete | malformed. Exit codes: 0 complete and clean (expected weak-policy
// attack successes are counted, not hidden); 1 any disagreement, violation or
// evidence mismatch; 2 incomplete, malformed or unsupported evidence (1 wins when both
// occur; both counts are always reported).

type OracleOptions struct {
	Run             string
	Openings        string
	VerifyBin       string // pinned verifier CLI (reused); required to bind receipts
	LegacyInventory string // declared inventory for schema-1 runs (separately identified replay/audit view)
	OutDir          string // where oracle.jsonl / oracle-summary.json / oracle.md go (default: Run)
}

type OracleRow struct {
	EvaluationID        string `json:"evaluation_id"`
	Fixture             string `json:"fixture"`
	Policy              string `json:"policy"`
	Status              string `json:"status"`
	ReceiptStatus       string `json:"receipt_status"` // verified | rejected | none | unchecked
	CorrectApprove      bool   `json:"correct_business_decision_approve"`
	PolicyShouldApprove bool   `json:"policy_semantics_approve"`
	PriorApproval       bool   `json:"prior_approval_in_ledger"`
	ExpectedInsert      bool   `json:"expected_insert"`
	ObservedInsert      bool   `json:"observed_insert_event"`
	AttackSuccess       bool   `json:"expected_weak_policy_attack_success"`
	WrongContext        bool   `json:"wrong_context_accepted"`
	Unsafe              bool   `json:"unsafe_approval"`
	DeniedLegit         bool   `json:"legitimate_denied"`
	Detail              string `json:"detail"`
}

type VerifierIdentity struct {
	Bin                  string `json:"bin"`
	SHA256               string `json:"sha256"`
	RecordedInProvenance string `json:"sha256_recorded_in_run_provenance,omitempty"`
	MatchesProvenance    bool   `json:"matches_run_provenance"`
	TrustSource          string `json:"trust_source"`
	UniquePairs          int    `json:"unique_receipt_image_pairs"`
	Verified             int    `json:"verified"`
	Rejected             int    `json:"rejected"`
	Failures             int    `json:"verifier_failures"`
}

type OracleSummary struct {
	RunDir            string           `json:"run_dir"`
	OutDir            string           `json:"out_dir"`
	Mode              string           `json:"mode"`
	ProducerSchema    int              `json:"producer_evidence_schema"`
	InventorySource   string           `json:"inventory_source"`
	Expected          int              `json:"evaluations_declared"`
	Rows              int              `json:"rows_read"`
	Scored            int              `json:"scored"`
	Agree             int              `json:"agree"`
	Disagree          int              `json:"disagreements"`
	Violations        int              `json:"violations"`
	EvidenceMismatch  int              `json:"evidence_mismatches"`
	Incomplete        int              `json:"incomplete"`
	Malformed         int              `json:"malformed"`
	RunErrors         []string         `json:"run_level_errors"`
	AttackSuccesses   int              `json:"expected_attack_successes"`
	AttackSuccessList []string         `json:"expected_attack_success_list"`
	WrongContext      string           `json:"wrong_context_accepted"`
	UnsafeApprovals   string           `json:"unsafe_approvals"`
	DeniedLegitimate  string           `json:"legitimate_denied"`
	Verifier          VerifierIdentity `json:"verifier"`
	Arithmetic        string           `json:"arithmetic"`
	Limitations       []string         `json:"limitations"`
	ExitCode          int              `json:"exit_code"`
	Note              string           `json:"note"`
}

// RunOracle keeps the earlier signature (schema-2 runs, default verifier path).
func RunOracle(run, openingsPath string) (*OracleSummary, []OracleRow, error) {
	return RunOracleOpts(OracleOptions{Run: run, Openings: openingsPath, VerifyBin: filepath.Join("zk", "target", "release", "zkverify")})
}

type verifyResult struct {
	verified bool
	journal  string
	kind     string
	msg      string
	err      error
}

// runVerifierCLI is the oracle's own small wrapper around the pinned verifier CLI
// (shared binary, separate wrapper).
func runVerifierCLI(bin string, receipt []byte, expectedImage string) verifyResult {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	in, _ := json.Marshal(map[string]string{"receipt_b64": base64.StdEncoding.EncodeToString(receipt), "expected_image_id_hex": expectedImage})
	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = bytes.NewReader(in)
	cmd.Env = append(os.Environ(), "RISC0_DEV_MODE=0")
	out, _ := cmd.Output()
	var r struct {
		OK            bool   `json:"ok"`
		Verified      bool   `json:"verified"`
		JournalHex    string `json:"journal_hex"`
		ReceiptSHA256 string `json:"receipt_sha256"`
		ReceiptKind   string `json:"receipt_kind"`
		Error         string `json:"error"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &r) != nil {
		return verifyResult{err: fmt.Errorf("verifier output unparseable: %s", firstLine(out))}
	}
	if !r.OK {
		return verifyResult{err: fmt.Errorf("verifier refused the input: %s", r.Error)}
	}
	sum := sha256.Sum256(receipt)
	if r.ReceiptSHA256 != hex.EncodeToString(sum[:]) {
		return verifyResult{err: fmt.Errorf("verifier reported a different receipt hash")}
	}
	return verifyResult{verified: r.Verified, journal: r.JournalHex, kind: r.ReceiptKind, msg: r.Error}
}

type evalCtx struct {
	entry     InventoryEntry
	row       *Row
	status    string
	detail    string
	markerSeq int
}

func (e *evalCtx) fail(status, detail string) {
	if e.status == "" {
		e.status, e.detail = status, detail
	}
}

var knownEventKinds = map[string]bool{"authority_reset": true, "authority_update": true, "zk_dispatch": true, "zk_result_received": true, "zk_decision": true, "approval_inserted": true, "zk_reuse": true}

// RunOracleOpts scores one run directory.
func RunOracleOpts(o OracleOptions) (*OracleSummary, []OracleRow, error) {
	if o.OutDir == "" {
		o.OutDir = o.Run
	}
	sum := &OracleSummary{RunDir: o.Run, OutDir: o.OutDir, RunErrors: []string{}, AttackSuccessList: []string{}, Limitations: []string{}, Arithmetic: "sums, commitments and journal decoding recomputed by the oracle's own routines (internal/zk/oracle_arith.go); production helpers and Evaluate are not called"}
	sum.Verifier.TrustSource = "pinned RISC Zero verifier CLI (zkverify) re-run by the oracle per unique (receipt, declared image id); a shared component, not an independent proof-system implementation"
	runErr := func(class, f string, a ...any) {
		msg := class + ": " + fmt.Sprintf(f, a...)
		sum.RunErrors = append(sum.RunErrors, msg)
		switch class {
		case "incomplete", "unsupported":
			sum.Incomplete++
		case "malformed":
			sum.Malformed++
		case "violation":
			sum.Violations++
		}
	}
	finish := func(rows []OracleRow) (*OracleSummary, []OracleRow, error) {
		switch {
		case sum.Disagree+sum.Violations+sum.EvidenceMismatch > 0:
			sum.ExitCode = 1
		case sum.Incomplete+sum.Malformed > 0 || sum.Expected == 0:
			sum.ExitCode = 2
		}
		sum.Note = "Offline business-decision oracle (completeness against the declared inventory, receipt bytes re-verified with the pinned verifier, ledgers reconstructed from ordered events, duplicate suppression derived from ledger history). Trusted: the declared inventory, the fixture authority history, the openings, the verifier binary."
		writeOracle(o.OutDir, sum, rows)
		return sum, rows, nil
	}

	// ---- inventory ------------------------------------------------------------------
	runInvPath := filepath.Join(o.Run, "run-inventory.json")
	var inv *Inventory
	_, hasRunInv := os.Stat(runInvPath)
	legacy := false
	switch {
	case hasRunInv == nil && o.LegacyInventory != "":
		runErr("malformed", "run has run-inventory.json; --legacy-inventory is only for schema-1 runs")
		return finish(nil)
	case hasRunInv == nil:
		var err error
		if inv, err = LoadInventory(runInvPath); err != nil {
			runErr("malformed", "%v", err)
			return finish(nil)
		}
		if inv.Kind != "run" {
			runErr("malformed", "run-inventory.json kind %q is not a pre-execution run inventory", inv.Kind)
			return finish(nil)
		}
		sum.Mode, sum.ProducerSchema, sum.InventorySource = "schema-2 (inventory declared before execution)", 2, runInvPath
	case o.LegacyInventory != "":
		var err error
		if inv, err = LoadInventory(o.LegacyInventory); err != nil {
			runErr("malformed", "%v", err)
			return finish(nil)
		}
		if inv.Kind != "legacy" {
			runErr("malformed", "legacy inventory kind %q", inv.Kind)
			return finish(nil)
		}
		legacy = true
		sum.Mode, sum.ProducerSchema, sum.InventorySource = "legacy replay/audit view of a schema-1 run (declared inventory supplied afterwards)", 1, o.LegacyInventory
		sum.Limitations = append(sum.Limitations,
			"schema-1 rows and events carry no evaluation id: markers are joined by the declared ordinal order per (request, policy)",
			"schema-1 rows carry no ledger id: ledger grouping is taken from the declared legacy inventory",
			"schema-1 approval events carry no evaluation id: an insert is attributed to the marker it immediately follows",
			"schema-1 producers emitted no decision marker for verification failures: those evaluations are bound to their retained receipt bytes only",
			"schema-1 runs have no ledgers.json: final ledger state is reconstructed from events only")
	default:
		runErr("unsupported", "no run-inventory.json in %s; a schema-1 run needs --legacy-inventory for the replay/audit view", o.Run)
		return finish(nil)
	}
	sum.Expected = len(inv.Evaluations)

	// ---- rows -----------------------------------------------------------------------
	rows, rerrs := loadRowsStrict(filepath.Join(o.Run, "decisions.jsonl"))
	for _, e := range rerrs {
		runErr("malformed", "%s", e)
	}
	sum.Rows = len(rows)
	rowsByEval := map[string][]*Row{}
	declared := map[string]InventoryEntry{}
	for _, e := range inv.Evaluations {
		declared[e.EvaluationID] = e
	}
	for i := range rows {
		r := &rows[i]
		if legacy {
			if r.EvaluationID == "" {
				r.EvaluationID = r.Fixture + "/" + r.Policy
			}
		} else if r.EvidenceSchema != EvidenceSchema || r.EvaluationID == "" {
			runErr("malformed", "row %s/%s lacks evidence_schema %d or an evaluation id", r.Fixture, r.Policy, EvidenceSchema)
			continue
		}
		if _, ok := declared[r.EvaluationID]; !ok {
			runErr("malformed", "unexpected evaluation %q (fixture %q policy %q) not in the declared inventory", r.EvaluationID, r.Fixture, r.Policy)
			continue
		}
		rowsByEval[r.EvaluationID] = append(rowsByEval[r.EvaluationID], r)
	}

	// ---- requests -------------------------------------------------------------------
	requests, reqErrs := loadRequestsStrict(filepath.Join(o.Run, "requests.json"))
	for _, e := range reqErrs {
		runErr("malformed", "%s", e)
	}

	// ---- events ---------------------------------------------------------------------
	events, evErrs := loadEventsStrict(filepath.Join(o.Run, "events.jsonl"))
	for _, e := range evErrs {
		runErr("malformed", "%s", e)
	}
	eventsBroken := len(evErrs) > 0 // sequence/scanner errors: the ordered stream cannot be interpreted
	// head of the authority BEFORE each seq (index = seq), from the ordered stream
	headBefore := make([]uint32, len(events)+2)
	head := uint32(1)
	for i, e := range events {
		headBefore[i+1] = head
		switch e.Kind {
		case "authority_update":
			head = uint32(toInt(e.Fields["head_version"]))
		case "authority_reset":
			head = 1
		}
	}
	headBefore[len(events)+1] = head
	eventBySeq := func(seq int) *Event {
		if seq >= 1 && seq <= len(events) && events[seq-1].Seq == seq {
			return &events[seq-1]
		}
		return nil
	}
	var markers, approvals []*Event
	for i := range events {
		switch events[i].Kind {
		case "zk_decision":
			markers = append(markers, &events[i])
		case "approval_inserted":
			approvals = append(approvals, &events[i])
		}
	}
	markersByEval := map[string][]*Event{}
	approvalsByEval := map[string][]*Event{}
	switch {
	case eventsBroken:
		// no joins: the stream cannot be interpreted; every evaluation is reported malformed
	case !legacy:
		for _, m := range markers {
			markersByEval[str(m.Fields["evaluation_id"])] = append(markersByEval[str(m.Fields["evaluation_id"])], m)
		}
		for _, a := range approvals {
			approvalsByEval[str(a.Fields["evaluation_id"])] = append(approvalsByEval[str(a.Fields["evaluation_id"])], a)
		}
	default:
		// legacy join: the k-th marker of (request, policy) belongs to the k-th declared
		// evaluation (ordinal order) of that (request, policy) whose prediction is not a
		// verification failure (schema-1 producers emitted no marker for those).
		byKey := map[string][]*Event{}
		for _, m := range markers {
			k := str(m.Fields["request_id"]) + "\x00" + str(m.Fields["policy"])
			byKey[k] = append(byKey[k], m)
		}
		seen := map[string]int{}
		for _, e := range inv.Evaluations {
			if e.VerifyFails {
				continue
			}
			k := e.RequestID + "\x00" + e.Policy
			idx := seen[k]
			seen[k]++
			if idx < len(byKey[k]) {
				markersByEval[e.EvaluationID] = []*Event{byKey[k][idx]}
			}
		}
		for k, ms := range byKey {
			if seen[k] < len(ms) {
				runErr("malformed", "legacy join: %d decision markers for (%s) but only %d declared evaluations", len(ms), strings.ReplaceAll(k, "\x00", ", "), seen[k])
			}
		}
		// legacy approvals: adjacency to a marker (seq+1) with the same request and policy
		markerOwner := map[int]string{}
		for id, ms := range markersByEval {
			markerOwner[ms[0].Seq] = id
		}
		for _, a := range approvals {
			if id, ok := markerOwner[a.Seq-1]; ok {
				m := eventBySeq(a.Seq - 1)
				if m != nil && str(m.Fields["request_id"]) == str(a.Fields["request_id"]) && str(m.Fields["policy"]) == str(a.Fields["policy"]) {
					approvalsByEval[id] = append(approvalsByEval[id], a)
				}
			}
		}
	}

	// ---- openings (independent arithmetic) --------------------------------------------
	openings, err := oracleLoadOpenings(o.Openings)
	if err != nil {
		runErr("incomplete", "%v", err)
		return finish(nil)
	}
	commitByVersion := map[uint32][32]byte{}
	passByVersion := map[uint32]bool{}
	for _, op := range openings {
		salt, err := hex.DecodeString(op.SaltHex)
		if err != nil {
			runErr("malformed", "opening v%d salt not hex", op.Version)
			continue
		}
		c, err := oracleCommitment(op.Portfolio, op.Version, salt, op.Holdings)
		if err != nil {
			runErr("malformed", "opening v%d: %v", op.Version, err)
			continue
		}
		commitByVersion[op.Version] = c
		passByVersion[op.Version] = oraclePass(op.Holdings)
	}

	// ---- verifier identity ------------------------------------------------------------
	sum.Verifier.Bin = o.VerifyBin
	verifierOK := false
	if b, err := os.ReadFile(o.VerifyBin); err == nil {
		s := sha256.Sum256(b)
		sum.Verifier.SHA256 = hex.EncodeToString(s[:])
		verifierOK = true
	} else {
		runErr("incomplete", "pinned verifier binary not available at %s; receipts cannot be re-verified", o.VerifyBin)
	}
	if pb, err := os.ReadFile(filepath.Join(o.Run, "provenance.json")); err == nil {
		var prov struct {
			SHA256 map[string]string `json:"sha256"`
		}
		if json.Unmarshal(pb, &prov) == nil {
			sum.Verifier.RecordedInProvenance = prov.SHA256["bin:verify"]
			sum.Verifier.MatchesProvenance = sum.Verifier.RecordedInProvenance != "" && sum.Verifier.RecordedInProvenance == sum.Verifier.SHA256
		}
	}
	if !sum.Verifier.MatchesProvenance {
		sum.Limitations = append(sum.Limitations, "the verifier binary used by the audit is not byte-identical to the one recorded in the run's provenance (or none was recorded)")
	}
	verifyCache := map[string]verifyResult{}
	verify := func(hash string, receipt []byte, image string) verifyResult {
		k := hash + "|" + image
		if r, ok := verifyCache[k]; ok {
			return r
		}
		r := runVerifierCLI(o.VerifyBin, receipt, image)
		verifyCache[k] = r
		sum.Verifier.UniquePairs++
		switch {
		case r.err != nil:
			sum.Verifier.Failures++
		case r.verified:
			sum.Verifier.Verified++
		default:
			sum.Verifier.Rejected++
		}
		return r
	}

	// ---- per evaluation ---------------------------------------------------------------
	var out []OracleRow
	var wcN, wcD, unN, unD, dlN, dlD int
	attributedApprovals := map[*Event]bool{}
	lastMarkerSeq := 0
	type ledgerApproval struct {
		seq     int
		request string
		eval    string
		receipt string
		marker  int
	}
	ledgerHistory := map[string][]ledgerApproval{} // ledger id -> approvals attributed so far (ordinal order == seq order)
	resultEvents := map[string][]*Event{}
	for i := range events {
		if events[i].Kind == "zk_result_received" {
			rid := str(events[i].Fields["request_id"])
			resultEvents[rid] = append(resultEvents[rid], &events[i])
		}
	}
	// Pre-pass: the ledger history is reconstructed from EVENTS alone (approval events
	// attributed to declared evaluations), independent of whether the rows are present
	// or well-formed, so a defective row cannot orphan or hide another evaluation's insert.
	for _, e := range inv.Evaluations {
		mseq := 0
		if ms := markersByEval[e.EvaluationID]; len(ms) == 1 {
			mseq = ms[0].Seq
		}
		for _, a := range approvalsByEval[e.EvaluationID] {
			attributedApprovals[a] = true
			ledgerHistory[e.LedgerID] = append(ledgerHistory[e.LedgerID], ledgerApproval{seq: a.Seq, request: e.RequestID, eval: e.EvaluationID, receipt: str(a.Fields["receipt_sha256"]), marker: mseq})
		}
	}
	for id := range ledgerHistory {
		h := ledgerHistory[id]
		sort.Slice(h, func(i, j int) bool { return h[i].seq < h[j].seq })
	}
	for _, e := range inv.Evaluations {
		ec := &evalCtx{entry: e}
		if eventsBroken {
			ec.fail("malformed", "event stream malformed (sequence or scanner errors; see run-level findings)")
		}
		or := OracleRow{EvaluationID: e.EvaluationID, Fixture: e.Fixture, Policy: e.Policy, ReceiptStatus: "unchecked"}
		rs := rowsByEval[e.EvaluationID]
		switch {
		case len(rs) == 0:
			ec.fail("incomplete", "no decision row for the declared evaluation")
		case len(rs) > 1:
			ec.fail("malformed", fmt.Sprintf("%d rows for one declared evaluation", len(rs)))
		}
		var r *Row
		if ec.status == "" {
			r = rs[0]
			ec.row = r
			switch {
			case r.Fixture != e.Fixture || r.Policy != e.Policy:
				ec.fail("malformed", "row fixture/policy disagree with the declared inventory")
			case r.RequestID != e.RequestID:
				ec.fail("malformed", fmt.Sprintf("row request %q, inventory declares %q", r.RequestID, e.RequestID))
			case r.Contract != e.Contract:
				ec.fail("malformed", fmt.Sprintf("row contract %q, inventory declares %q", r.Contract, e.Contract))
			case r.ExpectedImageID != e.ExpectedImageID:
				ec.fail("malformed", "row expected image id differs from the declared trust anchor; rows cannot choose the image id")
			case !legacy && r.LedgerID != e.LedgerID:
				ec.fail("malformed", fmt.Sprintf("row ledger %q, inventory declares %q", r.LedgerID, e.LedgerID))
			}
		}
		var req *Request
		if ec.status == "" {
			req = requests[e.RequestID]
			if req == nil {
				ec.fail("incomplete", "no trusted request record for "+e.RequestID)
			} else if req.Contract != Contract(e.Contract) || req.PinnedVersion != e.PinnedVersion {
				ec.fail("malformed", "request record disagrees with the declared contract/version")
			}
		}
		// receipt binding
		var vr verifyResult
		var jr oracleJournal
		if ec.status == "" {
			switch {
			case r.ReceiptSHA256 == "" && r.ProofValid:
				ec.fail("malformed", "row claims a verified proof without a receipt hash")
			case r.ReceiptSHA256 == "":
				or.ReceiptStatus = "none"
				ok := false
				for _, ev := range resultEvents[e.RequestID] {
					if str(ev.Fields["receipt_sha256"]) == "" {
						ok = true
					}
				}
				if !ok {
					ec.fail("incomplete", "no receipt hash and no recorded delivery failure for the request")
				}
			default:
				if !isHex64(r.ReceiptSHA256) {
					ec.fail("malformed", "receipt hash is not 64 hex characters")
					break
				}
				p := filepath.Join(o.Run, "receipts", r.ReceiptSHA256+".bin")
				st, err := os.Stat(p)
				if err != nil {
					ec.fail("incomplete", "receipt bytes "+r.ReceiptSHA256[:12]+"… are not retained")
					break
				}
				if st.Size() == 0 || st.Size() > MaxReceiptBytes {
					ec.fail("malformed", fmt.Sprintf("retained receipt size %d out of bounds", st.Size()))
					break
				}
				raw, _ := os.ReadFile(p)
				s := sha256.Sum256(raw)
				if hex.EncodeToString(s[:]) != r.ReceiptSHA256 {
					ec.fail("malformed", "retained bytes do not hash to their content address "+r.ReceiptSHA256[:12]+"…")
					break
				}
				if !verifierOK {
					ec.fail("incomplete", "verifier unavailable")
					break
				}
				vr = verify(r.ReceiptSHA256, raw, e.ExpectedImageID)
				if vr.err != nil {
					ec.fail("incomplete", "verifier could not run: "+vr.err.Error())
					break
				}
				if vr.verified {
					or.ReceiptStatus = "verified"
				} else {
					or.ReceiptStatus = "rejected"
				}
				if vr.verified != r.ProofValid {
					ec.fail("evidence_mismatch", fmt.Sprintf("pinned verifier says verified=%v (%s %s) but the row records proof_valid=%v", vr.verified, vr.kind, vr.msg, r.ProofValid))
					break
				}
				if vr.verified && vr.journal != r.VerifiedJournal {
					ec.fail("evidence_mismatch", "the verified journal of the retained receipt differs from the journal recorded in the row")
					break
				}
				if vr.verified {
					jb, err := hex.DecodeString(vr.journal)
					if err == nil {
						jr, err = oracleParseJournal(jb)
					}
					if err != nil {
						ec.fail("malformed", "verified journal not decodable: "+err.Error())
					}
				}
			}
		}
		// decision marker
		if ec.status == "" {
			ms := markersByEval[e.EvaluationID]
			expectMarker := !legacy || r.ProofValid
			switch {
			case expectMarker && len(ms) == 0:
				ec.fail("incomplete", "no zk_decision marker for the evaluation")
			case len(ms) > 1:
				ec.fail("malformed", fmt.Sprintf("%d zk_decision markers for one evaluation", len(ms)))
			case len(ms) == 1:
				m := ms[0]
				ec.markerSeq = m.Seq
				switch {
				case str(m.Fields["request_id"]) != e.RequestID || str(m.Fields["policy"]) != e.Policy || str(m.Fields["contract"]) != e.Contract:
					ec.fail("malformed", "marker request/policy/contract disagree with the declared evaluation")
				case !legacy && (str(m.Fields["ledger_id"]) != e.LedgerID || r.DecisionSeq != m.Seq):
					ec.fail("malformed", fmt.Sprintf("marker ledger/seq (%s, %d) disagree with the row (%s, %d)", str(m.Fields["ledger_id"]), m.Seq, r.LedgerID, r.DecisionSeq))
				case !legacy && m.Fields["proof_valid"] != nil && m.Fields["proof_valid"] != r.ProofValid:
					ec.fail("malformed", "marker proof_valid disagrees with the row")
				case m.Seq <= lastMarkerSeq:
					ec.fail("malformed", fmt.Sprintf("marker seq %d is not after the previous evaluation's marker %d: event order contradicts the declared ordinal order", m.Seq, lastMarkerSeq))
				}
				if ec.status == "" {
					lastMarkerSeq = m.Seq
				}
			}
		}
		// semantics
		var sem, correct, ctxOK, inputOK, passRecomputed bool
		var jv, headV uint32
		if ec.status == "" && r.ProofValid {
			for v, c := range commitByVersion {
				if bytes.Equal(c[:], jr.commitment[:]) {
					jv = v
				}
			}
			if jv == 0 {
				ec.fail("incomplete", "journal commitment matches no fixture opening; the oracle cannot recompute the result")
			} else {
				passRecomputed = passByVersion[jv]
				if passRecomputed != jr.pass {
					ec.fail("violation", fmt.Sprintf("verified journal pass=%v but the recomputed sum of opening v%d gives %v", jr.pass, jv, passRecomputed))
				}
			}
		}
		if ec.status == "" && r.ProofValid {
			var chal [16]byte
			cb, _ := hex.DecodeString(req.ChallengeHex)
			copy(chal[:], cb)
			ctxOK = jr.challenge == chal
			headV = headBefore[ec.markerSeq]
			authorized := e.PinnedVersion
			if Contract(e.Contract) == Current {
				authorized = headV
			}
			inputOK = jv == authorized
			correct = passRecomputed && ctxOK && inputOK
			switch e.Policy {
			case PolicyV0:
				sem = passRecomputed
			case PolicyVT:
				sem = passRecomputed && ctxOK
			case PolicyVI:
				sem = passRecomputed && inputOK
			case PolicyVTI:
				sem = passRecomputed && ctxOK && inputOK
			}
		}
		// ledger reconciliation
		var prior, observed bool
		if ec.status == "" {
			hist := ledgerHistory[e.LedgerID]
			for _, h := range hist {
				if h.request == e.RequestID && h.eval != e.EvaluationID && h.seq < ec.markerSeq {
					prior = true
				}
			}
			evs := approvalsByEval[e.EvaluationID]
			switch {
			case len(evs) > 1:
				ec.fail("violation", fmt.Sprintf("%d approval_inserted events for one evaluation", len(evs)))
			case len(evs) == 1:
				a := evs[0]
				observed = true
				f := a.Fields
				switch {
				case ec.markerSeq == 0 || a.Seq != ec.markerSeq+1:
					ec.fail("violation", fmt.Sprintf("approval event seq %d is not immediately after the decision marker %d", a.Seq, ec.markerSeq))
				case str(f["request_id"]) != e.RequestID || str(f["policy"]) != e.Policy:
					ec.fail("violation", "approval event request/policy differ from the evaluation")
				case !legacy && str(f["ledger_id"]) != e.LedgerID:
					ec.fail("violation", "approval event ledger differs from the declared ledger")
				case str(f["receipt_sha256"]) != r.ReceiptSHA256:
					ec.fail("violation", "approval event receipt hash differs from the scored receipt")
				case r.ProofValid && str(f["commitment_hex"]) != hex.EncodeToString(jr.commitment[:]):
					ec.fail("violation", "approval event commitment differs from the verified journal")
				case uint32(toInt(f["head_version"])) != headV:
					ec.fail("violation", fmt.Sprintf("approval event head_version %d, ordered events give v%d", toInt(f["head_version"]), headV))
				case !legacy && r.ApprovalSeq != a.Seq:
					ec.fail("malformed", "row approval_seq differs from the insert event")
				case !r.ApprovalInserted:
					ec.fail("violation", "approval_inserted event exists but the row records no insertion")
				case prior:
					ec.fail("violation", "approval inserted although the ledger already held an approval for this request (single-use rule broken)")
				}
			default:
				if r.ApprovalInserted {
					ec.fail("incomplete", "row claims an inserted approval but no approval_inserted event is attributed to the evaluation")
				}
			}
		}
		if ec.status == "" {
			// ledger count after this evaluation, reconstructed from events, vs the row
			count := 0
			for _, h := range ledgerHistory[e.LedgerID] {
				if h.seq <= ec.markerSeq+1 {
					count++
				}
			}
			switch {
			case r.ApprovalCount > count:
				ec.fail("incomplete", fmt.Sprintf("row records approval_count_after=%d but the events support only %d insertions in ledger %s", r.ApprovalCount, count, e.LedgerID))
			case r.ApprovalCount < count:
				ec.fail("violation", fmt.Sprintf("events show %d insertions in ledger %s but the row records approval_count_after=%d", count, e.LedgerID, r.ApprovalCount))
			}
		}
		// outcome
		if ec.status == "" {
			expected := sem && !prior
			or.CorrectApprove, or.PolicyShouldApprove, or.PriorApproval, or.ExpectedInsert, or.ObservedInsert = correct, sem, prior, expected, observed
			if observed == expected {
				ec.status = "agree"
			} else {
				ec.status, ec.detail = "disagree", fmt.Sprintf("policy semantics expect insert=%v (semantics approve=%v, prior approval=%v) but observed insert=%v", expected, sem, prior, observed)
			}
			or.AttackSuccess = observed && sem && !correct
			if or.AttackSuccess {
				sum.AttackSuccesses++
				sum.AttackSuccessList = append(sum.AttackSuccessList, e.EvaluationID)
			}
			if r.ProofValid {
				or.WrongContext = passRecomputed && !ctxOK && observed
				or.Unsafe = passRecomputed && !inputOK && observed
				or.DeniedLegit = correct && !prior && !observed
				if passRecomputed && !ctxOK {
					wcD++
					if observed {
						wcN++
					}
				}
				if passRecomputed && !inputOK {
					unD++
					if observed {
						unN++
					}
				}
				if correct && !prior {
					dlD++
					if !observed {
						dlN++
					}
				}
				if ec.detail == "" {
					ec.detail = fmt.Sprintf("journal=v%d recomputed_pass=%v ctx=%v head=v%d input=%v prior_approval=%v", jv, passRecomputed, ctxOK, headV, inputOK, prior)
				}
			} else if ec.detail == "" {
				ec.detail = "receipt rejected by the pinned verifier (or none delivered); deny is the only correct decision"
			}
		}
		or.Status, or.Detail = ec.status, ec.detail
		switch ec.status {
		case "agree":
			sum.Scored++
			sum.Agree++
		case "disagree":
			sum.Scored++
			sum.Disagree++
		case "violation":
			sum.Violations++
		case "evidence_mismatch":
			sum.EvidenceMismatch++
		case "incomplete":
			sum.Incomplete++
		case "malformed":
			sum.Malformed++
		}
		out = append(out, or)
	}
	// orphan approvals (not attributed to any declared evaluation)
	for _, a := range approvals {
		if !eventsBroken && !attributedApprovals[a] {
			runErr("violation", "orphan approval_inserted event seq %d (request %s, policy %s) is attributed to no declared evaluation", a.Seq, str(a.Fields["request_id"]), str(a.Fields["policy"]))
		}
	}
	// ledgers.json (schema 2): final state must equal the reconstruction
	if !legacy && !eventsBroken {
		lb, err := os.ReadFile(filepath.Join(o.Run, "ledgers.json"))
		if err != nil {
			runErr("incomplete", "ledgers.json missing")
		} else {
			var doc struct {
				Ledgers map[string][]Approval `json:"ledgers"`
			}
			if json.Unmarshal(lb, &doc) != nil {
				runErr("malformed", "ledgers.json unparseable")
			} else {
				for id, aps := range doc.Ledgers {
					if !strings.Contains(id, "/") {
						runErr("malformed", "ledgers.json has an undeclared ledger id %q", id)
					}
					hist := ledgerHistory[id]
					if len(aps) > len(hist) {
						runErr("incomplete", "ledgers.json records %d approvals for %s but the events support only %d", len(aps), id, len(hist))
						continue
					}
					if len(aps) < len(hist) {
						runErr("violation", "events show %d insertions in ledger %s but ledgers.json records %d", len(hist), id, len(aps))
						continue
					}
					for i := range aps {
						if aps[i].RequestID != hist[i].request || aps[i].Receipt != hist[i].receipt || aps[i].EvaluationID != hist[i].eval || aps[i].Seq != hist[i].seq {
							runErr("violation", "ledgers.json entry %d of %s differs from the reconstructed approval", i, id)
						}
					}
				}
				for id := range ledgerHistory {
					if _, ok := doc.Ledgers[id]; !ok && len(ledgerHistory[id]) > 0 {
						runErr("violation", "events show approvals in ledger %s that ledgers.json does not record", id)
					}
				}
			}
		}
	}
	sum.WrongContext = fmt.Sprintf("%d/%d", wcN, wcD)
	sum.UnsafeApprovals = fmt.Sprintf("%d/%d", unN, unD)
	sum.DeniedLegitimate = fmt.Sprintf("%d/%d", dlN, dlD)
	return finish(out)
}

func isHex64(s string) bool { return imageIDRe.MatchString(s) }

func str(v any) string {
	if v == nil {
		return ""
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

// loadRowsStrict reads decisions.jsonl: every line must be a JSON object; scanner
// errors and malformed/null lines are reported, never skipped silently.
func loadRowsStrict(path string) ([]Row, []string) {
	var errs []string
	f, err := os.Open(path)
	if err != nil {
		return nil, []string{err.Error()}
	}
	defer f.Close()
	var rows []Row
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var probe any
		if json.Unmarshal(line, &probe) != nil {
			errs = append(errs, fmt.Sprintf("decisions.jsonl line %d is not JSON", n))
			continue
		}
		if _, ok := probe.(map[string]any); !ok {
			errs = append(errs, fmt.Sprintf("decisions.jsonl line %d is not an object", n))
			continue
		}
		var r Row
		if err := json.Unmarshal(line, &r); err != nil {
			errs = append(errs, fmt.Sprintf("decisions.jsonl line %d: %v", n, err))
			continue
		}
		if !KnownPolicy(r.Policy) {
			errs = append(errs, fmt.Sprintf("decisions.jsonl line %d: unknown policy %q", n, r.Policy))
			continue
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, "decisions.jsonl: "+err.Error())
	}
	return rows, errs
}

// loadRequestsStrict reads requests.json: non-null records, unique ids, 32-hex
// challenges, known contracts, pinned version ≥ 1.
func loadRequestsStrict(path string) (map[string]*Request, []string) {
	var errs []string
	out := map[string]*Request{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out, []string{err.Error()}
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return out, []string{"requests.json: " + err.Error()}
	}
	for i, m := range raw {
		if bytes.Equal(bytes.TrimSpace(m), []byte("null")) {
			errs = append(errs, fmt.Sprintf("requests.json entry %d is null", i))
			continue
		}
		var r Request
		if err := json.Unmarshal(m, &r); err != nil {
			errs = append(errs, fmt.Sprintf("requests.json entry %d: %v", i, err))
			continue
		}
		cb, err := hex.DecodeString(r.ChallengeHex)
		switch {
		case r.ID == "":
			errs = append(errs, fmt.Sprintf("requests.json entry %d has no id", i))
			continue
		case err != nil || len(cb) != 16:
			errs = append(errs, fmt.Sprintf("requests.json %s: challenge is not 16 bytes of hex", r.ID))
			continue
		case r.Contract != Pinned && r.Contract != Current:
			errs = append(errs, fmt.Sprintf("requests.json %s: unknown contract %q", r.ID, r.Contract))
			continue
		case r.PinnedVersion == 0:
			errs = append(errs, fmt.Sprintf("requests.json %s: pinned version 0", r.ID))
			continue
		}
		if _, dup := out[r.ID]; dup {
			errs = append(errs, fmt.Sprintf("requests.json duplicates request id %s", r.ID))
			continue
		}
		copy(r.Challenge[:], cb)
		out[r.ID] = &r
	}
	return out, errs
}

// loadEventsStrict reads events.jsonl: JSON objects with known kinds and positive,
// strictly increasing, gap-free sequence numbers; a truncated or malformed line is
// an error, never the end of a complete stream.
func loadEventsStrict(path string) ([]Event, []string) {
	var errs []string
	f, err := os.Open(path)
	if err != nil {
		return nil, []string{err.Error()}
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	n, last := 0, 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil || e.Kind == "" {
			errs = append(errs, fmt.Sprintf("events.jsonl line %d malformed", n))
			continue
		}
		if !knownEventKinds[e.Kind] {
			errs = append(errs, fmt.Sprintf("events.jsonl line %d: unknown kind %q", n, e.Kind))
			continue
		}
		if e.Seq != last+1 { // reported once per anomaly; the stream is then unusable (eventsBroken)
			errs = append(errs, fmt.Sprintf("events.jsonl line %d: seq %d after %d (nonpositive, duplicate, gap or out of order)", n, e.Seq, last))
		}
		last = e.Seq
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, "events.jsonl: "+err.Error())
	}
	return out, errs
}

func writeOracle(dir string, sum *OracleSummary, rows []OracleRow) {
	os.MkdirAll(dir, 0o755)
	jf, _ := os.Create(filepath.Join(dir, "oracle.jsonl"))
	for _, r := range rows {
		b, _ := json.Marshal(r)
		jf.Write(append(b, '\n'))
	}
	jf.Close()
	sb, _ := json.MarshalIndent(sum, "", "  ")
	os.WriteFile(filepath.Join(dir, "oracle-summary.json"), sb, 0o644)
	var md strings.Builder
	fmt.Fprintf(&md, "# Offline business-decision oracle v2 for %s\n\nMode: %s · declared %d · rows read %d · scored %d (agree %d, disagree %d) · violations %d · evidence mismatches %d · incomplete %d · malformed %d · expected weak-policy attack successes %d · **exit %d**\n\n", sum.RunDir, sum.Mode, sum.Expected, sum.Rows, sum.Scored, sum.Agree, sum.Disagree, sum.Violations, sum.EvidenceMismatch, sum.Incomplete, sum.Malformed, sum.AttackSuccesses, sum.ExitCode)
	fmt.Fprintf(&md, "* Wrong-context receipts accepted: %s\n* Unsafe approvals (input not authorized under the contract at the decision point): %s\n* Legitimate approvals denied: %s\n* Expected attack successes (deliberately incomplete policies): %s\n* Verifier: %s sha256 %s (matches run provenance: %v); %d unique receipt/image pairs re-verified, %d verified, %d rejected, %d failures. %s\n* %s\n", sum.WrongContext, sum.UnsafeApprovals, sum.DeniedLegitimate, strings.Join(sum.AttackSuccessList, ", "), sum.Verifier.Bin, sum.Verifier.SHA256, sum.Verifier.MatchesProvenance, sum.Verifier.UniquePairs, sum.Verifier.Verified, sum.Verifier.Rejected, sum.Verifier.Failures, sum.Verifier.TrustSource, sum.Arithmetic)
	if len(sum.RunErrors) > 0 {
		md.WriteString("\nRun-level findings:\n")
		for _, e := range sum.RunErrors {
			fmt.Fprintf(&md, "* %s\n", e)
		}
	}
	if len(sum.Limitations) > 0 {
		md.WriteString("\nLimitations of this view:\n")
		for _, e := range sum.Limitations {
			fmt.Fprintf(&md, "* %s\n", e)
		}
	}
	md.WriteString("\n| evaluation | status | receipt | correct | semantics | prior approval | expected insert | observed insert | attack success | detail |\n|---|---|---|---|---|---|---|---|---|---|\n")
	sorted := append([]OracleRow(nil), rows...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Fixture < sorted[j].Fixture })
	for _, r := range sorted {
		fmt.Fprintf(&md, "| %s | %s | %s | %v | %v | %v | %v | %v | %v | %s |\n", r.EvaluationID, r.Status, r.ReceiptStatus, r.CorrectApprove, r.PolicyShouldApprove, r.PriorApproval, r.ExpectedInsert, r.ObservedInsert, r.AttackSuccess, r.Detail)
	}
	fmt.Fprintf(&md, "\n%s\n", sum.Note)
	os.WriteFile(filepath.Join(dir, "oracle.md"), []byte(md.String()), 0o644)
}
