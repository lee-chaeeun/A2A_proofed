package zk

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"a2aid/internal/matrix"
	"a2aid/internal/registry"
)

// Options for one ZK matrix run.
type Options struct {
	RunDir      string // identity lab run dir (run/), provisioned by scripts/setup.sh
	Out         string // results/zk
	ZKDir       string // zk/ (Rust workspace; binaries under target/release)
	Fixtures    string // fixtures/zk
	Predictions string // fixtures/zk/predictions.json
	Bin         string // a2aid binary for lab processes
}

// Row is one fixture × policy result (producer evidence schema 2).
type Row struct {
	EvidenceSchema   int    `json:"evidence_schema"`
	EvaluationID     string `json:"evaluation_id"`
	Ordinal          int    `json:"ordinal"`
	Fixture          string `json:"fixture"`
	Policy           string `json:"policy"`
	RequestID        string `json:"request_id"`
	TaskID           string `json:"a2a_task_id"`
	Contract         string `json:"contract"`
	LedgerID         string `json:"ledger_id"`
	ExpectedImageID  string `json:"expected_image_id_hex"`
	ReceiptSHA256    string `json:"receipt_sha256"`
	VerifiedJournal  string `json:"verified_journal_hex"`
	ProofValid       bool   `json:"proof_valid"`
	ResultPass       bool   `json:"result_pass"`
	ContextMatch     bool   `json:"context_match"`
	InputAuthorized  bool   `json:"input_authorized"`
	AuthorityVersion uint32 `json:"authority_version_at_decision"`
	DecisionSeq      int    `json:"decision_seq"`
	ApprovalSeq      int    `json:"approval_seq"`
	ExpectedApprove  bool   `json:"expected_approve"`
	ApprovalInserted bool   `json:"approval_inserted"`
	ApprovalCount    int    `json:"approval_count_after"`
	Match            bool   `json:"match"`
	Reason           string `json:"reason"`
	Note             string `json:"note,omitempty"`
}

type predictions struct {
	FrozenAt string `json:"frozen_at"`
	Fixtures map[string]struct {
		Title       string          `json:"title"`
		Approve     map[string]bool `json:"approve"`
		VerifyFails bool            `json:"verify_fails"`
	} `json:"fixtures"`
}

// LoadPredictions reads the frozen predictions file.
func LoadPredictions(path string) (predictions, []byte, error) {
	var pred predictions
	pb, err := os.ReadFile(path)
	if err != nil {
		return pred, nil, err
	}
	if err := json.Unmarshal(pb, &pred); err != nil {
		return pred, nil, fmt.Errorf("predictions: %w", err)
	}
	return pred, pb, nil
}

// Run executes the fixed ZK fixture matrix against a live lab (A is the worker).
// The inventory of expected evaluations is written BEFORE the lab boots.
func Run(o Options) (string, error) {
	t0 := time.Now()
	runID := t0.UTC().Format("20060102-150405")
	out := filepath.Join(o.Out, runID)
	os.MkdirAll(filepath.Join(out, "receipts"), 0o755)
	logf, _ := os.Create(filepath.Join(out, "run.log"))
	defer logf.Close()
	log := func(f string, a ...any) {
		line := fmt.Sprintf(time.Now().Format("15:04:05.000")+" "+f+"\n", a...)
		fmt.Print(line)
		logf.WriteString(line)
	}
	pred, pb, err := LoadPredictions(o.Predictions)
	if err != nil {
		return "", err
	}
	os.WriteFile(filepath.Join(out, "predictions-frozen.json"), pb, 0o644)
	abs, _ := filepath.Abs(o.RunDir)
	reg, err := registry.Load(filepath.Join(abs, "registry.json"))
	if err != nil {
		return "", fmt.Errorf("registry: %w (run scripts/setup.sh first)", err)
	}
	zkAbs, _ := filepath.Abs(o.ZKDir)
	fxAbs, _ := filepath.Abs(o.Fixtures)
	bins := map[string]string{"prove": filepath.Join(zkAbs, "target", "release", "zkprove"), "verify": filepath.Join(zkAbs, "target", "release", "zkverify"), "fake": filepath.Join(zkAbs, "target", "release", "zkfake")}
	for k, p := range bins {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("%s binary missing at %s (build zk/ first)", k, p)
		}
	}
	imageID, err := os.ReadFile(filepath.Join(zkAbs, "image-id.txt"))
	if err != nil {
		return "", fmt.Errorf("pinned image id (zk/image-id.txt) missing: %w", err)
	}
	pinnedImage := strings.TrimSpace(string(imageID))
	auth, err := LoadAuthority(filepath.Join(fxAbs, "authority.json"))
	if err != nil {
		return "", err
	}
	// Inventory first: the declared evaluations, before any lab process exists.
	inv, err := BuildInventory("run", runID, pinnedImage, pred)
	if err != nil {
		return "", err
	}
	if err := WriteInventory(filepath.Join(out, "run-inventory.json"), inv); err != nil {
		return "", err
	}
	log("inventory declared: %d evaluations (%d fixtures × %d policies) in %s", len(inv.Evaluations), len(inv.Fixtures), len(inv.Policies), filepath.Join(out, "run-inventory.json"))
	provenance(out, o, zkAbs, pinnedImage, bins)
	invByID := map[string]InventoryEntry{}
	for _, e := range inv.Evaluations {
		invByID[e.EvaluationID] = e
	}

	// Lab: controller, gate, agents (A is the honest worker; its ZK behaviour is set per fixture).
	rt := &matrix.Runtime{RunDir: o.RunDir, AbsRun: abs, OutDir: out, Bin: o.Bin, Reg: reg, HTTP: httpClient(), Started: t0, Log: logf}
	rt.Boot()
	defer rt.Shutdown()
	cacheDir := filepath.Join(zkAbs, "proof-cache")
	os.MkdirAll(cacheDir, 0o755)
	baseZK := map[string]any{"openings_path": filepath.Join(fxAbs, "openings.json"), "prover_bin": bins["prove"], "fake_bin": bins["fake"], "cache_dir": cacheDir}
	setWorker := func(extra map[string]any) {
		z := map[string]any{}
		for k, v := range baseZK {
			z[k] = v
		}
		for k, v := range extra {
			z[k] = v
		}
		rt.SetMode(matrix.AAdmin, map[string]any{"mode": "honest", "zk": z})
	}
	cacheBefore := countCacheFiles(cacheDir)

	trace, _ := os.Create(filepath.Join(out, "exchanges.jsonl"))
	defer trace.Close()
	req := &Requester{Reg: reg, RootCAs: rt.RootCAs, Resolver: matrix.DefaultResolver, Bridge: &Bridge{VerifyBin: bins["verify"], Timeout: 5 * time.Minute}, ImageIDHex: pinnedImage, Auth: auth, Trace: trace}
	ctx := context.Background()
	const endpoint = matrix.ATLSURL
	const portfolio = "desk-1/portfolio-7"

	var rows []Row
	var reqLog []*Request
	ledgersByID := map[string]*Ledger{}
	stats := struct{ exchanges, delivered, cacheHits, newProofs, replayed, fake, transportRejected int }{}
	saveReceipt := func(b []byte) string {
		if b == nil {
			return ""
		}
		s := sha256.Sum256(b)
		h := hex.EncodeToString(s[:])
		os.WriteFile(filepath.Join(out, "receipts", h+".bin"), b, 0o644)
		return h
	}
	ordinal := 0
	judge := func(fx string, r *Request, receipt []byte, ledgers map[string]*Ledger, imageID string, note string) []Decision {
		_, _, ds := req.Judge(ctx, fx, r, receipt, ledgers, imageID)
		p := pred.Fixtures[fx]
		for _, d := range ds {
			ordinal++
			e, declared := invByID[d.EvaluationID]
			if !declared || e.Ordinal != ordinal || e.LedgerID != d.LedgerID || e.RequestID != r.ID || e.ExpectedImageID != imageID {
				log("WARNING: evaluation %s deviates from the declared inventory (declared=%v ordinal %d/%d ledger %s/%s image match %v)", d.EvaluationID, declared, e.Ordinal, ordinal, e.LedgerID, d.LedgerID, e.ExpectedImageID == imageID)
			}
			row := Row{EvidenceSchema: EvidenceSchema, EvaluationID: d.EvaluationID, Ordinal: ordinal, Fixture: fx, Policy: d.Policy, RequestID: r.ID, TaskID: r.TaskID, Contract: string(r.Contract), LedgerID: d.LedgerID, ExpectedImageID: d.ExpectedImageID, ReceiptSHA256: d.ReceiptSHA256, VerifiedJournal: d.JournalHex,
				ProofValid: d.ProofValid, ResultPass: d.ResultPass, ContextMatch: d.ContextMatch, InputAuthorized: d.InputAuthorized, AuthorityVersion: d.AuthorityVersion, DecisionSeq: d.DecisionSeq, ApprovalSeq: d.ApprovalSeq,
				ExpectedApprove: p.Approve[d.Policy], ApprovalInserted: d.ApprovalInserted, ApprovalCount: ledgers[d.Policy].Count(), Reason: d.Reason, Note: note}
			row.Match = row.ExpectedApprove == row.ApprovalInserted && (!p.VerifyFails || !d.ProofValid)
			rows = append(rows, row)
			log("%-4s %-3s approve=%v expected=%v valid=%v pass=%v ctx=%v input=%v head=v%d seq=%d %s", fx, d.Policy, d.ApprovalInserted, row.ExpectedApprove, d.ProofValid, d.ResultPass, d.ContextMatch, d.InputAuthorized, d.AuthorityVersion, d.DecisionSeq, d.Reason)
		}
		return ds
	}
	newLedgers := func(group string) map[string]*Ledger {
		m := map[string]*Ledger{}
		for _, p := range Policies {
			l := NewLedgerID(group + "/" + p)
			m[p] = l
			ledgersByID[l.ID] = l
		}
		return m
	}
	dispatch := func(r *Request) ([]byte, error) {
		reqLog = append(reqLog, r)
		stats.exchanges++
		auth.Record("zk_dispatch", map[string]any{"request_id": r.ID, "contract": string(r.Contract), "version": r.PinnedVersion, "challenge_hex": r.ChallengeHex})
		ex, raw, err := req.Dispatch(ctx, endpoint, r)
		switch {
		case ex != nil && !ex.Transport.Accept:
			stats.transportRejected++
		case ex != nil && ex.Result.Cached:
			stats.cacheHits++
		case ex != nil && ex.Result.ProveMS > 0:
			stats.newProofs++
		}
		auth.Record("zk_result_received", map[string]any{"request_id": r.ID, "a2a_task_id": r.TaskID, "receipt_sha256": saveReceipt(raw), "task_sent": ex != nil && ex.TaskSent, "transport_accept": ex != nil && ex.Transport.Accept, "err": errStr(err)})
		if raw != nil {
			stats.delivered++
		}
		return raw, err
	}

	// ---- Z1 honest Pinned v1 ---------------------------------------------------
	auth.Reset()
	setWorker(nil)
	r1 := NewRequest("Z1", portfolio, Pinned, 1, "A")
	rc1, err := dispatch(r1)
	if err != nil {
		log("Z1 dispatch error: %v", err)
	}
	led1 := newLedgers("Z1")
	judge("Z1", r1, rc1, led1, pinnedImage, "")
	// ---- Z11 duplicate: deliver the SAME accepted result again (shared ledgers) -----
	judge("Z11", r1, rc1, led1, pinnedImage, "second delivery of Z1's result into Z1's ledgers")
	// ---- Z9a corrupted genuine receipt (requester-side view of Z1's bytes) -----------
	var bad []byte
	if rc1 != nil {
		bad = append([]byte(nil), rc1...)
		bad[len(bad)/2] ^= 0x01
		saveReceipt(bad)
	}
	judge("Z9a", r1, bad, newLedgers("Z9a"), pinnedImage, "one byte flipped in Z1's genuine receipt")
	// ---- Z9b wrong expected image id (requester misconfiguration) --------------------
	judge("Z9b", r1, rc1, newLedgers("Z9b"), WrongImageID(pinnedImage), "requester pinned a different image id")

	// ---- Z2 honest Current at v2 (above limit) -----------------------------------
	auth.Reset()
	auth.Advance()
	setWorker(nil)
	r2 := NewRequest("Z2", portfolio, Current, 2, "A")
	rc2, _ := dispatch(r2)
	judge("Z2", r2, rc2, newLedgers("Z2"), pinnedImage, "")

	// ---- Z3 substituted receipt: A's receipt delivered for B's request -----------
	auth.Reset()
	setWorker(map[string]any{"replay_receipt_b64": base64.StdEncoding.EncodeToString(rc1)})
	rB := NewRequest("Z3-B", portfolio, Pinned, 1, "A")
	rc3, _ := dispatch(rB)
	stats.replayed++
	judge("Z3", rB, rc3, newLedgers("Z3"), pinnedImage, "worker replayed Z1's genuine receipt (same authorized input v1)")
	// ---- Z3P positive control: B gets its own correctly bound proof ---------------
	setWorker(nil)
	rBp := NewRequest("Z3P-B", portfolio, Pinned, 1, "A")
	rc3p, _ := dispatch(rBp)
	judge("Z3P", rBp, rc3p, newLedgers("Z3P"), pinnedImage, "")

	// ---- Z4 stale input, new challenge, Current at v2 ------------------------------
	auth.Reset()
	auth.Advance()
	setWorker(map[string]any{"witness_version": 1})
	r4 := NewRequest("Z4", portfolio, Current, 2, "A")
	rc4, _ := dispatch(r4)
	judge("Z4", r4, rc4, newLedgers("Z4"), pinnedImage, "REAL proof over the obsolete v1 opening with Z4's challenge")
	// ---- Z5 wrong challenge AND stale input under Current ---------------------------
	setWorker(map[string]any{"witness_version": 1, "wrong_challenge": true})
	r5 := NewRequest("Z5", portfolio, Current, 2, "A")
	rc5, _ := dispatch(r5)
	judge("Z5", r5, rc5, newLedgers("Z5"), pinnedImage, "")

	// ---- Z6 delayed Pinned(v1) result, authority moves to v2 before the decision ------
	auth.Reset()
	setWorker(nil)
	r6 := NewRequest("Z6", portfolio, Pinned, 1, "A")
	rc6, _ := dispatch(r6)
	auth.Advance()
	judge("Z6", r6, rc6, newLedgers("Z6"), pinnedImage, "authority_update happened after receipt, before the approval decision")
	// ---- Z7 identical bytes + challenge, isolated Current contract at v2 ---------------
	r7 := &Request{ID: "Z7", Challenge: r6.Challenge, ChallengeHex: r6.ChallengeHex, Portfolio: portfolio, Contract: Current, PinnedVersion: 1, ExpectedWorker: "A", TaskID: r6.TaskID}
	reqLog = append(reqLog, r7)
	auth.Record("zk_reuse", map[string]any{"request_id": "Z7", "reuses_request": "Z6", "receipt_sha256": hexSum(rc6), "note": "controlled comparison: same bytes and challenge, different stored contract"})
	judge("Z7", r7, rc6, newLedgers("Z7"), pinnedImage, "same receipt bytes and challenge as Z6 (hash recorded), Current contract")

	// ---- Z8 genuine failing journal, outer metadata claims pass ----------------------
	auth.Reset()
	auth.Advance()
	setWorker(map[string]any{"claim_pass": true})
	r8 := NewRequest("Z8", portfolio, Current, 2, "A")
	rc8, _ := dispatch(r8)
	judge("Z8", r8, rc8, newLedgers("Z8"), pinnedImage, "")

	// ---- Z10 fake/dev receipt through the production verifier ----------------------
	auth.Reset()
	setWorker(map[string]any{"fake": true})
	r10 := NewRequest("Z10", portfolio, Pinned, 1, "A")
	rc10, _ := dispatch(r10)
	stats.fake++
	judge("Z10", r10, rc10, newLedgers("Z10"), pinnedImage, "worker used the test-only dev-mode tool")
	setWorker(nil)

	// ---- outputs -------------------------------------------------------------------
	writeRows(out, rows)
	wj, _ := json.MarshalIndent(reqLog, "", " ")
	os.WriteFile(filepath.Join(out, "requests.json"), wj, 0o644)
	ef, _ := os.Create(filepath.Join(out, "events.jsonl"))
	for _, e := range auth.Events {
		b, _ := json.Marshal(e)
		ef.Write(append(b, '\n'))
	}
	ef.Close()
	ledgerDump := map[string][]Approval{}
	for id, l := range ledgersByID {
		ledgerDump[id] = l.Approvals()
	}
	lb, _ := json.MarshalIndent(map[string]any{"ledger_schema": 1, "note": "final approvals per isolated ledger (id = <ledger group>/<policy>); Z1 and Z11 share group Z1", "ledgers": ledgerDump}, "", " ")
	os.WriteFile(filepath.Join(out, "ledgers.json"), lb, 0o644)
	newCacheFiles := countCacheFiles(cacheDir) - cacheBefore
	// stats.newProofs counts worker-reported fresh proofs (excluding replay/fake); the
	// cache-file delta is the independent on-disk measure of the same quantity.
	stat := map[string]any{"rows": len(rows), "evaluations_declared": len(inv.Evaluations), "a2a_exchanges": stats.exchanges, "results_delivered": stats.delivered, "transport_rejected": stats.transportRejected, "new_proofs_worker_reported": stats.newProofs, "cache_hits_worker_reported": stats.cacheHits, "new_cache_files": newCacheFiles, "replayed_receipts": stats.replayed, "fake_receipts": stats.fake, "wall_seconds": time.Since(t0).Seconds()}
	sb, _ := json.MarshalIndent(stat, "", " ")
	os.WriteFile(filepath.Join(out, "run-stats.json"), sb, 0o644)
	summary := summarize(rows, pred, stat, out)
	os.WriteFile(filepath.Join(out, "summary.md"), []byte(summary), 0o644)
	log("done: %d rows, %d A2A exchanges, %d new proofs (worker-reported), %d cache hits, %d new cache files, outputs in %s", len(rows), stats.exchanges, stats.newProofs, stats.cacheHits, newCacheFiles, out)
	return out, nil
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func hexSum(b []byte) string {
	if b == nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// countCacheFiles counts image-qualified cache entries.
func countCacheFiles(dir string) int {
	n := 0
	filepath.Walk(filepath.Join(dir, CacheVersion), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, ".json") {
			n++
		}
		return nil
	})
	return n
}

func writeRows(out string, rows []Row) {
	jf, _ := os.Create(filepath.Join(out, "decisions.jsonl"))
	for _, r := range rows {
		b, _ := json.Marshal(r)
		jf.Write(append(b, '\n'))
	}
	jf.Close()
	cf, _ := os.Create(filepath.Join(out, "decisions.csv"))
	w := csv.NewWriter(cf)
	w.Write([]string{"evaluation_id", "ordinal", "fixture", "policy", "request_id", "a2a_task_id", "contract", "ledger_id", "expected_image_id_hex", "receipt_sha256", "verified_journal_hex", "proof_valid", "result_pass", "context_match", "input_authorized", "authority_version_at_decision", "decision_seq", "approval_seq", "expected_approve", "approval_inserted", "approval_count_after", "match", "reason", "note"})
	for _, r := range rows {
		w.Write([]string{r.EvaluationID, fmt.Sprint(r.Ordinal), r.Fixture, r.Policy, r.RequestID, r.TaskID, r.Contract, r.LedgerID, r.ExpectedImageID, r.ReceiptSHA256, r.VerifiedJournal, fmt.Sprint(r.ProofValid), fmt.Sprint(r.ResultPass), fmt.Sprint(r.ContextMatch), fmt.Sprint(r.InputAuthorized), fmt.Sprint(r.AuthorityVersion), fmt.Sprint(r.DecisionSeq), fmt.Sprint(r.ApprovalSeq), fmt.Sprint(r.ExpectedApprove), fmt.Sprint(r.ApprovalInserted), fmt.Sprint(r.ApprovalCount), fmt.Sprint(r.Match), r.Reason, r.Note})
	}
	w.Flush()
	cf.Close()
}

func summarize(rows []Row, pred predictions, stat map[string]any, out string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# ZK matrix summary (%s)\n\nRows: %d (fixture × policy; %v declared in run-inventory.json before execution). A2A exchanges: %v (results delivered %v, transport rejections %v). New genuine proofs this run (worker-reported): %v; proof-cache hits: %v; new cache files: %v; replayed receipts: %v; fake receipts: %v. Wall time: %.1fs.\n\n",
		out, len(rows), stat["evaluations_declared"], stat["a2a_exchanges"], stat["results_delivered"], stat["transport_rejected"], stat["new_proofs_worker_reported"], stat["cache_hits_worker_reported"], stat["new_cache_files"], stat["replayed_receipts"], stat["fake_receipts"], stat["wall_seconds"])
	sb.WriteString("| fixture | V0 | VT | VI | VTI | proof valid | pass | notes |\n|---|---|---|---|---|---|---|---|\n")
	order := []string{"Z1", "Z2", "Z3", "Z3P", "Z4", "Z5", "Z6", "Z7", "Z8", "Z9a", "Z9b", "Z10", "Z11"}
	byFx := map[string]map[string]Row{}
	for _, r := range rows {
		if byFx[r.Fixture] == nil {
			byFx[r.Fixture] = map[string]Row{}
		}
		byFx[r.Fixture][r.Policy] = r
	}
	matches, total := 0, 0
	var wrongCtxAccepted, wrongCtxTotal, unsafeApproved, unsafeTotal, deniedLegit, legitTotal int
	for _, fx := range order {
		m := byFx[fx]
		if m == nil {
			continue
		}
		cells := []string{}
		for _, p := range Policies {
			r := m[p]
			total++
			if r.Match {
				matches++
			}
			mark := map[bool]string{true: "✓", false: "–"}[r.ApprovalInserted]
			if !r.Match {
				mark += "†"
			}
			cells = append(cells, mark)
			// metrics (denominators = rows in which the condition holds)
			if r.ProofValid && r.ResultPass && !r.ContextMatch {
				wrongCtxTotal++
				if r.ApprovalInserted {
					wrongCtxAccepted++
				}
			}
			if r.ProofValid && r.ResultPass && !r.InputAuthorized {
				unsafeTotal++
				if r.ApprovalInserted {
					unsafeApproved++
				}
			}
			if fx != "Z11" && r.ProofValid && r.ResultPass && r.ContextMatch && r.InputAuthorized {
				legitTotal++
				if !r.ApprovalInserted {
					deniedLegit++
				}
			}
		}
		any := m["V0"]
		fmt.Fprintf(&sb, "| %s %s | %s | %v | %v | %s |\n", fx, pred.Fixtures[fx].Title, strings.Join(cells, " | "), any.ProofValid, any.ResultPass, any.Note)
	}
	fmt.Fprintf(&sb, "\n✓ approval inserted, – no approval, † differs from the frozen prediction.\n\n")
	fmt.Fprintf(&sb, "* Cells matching the frozen prediction: %d / %d\n", matches, total)
	fmt.Fprintf(&sb, "* Wrong-context receipts accepted (valid, passing, challenge mismatch): %d / %d policy-cells\n", wrongCtxAccepted, wrongCtxTotal)
	fmt.Fprintf(&sb, "* Unsafe approvals (valid, passing, input not the authorized one under the contract): %d / %d policy-cells\n", unsafeApproved, unsafeTotal)
	fmt.Fprintf(&sb, "* Legitimate approvals denied (valid, passing, context and input correct): %d / %d policy-cells\n", deniedLegit, legitTotal)
	sb.WriteString("\nThese are coverage counts over hand-selected fixtures, not prevalence estimates. The 52 cells come from 9 A2A exchanges plus local reuse/modification evaluations (Z7, Z9a, Z9b, Z11); repeated verification is a regression check, not independent proving trials.\n")
	return sb.String()
}

func provenance(out string, o Options, zkAbs, image string, bins map[string]string) {
	prov := map[string]any{"pinned_image_id_hex": image, "zk_dir": zkAbs, "fixtures": o.Fixtures, "predictions": o.Predictions, "started_utc": time.Now().UTC().Format(time.RFC3339Nano), "evidence_schema": EvidenceSchema, "inventory_schema": InventorySchema}
	hashes := map[string]string{}
	filepath.Walk(zkAbs, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && (info.Name() == "target" || info.Name() == "proof-cache") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(zkAbs, p)
		hashes["zk/"+rel] = fileSHA(p)
		return nil
	})
	for _, f := range []string{"internal/zk/commit.go", "internal/zk/policy.go", "internal/zk/authority.go", "internal/zk/bridge.go", "internal/zk/requester.go", "internal/zk/requester_root.go", "internal/zk/matrix.go", "internal/zk/inventory.go", "internal/zk/oracle.go", "internal/zk/oracle_arith.go", "internal/zk/fixtures.go", "internal/agent/zk.go", "internal/wire/wire.go", "internal/verifier/verifier.go", "internal/verifier/transport.go", "go.mod", "go.sum", o.Predictions, filepath.Join(o.Fixtures, "authority.json"), filepath.Join(o.Fixtures, "openings.json")} {
		hashes[f] = fileSHA(f)
	}
	for k, p := range bins {
		hashes["bin:"+k] = fileSHA(p)
	}
	prov["sha256"] = hashes
	prov["a2aid_binary_sha256"] = fileSHA(o.Bin)
	ver := map[string]string{}
	for _, c := range [][]string{{"rustc", "--version"}, {"cargo", "--version"}, {"cargo", "risczero", "--version"}, {"r0vm", "--version"}} {
		b, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		ver[strings.Join(c, " ")] = strings.TrimSpace(string(b)) + errSuffix(err)
	}
	prov["toolchain"] = ver
	b, _ := json.MarshalIndent(prov, "", "  ")
	os.WriteFile(filepath.Join(out, "provenance.json"), b, 0o644)
}

func errSuffix(err error) string {
	if err != nil {
		return " (" + err.Error() + ")"
	}
	return ""
}

func fileSHA(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return "missing"
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
