package discover

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Main is `a2aid discover`. Default: offline mock planner only. Paid paths need
// explicit flags AND satisfiable budget checks; credential presence alone never
// starts anything.
func Main(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	out := fs.String("out", "results/discover", "")
	n := fs.Int("plans", 20, "candidate plans per planner (pilot default 20)")
	planner := fs.String("planner", "mock", "mock | adaption")
	phase := fs.String("phase", "pilot", "pilot | discovery | heldout | replication")
	model := fs.String("model", "", "hosted model id from GET /api/v1/models (required for planner=adaption)")
	dryRun := fs.Bool("dry-run", true, "with planner=adaption: list models, print a dataset estimate and the budget state; make no paid call")
	execute := fs.Bool("execute", false, "with planner=adaption: perform paid calls within the caps (requires --dry-run=false)")
	price := fs.String("credits-per-1k-tokens", "", "VERIFIED inference price in credits per 1000 tokens, supplied by the operator; without it paid inference stays disabled")
	ledgerPath := fs.String("ledger", "results/discover/ledger.json", "")
	fs.Parse(args)

	runDir := filepath.Join(*out, time.Now().Format("20060102-150405")+"-"+*planner)
	os.MkdirAll(runDir, 0o755)
	caps := Capabilities{EnrolledSigner: true, Unenrolled: true}
	lab := NewLab(caps)

	var pl Planner = Mock{}
	usageTotal := Usage{}
	if *planner == "adaption" {
		api, err := NewAdaption()
		if err != nil {
			fmt.Fprintln(os.Stderr, "adaption planner unavailable:", err, "- the core study does not need it; run with --planner mock")
			os.Exit(2)
		}
		led := LoadLedger(*ledgerPath)
		ctx := context.Background()
		models, err := api.Models(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "models:", err)
			os.Exit(1)
		}
		est, estErr := api.InventEstimate(ctx, 20, "adversarial mutation plans for a PTV routine-mode attestation response verifier")
		if estErr == nil {
			led.SetBalance(est.AvailableCredits)
		}
		charged, reserved, tc, tr := led.Totals()
		report := map[string]any{"models": models, "invent_estimate_20_rows": est, "invent_estimate_error": errStr(estErr), "ledger_charged": charged, "ledger_reserved": reserved, "total_charged": tc, "total_reserved": tr, "phase_caps": PhaseCaps, "total_cap": TotalCap, "reserve": Reserve}
		writeJSON(filepath.Join(runDir, "dry-run.json"), report)
		fmt.Println("Adaption dry run written to", filepath.Join(runDir, "dry-run.json"))
		fmt.Printf("models available: %d; dataset invent estimate for 20 rows: %+v (err=%v)\n", len(models), est, estErr)
		fmt.Println("Inference pricing: the Responses API documents token usage but no credit cost; paid inference stays disabled unless --credits-per-1k-tokens is supplied from a verified source.")
		if *dryRun || !*execute {
			fmt.Println("No paid call was made (dry run). Re-run with --dry-run=false --execute --model <id> --credits-per-1k-tokens <verified price> to spend within the caps.")
			return
		}
		if *model == "" {
			fmt.Fprintln(os.Stderr, "--model is required; choose an id from the models list (never hard-coded)")
			os.Exit(2)
		}
		found := false
		for _, m := range models {
			if m.ID == *model {
				found = true
			}
		}
		if !found {
			fmt.Fprintln(os.Stderr, "model id not in GET /api/v1/models for this organization")
			os.Exit(2)
		}
		p, err := strconv.ParseFloat(*price, 64)
		if err != nil || p <= 0 {
			fmt.Fprintln(os.Stderr, "paid inference disabled: no verified credits-per-1k-tokens price supplied; cost cannot be bounded in credits")
			os.Exit(2)
		}
		maxOut := 4000
		bound := int((float64(maxOut+2000)/1000.0)*p) + 1 // conservative: full output budget + prompt
		ref := filepath.Base(runDir)
		if err := led.Reserve(*phase, ref, bound); err != nil {
			fmt.Fprintln(os.Stderr, "budget refused:", err)
			os.Exit(2)
		}
		mp := &ModelPlanner{API: api, Model: *model, Temperature: 0.7, MaxOut: maxOut, Caps: caps, Family: *phase, OnUsage: func(u Usage) {
			usageTotal.InputTokens += u.InputTokens
			usageTotal.OutputTokens += u.OutputTokens
			usageTotal.TotalTokens += u.TotalTokens
		}}
		pl = mp
		defer func() {
			credits := int(float64(usageTotal.TotalTokens)/1000.0*p) + 1
			led.Settle(*phase, ref, credits, usageTotal.TotalTokens == 0, fmt.Sprintf("tokens=%d price=%s/1k (operator-supplied)", usageTotal.TotalTokens, *price))
		}()
	}

	plans, err := pl.Propose(*n)
	if err != nil {
		fmt.Fprintln(os.Stderr, "planner error (counted as discovery cost):", err)
		writeJSON(filepath.Join(runDir, "planner-error.json"), map[string]any{"planner": pl.Name(), "error": err.Error(), "usage": usageTotal})
		os.Exit(1)
	}
	type family struct {
		Stage, Code string
	}
	seen := map[string]bool{}
	var outcomes []Outcome
	rootCauses := map[family]int{}
	var invalid, dup, findings, identity int
	for _, p := range plans {
		o := lab.Execute(p)
		if !o.Valid {
			invalid++
		}
		if seen[o.Canonical] {
			dup++
			o.Invalid = strings.TrimSpace(o.Invalid + " duplicate-of-earlier-plan")
		}
		seen[o.Canonical] = true
		if o.Finding {
			findings++
		}
		if o.Identity {
			identity++
		}
		if o.Valid && o.Verifier == "reject" {
			rootCauses[family{o.Stage, o.Code}]++
		}
		outcomes = append(outcomes, o)
	}
	f, _ := os.Create(filepath.Join(runDir, "outcomes.jsonl"))
	for _, o := range outcomes {
		b, _ := json.Marshal(o)
		f.Write(append(b, '\n'))
	}
	f.Close()
	writeJSON(filepath.Join(runDir, "plans.json"), plans)
	keys := make([]string, 0)
	for k, v := range rootCauses {
		keys = append(keys, fmt.Sprintf("%s/%s: %d", k.Stage, k.Code, v))
	}
	sort.Strings(keys)
	sum := map[string]any{"planner": pl.Name(), "plans": len(plans), "invalid_plans": invalid, "duplicate_plans": dup, "identity_plans": identity, "executable_unique_plans": len(seen) - invalidUnique(outcomes), "findings_verifier_accepted_should_reject": findings, "rejection_families_stage_code": keys, "usage_tokens": usageTotal, "note": "a 'finding' is a verifier acceptance the specification oracle says must be rejected; zero findings means this budget found none, not that none exist"}
	writeJSON(filepath.Join(runDir, "summary.json"), sum)
	b, _ := json.MarshalIndent(sum, "", "  ")
	fmt.Println(string(b))
	if findings > 0 {
		os.Exit(3)
	}
}

func invalidUnique(os []Outcome) int {
	seen := map[string]bool{}
	n := 0
	for _, o := range os {
		if !o.Valid && !seen[o.Canonical] {
			seen[o.Canonical] = true
			n++
		}
	}
	return n
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, b, 0o644)
}
