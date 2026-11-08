package matrix

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"a2aid/internal/cardsig"
	"a2aid/internal/registry"
	"a2aid/internal/tpmsig"
	"a2aid/internal/verifier"
)

// ReverifyMain is the offline verifier: it re-derives every cryptographic verdict
// from the retained per-cell records (raw evidence, issued session, enrollment
// registry, the card as fetched) and compares with the recorded decision.
// Transport facts (which TLS peer answered, endpoint equality) cannot be
// re-derived offline and are reported as "copied from record".
func ReverifyMain(args []string) {
	fs := flag.NewFlagSet("reverify", flag.ExitOnError)
	res := fs.String("results", "", "results run directory")
	fs.Parse(args)
	if *res == "" {
		fs.Usage()
		os.Exit(2)
	}
	reg, err := registry.Load(filepath.Join(*res, "enrollment-registry.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cells, _ := filepath.Glob(filepath.Join(*res, "cells", "*", "decision.json"))
	sort.Strings(cells)
	type rec struct {
		Cell          string `json:"cell"`
		Index         int    `json:"appraisal_index"`
		Policy        string `json:"policy"`
		RecordedAcc   bool   `json:"recorded_accept"`
		RecordedStage string `json:"recorded_stage"`
		OfflineAcc    bool   `json:"offline_accept"`
		OfflineStage  string `json:"offline_stage"`
		CardRecorded  bool   `json:"card_recorded_valid"`
		CardOffline   string `json:"card_offline"` // valid | invalid | no card in trace
		Agree         bool   `json:"agree"`
		Note          string `json:"note,omitempty"`
	}
	var out []rec
	agree, total := 0, 0
	jf, _ := os.Create(filepath.Join(*res, "reverify.jsonl"))
	defer jf.Close()
	for _, path := range cells {
		cellDir := filepath.Dir(path)
		cell := filepath.Base(cellDir)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var doc struct {
			Decisions []*verifier.Decision `json:"decisions"`
			Sessions  []verifier.Session   `json:"sessions"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			out = append(out, rec{Cell: cell, Note: "unreadable: " + err.Error()})
			continue
		}
		byNonce := map[string]verifier.Session{}
		for _, s := range doc.Sessions {
			byNonce[s.Nonce] = s
		}
		cards := cardsFromTrace(filepath.Join(cellDir, "requester-trace.jsonl"))
		for i, d := range doc.Decisions {
			if d == nil {
				continue
			}
			r := rec{Cell: cell, Index: i + 1, Policy: d.Policy, RecordedAcc: d.Accept, RecordedStage: d.FailureStage, CardRecorded: d.Card.Valid, CardOffline: "no card in trace"}
			// card re-verification from the trace
			if i < len(cards) {
				dep := reg.Deployments[d.Expected]
				v := cardsig.Verify(cards[i], func(kid string) (*ecdsa.PublicKey, error) {
					if dep == nil || kid != dep.CardKeyID {
						return nil, fmt.Errorf("kid not enrolled for expected deployment")
					}
					return tpmsig.ParsePublicPEM(dep.CardPublicPEM)
				})
				r.CardOffline = map[bool]string{true: "valid", false: "invalid"}[v.Valid]
			}
			if strings.HasPrefix(d.FailureStage, "connect") || d.FailureStage == "policy" || d.FailureStage == "exchange" {
				r.OfflineAcc, r.OfflineStage, r.Note = false, d.FailureStage, "transport-stage failure: copied from record (not re-derivable offline)"
				r.Agree = true
			} else {
				rq := verifier.New(reg, nil, nil)
				od := rq.Reappraise(d, byNonce[d.Nonce])
				r.OfflineAcc, r.OfflineStage = od.Accept, od.FailureStage
				r.Agree = od.Accept == d.Accept && od.FailureStage == d.FailureStage && od.Code == d.Code
				if d.NonceVerdict == "consumed" {
					r.Note = "nonce-consumption order copied from record; crypto re-derived"
				}
				if od.Accept != d.Accept {
					r.Note = "ACCEPT DISAGREEMENT: " + od.Reason
				} else if !r.Agree {
					r.Note = fmt.Sprintf("stage/code differ: offline %s/%s vs recorded %s/%s", od.FailureStage, od.Code, d.FailureStage, d.Code)
				}
			}
			if r.CardOffline != "no card in trace" && (r.CardOffline == "valid") != r.CardRecorded {
				r.Agree = false
				r.Note += " card verdict differs offline"
			}
			total++
			if r.Agree {
				agree++
			}
			out = append(out, r)
			jb, _ := json.Marshal(r)
			jf.Write(append(jb, '\n'))
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Offline reverification of %s\n\n%d / %d appraisals agree with the recorded decision (accept, failure stage, PTV code, card verdict).\n\n", *res, agree, total)
	var recomputed, copiedTransport, copiedOrder int
	for _, r := range out {
		switch {
		case strings.Contains(r.Note, "copied from record"):
			copiedTransport++
		case strings.Contains(r.Note, "consumption order"):
			copiedOrder++
		default:
			recomputed++
		}
	}
	fmt.Fprintf(&sb, "Agreement is not one aggregate verification score. By how each verdict was established:\n\n* independently recomputed cryptographic primitives (card JWS, signatures, quotes, envelopes, bound nonces): %d\n* shared-code reappraisal that reused the production appraisal path: included in the recomputed count above (so these are consistency, not independence)\n* copied transport/exchange-stage facts (not re-derivable offline): %d\n* copied nonce-consumption order: %d\n\nCopied facts are reported, never summed into an independent-verification claim.\n\n", recomputed, copiedTransport, copiedOrder)
	sb.WriteString("Re-derived offline: card JWS (from the fetched card in the requester trace), nonce-session context and expiry (from the stored session with the clock fixed at the recorded appraisal time), S signatures, S-env envelope, TPM quote structure/signature/PCR digest, PTV envelope signature/schema/freshness, channel-bound nonce (from the requester's stored exporter value). Copied from the record, not re-derivable: TLS peer identity, endpoint equality, controller events.\n\n| Cell | # | policy | recorded | offline | card | agree | note |\n|---|---|---|---|---|---|---|---|\n")
	for _, r := range out {
		fmt.Fprintf(&sb, "| %s | %d | %s | %v/%s | %v/%s | %v/%s | %v | %s |\n", r.Cell, r.Index, r.Policy, r.RecordedAcc, r.RecordedStage, r.OfflineAcc, r.OfflineStage, r.CardRecorded, r.CardOffline, r.Agree, r.Note)
	}
	os.WriteFile(filepath.Join(*res, "reverify.md"), []byte(sb.String()), 0o644)
	fmt.Printf("reverify: %d/%d agree; wrote %s\n", agree, total, filepath.Join(*res, "reverify.md"))
	if agree != total {
		os.Exit(1)
	}
}

// cardsFromTrace returns the agent cards the requester fetched, in order.
func cardsFromTrace(path string) []*a2a.AgentCard {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []*a2a.AgentCard
	dec := json.NewDecoder(f)
	for dec.More() {
		var m struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if dec.Decode(&m) != nil {
			continue
		}
		if m.Kind == "agent_card" {
			var c a2a.AgentCard
			if json.Unmarshal(m.Data, &c) == nil {
				out = append(out, &c)
			}
		}
	}
	return out
}
