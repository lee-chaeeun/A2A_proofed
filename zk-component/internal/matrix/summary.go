package matrix

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"a2aid/internal/wire"
)

// attackFixture reports whether the attacker endpoint is the one contacted (the
// relevant denominator for false endpoint acceptance). Concurrency and nonce-burn
// fixtures are counted separately.
func attackFixture(fx Fixture) bool {
	return (fx.Endpoint == "B" || fx.Endpoint == "A-hijacked") && fx.ID != "F12" && fx.ID != "F13"
}

func summary(man Manifest, rows []Row, apps []Appraisal, rt *Runtime, raceSummary string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Matrix summary\n\nRun %s started %s, %d cells, %d appraisals, manifest v%d frozen %s.\n\n", rt.OutDir, rt.Started.UTC().Format(time.RFC3339), len(rows), len(apps), man.Version, man.FrozenAt)
	fxByID := map[string]Fixture{}
	for _, fx := range man.Fixtures {
		fxByID[fx.ID] = fx
	}
	sb.WriteString("## Decisions (observed → job recipient; bold = divergence from the frozen prediction)\n\n| Fixture | " + strings.Join(man.Policies, " | ") + " |\n|---|" + strings.Repeat("---|", len(man.Policies)) + "\n")
	byCell := map[string]Row{}
	for _, r := range rows {
		byCell[r.Cell] = r
	}
	for _, fx := range man.Fixtures {
		cells := []string{}
		for _, p := range man.Policies {
			r, ok := byCell[fx.ID+"_"+p]
			if !ok {
				cells = append(cells, "—")
				continue
			}
			s := r.ObservedResult
			if r.ObservedResult != "n/a" {
				s += " → " + r.JobRecipients
			}
			if !r.Match {
				s = "**" + s + " (expected " + r.ExpectedResult + ")**"
			}
			cells = append(cells, s)
		}
		fmt.Fprintf(&sb, "| %s %s | %s |\n", fx.ID, fx.Title, strings.Join(cells, " | "))
	}

	// ---- counts with denominators -------------------------------------------------
	type cnt struct{ n, d int }
	perPolicyFE := map[string]*cnt{}
	var matchN int
	var divergences []string
	var feN, feD, honRej, honD, dupDisp, dupRcpt, concD, concToB, concToA, concZero int
	var fsN, fsD, custN, legitRejCfg, nonceBurnLegit, toctou, telemetryMissing, unobserved int
	var recChecked, recMatch, decMatch int
	classCount := map[string]int{}
	for _, r := range rows {
		if r.ObservedResult != "n/a" {
			cls, explicit := fxByID[r.Fixture].class()
			if !explicit {
				cls += " (derived)"
			}
			classCount[cls]++
		}
	}
	for _, r := range rows {
		if r.ObservedResult == "n/a" {
			continue
		}
		if r.Match {
			matchN++
		} else {
			divergences = append(divergences, fmt.Sprintf("%s: expected %s, observed %s (%s)", r.Cell, r.ExpectedResult, r.ObservedResult, r.Reason))
		}
		fx := fxByID[r.Fixture]
		if attackFixture(fx) {
			feD++
			if perPolicyFE[r.Policy] == nil {
				perPolicyFE[r.Policy] = &cnt{}
			}
			perPolicyFE[r.Policy].d++
			if strings.Contains(r.JobRecipients, "B") {
				feN++
				perPolicyFE[r.Policy].n++
			}
		}
		if cls, _ := fxByID[r.Fixture].class(); cls == "honest" { // explicit class, or derived from endpoint=A for older manifests
			honD++
			if r.Decision != "accept" || !strings.Contains(r.JobRecipients, "A") {
				honRej++
			}
		}
		if r.RecipientChecked {
			recChecked++
			if r.RecipientMatch {
				recMatch++
			}
			if r.DecisionMatch {
				decMatch++
			}
		}
		if r.Fixture == "F9" && r.Decision != "accept" {
			legitRejCfg++
		}
		if r.Fixture == "F13" {
			concD++
			switch {
			case r.Releases == 0:
				concZero++
			case strings.Contains(r.JobRecipients, "B"):
				concToB++
			default:
				concToA++
			}
		}
		if r.DuplicateDispatch {
			dupDisp++
		}
		if r.DuplicateReceipt {
			dupRcpt++
		}
	}
	for _, a := range apps {
		fx := fxByID[a.Fixture]
		pol, _ := wire.ParsePolicy(a.Policy)
		if a.Accept && pol.HasProof() && fx.Endpoint != "A" {
			fsD++
			if a.SignerOK == "false-attribution" {
				fsN++
			}
			if a.CustodyBroken {
				custN++
			}
		}
		if a.Fixture == "F12" && a.Index == 2 && !a.Accept && a.NonceVerdict == "consumed" {
			nonceBurnLegit++
		}
		if a.ConfigChanged == "yes" {
			toctou++
		}
		if a.Telemetry != "complete" {
			telemetryMissing++
		}
		if a.ObservedRecipient == "unobserved" {
			unobserved++
		}
	}
	fmt.Fprintf(&sb, "\n## Counts (denominators stated; coverage of this fixture set, not prevalence)\n\n")
	fmt.Fprintf(&sb, "* Cells matching the frozen prediction: %d / %d applicable\n", matchN, matchN+len(divergences))
	fmt.Fprintf(&sb, "* False endpoint acceptances (job to B while expecting A): %d / %d attacker-endpoint cells (F12/F13 excluded)\n", feN, feD)
	pols := make([]string, 0, len(perPolicyFE))
	for p := range perPolicyFE {
		pols = append(pols, p)
	}
	sort.Slice(pols, func(i, j int) bool { return indexOf(man.Policies, pols[i]) < indexOf(man.Policies, pols[j]) })
	parts := []string{}
	for _, p := range pols {
		parts = append(parts, fmt.Sprintf("%s %d/%d", p, perPolicyFE[p].n, perPolicyFE[p].d))
	}
	fmt.Fprintf(&sb, "  * per policy: %s\n", strings.Join(parts, "; "))
	fmt.Fprintf(&sb, "* Honest-class cells (explicit fixture class, or derived from endpoint=A for older manifests) not delivering to A: %d / %d cells; cells by class: %v\n", honRej, honD, classCount)
	if recChecked > 0 {
		fmt.Fprintf(&sb, "* Separate predictions: decision matches %d / %d, recipient matches %d / %d (predicted separately; accept is not delivery to A)\n", decMatch, recChecked, recMatch, recChecked)
	}
	fmt.Fprintf(&sb, "* Changed-configuration rejections (F9, reported separately, legitimate by policy): %d cells\n", legitRejCfg)
	fmt.Fprintf(&sb, "* Nonce burning (F12): valid second responses rejected because the nonce was consumed: %d appraisals (availability cost of consume-on-failure)\n", nonceBurnLegit)
	fmt.Fprintf(&sb, "* Concurrent valid responses (F13): %d cells; one job to B: %d; one job to A: %d; zero jobs: %d\n", concD, concToB, concToA, concZero)
	fmt.Fprintf(&sb, "* Duplicate dispatch (two job_released for one nonce): %d cells; duplicate receipt (one token received twice): %d cells\n", dupDisp, dupRcpt)
	fmt.Fprintf(&sb, "* False signer attributions (accepted attack appraisal with no A-enrolled key used, typed): %d / %d accepted attack appraisals with a proof\n", fsN, fsD)
	fmt.Fprintf(&sb, "* Custody broken (A's key used by B's process or from copied materials) among those: %d / %d\n", custN, fsD)
	fmt.Fprintf(&sb, "* TOCTOU (F18): jobs delivered after the appraised configuration changed: %d appraisals (no continuity is enforced by any policy)\n", toctou)
	fmt.Fprintf(&sb, "* Telemetry incomplete: %d appraisals; released tokens never observed at a recipient: %d\n", telemetryMissing, unobserved)
	if len(divergences) > 0 {
		sb.WriteString("\n## Divergences from frozen predictions\n\n")
		for _, d := range divergences {
			sb.WriteString("* " + d + "\n")
		}
	} else {
		sb.WriteString("\nNo divergences from the frozen predictions.\n")
	}
	if raceSummary != "" {
		sb.WriteString("\n" + raceSummary)
	}
	sb.WriteString("\n## Per-appraisal detail\n\n| Cell | # | endpoint | eq | tls | cb | keys | invokers | job → | accept | stage | code | reason | telemetry |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, a := range apps {
		fmt.Fprintf(&sb, "| %s | %d | %s | %s | %s/%s | %s | %s | %s | %s | %v | %s | %s | %s | %s |\n", a.Cell, a.Index, a.EndpointContacted, a.EndpointEqual, a.TLSAuthenticated, a.TLSNameMatch, a.CBMatched, strings.Join(a.KeysUsed, ";"), strings.Join(a.Invokers, ";"), a.ObservedRecipient, a.Accept, a.FailureStage, a.Code, strings.ReplaceAll(a.Reason, "|", "/"), a.Telemetry)
	}
	return sb.String()
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return len(list)
}
