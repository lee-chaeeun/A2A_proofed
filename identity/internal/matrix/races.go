package matrix

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"a2aid/internal/verifier"
	"a2aid/internal/wire"
)

// RaceTrial is one randomized concurrent-delivery trial (F13 with real timing).
type RaceTrial struct {
	Policy     string  `json:"policy"`
	Trial      int     `json:"trial"`
	Seed       int64   `json:"seed"`
	DelayAMs   int     `json:"delay_a_ms"` // A's processing delay (applies to both legs, A serves the relay too)
	DelayBMs   int     `json:"delay_b_ms"` // B's extra relay delay
	LatencyAMs float64 `json:"latency_a_ms"`
	LatencyBMs float64 `json:"latency_b_ms"`
	AcceptA    bool    `json:"accept_a"`
	AcceptB    bool    `json:"accept_b"`
	Releases   int     `json:"releases"`
	Winner     string  `json:"winner"` // A | B | none
	Recipient  string  `json:"observed_recipient"`
	Receipts   int     `json:"receipts"`
	ErrA       string  `json:"err_a,omitempty"`
	ErrB       string  `json:"err_b,omitempty"`
}

// runRaces: after the deterministic F13 cells, run count trials per policy in which
// both legs are sent concurrently, each response is appraised AS SOON AS IT ARRIVES,
// and A/B processing delays are drawn from a seeded RNG. Every trial is retained.
func runRaces(rt *Runtime, spec RaceSpec) string {
	dir := filepath.Join(rt.OutDir, "races")
	os.MkdirAll(dir, 0o755)
	copiedCard := filepath.Join(rt.AbsRun, "B", "copied-volume", "app", "card.json")
	bOwnCard := filepath.Join(rt.AbsRun, "B", "app", "card.json")
	writeJSON(filepath.Join(rt.OutDir, "copy-manifest-races.json"), rt.CopyVolume("races", []string{"card.json", "config.json", "sfile.key"}))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Randomized race trials (%d per policy, seeds %d..%d, delays U[0,%d] ms)\n\n", spec.Count, spec.SeedBase, spec.SeedBase+int64(spec.Count)-1, spec.MaxDelayMs)
	sb.WriteString("Each trial: one nonce, challenge sent to A directly and to B (relay to A) concurrently; each response appraised on arrival. These trials share one deployment pair and one implementation: they measure this harness's race behaviour, not attack prevalence.\n\n| Policy | trials | B wins | A wins | zero releases | two releases | errors | A latency p50/p90 ms | B latency p50/p90 ms |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, policy := range spec.Policies {
		pol, err := wire.ParsePolicy(policy)
		if err != nil {
			panic(err)
		}
		f, _ := os.Create(filepath.Join(dir, policy+".jsonl"))
		var trials []RaceTrial
		for i := 0; i < spec.Count; i++ {
			seed := spec.SeedBase + int64(i)
			rng := rand.New(rand.NewSource(seed))
			dA, dB := rng.Intn(spec.MaxDelayMs+1), rng.Intn(spec.MaxDelayMs+1)
			rt.SetMode(AAdmin, map[string]any{"mode": "honest", "card_path": filepath.Join(rt.AbsRun, "A", "app", "card.json"), "delay_ms": dA})
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, map[string]any{"delay_ms": dB}))
			id := fmt.Sprintf("R_%s_%03d", policy, i)
			c := newCell(rt, id, DefaultResolver)
			tr := raceTrial(c, policy, pol, i, seed, dA, dB)
			c.finish(nil)
			t := c.truth()
			for _, who := range t.recipients {
				tr.Recipient = who
			}
			for _, n := range t.receipts {
				tr.Receipts += n
			}
			trials = append(trials, tr)
			b, _ := json.Marshal(tr)
			f.Write(append(b, '\n'))
			if i%20 == 0 {
				rt.logf("race %s trial %d: winner=%s releases=%d", policy, i, tr.Winner, tr.Releases)
			}
		}
		f.Close()
		var bw, aw, zero, two, errs int
		var la, lb []float64
		for _, tr := range trials {
			switch tr.Winner {
			case "B":
				bw++
			case "A":
				aw++
			default:
				zero++
			}
			if tr.Releases > 1 {
				two++
			}
			if tr.ErrA != "" || tr.ErrB != "" {
				errs++
			}
			la = append(la, tr.LatencyAMs)
			lb = append(lb, tr.LatencyBMs)
		}
		fmt.Fprintf(&sb, "| %s | %d | %d | %d | %d | %d | %d | %.1f/%.1f | %.1f/%.1f |\n", policy, len(trials), bw, aw, zero, two, errs, pct(la, 50), pct(la, 90), pct(lb, 50), pct(lb, 90))
	}
	rt.SetMode(AAdmin, map[string]any{"mode": "honest", "card_path": filepath.Join(rt.AbsRun, "A", "app", "card.json")})
	rt.SetMode(BAdmin, honest(bOwnCard))
	os.WriteFile(filepath.Join(dir, "summary.md"), []byte(sb.String()), 0o644)
	return sb.String()
}

func raceTrial(c *cell, policy string, pol wire.Policy, i int, seed int64, dA, dB int) RaceTrial {
	ctx := context.Background()
	tr := RaceTrial{Policy: policy, Trial: i, Seed: seed, DelayAMs: dA, DelayBMs: dB, Winner: "none"}
	dAdec := &verifier.Decision{Policy: policy, Expected: "A"}
	dBdec := &verifier.Decision{Policy: policy, Expected: "A"}
	ca, err := c.req.Connect(ctx, endpointURL("A", pol), "A", dAdec)
	if err != nil {
		tr.ErrA = err.Error()
		return tr
	}
	defer ca.Destroy()
	cb, err := c.req.Connect(ctx, endpointURL("B", pol), "A", dBdec)
	if err != nil {
		tr.ErrB = err.Error()
		return tr
	}
	defer cb.Destroy()
	nonce, _ := c.req.Issue("A", policy)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		t0 := time.Now()
		raw, err := c.req.SendChallenge(ctx, ca, policy, nonce, "A", nil)
		tr.LatencyAMs = float64(time.Since(t0).Microseconds()) / 1000
		if err != nil {
			tr.ErrA = err.Error()
			c.req.Store.Claim(nonce)
			return
		}
		c.req.Appraise(policy, nonce, "A", raw, dAdec)
		c.req.Release(ctx, ca, nonce, dAdec)
	}()
	go func() {
		defer wg.Done()
		t0 := time.Now()
		raw, err := c.req.SendChallenge(ctx, cb, policy, nonce, "A", nil)
		tr.LatencyBMs = float64(time.Since(t0).Microseconds()) / 1000
		if err != nil {
			tr.ErrB = err.Error()
			c.req.Store.Claim(nonce)
			return
		}
		c.req.Appraise(policy, nonce, "A", raw, dBdec)
		c.req.Release(ctx, cb, nonce, dBdec)
	}()
	wg.Wait()
	tr.AcceptA, tr.AcceptB = dAdec.Accept, dBdec.Accept
	if dAdec.JobReleased {
		tr.Releases++
		tr.Winner = "A"
	}
	if dBdec.JobReleased {
		tr.Releases++
		tr.Winner = "B"
	}
	if tr.Releases > 1 {
		tr.Winner = "both"
	}
	return tr
}

func pct(v []float64, p int) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	i := (len(s) - 1) * p / 100
	return s[i]
}
