package zk

// Oracle controls over COPIES of the retained ZK run. They re-run the pinned verifier
// on the retained genuine receipts, so they skip when the run or the built zkverify
// binary is absent. A removed fixture, a duplicated row, replaced receipt bytes and
// removed approval events must be rejected; the unmodified run must be clean.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type oracleFixture struct {
	root, run, openings, verify string
}

func retainedRun(t *testing.T, rel string) *oracleFixture {
	t.Helper()
	root, _ := filepath.Abs("../..")
	f := &oracleFixture{root: root, run: filepath.Join(root, rel), openings: filepath.Join(root, "fixtures", "zk", "openings.json"), verify: filepath.Join(root, "zk", "target", "release", "zkverify")}
	if _, err := os.Stat(filepath.Join(f.run, "decisions.jsonl")); err != nil {
		t.Skip("retained run not present: " + rel)
	}
	if _, err := os.Stat(f.verify); err != nil {
		t.Skip("pinned verifier binary not built")
	}
	return f
}

// copyRun copies the run and applies a mutation; returns the copy path.
func (f *oracleFixture) copyRun(t *testing.T, mutate func(dir string)) string {
	t.Helper()
	cp := filepath.Join(t.TempDir(), "run")
	if err := copyTree(f.run, cp); err != nil {
		t.Fatal(err)
	}
	for _, stale := range []string{"oracle.jsonl", "oracle-summary.json", "oracle.md"} {
		os.Remove(filepath.Join(cp, stale))
	}
	if mutate != nil {
		mutate(cp)
	}
	return cp
}

func (f *oracleFixture) score(t *testing.T, dir string) *OracleSummary {
	t.Helper()
	sum, _, err := RunOracleOpts(OracleOptions{Run: dir, Openings: f.openings, VerifyBin: f.verify})
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func readLines(t *testing.T, p string) []string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func writeLines(t *testing.T, p string, lines []string) {
	t.Helper()
	os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func reseqEvents(t *testing.T, p string, keep func(map[string]any) bool) {
	t.Helper()
	var out []string
	n := 0
	for _, l := range readLines(t, p) {
		var e map[string]any
		json.Unmarshal([]byte(l), &e)
		if !keep(e) {
			continue
		}
		n++
		e["seq"] = n
		b, _ := json.Marshal(e)
		out = append(out, string(b))
	}
	writeLines(t, p, out)
}

// neutralizeEvents keeps every event's sequence number but turns the selected ones into
// an inert known kind (the insert itself disappears; row<->event links stay intact).
func neutralizeEvents(t *testing.T, p string, sel func(map[string]any) bool) {
	t.Helper()
	var out []string
	for _, l := range readLines(t, p) {
		var e map[string]any
		json.Unmarshal([]byte(l), &e)
		if sel(e) {
			e = map[string]any{"seq": e["seq"], "kind": "zk_reuse", "at": e["at"], "fields": map[string]any{"note": "test: neutralized"}}
		}
		b, _ := json.Marshal(e)
		out = append(out, string(b))
	}
	writeLines(t, p, out)
}

func runOracleCases(t *testing.T, f *oracleFixture) {
	t.Helper()
	// unmodified: complete and clean; every receipt/image pair re-verified
	sum := f.score(t, f.copyRun(t, nil))
	if sum.ExitCode != 0 || sum.Expected != 52 || sum.Scored != 52 || sum.Agree != 52 || sum.Incomplete+sum.Malformed+sum.Violations+sum.EvidenceMismatch+sum.Disagree != 0 || len(sum.RunErrors) != 0 {
		t.Fatalf("unmodified run must be clean: %+v", sum)
	}
	if sum.Verifier.UniquePairs != 10 || sum.Verifier.Verified != 7 || sum.Verifier.Rejected != 3 || sum.Verifier.Failures != 0 || sum.Verifier.SHA256 == "" {
		t.Fatalf("receipt re-verification: %+v", sum.Verifier)
	}
	if sum.AttackSuccesses != 7 || sum.WrongContext != "3/8" || sum.UnsafeApprovals != "5/12" || sum.DeniedLegitimate != "0/12" {
		t.Fatalf("expected attack successes/metrics: %d %s %s %s", sum.AttackSuccesses, sum.WrongContext, sum.UnsafeApprovals, sum.DeniedLegitimate)
	}
	type tc struct {
		name   string
		mutate func(dir string)
		exit   int
		check  func(*OracleSummary) bool
	}
	cases := []tc{
		{"remove all Z4 rows", func(d string) {
			var keep []string
			for _, l := range readLines(t, filepath.Join(d, "decisions.jsonl")) {
				if !strings.Contains(l, `"fixture":"Z4"`) {
					keep = append(keep, l)
				}
			}
			writeLines(t, filepath.Join(d, "decisions.jsonl"), keep)
		}, 2, func(s *OracleSummary) bool { return s.Incomplete == 4 && s.Rows == 48 && s.Scored == 48 }},
		{"duplicate first row", func(d string) {
			ls := readLines(t, filepath.Join(d, "decisions.jsonl"))
			writeLines(t, filepath.Join(d, "decisions.jsonl"), append(ls, ls[0]))
		}, 2, func(s *OracleSummary) bool { return s.Malformed >= 1 && s.Rows == 53 && s.Scored == 51 }},
		{"replace every receipt file with not-a-receipt", func(d string) {
			es, _ := os.ReadDir(filepath.Join(d, "receipts"))
			for _, e := range es {
				os.WriteFile(filepath.Join(d, "receipts", e.Name()), []byte("not-a-receipt"), 0o644)
			}
		}, 2, func(s *OracleSummary) bool { return s.Malformed == 52 && s.Scored == 0 }},
		{"neutralize every approval_inserted event (sequence kept)", func(d string) {
			neutralizeEvents(t, filepath.Join(d, "events.jsonl"), func(e map[string]any) bool { return e["kind"] == "approval_inserted" })
		}, 2, func(s *OracleSummary) bool { return s.Incomplete >= 19 && s.Scored < 52 && s.Violations == 0 }},
		{"remove every approval_inserted event (gap left)", func(d string) {
			reseqEvents(t, filepath.Join(d, "events.jsonl"), func(e map[string]any) bool { return e["kind"] != "approval_inserted" })
		}, 2, func(s *OracleSummary) bool { return s.Incomplete+s.Malformed >= 19 && s.Scored < 52 }},
		{"row journal altered (receipt intact)", func(d string) {
			ls := readLines(t, filepath.Join(d, "decisions.jsonl"))
			for i, l := range ls {
				if strings.Contains(l, `"evaluation_id":"Z1/VTI"`) || (strings.Contains(l, `"fixture":"Z1"`) && strings.Contains(l, `"policy":"VTI"`)) {
					var r map[string]any
					json.Unmarshal([]byte(l), &r)
					j := r["verified_journal_hex"].(string)
					r["verified_journal_hex"] = "01000000ff" + j[10:]
					b, _ := json.Marshal(r)
					ls[i] = string(b)
				}
			}
			writeLines(t, filepath.Join(d, "decisions.jsonl"), ls)
		}, 1, func(s *OracleSummary) bool { return s.EvidenceMismatch == 1 }},
		{"proof_valid flipped true on corrupted Z9a", func(d string) {
			ls := readLines(t, filepath.Join(d, "decisions.jsonl"))
			for i, l := range ls {
				if strings.Contains(l, `"fixture":"Z9a"`) && strings.Contains(l, `"policy":"V0"`) {
					ls[i] = strings.Replace(l, `"proof_valid":false`, `"proof_valid":true`, 1)
				}
			}
			writeLines(t, filepath.Join(d, "decisions.jsonl"), ls)
		}, 1, func(s *OracleSummary) bool { return s.EvidenceMismatch == 1 }},
		{"orphan approval event", func(d string) {
			ls := readLines(t, filepath.Join(d, "events.jsonl"))
			var tmpl map[string]any
			for _, l := range ls {
				if strings.Contains(l, `"kind":"approval_inserted"`) {
					json.Unmarshal([]byte(l), &tmpl)
					break
				}
			}
			tmpl["seq"] = len(ls) + 1
			tmpl["fields"].(map[string]any)["request_id"] = "Z2"
			if _, ok := tmpl["fields"].(map[string]any)["evaluation_id"]; ok {
				tmpl["fields"].(map[string]any)["evaluation_id"] = "Z2/V0"
			}
			b, _ := json.Marshal(tmpl)
			writeLines(t, filepath.Join(d, "events.jsonl"), append(ls, string(b)))
		}, 1, func(s *OracleSummary) bool { return s.Violations >= 1 }},
		{"events truncated mid-line", func(d string) {
			b, _ := os.ReadFile(filepath.Join(d, "events.jsonl"))
			os.WriteFile(filepath.Join(d, "events.jsonl"), b[:len(b)-30], 0o644)
		}, 2, func(s *OracleSummary) bool { return s.Malformed >= 1 }},
		{"sequence gap", func(d string) {
			ls := readLines(t, filepath.Join(d, "events.jsonl"))
			writeLines(t, filepath.Join(d, "events.jsonl"), append(ls[:10], ls[11:]...))
		}, 2, func(s *OracleSummary) bool { return s.Malformed >= 1 && s.Scored == 0 }},
		{"null request record", func(d string) {
			b, _ := os.ReadFile(filepath.Join(d, "requests.json"))
			var rq []json.RawMessage
			json.Unmarshal(b, &rq)
			rq[0] = json.RawMessage("null")
			nb, _ := json.Marshal(rq)
			os.WriteFile(filepath.Join(d, "requests.json"), nb, 0o644)
		}, 2, func(s *OracleSummary) bool { return s.Incomplete == 16 && s.Malformed >= 1 }},
		{"row expected image id changed on Z9b", func(d string) {
			ls := readLines(t, filepath.Join(d, "decisions.jsonl"))
			for i, l := range ls {
				if strings.Contains(l, `"fixture":"Z9b"`) && strings.Contains(l, `"policy":"V0"`) {
					ls[i] = strings.Replace(l, `"expected_image_id_hex":"0f1e`, `"expected_image_id_hex":"4f1e`, 1)
				}
			}
			writeLines(t, filepath.Join(d, "decisions.jsonl"), ls)
		}, 2, func(s *OracleSummary) bool { return s.Malformed == 1 }},
	}
	for _, c := range cases {
		sum := f.score(t, f.copyRun(t, c.mutate))
		if sum.ExitCode != c.exit || !c.check(sum) {
			t.Errorf("%s: want exit %d, got %+v", c.name, c.exit, sum)
		}
	}
}

func TestOracle_RetainedRun(t *testing.T) {
	root, _ := filepath.Abs("../..")
	runs, _ := filepath.Glob(filepath.Join(root, "results", "zk", "*", "run-inventory.json"))
	if len(runs) == 0 {
		t.Skip("no retained run present")
	}
	rel, _ := filepath.Rel(root, filepath.Dir(runs[len(runs)-1]))
	f := retainedRun(t, rel)
	runOracleCases(t, f)
	// ledgers.json must agree with the events; an explicit inventory is refused for a run that declares its own
	sum := f.score(t, f.copyRun(t, func(d string) { os.Remove(filepath.Join(d, "ledgers.json")) }))
	if sum.ExitCode != 2 {
		t.Fatalf("missing ledgers.json must be incomplete: %+v", sum)
	}
	bad, _, _ := RunOracleOpts(OracleOptions{Run: f.copyRun(t, nil), Openings: f.openings, VerifyBin: f.verify, LegacyInventory: filepath.Join(t.TempDir(), "explicit-inventory.json")})
	if bad.ExitCode != 2 {
		t.Fatalf("an explicit inventory for a run that declares its own must be refused: %+v", bad)
	}
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			if info.Name() == "oracle-controls" || info.Name() == "process-logs" || info.Name() == "boot" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}
