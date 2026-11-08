package pqaudit

// Permanent tests of the composite audit on the six-cell fixture run
// (fixtures/testdata/pq-mini-run: six cells of a retained PQ run with a restricted
// inventory). Mutations mirror scripts/pq_audit_controls.py (ten proof/schema controls
// and seven release-evidence controls R1–R7) and the expected exit
// codes come from the frozen table fixtures/pq-audit-controls-expected.json. The CLI
// test builds the real a2aid binary and asserts the process exit codes.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const cell = "P1_PQ-device+cb"

func fixtureRun(t *testing.T) string {
	t.Helper()
	p, _ := filepath.Abs("../../fixtures/testdata/pq-mini-run")
	if _, err := os.Stat(filepath.Join(p, "run-inventory.json")); err != nil {
		t.Skip("fixture run missing")
	}
	return p
}

func expectedTable(t *testing.T) map[string]int {
	t.Helper()
	b, err := os.ReadFile("../../fixtures/pq-audit-controls-expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Expected map[string]int `json:"expected_exit"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Expected
}

func copyRun(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "run")
	if out, err := exec.Command("cp", "-R", src, dst).CombinedOutput(); err != nil {
		t.Fatalf("copy: %v %s", err, out)
	}
	return dst
}

func decision(t *testing.T, run, c string) (string, map[string]any) {
	t.Helper()
	p := filepath.Join(run, "cells", c, "decision.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var j map[string]any
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	return p, j
}

func save(t *testing.T, p string, j any) {
	t.Helper()
	b, _ := json.MarshalIndent(j, "", " ")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func first(j map[string]any) map[string]any { return j["decisions"].([]any)[0].(map[string]any) }

func events(t *testing.T, run, c string) (string, []map[string]any) {
	t.Helper()
	p := filepath.Join(run, "cells", c, "controller-events.jsonl")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return p, out
}

func writeEvents(t *testing.T, p string, evs []map[string]any) {
	t.Helper()
	var sb strings.Builder
	for _, e := range evs {
		b, _ := json.Marshal(e)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func flipB64(t *testing.T, s string, at int) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if at < 0 {
		at = len(b) + at
	}
	b[at] ^= 1
	return base64.StdEncoding.EncodeToString(b)
}

// mutations keyed exactly as in scripts/pq_audit_controls.py.
func mutations(t *testing.T) map[string]func(run string) {
	return map[string]func(run string){
		"unmodified":                   func(string) {},
		"removed-cell-P1_PQ-device+cb": func(run string) { os.RemoveAll(filepath.Join(run, "cells", cell)) },
		"duplicate-decision-P1_PQ-env+cb": func(run string) {
			p, j := decision(t, run, "P1_PQ-env+cb")
			j["decisions"] = append(j["decisions"].([]any), j["decisions"].([]any)[0])
			save(t, p, j)
		},
		"altered-context-bytes-P1_PQ-device+cb": func(run string) {
			p, j := decision(t, run, cell)
			pv := first(j)["raw_evidence"].(map[string]any)["proof_v4"].(map[string]any)
			pv["context"] = flipB64(t, pv["context"].(string), -1)
			save(t, p, j)
		},
		"changed-signature-P1_PQ-env+tls": func(run string) {
			p, j := decision(t, run, "P1_PQ-env+tls")
			pv := first(j)["raw_evidence"].(map[string]any)["proof_v4"].(map[string]any)
			pv["signature"] = flipB64(t, pv["signature"].(string), 100)
			save(t, p, j)
		},
		"substituted-registry-key-PQ-device": func(run string) {
			p := filepath.Join(run, "enrollment-registry.json")
			b, _ := os.ReadFile(p)
			var r map[string]any
			json.Unmarshal(b, &r)
			deps := r["deployments"].(map[string]any)
			a := deps["A"].(map[string]any)["v4_keys"].(map[string]any)["PQ-device"].(map[string]any)
			bk := deps["B"].(map[string]any)["v4_keys"].(map[string]any)["PQ-device"].(map[string]any)
			a["public_b64"] = bk["public_b64"]
			save(t, p, r)
		},
		"proof-removed-accept-kept-P1_EC-env+cb": func(run string) {
			p, j := decision(t, run, "P1_EC-env+cb")
			delete(first(j)["raw_evidence"].(map[string]any), "proof_v4")
			save(t, p, j)
		},
		"unknown-algorithm-label-P1_PQ-env+cb": func(run string) {
			p, j := decision(t, run, "P1_PQ-env+cb")
			first(j)["raw_evidence"].(map[string]any)["proof_v4"].(map[string]any)["alg"] = "ML-DSA-87"
			save(t, p, j)
		},
		"policy-downgrade-P8_PQ-env+cb": func(run string) {
			p, j := decision(t, run, "P8_PQ-env+cb")
			first(j)["policy"] = "PQ-env+tls"
			save(t, p, j)
		},
		"accept-flag-forged-P8_PQ-env+cb": func(run string) {
			p, j := decision(t, run, "P8_PQ-env+cb")
			d := first(j)
			d["accept"] = true
			pv := d["proof_v4"].(map[string]any)
			for _, k := range []string{"signature_valid_under_pinned_key", "context_matches_expected", "expiry_ok"} {
				pv[k] = true
			}
			save(t, p, j)
		},
		"R1-missing-requester-events-P1_PQ-device+cb": func(run string) {
			p, j := decision(t, run, cell)
			first(j)["requester_events"] = []any{}
			save(t, p, j)
		},
		"R2-dispatch-connection-swap-P1_PQ-device+cb": func(run string) {
			p, j := decision(t, run, cell)
			first(j)["dispatch_conn_id"] = 999
			first(j)["job_reused_proof_connection"] = false
			save(t, p, j)
		},
		"R3-dispatch-context-action-P1_PQ-device+cb": func(run string) {
			p, j := decision(t, run, cell)
			first(j)["dispatch_context"].(map[string]any)["action"] = "release-something-else"
			save(t, p, j)
		},
		"R4-missing-issued-sessions-P1_PQ-device+cb": func(run string) {
			p, j := decision(t, run, cell)
			delete(j, "sessions")
			save(t, p, j)
		},
		"R5-invalid-appraisal-time-P1_PQ-device+cb": func(run string) {
			p, j := decision(t, run, cell)
			first(j)["appraised_at"] = "not-a-time"
			save(t, p, j)
		},
		"R6-duplicate-receipt-P1_PQ-device+cb": func(run string) {
			p, evs := events(t, run, cell)
			for _, e := range evs {
				if e["kind"] == "job_received" {
					evs = append(evs, e)
					break
				}
			}
			writeEvents(t, p, evs)
		},
		"R7-receipt-id-token-exporter-P1_PQ-device+cb": func(run string) {
			p, evs := events(t, run, cell)
			for _, e := range evs {
				if e["kind"] == "job_received" {
					d := e["data"].(map[string]any)
					d["decision_id"], d["token"], d["exporter_hex"] = "ffffffffffffffff", "deadbeefdeadbeefdeadbeef", strings.Repeat("00", 32)
				}
			}
			writeEvents(t, p, evs)
		},
	}
}

func TestComposite_UnmodifiedFixtureIsClean(t *testing.T) {
	run := copyRun(t, fixtureRun(t))
	sum, cells, err := Run(Options{Run: run, OutDir: t.TempDir()})
	if err != nil || sum.ExitCode != 0 || sum.Agree != 6 || sum.AttackSuccess != 1 || sum.ProofsVerified != 5 || sum.ProofsInvalid != 1 {
		t.Fatalf("clean fixture: %+v err=%v", sum, err)
	}
	for _, c := range cells {
		if c.Status != "agree" || len(c.Audits) != 1 {
			t.Fatalf("cell %s: %+v", c.Cell, c)
		}
		for _, a := range c.Audits {
			if a.StructuralOutcome == "unsupported_historical_schema" || a.StructuralOutcome == "malformed" || a.StructuralOutcome == "insufficient_evidence" {
				t.Fatalf("cell %s structural %s", c.Cell, a.StructuralOutcome)
			}
		}
	}
	if sum.StructuralOutcomes["violation_expected_by_fixture"] != 1 || sum.StructuralOutcomes["verified_dispatch"] != 4 {
		t.Fatalf("structural outcomes: %v", sum.StructuralOutcomes)
	}
}

func TestComposite_MutationsClassifyAsFrozen(t *testing.T) {
	src := fixtureRun(t)
	exp := expectedTable(t)
	muts := mutations(t)
	for name := range exp {
		if _, ok := muts[name]; !ok {
			t.Fatalf("expectation table names %q but the test has no such mutation", name)
		}
	}
	for name, fn := range muts {
		want, ok := exp[name]
		if !ok {
			t.Fatalf("mutation %q has no frozen expectation", name)
		}
		run := copyRun(t, src)
		fn(run)
		sum, _, err := Run(Options{Run: run, OutDir: t.TempDir()})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if sum.ExitCode != want {
			t.Errorf("%s: exit %d, frozen expectation %d (%v)", name, sum.ExitCode, want, sum.RunErrors)
		}
		if name != "unmodified" && sum.ExitCode == 0 {
			t.Errorf("%s: a mutation must never be clean", name)
		}
	}
}

func TestComposite_OldRecordsWithoutTypedContextAreUnsupported(t *testing.T) {
	run := copyRun(t, fixtureRun(t))
	p, j := decision(t, run, cell)
	delete(first(j), "context")
	save(t, p, j)
	sum, cells, _ := Run(Options{Run: run, OutDir: t.TempDir()})
	if sum.ExitCode != 2 || sum.Unsupported != 1 {
		t.Fatalf("record without typed context must be unsupported, not upgraded: %+v", sum)
	}
	for _, c := range cells {
		if c.Cell == cell && c.Status != "unsupported" {
			t.Fatalf("%+v", c)
		}
	}
}

// The actual CLI: build a2aid, run audit-pq on the clean fixture and on R2/R5, assert
// process exit codes and that --out keeps the run directory untouched.
func TestComposite_CLIExitCodes(t *testing.T) {
	src := fixtureRun(t)
	bin := filepath.Join(t.TempDir(), "a2aid")
	build := exec.Command("go", "build", "-o", bin, "./cmd/a2aid")
	build.Dir, _ = filepath.Abs("../..")
	build.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	exp := expectedTable(t)
	muts := mutations(t)
	for _, name := range []string{"unmodified", "R2-dispatch-connection-swap-P1_PQ-device+cb", "R5-invalid-appraisal-time-P1_PQ-device+cb", "R7-receipt-id-token-exporter-P1_PQ-device+cb"} {
		run := copyRun(t, src)
		muts[name](run)
		before, _ := exec.Command("find", run, "-type", "f").Output()
		outDir := t.TempDir()
		cmd := exec.Command(bin, "audit-pq", "--results", run, "--out", outDir)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if code != exp[name] {
			t.Errorf("%s: CLI exit %d, frozen %d\n%s", name, code, exp[name], out)
		}
		after, _ := exec.Command("find", run, "-type", "f").Output()
		if string(before) != string(after) {
			t.Errorf("%s: --out must leave the run directory untouched", name)
		}
		if _, err := os.Stat(filepath.Join(outDir, "pq-audit-summary.json")); err != nil {
			t.Errorf("%s: no summary written to --out", name)
		}
	}
}
