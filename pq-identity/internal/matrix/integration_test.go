package matrix

// [NETWORKED/integration] Drives real A2A traffic (SDK card resolver, JSON-RPC
// SendMessage with DataParts, task artifacts) through discovery, challenge,
// appraisal and job delivery for the key baseline/defense policies, and asserts
// the frozen expectations. It needs swtpm and exclusive use of the lab ports
// (9100, 9110, 9101/9102, 9443/9444), so it only runs with A2AID_INTEGRATION=1.

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIntegration_DiscoveryChallengeDelivery(t *testing.T) {
	if os.Getenv("A2AID_INTEGRATION") == "" {
		t.Skip("set A2AID_INTEGRATION=1 (needs swtpm and the lab ports)")
	}
	root, _ := filepath.Abs("../..")
	bin := filepath.Join(t.TempDir(), "a2aid")
	build := exec.Command("go", "build", "-o", bin, "./cmd/a2aid")
	build.Dir, build.Env = root, append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	runDir := filepath.Join(os.TempDir(), "a2aid-it") // short path: unix sockets
	os.RemoveAll(runDir)
	setup := exec.Command(bin, "setup", "--run-dir", runDir)
	if out, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("setup: %v %s", err, out)
	}
	defer func() {
		exec.Command("sh", "-c", "for p in "+runDir+"/tpm*/pid; do kill $(cat $p) 2>/dev/null; done").Run()
		os.RemoveAll(runDir)
	}()
	oldwd, _ := os.Getwd()
	os.Chdir(root)
	defer os.Chdir(oldwd)
	rows, apps, outDir := Run(RunOptions{RunDir: runDir, Out: filepath.Join(root, "results", "integration"), Fixtures: []string{"F1", "F2", "F6", "F14", "F15", "F16", "F20"},
		Policies: []string{"C", "T", "C+url", "C+tls", "T+tls", "S-env+cb", "T+cb"}, Manifest: "fixtures/manifest-v2.json", Predictions: "fixtures/predictions-v2.md", Races: false, Bin: bin})
	t.Logf("outputs: %s (%d appraisals)", outDir, len(apps))
	for _, r := range rows {
		if r.ObservedResult == "n/a" {
			continue
		}
		if !r.Match {
			t.Errorf("%s: expected %s observed %s (%s)", r.Cell, r.ExpectedResult, r.ObservedResult, r.Reason)
		}
	}
	// defense-specific assertions, stated explicitly
	want := map[string]string{"F6_C+url": "none", "F14_C+url": "B", "F14_C+tls": "none", "F15_T+tls": "B", "F15_T+cb": "none", "F16_T+cb": "none", "F20_T+cb": "B", "F1_T+cb": "A", "F2_S-env+cb": "A"}
	for _, r := range rows {
		if w, ok := want[r.Cell]; ok && r.JobRecipients != w {
			t.Errorf("%s: job recipients %q, want %q", r.Cell, r.JobRecipients, w)
		}
	}
	for _, a := range apps {
		if a.Telemetry != "complete" {
			t.Errorf("%s: telemetry %s", a.Cell, a.Telemetry)
		}
	}
}
