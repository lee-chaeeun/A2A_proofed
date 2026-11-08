package zk

// [NETWORKED/integration, opt-in] Runs the complete ZK fixture matrix over real A2A
// HTTPS against the provisioned lab and the built Rust binaries, then scores it with
// the offline oracle. Needs swtpm-free lab ports (controller/gate/agents), the built
// zk/ workspace, zk/image-id.txt and the fixtures. Set A2AID_ZK_INTEGRATION=1.
// Genuine proving happens inside (≈25 s per new challenge, 7 proofs).

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIntegration_ZKMatrixAndOracle(t *testing.T) {
	if os.Getenv("A2AID_ZK_INTEGRATION") == "" {
		t.Skip("set A2AID_ZK_INTEGRATION=1 (needs the lab, the built zk/ workspace and ~3 minutes)")
	}
	root, _ := filepath.Abs("../..")
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin", "a2aid")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("bin/a2aid not built")
	}
	out, err := Run(Options{RunDir: "run", Out: filepath.Join(root, "results", "zk-integration"), ZKDir: "zk", Fixtures: "fixtures/zk", Predictions: "fixtures/zk/predictions.json", Bin: bin})
	if err != nil {
		t.Fatal(err)
	}
	sum, rows, err := RunOracleOpts(OracleOptions{Run: out, Openings: "fixtures/zk/openings.json", VerifyBin: filepath.Join("zk", "target", "release", "zkverify")})
	if err != nil {
		t.Fatal(err)
	}
	if sum.ExitCode != 0 || sum.Expected != 52 || sum.Rows != 52 || sum.Scored != 52 || sum.Incomplete != 0 || sum.Malformed != 0 || sum.Disagree != 0 || sum.Violations != 0 || sum.EvidenceMismatch != 0 || len(sum.RunErrors) != 0 {
		t.Fatalf("oracle: %+v", sum)
	}
	if len(rows) != 52 || sum.Verifier.UniquePairs != 10 || sum.Verifier.Verified != 7 || sum.Verifier.Rejected != 3 {
		t.Fatalf("expected 52 rows and 10 re-verified pairs (7 valid, 3 rejected): rows=%d verifier=%+v", len(rows), sum.Verifier)
	}
	t.Logf("zk integration run %s: %d rows scored, oracle exit %d", out, sum.Scored, sum.ExitCode)
}
