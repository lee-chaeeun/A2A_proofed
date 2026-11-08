package zk

// [NETWORKED/integration, opt-in] ZK task delivery over PQ-appraised transport
// (A2AID_PQ_ZK_SMOKE=1). Honest case: the requester runs the PQ-device+cb identity
// appraisal (ML-DSA-65 key inside A's emulated device, context bound to the
// requester's own exporter), then sends the zk_task through GuardedSend (sealed
// transport, dispatch pinned to the proof connection); the worker proves fresh
// (≈20–25 s) and the existing policies approve under the pinned guest image id.
// Negative case: B (A's TLS credentials, its own keys under A's key ids, A's name
// hijacked) fails the PQ appraisal and NO task is sent (no zk_task_served event at B).
// The ZK guest, image id and policies are unchanged; this test does not relabel the
// 52-cell matrix as PQ-authenticated. Connection replacement, refused reconnect,
// unknown outcome and fresh-decision recovery are covered by pq_transport_test.go
// (real HTTPS, server counters, software test key, stub receipt).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"a2aid/internal/matrix"
	"a2aid/internal/registry"
)

func TestPQSmoke_ZKTaskOverPQDeviceTransport(t *testing.T) {
	if os.Getenv("A2AID_PQ_ZK_SMOKE") == "" {
		t.Skip("set A2AID_PQ_ZK_SMOKE=1 (needs the provisioned lab incl. PQ devices and zk/target/release binaries)")
	}
	root, _ := filepath.Abs("../..")
	os.Chdir(root)
	out := filepath.Join(root, "results", "zk-pq-smoke", time.Now().UTC().Format("20060102-150405"))
	os.MkdirAll(filepath.Join(out, "receipts"), 0o755)
	abs := filepath.Join(root, "run")
	reg, err := registry.Load(filepath.Join(abs, "registry.json"))
	if err != nil {
		t.Skip("lab not provisioned")
	}
	bins := map[string]string{"prove": filepath.Join(root, "zk", "target", "release", "zkprove"), "verify": filepath.Join(root, "zk", "target", "release", "zkverify"), "fake": filepath.Join(root, "zk", "target", "release", "zkfake")}
	for _, p := range bins {
		if _, err := os.Stat(p); err != nil {
			t.Skip("zk binaries missing")
		}
	}
	imgb, _ := os.ReadFile(filepath.Join(root, "zk", "image-id.txt"))
	pinned := string(imgb[:64])
	auth, err := LoadAuthority(filepath.Join(root, "fixtures", "zk", "authority.json"))
	if err != nil {
		t.Fatal(err)
	}
	logf, _ := os.Create(filepath.Join(out, "run.log"))
	defer logf.Close()
	rt := &matrix.Runtime{RunDir: "run", AbsRun: abs, OutDir: out, Bin: filepath.Join(root, "bin", "a2aid"), Reg: reg, HTTP: httpClient(), Started: time.Now(), Log: logf}
	rt.Boot()
	defer rt.Shutdown()
	cacheDir := filepath.Join(root, "zk", "proof-cache")
	zkCfg := map[string]any{"openings_path": filepath.Join(root, "fixtures", "zk", "openings.json"), "prover_bin": bins["prove"], "fake_bin": bins["fake"], "cache_dir": cacheDir}
	rt.SetMode(matrix.AAdmin, map[string]any{"mode": "honest", "zk": zkCfg})
	trace, _ := os.Create(filepath.Join(out, "exchanges.jsonl"))
	defer trace.Close()
	ctx := context.Background()
	rec := map[string]any{}

	// honest: PQ-device+cb appraisal, then the task, fresh proof, VTI approves
	rq := &Requester{Reg: reg, RootCAs: rt.RootCAs, Resolver: matrix.DefaultResolver, Bridge: &Bridge{VerifyBin: bins["verify"], Timeout: 5 * time.Minute}, ImageIDHex: pinned, Auth: auth, Trace: trace, Policy: "PQ-device+cb"}
	auth.Reset()
	r1 := NewRequest("PQZ1", "desk-1/portfolio-7", Pinned, 1, "A")
	ex, raw, err := rq.Dispatch(ctx, matrix.ATLSURL, r1)
	if err != nil || raw == nil || !ex.Transport.Accept || !ex.TaskSent || ex.Delivery != "delivered" || ex.Identity == nil || ex.Identity.DispatchConnID != ex.Identity.ProofConnID || ex.Identity.ProofConnID == 0 {
		t.Fatalf("honest PQ-device+cb dispatch: err=%v accept=%v sent=%v delivery=%s identity=%+v", err, ex.Transport.Accept, ex.TaskSent, ex.Delivery, ex.Identity)
	}
	os.WriteFile(filepath.Join(out, "receipts", hexSum(raw)+".bin"), raw, 0o644)
	leds := map[string]*Ledger{}
	for _, p := range Policies {
		leds[p] = NewLedgerID("PQZ1/" + p)
	}
	_, verr, ds := rq.Judge(ctx, "PQZ1", r1, raw, leds, pinned)
	if verr != nil {
		t.Fatalf("receipt did not verify under the pinned image id: %v", verr)
	}
	for _, d := range ds {
		if !d.ProofValid || !d.ApprovalInserted {
			t.Fatalf("honest PQ-transport task: policy %s did not approve: %s", d.Policy, d.Reason)
		}
	}
	rec["honest"] = map[string]any{"transport": ex.Transport, "task_sent": ex.TaskSent, "delivery_outcome": ex.Delivery, "identity": ex.Identity, "a2a_task_id": ex.TaskID, "receipt_sha256": ex.ReceiptSHA256, "prove_ms": ex.Result.ProveMS, "cached": ex.Result.Cached, "decisions": ds}

	// negative: B with A's TLS credentials and its own keys under A's kids, A's name hijacked
	rt.SetMode(matrix.BAdmin, map[string]any{"mode": "impostor-own-keys", "card_path": filepath.Join(abs, "A", "app", "card.json"), "tls_identity_dir": filepath.Join(abs, "A", "tls"), "claim_kid_prefix": "A", "zk": zkCfg})
	rq2 := &Requester{Reg: reg, RootCAs: rt.RootCAs, Resolver: matrix.HijackResolver, Bridge: rq.Bridge, ImageIDHex: pinned, Auth: auth, Trace: trace, Policy: "PQ-device+cb"}
	r2 := NewRequest("PQZ2", "desk-1/portfolio-7", Pinned, 1, "A")
	ex2, raw2, err2 := rq2.Dispatch(ctx, matrix.ATLSURL, r2)
	if !errors.Is(err2, ErrTransportRejected) || raw2 != nil || ex2.TaskSent || ex2.Transport.Accept {
		t.Fatalf("invalid PQ proof must prevent task delivery: err=%v sent=%v accept=%v", err2, ex2.TaskSent, ex2.Transport.Accept)
	}
	time.Sleep(300 * time.Millisecond)
	evs, _ := rt.Ctl.Events("")
	served := 0
	for _, e := range evs {
		if e.Kind == "zk_task_served" && e.Data["by"] == "B" {
			served++
		}
	}
	if served != 0 {
		t.Fatalf("B served %d zk_task(s) although the PQ appraisal failed", served)
	}
	rec["invalid_pq"] = map[string]any{"transport": ex2.Transport, "task_sent": ex2.TaskSent, "error": err2.Error(), "zk_task_served_at_B": served}
	// unsupported transport policy is refused before any network activity
	rq3 := *rq
	rq3.Policy = "PQ-env+cb"
	if _, _, err := rq3.Dispatch(ctx, matrix.ATLSURL, NewRequest("PQZ3", "desk-1/portfolio-7", Pinned, 1, "A")); !errors.Is(err, ErrUnsupportedTransportPolicy) {
		t.Fatalf("PQ-env+cb must be refused by the ZK requester: %v", err)
	}
	rec["pinned_image_id"] = pinned
	rec["note"] = "ZK task delivery gated by the PQ-device+cb identity appraisal and sent through GuardedSend (sealed transport, dispatch on the proof connection; identity record retained). The ZK guest, image id and policies are unchanged. Not a relabelling of the 52-cell matrix; replacement/refusal/recovery cases are in pq_transport_test.go."
	b, _ := json.MarshalIndent(rec, "", " ")
	os.WriteFile(filepath.Join(out, "zk-pq-smoke.json"), b, 0o644)
	t.Logf("ZK over PQ-device+cb smoke written to %s", out)
}
