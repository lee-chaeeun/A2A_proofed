package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"a2aid/internal/wire"
	"a2aid/internal/zk"
)

// ZKMode configures the worker side of the optional proof-carrying component. An
// honest worker proves the REQUESTED snapshot version from its private openings with
// the requester's challenge. The remaining fields are lab attack behaviours: the
// worker keeps real proofs, chooses witnesses and rewrites outer A2A fields; it can
// never change the requester's authority or stored contract.
type ZKMode struct {
	OpeningsPath     string `json:"openings_path"`
	ProverBin        string `json:"prover_bin"`
	FakeBin          string `json:"fake_bin,omitempty"`
	CacheDir         string `json:"cache_dir,omitempty"`
	WitnessVersion   uint32 `json:"witness_version,omitempty"`    // 0 = as requested; otherwise prove this (possibly obsolete) opening with the request's challenge
	WrongChallenge   bool   `json:"wrong_challenge,omitempty"`    // prove with a random challenge instead of the request's
	ClaimPass        bool   `json:"claim_pass,omitempty"`         // outer metadata claims pass regardless of the journal
	CorruptByte      bool   `json:"corrupt_byte,omitempty"`       // flip one byte of the (genuine) receipt before delivery
	Fake             bool   `json:"fake,omitempty"`               // deliver a dev-mode (fake) receipt from the test-only tool
	ReplayReceiptB64 string `json:"replay_receipt_b64,omitempty"` // deliver this earlier genuine receipt instead of proving
}

func (a *Agent) handleZKTask(ctx context.Context, d map[string]any) map[string]any {
	a.mu.Lock()
	mode := a.mode
	a.mu.Unlock()
	var task wire.ZKTask
	_ = wire.FromMap(d, &task)
	res := wire.ZKResult{Type: "zk_result", Schema: wire.ZKSchema, RequestID: task.RequestID, WorkerDeployment: a.own.DeploymentID}
	zm := mode.ZK
	if zm == nil || zm.OpeningsPath == "" || zm.ProverBin == "" {
		res.Error = "worker has no ZK configuration"
		return wire.ToMap(res)
	}
	if task.Schema != wire.ZKSchema {
		res.Error = fmt.Sprintf("unsupported zk_task schema %d", task.Schema)
		return wire.ToMap(res)
	}
	var receipt []byte
	var journalHex string
	usedVersion := task.Version
	switch {
	case zm.ReplayReceiptB64 != "":
		b, err := base64.StdEncoding.DecodeString(zm.ReplayReceiptB64)
		if err != nil {
			res.Error = "bad replay receipt"
			return wire.ToMap(res)
		}
		receipt = b
		usedVersion = 0
	default:
		openings, err := zk.LoadOpenings(zm.OpeningsPath)
		if err != nil {
			res.Error = "openings: " + err.Error()
			return wire.ToMap(res)
		}
		if zm.WitnessVersion != 0 {
			usedVersion = zm.WitnessVersion
		}
		op, ok := zk.OpeningFor(openings, usedVersion)
		if !ok || op.Portfolio != task.Portfolio {
			res.Error = fmt.Sprintf("no opening for %s v%d", task.Portfolio, usedVersion)
			return wire.ToMap(res)
		}
		chal := task.ChallengeHex
		if zm.WrongChallenge {
			var c [16]byte
			rand.Read(c[:])
			chal = hex.EncodeToString(c[:])
		}
		br := &zk.Bridge{ProverBin: zm.ProverBin, FakeBin: zm.FakeBin, CacheDir: zm.CacheDir, Timeout: 20 * time.Minute}
		pr, raw, err := br.Prove(ctx, zk.ProveRequest{Portfolio: op.Portfolio, Version: op.Version, SaltHex: op.SaltHex, Holdings: op.Holdings, ChallengeHex: chal}, zm.Fake)
		if err != nil {
			res.Error = "prove: " + err.Error()
			a.Ctl.Emit("zk_prove_failed", map[string]any{"by": a.Label, "request_id": task.RequestID, "err": err.Error()})
			return wire.ToMap(res)
		}
		receipt, journalHex = raw, pr.JournalHex
		res.ClaimedImageID, res.ProveMS, res.Cached = pr.ImageIDHex, pr.ProveMS, pr.Cached
	}
	if zm.CorruptByte && len(receipt) > 64 {
		receipt[len(receipt)/2] ^= 0x01
	}
	sum := sha256.Sum256(receipt)
	res.ReceiptB64, res.ReceiptSHA256 = base64.StdEncoding.EncodeToString(receipt), hex.EncodeToString(sum[:])
	if j, err := hex.DecodeString(journalHex); err == nil && len(j) == zk.JournalLen {
		res.ClaimedPass = j[zk.JournalLen-1] == 1
	}
	if zm.ClaimPass {
		res.ClaimedPass = true
	}
	// Controller record: which witness version was used, never the opening itself.
	a.Ctl.Emit("zk_task_served", map[string]any{"by": a.Label, "request_id": task.RequestID, "requested_version": task.Version, "witness_version_used": usedVersion, "replayed": zm.ReplayReceiptB64 != "", "wrong_challenge": zm.WrongChallenge, "corrupt_byte": zm.CorruptByte, "fake": zm.Fake, "claim_pass_override": zm.ClaimPass, "receipt_sha256": res.ReceiptSHA256, "cached": res.Cached, "prove_ms": res.ProveMS})
	return wire.ToMap(res)
}
