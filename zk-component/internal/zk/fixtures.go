package zk

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateFixtures writes the synthetic private openings (worker + oracle side) and
// the public authority history (requester side) for the fixed portfolio. Salts are
// fresh random values; the values themselves are the brainstorm's two snapshots.
// The disclosed openings are for reproducibility only; they are not claimed private.
func GenerateFixtures(dir string) error {
	openings := []Opening{
		{Portfolio: "desk-1/portfolio-7", Version: 1, SaltHex: hex.EncodeToString(sliceOf(NewSalt())), Holdings: [4]uint32{10, 20, 20, 30}},
		{Portfolio: "desk-1/portfolio-7", Version: 2, SaltHex: hex.EncodeToString(sliceOf(NewSalt())), Holdings: [4]uint32{20, 30, 30, 40}},
	}
	auth, err := NewAuthority(openings)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ob, _ := json.MarshalIndent(map[string]any{"note": "SYNTHETIC private openings (worker and offline oracle). Disclosed for reproducibility; never claimed private. Not read by the requester.", "openings": openings}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "openings.json"), ob, 0o644); err != nil {
		return err
	}
	ab, _ := json.MarshalIndent(map[string]any{"note": "PUBLIC trusted fixture authority: ordered snapshot history (commitments only). The requester reads this; the worker cannot write it.", "commitment": "sha256(" + CommitDomain + " || 0 || portfolio || 0 || version u32 LE || salt[32] || h1..h4 u32 LE)", "limit": Limit, "history": auth.history}, "", "  ")
	return os.WriteFile(filepath.Join(dir, "authority.json"), ab, 0o644)
}

func sliceOf(s [32]byte) []byte { return s[:] }

func LoadOpenings(path string) ([]Opening, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Openings []Opening `json:"openings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("openings: %w", err)
	}
	return doc.Openings, nil
}

func OpeningFor(openings []Opening, version uint32) (Opening, bool) {
	for _, o := range openings {
		if o.Version == version {
			return o, true
		}
	}
	return Opening{}, false
}
