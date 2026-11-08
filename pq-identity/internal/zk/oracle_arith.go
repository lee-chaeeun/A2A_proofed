package zk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Independent scorer routines. These are written separately from commit.go so that
// the offline oracle does not call the production helpers (Commitment, Sum, Pass,
// ParseJournal, LoadOpenings); zk_test.go asserts that both implementations agree on
// vectors. The proof system itself is NOT reimplemented: receipt validity comes from
// re-running the pinned verifier CLI (see oracle.go), which is a shared component.

const (
	oracleDomain     = "a2aid-zk-commit-v1"
	oracleLimit      = 100
	oracleJournalLen = 61
)

type oracleOpening struct {
	Portfolio string    `json:"portfolio"`
	Version   uint32    `json:"version"`
	SaltHex   string    `json:"salt_hex"`
	Holdings  [4]uint32 `json:"holdings"`
}

// oracleCommitment = SHA-256(domain ‖ 0 ‖ portfolio ‖ 0 ‖ version LE32 ‖ salt ‖ h1..h4 LE32).
func oracleCommitment(portfolio string, version uint32, salt []byte, holdings [4]uint32) ([32]byte, error) {
	if len(salt) != 32 {
		return [32]byte{}, errors.New("salt must be 32 bytes")
	}
	buf := make([]byte, 0, len(oracleDomain)+2+len(portfolio)+4+32+16)
	buf = append(buf, oracleDomain...)
	buf = append(buf, 0)
	buf = append(buf, portfolio...)
	buf = append(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, version)
	buf = append(buf, salt...)
	for i := 0; i < 4; i++ {
		buf = binary.LittleEndian.AppendUint32(buf, holdings[i])
	}
	return sha256.Sum256(buf), nil
}

// oracleSum is the bounded sum the guest computes (u64 accumulation of four u32).
func oracleSum(h [4]uint32) uint64 {
	return uint64(h[0]) + uint64(h[1]) + uint64(h[2]) + uint64(h[3])
}

func oraclePass(h [4]uint32) bool { return oracleSum(h) <= oracleLimit }

type oracleJournal struct {
	challenge  [16]byte
	commitment [32]byte
	pass       bool
}

// oracleParseJournal decodes the canonical 61-byte journal strictly.
func oracleParseJournal(b []byte) (oracleJournal, error) {
	var j oracleJournal
	if len(b) != oracleJournalLen {
		return j, fmt.Errorf("journal length %d", len(b))
	}
	if binary.LittleEndian.Uint32(b[0:4]) != 1 {
		return j, errors.New("journal schema is not 1")
	}
	copy(j.challenge[:], b[4:20])
	copy(j.commitment[:], b[20:52])
	if binary.LittleEndian.Uint64(b[52:60]) != oracleLimit {
		return j, errors.New("journal limit is not 100")
	}
	switch b[60] {
	case 0:
	case 1:
		j.pass = true
	default:
		return j, errors.New("journal pass byte not 0/1")
	}
	return j, nil
}

// oracleLoadOpenings parses the synthetic openings file (oracle side).
func oracleLoadOpenings(path string) ([]oracleOpening, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Openings []oracleOpening `json:"openings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("openings: %w", err)
	}
	if len(doc.Openings) == 0 {
		return nil, errors.New("openings: none")
	}
	return doc.Openings, nil
}
