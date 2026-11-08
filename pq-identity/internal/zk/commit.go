// Package zk is the proof-carrying task-result component: canonical commitment and
// journal encodings (mirrored by the Rust guest), the trusted fixture authority, the
// requester-side request/contract store, the serialized approval ledger, the four
// relying-party policies, and the subprocess bridge to the local RISC Zero prover and
// verifier CLIs. Nothing here verifies a receipt itself; verification happens in the
// pinned `zkverify` binary and only the VERIFIED journal is interpreted.
package zk

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Encoding constants, mirrored byte-for-byte by zk/methods/guest/src/main.rs.
const (
	CommitDomain  = "a2aid-zk-commit-v1"
	JournalSchema = uint32(1)
	Limit         = uint64(100)
	MaxHolding    = uint32(1 << 20)
	JournalLen    = 4 + 16 + 32 + 8 + 1
)

// Opening is the private witness of one snapshot (held by the worker and the
// offline oracle; disclosed in fixtures/zk/openings.json for reproducibility).
type Opening struct {
	Portfolio string    `json:"portfolio"`
	Version   uint32    `json:"version"`
	SaltHex   string    `json:"salt_hex"`
	Holdings  [4]uint32 `json:"holdings"`
}

// Commitment = SHA-256(domain ‖ 0 ‖ portfolio ‖ 0 ‖ version u32 LE ‖ salt[32] ‖ h1..h4 u32 LE).
func Commitment(portfolio string, version uint32, salt [32]byte, holdings [4]uint32) [32]byte {
	h := sha256.New()
	h.Write([]byte(CommitDomain))
	h.Write([]byte{0})
	h.Write([]byte(portfolio))
	h.Write([]byte{0})
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], version)
	h.Write(b4[:])
	h.Write(salt[:])
	for _, v := range holdings {
		binary.LittleEndian.PutUint32(b4[:], v)
		h.Write(b4[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Sum and Pass are what the guest computes; the oracle recomputes them from openings.
func Sum(h [4]uint32) uint64 {
	var s uint64
	for _, v := range h {
		s += uint64(v)
	}
	return s
}
func Pass(h [4]uint32) bool { return Sum(h) <= Limit }

func (o Opening) Salt() ([32]byte, error) {
	var s [32]byte
	b, err := hex.DecodeString(o.SaltHex)
	if err != nil || len(b) != 32 {
		return s, errors.New("salt must be 32 bytes of hex")
	}
	copy(s[:], b)
	return s, nil
}

func (o Opening) Commitment() ([32]byte, error) {
	s, err := o.Salt()
	if err != nil {
		return [32]byte{}, err
	}
	return Commitment(o.Portfolio, o.Version, s, o.Holdings), nil
}

// Journal is the decoded VERIFIED public output of the guest.
type Journal struct {
	Schema     uint32
	Challenge  [16]byte
	Commitment [32]byte
	Limit      uint64
	Pass       bool
}

// ParseJournal decodes the canonical journal; any deviation is an error.
func ParseJournal(b []byte) (Journal, error) {
	var j Journal
	if len(b) != JournalLen {
		return j, fmt.Errorf("journal length %d != %d", len(b), JournalLen)
	}
	j.Schema = binary.LittleEndian.Uint32(b[0:4])
	if j.Schema != JournalSchema {
		return j, fmt.Errorf("journal schema %d != %d", j.Schema, JournalSchema)
	}
	copy(j.Challenge[:], b[4:20])
	copy(j.Commitment[:], b[20:52])
	j.Limit = binary.LittleEndian.Uint64(b[52:60])
	if j.Limit != Limit {
		return j, fmt.Errorf("journal limit %d != %d", j.Limit, Limit)
	}
	switch b[60] {
	case 0:
		j.Pass = false
	case 1:
		j.Pass = true
	default:
		return j, fmt.Errorf("journal pass byte %d is not 0/1", b[60])
	}
	return j, nil
}

// NewChallenge returns a fresh 128-bit requester challenge.
func NewChallenge() [16]byte {
	var c [16]byte
	if _, err := rand.Read(c[:]); err != nil {
		panic(err)
	}
	return c
}

func NewSalt() [32]byte {
	var s [32]byte
	if _, err := rand.Read(s[:]); err != nil {
		panic(err)
	}
	return s
}
