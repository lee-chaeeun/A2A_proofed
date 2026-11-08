package zk

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuthorityEntry is one PUBLIC snapshot record (no salt, no holdings).
type AuthorityEntry struct {
	Portfolio     string `json:"portfolio"`
	Version       uint32 `json:"version"`
	CommitmentHex string `json:"commitment_hex"`
}

// Authority is the trusted fixture authority: the ordered snapshot history of one
// portfolio and the current head. The requester reads it through the read-only
// methods; only the test controller advances it. The same mutex also serializes the
// Current-contract approval decision (see Ledger.Approve), so "compare head and
// insert approval" is one critical section whose linearization point is the insert.
type Authority struct {
	mu      sync.Mutex
	history []AuthorityEntry
	head    int // index into history
	Events  []Event
}

// Event is an ordered controller-side record (authority updates and approvals).
type Event struct {
	Seq    int            `json:"seq"`
	Kind   string         `json:"kind"`
	At     string         `json:"at"`
	Fields map[string]any `json:"fields,omitempty"`
}

func LoadAuthority(path string) (*Authority, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		History []AuthorityEntry `json:"history"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}
	if len(doc.History) == 0 {
		return nil, errors.New("authority history is empty")
	}
	for i, e := range doc.History {
		if e.Version != uint32(i+1) {
			return nil, fmt.Errorf("authority versions must be 1..n in order (got %d at %d)", e.Version, i)
		}
		if b, err := hex.DecodeString(e.CommitmentHex); err != nil || len(b) != 32 {
			return nil, fmt.Errorf("authority v%d commitment is not 32 bytes of hex", e.Version)
		}
	}
	return &Authority{history: doc.History, head: 0}, nil
}

// NewAuthority builds an authority from openings (test/fixture generation only).
func NewAuthority(openings []Opening) (*Authority, error) {
	a := &Authority{}
	for i, o := range openings {
		c, err := o.Commitment()
		if err != nil {
			return nil, err
		}
		if o.Version != uint32(i+1) {
			return nil, fmt.Errorf("openings must be versions 1..n in order")
		}
		a.history = append(a.history, AuthorityEntry{Portfolio: o.Portfolio, Version: o.Version, CommitmentHex: hex.EncodeToString(c[:])})
	}
	return a, nil
}

// event appends an ordered controller-side record and returns its sequence number
// (1-based, gap-free). Callers hold a.mu or are the single-threaded test controller.
func (a *Authority) event(kind string, f map[string]any) int {
	seq := len(a.Events) + 1
	a.Events = append(a.Events, Event{Seq: seq, Kind: kind, At: time.Now().UTC().Format(time.RFC3339Nano), Fields: f})
	return seq
}

// Record appends a controller-side event from the test controller (matrix). It takes
// the mutex so it can never interleave with an evaluation's critical section.
func (a *Authority) Record(kind string, f map[string]any) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.event(kind, f)
}

// Head returns the authoritative (version, commitment) now. Read-only.
func (a *Authority) Head() (uint32, [32]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.headLocked()
}

func (a *Authority) headLocked() (uint32, [32]byte) {
	e := a.history[a.head]
	var c [32]byte
	b, _ := hex.DecodeString(e.CommitmentHex)
	copy(c[:], b)
	return e.Version, c
}

// Commitment returns the trusted commitment of a specific version (0 if unknown).
func (a *Authority) Commitment(version uint32) ([32]byte, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.commitmentLocked(version)
}

func (a *Authority) commitmentLocked(version uint32) ([32]byte, bool) {
	if version == 0 || int(version) > len(a.history) {
		return [32]byte{}, false
	}
	var c [32]byte
	b, _ := hex.DecodeString(a.history[version-1].CommitmentHex)
	copy(c[:], b)
	return c, true
}

// Advance moves the head to the next version (test controller only).
func (a *Authority) Advance() (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.head+1 >= len(a.history) {
		return 0, errors.New("no newer snapshot")
	}
	a.head++
	v, c := a.headLocked()
	a.event("authority_update", map[string]any{"head_version": v, "commitment_hex": hex.EncodeToString(c[:])})
	return v, nil
}

// Reset returns the head to version 1 (between isolated cells).
func (a *Authority) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.head = 0
	a.event("authority_reset", map[string]any{"head_version": 1})
}

func (a *Authority) Versions() int { return len(a.history) }
