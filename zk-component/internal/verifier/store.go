package verifier

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// DefaultNonceTTL bounds the life of an ISSUED, UNUSED nonce (issuance/session
// freshness). It is distinct from the PTV signed-envelope timestamp window
// (ptv.FreshnessWindow, 300 s), which judges the attester's clock claim.
const DefaultNonceTTL = 120 * time.Second

// Session is one issued verifier nonce (draft §4.2, verifier-issued mode).
type Session struct {
	Nonce      string    `json:"nonce"`
	Expected   string    `json:"expected_deployment"`
	Action     string    `json:"action"`
	Policy     string    `json:"policy"`
	Audience   string    `json:"audience,omitempty"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Consumed   bool      `json:"consumed"`
	ConsumedAt time.Time `json:"consumed_at,omitempty"`
	Result     string    `json:"result,omitempty"`
	Released   bool      `json:"released"`
	JobToken   string    `json:"job_token,omitempty"`
	Appraisals int       `json:"appraisals"`
}

var (
	ErrUnknownNonce  = errors.New("nonce not associated with an issued session")
	ErrConsumedNonce = errors.New("nonce already consumed")
	ErrExpiredNonce  = errors.New("nonce session expired")
)

// Store is an isolated, in-memory session store (one per policy/fixture cell).
// It is NOT durable: a process restart forgets issued nonces and release flags.
type Store struct {
	mu   sync.Mutex
	sess map[string]*Session
	Now  func() time.Time
	TTL  time.Duration
}

func NewStore() *Store {
	return &Store{sess: map[string]*Session{}, Now: time.Now, TTL: DefaultNonceTTL}
}

func (s *Store) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func (s *Store) Issue(nonce, expected, action, policy, audience string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.now()
	se := &Session{Nonce: nonce, Expected: expected, Action: action, Policy: policy, Audience: audience, IssuedAt: n, ExpiresAt: n.Add(s.TTL)}
	s.sess[nonce] = se
	return se
}

// Claim atomically consumes an issued nonce on first appraisal (success or failure,
// draft §4.2). An expired session is consumed as well and reported as expired: a
// nonce is valid strictly before its expiry instant (now < ExpiresAt).
func (s *Store) Claim(nonce string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	se, ok := s.sess[nonce]
	if !ok {
		return nil, ErrUnknownNonce
	}
	se.Appraisals++
	if se.Consumed {
		return se, ErrConsumedNonce
	}
	se.Consumed = true
	se.ConsumedAt = s.now()
	if !se.ConsumedAt.Before(se.ExpiresAt) {
		return se, ErrExpiredNonce
	}
	return se, nil
}

// Get returns a copy of a session without consuming it.
func (s *Store) Get(nonce string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	se, ok := s.sess[nonce]
	if !ok {
		return Session{}, false
	}
	return *se, true
}

func (s *Store) SetResult(nonce, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if se := s.sess[nonce]; se != nil {
		se.Result = result
	}
}

// TryRelease returns a job token exactly once per nonce within this process
// (idempotent release flag; in-memory, not durable exactly-once execution).
func (s *Store) TryRelease(nonce string) (token string, first bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.sess[nonce]
	if se == nil {
		return "", false
	}
	if se.Released {
		return se.JobToken, false
	}
	b := make([]byte, 12)
	rand.Read(b)
	se.Released, se.JobToken = true, hex.EncodeToString(b)
	return se.JobToken, true
}

func (s *Store) Dump() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Session, 0, len(s.sess))
	for _, se := range s.sess {
		c := *se
		out = append(out, &c)
	}
	return out
}
