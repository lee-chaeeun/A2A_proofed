// Package wire defines the JSON payloads carried in A2A DataParts between the
// requester and the agents, the policy vocabulary, the software-challenge binding
// and the TLS channel-binding derivation.
package wire

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Base policy names. The first five are the v1 (historical) definitions and keep
// their v1 semantics; S-env is the v2 matched software-envelope control.
const (
	PolicyC     = "C"
	PolicySFile = "S-file"
	PolicySIso  = "S-iso"
	PolicySEnv  = "S-env"
	PolicyT     = "T"
	PolicyP     = "P"
)

// Modifiers (v2 transport controls), appended as "+url", "+tls", "+cb".
const (
	ModURL = "url" // signed-card interface URL must equal the discovery endpoint
	ModTLS = "tls" // authenticated HTTPS; peer name must be the enrolled name (implies url)
	ModCB  = "cb"  // RFC 9266 tls-exporter channel binding in every signed proof (implies tls)
)

// Policy is a parsed policy string.
type Policy struct {
	Base string
	URL  bool
	TLS  bool
	CB   bool
}

func (p Policy) String() string {
	s := p.Base
	if p.URL && !p.TLS {
		s += "+url"
	}
	if p.TLS && !p.CB {
		s += "+tls"
	}
	if p.CB {
		s += "+cb"
	}
	return s
}

// HasProof reports whether the base policy requires a fresh proof (nonce session).
func (p Policy) HasProof() bool { return p.Base != PolicyC }

var bases = map[string]bool{PolicyC: true, PolicySFile: true, PolicySIso: true, PolicySEnv: true, PolicyT: true, PolicyP: true}

// ErrUnknownPolicy is returned for any policy string outside the closed vocabulary.
var ErrUnknownPolicy = errors.New("unknown policy")

// ParsePolicy parses "Base[+mod]*" and rejects anything unknown. Modifier
// implication: cb ⇒ tls ⇒ url.
func ParsePolicy(s string) (Policy, error) {
	parts := strings.Split(s, "+")
	p := Policy{Base: parts[0]}
	if !bases[p.Base] {
		return Policy{}, fmt.Errorf("%w: %q", ErrUnknownPolicy, s)
	}
	for _, m := range parts[1:] {
		switch m {
		case ModURL:
			p.URL = true
		case ModTLS:
			p.TLS = true
		case ModCB:
			p.CB = true
		default:
			return Policy{}, fmt.Errorf("%w: modifier %q in %q", ErrUnknownPolicy, m, s)
		}
	}
	if p.CB {
		p.TLS = true
	}
	if p.TLS {
		p.URL = true
	}
	return p, nil
}

// V1Policies are the historical baseline definitions.
var V1Policies = []string{PolicyC, PolicySFile, PolicySIso, PolicyT, PolicyP}

// Challenge is sent by the requester (type "challenge").
type Challenge struct {
	Type               string            `json:"type"`
	Policy             string            `json:"policy"`
	Nonce              string            `json:"nonce"` // base64 32 bytes, as issued
	ExpectedDeployment string            `json:"expected_deployment"`
	Action             string            `json:"action"`
	Audience           string            `json:"audience,omitempty"` // requester identity for S-env
	Binding            string            `json:"binding,omitempty"`  // "" or "tls-exporter"
	Hooks              map[string]string `json:"hooks,omitempty"`    // lab-only test hooks
}

// Evidence is the agent's answer (type "evidence"). Fields are policy-specific.
type Evidence struct {
	Type         string `json:"type"`
	Policy       string `json:"policy"`
	DeploymentID string `json:"deployment_id"`
	Nonce        string `json:"nonce"`
	Timestamp    string `json:"timestamp"` // RFC3339; UNAUTHENTICATED outer metadata for C/S/T
	// S policies
	SigAlg string `json:"sig_alg,omitempty"`
	SigKID string `json:"sig_kid,omitempty"`
	Sig    string `json:"sig,omitempty"` // base64 ASN.1 ECDSA over Binding()
	// T policy
	Quote *QuoteEvidence `json:"quote,omitempty"`
	// P policy (PTV COSE_Sign1) and S-env (software COSE_Sign1)
	COSESign1 string `json:"cose_sign1,omitempty"` // base64 of exact COSE_Sign1 bytes
	// Channel binding the agent derived from ITS OWN TLS connection (diagnostic; the
	// verifier never trusts this value, it recomputes its own).
	CBHex string `json:"cb_hex,omitempty"`
	Error string `json:"error,omitempty"`
}

type QuoteEvidence struct {
	Quoted    string `json:"quoted"`    // base64 TPMS_ATTEST
	Signature string `json:"signature"` // base64 TPMT_SIGNATURE
	Bank      string `json:"bank"`
	Index     int    `json:"index"`
	PCRValue  string `json:"pcr_value_hex"`
	AKName    string `json:"ak_name"`
}

// Job is the synthetic job release (type "job").
type Job struct {
	Type       string `json:"type"`
	Token      string `json:"token"`
	Nonce      string `json:"nonce"`
	DecisionID string `json:"decision_id,omitempty"` // causal id echoed by the recipient in job_received
}

type JobAck struct {
	Type          string `json:"type"`
	DeploymentID  string `json:"deployment_id"`
	Token         string `json:"token"`
	PCRAtReceipt  string `json:"pcr_at_receipt_hex,omitempty"` // honest agents report their PCR 16 when the job lands
	ReceivedAtUTC string `json:"received_at,omitempty"`
}

func NewNonce() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func B64(b []byte) string            { return base64.StdEncoding.EncodeToString(b) }
func UnB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// Binding is the digest signed by the S policies.
func Binding(nonce []byte, deploymentID, action string) []byte {
	h := sha256.New()
	h.Write([]byte("a2aid-challenge-v1\x00"))
	h.Write(nonce)
	h.Write([]byte("\x00" + deploymentID + "\x00" + action))
	return h.Sum(nil)
}

// CBLabel is the RFC 9266 exporter label.
const CBLabel = "EXPORTER-Channel-Binding"

// BoundNonce (v2, retained) derives sha256("a2aid-cb-v1" || nonce || cb), or the
// nonce unchanged when cb is empty. It is kept only so the v2 reproduction and the
// chosen-nonce attacker can compute the value the v2 verifier expected. Production
// code uses ProofContext.
func BoundNonce(nonce, cb []byte) []byte {
	if len(cb) == 0 {
		return nonce
	}
	h := sha256.New()
	h.Write([]byte("a2aid-cb-v1\x00"))
	h.Write(nonce)
	h.Write([]byte{0})
	h.Write(cb)
	return h.Sum(nil)
}

// ProofDomain is the version tag the signed proof context commits to.
const ProofDomain = "a2aid-proof-v3"

// ProofContext is the domain-separated 32-byte value every proof commits to, in
// place of a raw attacker-chosen nonce. It binds the exact policy string and, for a
// channel-bound policy, the signer's OWN TLS exporter:
//
//	sha256(ProofDomain \0 policy \0 issuedNonce \0 selfExporter)
//
// The signer computes it from its own parsed policy and its own connection, and the
// verifier from its own policy and the connection it terminated; neither trusts a
// value supplied in the message. Consequences:
//   - a proof made under policy X cannot satisfy a verifier running policy Y
//     (different domain), so a weaker mode is not an oracle for a stronger one;
//   - a +cb proof is bound to the signer's exporter, so a relay that terminates a
//     different connection produces a different, non-matching value even if it can
//     make the honest signer sign (the signer mixes ITS exporter, not the relay's).
//
// selfExporter is empty for non-+cb policies; the policy string still domain-separates.
func ProofContext(policy string, issuedNonce, selfExporter []byte) []byte {
	h := sha256.New()
	h.Write([]byte(ProofDomain))
	h.Write([]byte{0})
	h.Write([]byte(policy))
	h.Write([]byte{0})
	h.Write(issuedNonce)
	h.Write([]byte{0})
	h.Write(selfExporter)
	return h.Sum(nil)
}

func SignBinding(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, key, digest)
}

func VerifyBinding(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	if pub == nil || len(sig) == 0 {
		return false
	}
	return ecdsa.VerifyASN1(pub, digest, sig)
}

// ToMap converts a struct to the map[string]any that a2a DataParts carry.
func ToMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// FromMap decodes a DataPart map into a struct.
func FromMap(m any, out any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// NormalizeURL implements the documented endpoint-equality policy: absolute http(s)
// URL, lowercase scheme and host, default port removed, empty path and "/" equal,
// no userinfo, query or fragment. Anything else is an error (fail closed).
func NormalizeURL(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("not an absolute http(s) URL: %q", s)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("userinfo, query or fragment not allowed in an endpoint URL: %q", s)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || !validHost(host) {
		return "", fmt.Errorf("invalid host %q in %q", host, s)
	}
	if strings.Contains(host, ":") { // IPv6 literal: must have been bracketed, and is re-bracketed
		if !strings.HasPrefix(u.Host, "[") {
			return "", fmt.Errorf("unbracketed IPv6 host in %q", s)
		}
		host = "[" + host + "]"
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid port in %q", s)
		}
		port = strconv.Itoa(n)
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	hp := host
	if port != "" {
		hp = host + ":" + port
	}
	// Trailing slashes (any number) are insignificant; "" and "/" are the same root.
	path := strings.TrimRight(u.EscapedPath(), "/")
	if strings.Contains(path, "//") {
		return "", fmt.Errorf("empty path segment in %q", s)
	}
	return strings.ToLower(u.Scheme) + "://" + hp + path, nil
}

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// validHost accepts an IPv4/IPv6 literal or a lowercase DNS name.
func validHost(h string) bool {
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return true
	}
	return hostRE.MatchString(h)
}

// SortedKeys is a small helper for deterministic output.
func SortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
