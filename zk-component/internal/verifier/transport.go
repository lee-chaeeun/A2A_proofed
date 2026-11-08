package verifier

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"a2aid/internal/wire"
)

// ConnRecord is the requester's own observation of one TLS connection it opened
// during a decision: a per-decision id (dial order), the authenticated peer
// certificate fingerprint and the RFC 9266 exporter. It is evidence the requester
// observed itself; nothing in it comes from the agent.
type ConnRecord struct {
	ID             int    `json:"conn_id"`
	PeerCertSHA256 string `json:"peer_cert_sha256,omitempty"`
	PeerName       string `json:"peer_name,omitempty"`
	ExporterHex    string `json:"exporter_hex,omitempty"`
	TLSVersion     string `json:"tls_version,omitempty"`
}

// connRecorder keeps every TLS connection one decision opened, so the requester can
// (a) report which authenticated peer it actually talked to, (b) derive its OWN
// RFC 9266 tls-exporter channel binding, independent of anything the agent says,
// and (c) refuse any new connection once the proof connection is sealed.
type connRecorder struct {
	mu      sync.Mutex
	conns   []*tls.Conn
	recs    []ConnRecord
	sealed  bool
	dials   int // TLS dials attempted (including refused ones after sealing)
	refused int // dials refused because the recorder was sealed
}

// seal freezes the set of connections after a successful appraisal. A job may only
// reuse a connection that carried the proof; opening a NEW TLS connection after this
// is refused BEFORE the dial, so a job is never written to a connection the proof
// did not use (v3 P0-B fix). A legitimate reconnect must obtain a fresh proof (a new
// decision).
func (c *connRecorder) seal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sealed = true
}

// ErrSealed is returned when the transport tries to open a new connection after the
// proof connection was sealed.
var ErrSealed = errors.New("reconnect after proof not allowed; a fresh proof is required before dispatch")

// preDial accounts for a dial attempt and refuses it when sealed (no bytes are sent).
func (c *connRecorder) preDial() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dials++
	if c.sealed {
		c.refused++
		return ErrSealed
	}
	return nil
}

func (c *connRecorder) add(conn *tls.Conn) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealed { // the dial raced with the seal: still refuse, close and count it
		c.refused++
		return 0, ErrSealed
	}
	c.conns = append(c.conns, conn)
	id := len(c.conns)
	rec := ConnRecord{ID: id}
	cs := conn.ConnectionState()
	rec.TLSVersion = tls.VersionName(cs.Version)
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		rec.PeerCertSHA256 = hex.EncodeToString(sha256Sum(leaf.Raw))
		if len(leaf.DNSNames) > 0 {
			rec.PeerName = leaf.DNSNames[0]
		} else {
			rec.PeerName = leaf.Subject.CommonName
		}
	}
	if b, err := cs.ExportKeyingMaterial(wire.CBLabel, nil, 32); err == nil && len(b) > 0 {
		rec.ExporterHex = hex.EncodeToString(b)
	}
	c.recs = append(c.recs, rec)
	return id, nil
}

func (c *connRecorder) all() []*tls.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*tls.Conn(nil), c.conns...)
}

// records returns a copy of the per-connection observations.
func (c *connRecorder) records() []ConnRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ConnRecord(nil), c.recs...)
}

// idOf maps a net.Conn handed back by the HTTP transport (httptrace GotConn) to the
// recorder's connection id; 0 when it is not one of ours.
func (c *connRecorder) idOf(conn net.Conn) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, tc := range c.conns {
		if net.Conn(tc) == conn {
			return i + 1
		}
	}
	return 0
}

// counters returns (dials, refused).
func (c *connRecorder) counters() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dials, c.refused
}

// ekms returns the exporter value of every recorded connection (hex -> bytes).
func (c *connRecorder) ekms() map[string][]byte {
	out := map[string][]byte{}
	for _, conn := range c.all() {
		cs := conn.ConnectionState()
		if !cs.HandshakeComplete {
			continue
		}
		b, err := cs.ExportKeyingMaterial(wire.CBLabel, nil, 32)
		if err != nil || len(b) == 0 {
			continue
		}
		out[hex.EncodeToString(b)] = b
	}
	return out
}

// ErrRedirect is returned for any HTTP redirect: the endpoint policy is fail-closed,
// a discovery or JSON-RPC URL that redirects is treated as a failed connection.
var ErrRedirect = errors.New("redirects are not followed (fail-closed endpoint policy)")

// newHTTP builds the per-decision HTTP client. Name resolution goes through the
// requester's lab resolver (addr -> addr), TLS always validates the server
// certificate against the lab root CA for the URL's host name (standard
// validation), minimum TLS 1.3 so that exporters are defined, HTTP/1.1 only.
// InsecureSkipVerify is never set anywhere in this code base.
func (r *Requester) newHTTP(rec *connRecorder) *http.Client {
	resolve := func(addr string) string {
		if r.Resolver != nil {
			if to, ok := r.Resolver[addr]; ok {
				return to
			}
		}
		return addr
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: false,
		MaxConnsPerHost:   1,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{}, // disable h2
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, resolve(addr))
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if err := rec.preDial(); err != nil { // refused before any dial once sealed
				return nil, err
			}
			raw, err := dialer.DialContext(ctx, network, resolve(addr))
			if err != nil {
				return nil, err
			}
			cfg := &tls.Config{RootCAs: r.RootCAs, ServerName: host, MinVersion: tls.VersionTLS13}
			tc := tls.Client(raw, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			if _, err := rec.add(tc); err != nil { // refused if sealed meanwhile
				tc.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	to := r.HTTPTimeout
	if to == 0 {
		to = 20 * time.Second
	}
	return &http.Client{Timeout: to, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect }}
}

// tlsVerdictFrom summarises the authenticated peer of the recorded connections and
// compares it with the ENROLLED name of the expected deployment (not the URL).
func tlsVerdictFrom(rec *connRecorder, expectedName string) *TLSVerdict {
	v := &TLSVerdict{ExpectedName: expectedName}
	conns := rec.all()
	v.Conns = len(conns)
	if len(conns) == 0 {
		v.Reason = "no TLS connection was used"
		return v
	}
	cs := conns[len(conns)-1].ConnectionState()
	v.Used = true
	v.Version = tls.VersionName(cs.Version)
	if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		v.Reason = "peer certificate not verified"
		return v
	}
	v.Authenticated = true
	leaf := cs.PeerCertificates[0]
	if len(leaf.DNSNames) > 0 {
		v.PeerName = leaf.DNSNames[0]
	} else {
		v.PeerName = leaf.Subject.CommonName
	}
	v.PeerCertSHA256 = hex.EncodeToString(sha256Sum(leaf.Raw))
	if expectedName != "" && leaf.VerifyHostname(expectedName) == nil {
		v.NameMatch = true
	} else {
		v.Reason = "authenticated peer " + v.PeerName + " is not the enrolled name " + expectedName
	}
	// Every connection of this decision must authenticate the same identity.
	for _, c := range conns[:len(conns)-1] {
		s := c.ConnectionState()
		if len(s.PeerCertificates) == 0 || !s.PeerCertificates[0].Equal(leaf) {
			v.NameMatch = false
			v.Reason = "connections of one decision authenticated different peers"
		}
	}
	return v
}

func sha256Sum(b []byte) []byte {
	h := x509Sha256(b)
	return h[:]
}
