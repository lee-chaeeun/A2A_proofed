// Package gate is the signer access boundary. It fronts each swtpm data socket and
// each isolated software signer with a unix socket whose peer process is identified
// by SO_PEERCRED pid and mapped to a label registered by the runner. An ACL per
// signer decides which labels may connect. Every decision is reported to the
// controller. This is a HARNESS-ENFORCED boundary: all processes share one OS
// account, so the OS itself does not isolate them.
package gate

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"a2aid/internal/ctl"
	"a2aid/internal/wire"
)

type Signer struct {
	Name     string // tpmA, tpmB, swA, swB
	Kind     string // "tpm" (proxy to Upstream) or "sw" (in-process ECDSA signer)
	Listen   string // gate socket path
	Upstream string // swtpm socket for tpm kind
	Key      *ecdsa.PrivateKey
	Token    string // required auth token for sw kind (equivalent of the AK password)
}

type Gate struct {
	mu      sync.Mutex
	labels  map[int32]string    // pid -> label
	acl     map[string][]string // signer -> allowed labels
	signers map[string]*Signer
	ctl     *ctl.Client
}

func New(c *ctl.Client) *Gate {
	return &Gate{labels: map[int32]string{}, acl: map[string][]string{}, signers: map[string]*Signer{}, ctl: c}
}

func (g *Gate) Add(s *Signer) { g.signers[s.Name] = s }

// AdminHandler: POST /pids {"pid":label}, POST /acl {"signer":["A"]}, GET /acl
func (g *Gate) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pids", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		g.mu.Lock()
		for pid, label := range m {
			var p int32
			fmt.Sscanf(pid, "%d", &p)
			g.labels[p] = label
		}
		g.mu.Unlock()
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /acl", func(w http.ResponseWriter, r *http.Request) {
		var m map[string][]string
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		g.mu.Lock()
		g.acl = m
		g.mu.Unlock()
		g.ctl.Emit("gate_acl_set", map[string]any{"acl": m})
		w.WriteHeader(204)
	})
	// POST /signers adds a TPM proxy entry at runtime (emulator-state clone fixture).
	mux.HandleFunc("POST /signers", func(w http.ResponseWriter, r *http.Request) {
		var s Signer
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil || s.Kind != "tpm" || s.Name == "" || s.Listen == "" || s.Upstream == "" {
			http.Error(w, "bad signer", 400)
			return
		}
		g.mu.Lock()
		_, exists := g.signers[s.Name]
		if !exists {
			g.signers[s.Name] = &s
		}
		g.mu.Unlock()
		if !exists {
			if err := g.listen(&s); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}
		g.ctl.Emit("gate_signer_added", map[string]any{"signer": s.Name, "upstream": s.Upstream})
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /acl", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"acl": g.acl, "pids": g.labels})
	})
	return mux
}

// ownerOf maps a signer name (tpmA, swB, tpmAclone) to the deployment label whose
// key material it holds.
func ownerOf(name string) string {
	for _, p := range []string{"tpm", "sw"} {
		if len(name) > len(p) && name[:len(p)] == p {
			return name[len(p) : len(p)+1]
		}
	}
	return ""
}

func peerPID(c net.Conn) int32 {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1
	}
	var pid int32 = -1
	raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err == nil {
			pid = cred.Pid
		}
	})
	return pid
}

func (g *Gate) allowed(signer string, pid int32) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	label, ok := g.labels[pid]
	if !ok {
		label = "unregistered"
	}
	for _, l := range g.acl[signer] {
		if l == label {
			return label, true
		}
	}
	return label, false
}

func (g *Gate) listen(s *Signer) error {
	os.Remove(s.Listen)
	ln, err := net.Listen("unix", s.Listen)
	if err != nil {
		return err
	}
	os.Chmod(s.Listen, 0o600)
	go g.accept(ln, s)
	return nil
}

// Serve listens on every signer socket (blocking).
func (g *Gate) Serve() error {
	g.mu.Lock()
	signers := make([]*Signer, 0, len(g.signers))
	for _, s := range g.signers {
		signers = append(signers, s)
	}
	g.mu.Unlock()
	for _, s := range signers {
		if err := g.listen(s); err != nil {
			return err
		}
	}
	select {}
}

func (g *Gate) accept(ln net.Listener, s *Signer) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go g.handle(c, s)
	}
}

func (g *Gate) handle(c net.Conn, s *Signer) {
	defer c.Close()
	pid := peerPID(c)
	label, ok := g.allowed(s.Name, pid)
	g.ctl.Emit("gate_conn", map[string]any{"signer": s.Name, "kind": s.Kind, "owner": ownerOf(s.Name), "peer_pid": pid, "peer_label": label, "allowed": ok})
	if !ok {
		return // connection closed: the client sees EOF
	}
	switch s.Kind {
	case "tpm":
		up, err := net.Dial("unix", s.Upstream)
		if err != nil {
			g.ctl.Emit("gate_error", map[string]any{"signer": s.Name, "err": err.Error()})
			return
		}
		defer up.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(up, c); done <- struct{}{} }()
		go func() { io.Copy(c, up); done <- struct{}{} }()
		<-done
	case "sw":
		g.serveSoftware(c, s, label)
	}
}

// Software signer protocol: one JSON line request -> one JSON line response.
type SWRequest struct {
	Token  string `json:"token"`
	Digest string `json:"digest"` // base64 sha256 digest to sign
}
type SWResponse struct {
	Sig   string `json:"sig,omitempty"`
	Error string `json:"error,omitempty"`
}

func (g *Gate) serveSoftware(c net.Conn, s *Signer, label string) {
	rd := bufio.NewReader(c)
	line, err := rd.ReadBytes('\n')
	if err != nil {
		return
	}
	var req SWRequest
	resp := SWResponse{}
	if json.Unmarshal(line, &req) != nil {
		resp.Error = "bad request"
	} else if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.Token)) != 1 {
		resp.Error = "auth failure"
		g.ctl.Emit("sw_signer_auth_fail", map[string]any{"signer": s.Name, "peer_label": label})
	} else if d, err := wire.UnB64(req.Digest); err != nil || len(d) != 32 {
		resp.Error = "bad digest"
	} else if sig, err := wire.SignBinding(s.Key, d); err != nil {
		resp.Error = err.Error()
	} else {
		resp.Sig = wire.B64(sig)
		g.ctl.Emit("sw_signer_signed", map[string]any{"signer": s.Name, "peer_label": label})
	}
	b, _ := json.Marshal(resp)
	c.Write(append(b, '\n'))
}

// SignViaGate is the client side used by agents for S-iso.
func SignViaGate(sock, token string, digest []byte) ([]byte, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("gate dial: %w", err)
	}
	defer c.Close()
	b, _ := json.Marshal(SWRequest{Token: token, Digest: wire.B64(digest)})
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("gate denied or closed: %w", err)
	}
	var resp SWResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("signer: %s", resp.Error)
	}
	return wire.UnB64(resp.Sig)
}
