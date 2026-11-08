// Package matrix orchestrates processes and runs the fixture x policy matrix.
package matrix

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"a2aid/internal/ctl"
	"a2aid/internal/pqdev"
	"a2aid/internal/registry"
	"a2aid/internal/tpmsig"
)

// Lab names and listeners. Names resolve only through the requester's and the
// relay's static resolver (no DNS): a.a2aid.test / b.a2aid.test -> 127.0.0.1.
const (
	ControllerURL = "http://127.0.0.1:9100"
	GateAdminURL  = "http://127.0.0.1:9110"
	AName         = "a.a2aid.test"
	BName         = "b.a2aid.test"
	AURL          = "http://a.a2aid.test:9101"
	BURL          = "http://b.a2aid.test:9102"
	ATLSURL       = "https://a.a2aid.test:9443"
	BTLSURL       = "https://b.a2aid.test:9444"
)

// DefaultResolver is honest name resolution.
var DefaultResolver = map[string]string{
	"a.a2aid.test:9101": "127.0.0.1:9101", "a.a2aid.test:9443": "127.0.0.1:9443",
	"b.a2aid.test:9102": "127.0.0.1:9102", "b.a2aid.test:9444": "127.0.0.1:9444",
}

// HijackResolver sends A's names to B's listeners (address takeover / DNS hijack).
var HijackResolver = map[string]string{
	"a.a2aid.test:9101": "127.0.0.1:9102", "a.a2aid.test:9443": "127.0.0.1:9444",
	"b.a2aid.test:9102": "127.0.0.1:9102", "b.a2aid.test:9444": "127.0.0.1:9444",
}

// Runtime owns the child processes and shared paths for one matrix run.
type Runtime struct {
	RunDir          string
	AbsRun          string
	OutDir          string
	Bin             string
	Reg             *registry.Registry
	Ctl             *ctl.Client
	procs           []*exec.Cmd
	HTTP            *http.Client
	Started         time.Time
	Log             *os.File
	Cmds            []string
	ACLDefault      map[string][]string
	RootCAs         *x509.CertPool
	Clone           *tpmsig.SWTPM
	FWClone         *pqdev.FWTPM
	pqFileKeyBackup *registry.V4Key
}

func (rt *Runtime) logf(format string, a ...any) {
	line := fmt.Sprintf(time.Now().Format("15:04:05.000")+" "+format+"\n", a...)
	fmt.Print(line)
	if rt.Log != nil {
		rt.Log.WriteString(line)
	}
}

func (rt *Runtime) start(name string, args ...string) *exec.Cmd {
	logDir := filepath.Join(rt.OutDir, "process-logs")
	os.MkdirAll(logDir, 0o755)
	f, _ := os.Create(filepath.Join(logDir, name+".log"))
	cmd := exec.Command(rt.Bin, args...)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		panic(fmt.Errorf("start %s: %w", name, err))
	}
	rt.procs = append(rt.procs, cmd)
	rt.Cmds = append(rt.Cmds, rt.Bin+" "+strings.Join(args, " "))
	os.MkdirAll(filepath.Join(rt.AbsRun, "pids"), 0o755)
	os.WriteFile(filepath.Join(rt.AbsRun, "pids", name+".pid"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o644)
	return cmd
}

func (rt *Runtime) waitHTTP(url string) {
	for i := 0; i < 100; i++ {
		resp, err := rt.HTTP.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	panic("not reachable: " + url)
}

func (rt *Runtime) postJSON(url string, v any) error {
	b, _ := json.Marshal(v)
	resp, err := rt.HTTP.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s %s", url, resp.Status, body)
	}
	return nil
}

// Boot starts controller, gate, A and B (HTTP + HTTPS); registers pids; sets the
// default ACL; loads the lab root.
func (rt *Runtime) Boot() {
	caPEM, err := os.ReadFile(filepath.Join(rt.AbsRun, "ca", "ca.pem"))
	if err != nil {
		panic("lab CA missing; run `a2aid setup` first: " + err.Error())
	}
	rt.RootCAs = x509.NewCertPool()
	rt.RootCAs.AppendCertsFromPEM(caPEM)
	rt.start("controller", "controller", "--listen", "127.0.0.1:9100")
	rt.waitHTTP(ControllerURL + "/healthz")
	rt.Ctl = ctl.New(ControllerURL, "operator")
	rt.Ctl.SetCell("boot", filepath.Join(rt.OutDir, "boot"))
	rt.start("gate", "gate", "--config", filepath.Join(rt.AbsRun, "gate", "config.json"), "--admin", "127.0.0.1:9110", "--controller", ControllerURL)
	rt.waitHTTP(GateAdminURL + "/acl")
	ca := filepath.Join(rt.AbsRun, "ca", "ca.pem")
	a := rt.start("agent-A", "agent", "--label", "A", "--listen", "127.0.0.1:9101", "--tls-listen", "127.0.0.1:9443", "--tls-dir", filepath.Join(rt.AbsRun, "A", "tls"), "--ca", ca, "--app-dir", filepath.Join(rt.AbsRun, "A", "app"), "--signer-dir", filepath.Join(rt.AbsRun, "A", "signer"), "--controller", ControllerURL)
	b := rt.start("agent-B", "agent", "--label", "B", "--listen", "127.0.0.1:9102", "--tls-listen", "127.0.0.1:9444", "--tls-dir", filepath.Join(rt.AbsRun, "B", "tls"), "--ca", ca, "--app-dir", filepath.Join(rt.AbsRun, "B", "app"), "--signer-dir", filepath.Join(rt.AbsRun, "B", "signer"), "--controller", ControllerURL)
	rt.waitHTTP("http://127.0.0.1:9101/admin/state")
	rt.waitHTTP("http://127.0.0.1:9102/admin/state")
	pids := map[string]string{fmt.Sprint(a.Process.Pid): "A", fmt.Sprint(b.Process.Pid): "B", fmt.Sprint(os.Getpid()): "operator"}
	if err := rt.postJSON(GateAdminURL+"/pids", pids); err != nil {
		panic(err)
	}
	rt.ACLDefault = map[string][]string{"tpmA": {"A", "operator"}, "tpmB": {"B", "operator"}, "swA": {"A"}, "swB": {"B"},
		"ecA": {"A"}, "pqA": {"A"}, "devA": {"A"}, "ecB": {"B"}, "pqB": {"B"}, "devB": {"B"}, "devAclone": {}}
	rt.SetACL(rt.ACLDefault)
	rt.logf("booted: controller, gate, A(pid %d), B(pid %d), operator pid %d", a.Process.Pid, b.Process.Pid, os.Getpid())
}

func (rt *Runtime) SetACL(acl map[string][]string) {
	if err := rt.postJSON(GateAdminURL+"/acl", acl); err != nil {
		panic(err)
	}
}

// AddGateSigner registers a TPM proxy entry at runtime (clone fixture).
func (rt *Runtime) AddGateSigner(name, listen, upstream string) {
	if err := rt.postJSON(GateAdminURL+"/signers", map[string]string{"Name": name, "Kind": "tpm", "Listen": listen, "Upstream": upstream}); err != nil {
		panic(err)
	}
}

func (rt *Runtime) Shutdown() {
	if rt.Clone != nil {
		rt.Clone.Stop()
	}
	if rt.FWClone != nil {
		rt.FWClone.Stop()
	}
	for _, p := range rt.procs {
		if p.Process != nil {
			p.Process.Kill()
			p.Wait()
		}
	}
}

// SetMode configures an agent before a cell (admin endpoint, plain HTTP loopback).
func (rt *Runtime) SetMode(adminURL string, mode map[string]any) {
	if err := rt.postJSON(adminURL+"/admin/mode", mode); err != nil {
		panic(err)
	}
}

const AAdmin, BAdmin = "http://127.0.0.1:9101", "http://127.0.0.1:9102"

// Publish re-signs and reloads a card (operator action, out of band).
func (rt *Runtime) Publish(label, name, version string, urls []string, adminURL string) {
	cmd := exec.Command(rt.Bin, "publish-card", "--run-dir", rt.AbsRun, "--label", label, "--name", name, "--version", version, "--urls", strings.Join(urls, ","), "--reload", adminURL)
	out, err := cmd.CombinedOutput()
	rt.Cmds = append(rt.Cmds, strings.Join(cmd.Args, " "))
	if err != nil {
		panic(fmt.Errorf("publish: %v %s", err, out))
	}
}

// OperatorTPM opens A's or B's TPM through the gate as the operator.
func (rt *Runtime) OperatorTPM(label string) *tpmsig.Conn {
	c, err := tpmsig.Open(filepath.Join(rt.AbsRun, "gate", "tpm"+label+".sock"))
	if err != nil {
		panic(err)
	}
	return c
}

// CopyManifest records exactly which files B received in a copy fixture.
type CopyManifest struct {
	Fixture  string            `json:"fixture"`
	Source   string            `json:"source"`
	Dest     string            `json:"dest"`
	Included map[string]string `json:"included_sha256"`
	Excluded []string          `json:"excluded"`
	Extra    map[string]any    `json:"extra,omitempty"`
}

// CopyVolume copies A's application volume (and nothing else) for B.
func (rt *Runtime) CopyVolume(fixture string, files []string) CopyManifest {
	src := filepath.Join(rt.AbsRun, "A", "app")
	dst := filepath.Join(rt.AbsRun, "B", "copied-volume", "app")
	os.RemoveAll(dst)
	os.MkdirAll(dst, 0o755)
	m := CopyManifest{Fixture: fixture, Source: src, Dest: dst, Included: map[string]string{},
		Excluded: []string{"run/A/signer/ak_auth (AK password)", "run/A/signer/siso_token", "run/A/signer/siso.key", "run/A/publisher/card.key", "run/A/tls (server certificate key)", "run/tpmA/state (emulator NVRAM holding the AK)", "run/gate/*.sock access (ACL)"}}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			panic(err)
		}
		os.WriteFile(filepath.Join(dst, f), b, 0o600)
		h := sha256.Sum256(b)
		m.Included["app/"+f] = hex.EncodeToString(h[:])
	}
	return m
}

// CloneTPM starts a third swtpm from a byte copy of A's state directory and exposes
// it through the gate as "tpmAclone" (ACL: B and operator). The copied-volume
// config is rewritten so B's foreign materials point at the clone.
func (rt *Runtime) CloneTPM(fixture string) CopyManifest {
	src := filepath.Join(rt.AbsRun, "tpmA", "state")
	dir := filepath.Join(rt.AbsRun, "tpmAclone")
	os.RemoveAll(dir)
	sizes, err := tpmsig.CloneState(src, filepath.Join(dir, "state"))
	if err != nil {
		panic(err)
	}
	sw, err := tpmsig.StartSWTPM(dir)
	if err != nil {
		panic(err)
	}
	rt.Clone = sw
	rt.Cmds = append(rt.Cmds, "swtpm socket --tpm2 --tpmstate dir="+filepath.Join(dir, "state")+" (byte copy of run/tpmA/state)")
	gateSock := filepath.Join(rt.AbsRun, "gate", "tpmAclone.sock")
	rt.AddGateSigner("tpmAclone", gateSock, sw.Sock)
	acl := map[string][]string{}
	for k, v := range rt.ACLDefault {
		acl[k] = v
	}
	acl["tpmAclone"] = []string{"B", "operator"}
	rt.SetACL(acl)
	// rewrite copied volume config to use the clone through the gate
	cfgPath := filepath.Join(rt.AbsRun, "B", "copied-volume", "app", "config.json")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		panic(err)
	}
	var cfg map[string]any
	json.Unmarshal(b, &cfg)
	cfg["tpm_gate_sock"] = gateSock
	nb, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(cfgPath, nb, 0o600)
	m := CopyManifest{Fixture: fixture, Source: src, Dest: filepath.Join(dir, "state"), Included: map[string]string{}, Excluded: []string{"run/A/signer/siso_token", "run/A/signer/siso.key", "run/A/publisher/card.key", "run/A/tls", "run/gate/tpmA.sock access (B uses tpmAclone instead)"}, Extra: map[string]any{"state_files_bytes": sizes, "ak_auth_granted": true, "note": "emulator NVRAM is an ordinary file; a hardware TPM is supposed to make this copy impossible. This fixture measures the emulator, not hardware."}}
	for name := range sizes {
		m.Included["state/"+name] = "(copied; emulator state is not hashed into results)"
	}
	return m
}

// CloneFWTPM copies A's emulated-PQ-device NV file into a third fwTPM instance (the
// state-cloning capability control X2), starts it on the clone port and points the
// copied volume's device gate at the pre-registered devAclone signer, which holds
// A's authValue. Nothing here is hardware: the NV file is an ordinary file.
func (rt *Runtime) CloneFWTPM(fixture string, bin string, port int) CopyManifest {
	src := filepath.Join(rt.AbsRun, "fwtpmA")
	dir := filepath.Join(rt.AbsRun, "fwtpmAclone")
	os.RemoveAll(dir)
	sizes, err := pqdev.CloneNV(src, dir)
	if err != nil {
		panic(err)
	}
	fw, err := pqdev.StartFWTPM(bin, dir, port, false)
	if err != nil {
		panic(err)
	}
	rt.FWClone = fw
	rt.Cmds = append(rt.Cmds, bin+" --port "+fmt.Sprint(port)+" (cwd "+dir+", byte copy of run/fwtpmA/fwtpm_nv.bin)")
	acl := map[string][]string{}
	for k, v := range rt.ACLDefault {
		acl[k] = v
	}
	acl["devAclone"] = []string{"B", "operator"}
	rt.SetACL(acl)
	cfgPath := filepath.Join(rt.AbsRun, "B", "copied-volume", "app", "config.json")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		panic(err)
	}
	var cfg map[string]any
	json.Unmarshal(b, &cfg)
	cfg["pqdev_gate_sock"] = filepath.Join(rt.AbsRun, "gate", "devAclone.sock")
	nb, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(cfgPath, nb, 0o600)
	inc := map[string]string{}
	for name, n := range sizes {
		inc[name] = fmt.Sprintf("%d bytes copied (emulator state: NV journal with the ML-DSA private key and its journal HMAC key; not hashed into results)", n)
	}
	return CopyManifest{Fixture: fixture, Source: src, Dest: dir, Included: inc, Excluded: []string{"run/A/signer/env_token is NOT copied: the harness grants B the devAclone ACL and the clone signer holds A's dev_auth (declared capability)"}, Extra: map[string]any{"note": "emulator NV is an ordinary file; a physical device is supposed to make this copy impossible. This control measures the emulator, not hardware."}}
}

// StopFWClone tears the PQ-device clone down after its fixture.
func (rt *Runtime) StopFWClone() {
	if rt.FWClone != nil {
		rt.FWClone.Stop()
		rt.FWClone = nil
	}
	rt.SetACL(rt.ACLDefault)
}

// StopClone tears the clone down after its fixture.
func (rt *Runtime) StopClone() {
	if rt.Clone != nil {
		rt.Clone.Stop()
		rt.Clone = nil
	}
	rt.SetACL(rt.ACLDefault)
}

func Versions() string {
	bi, _ := debug.ReadBuildInfo()
	var sb strings.Builder
	if bi != nil {
		sb.WriteString("go " + bi.GoVersion + "\n")
		for _, d := range bi.Deps {
			sb.WriteString(d.Path + " " + d.Version + "\n")
		}
	}
	if out, err := exec.Command("swtpm", "--version").Output(); err == nil {
		sb.WriteString(strings.TrimSpace(string(out)) + "\n")
	}
	sb.WriteString("draft-anandakrishnan-rats-ptv-agent-identity-01 (29 September 2026)\n")
	return sb.String()
}

// Provenance is written before the first cell and completed at the end.
type Provenance struct {
	RunID            string            `json:"run_id"`
	StartedUTC       string            `json:"started_utc"`
	FinishedUTC      string            `json:"finished_utc,omitempty"`
	WallSeconds      float64           `json:"wall_seconds,omitempty"`
	ManifestPath     string            `json:"manifest_path"`
	ManifestSHA256   string            `json:"manifest_sha256"`
	PredictionsSHA   string            `json:"predictions_sha256,omitempty"`
	BinarySHA256     string            `json:"binary_sha256"`
	SourceSHA256     map[string]string `json:"source_sha256"`
	SourceTreeSHA256 string            `json:"source_tree_sha256"`
	Versions         string            `json:"versions"`
	Commands         []string          `json:"commands,omitempty"`
	Notes            []string          `json:"notes,omitempty"`
}

func fileSHA(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// sourceHashes hashes every tracked source file under root (cmd, internal,
// fixtures, scripts, go.mod, go.sum) and a combined tree hash.
func sourceHashes(root string) (map[string]string, string) {
	out := map[string]string{}
	for _, top := range []string{"cmd", "internal", "fixtures", "scripts"} {
		filepath.Walk(filepath.Join(root, top), func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			out[rel] = fileSHA(p)
			return nil
		})
	}
	for _, f := range []string{"go.mod", "go.sum"} {
		out[f] = fileSHA(filepath.Join(root, f))
	}
	if mds, err := filepath.Glob(filepath.Join(root, "*.md")); err == nil { // plans, results, scope notes at the root
		for _, m := range mds {
			rel, _ := filepath.Rel(root, m)
			out[rel] = fileSHA(m)
		}
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%s %s\n", out[k], k)
	}
	return out, hex.EncodeToString(h.Sum(nil))
}
