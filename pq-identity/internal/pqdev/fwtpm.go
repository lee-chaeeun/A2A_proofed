package pqdev

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// FWTPM is one running wolfTPM firmware-TPM server instance (socket transport). Its
// NV state lives in <Dir>/fwtpm_nv.bin; the process is started with Dir as its working
// directory so that each deployment (and the clone control) has its own state file.
type FWTPM struct {
	Dir  string
	Port int // command port; the platform port is Port+1
	PID  int
}

// DefaultBin returns the task-local fwtpm_server path unless A2AID_FWTPM overrides it.
func DefaultBin(root string) string {
	if p := os.Getenv("A2AID_FWTPM"); p != "" {
		return p
	}
	p, _ := filepath.Abs(filepath.Join(root, ".toolchain", "wolftpm", "bin", "fwtpm_server"))
	return p
}

// DefaultBridge returns the task-local pqtpm path unless A2AID_PQTPM overrides it.
func DefaultBridge(root string) string {
	if p := os.Getenv("A2AID_PQTPM"); p != "" {
		return p
	}
	p, _ := filepath.Abs(filepath.Join(root, "tools", "pqtpm", "pqtpm"))
	return p
}

// StartFWTPM starts fwtpm_server in dir on the given port (platform port+1), writes
// its pid to <dir>/pid and waits until the command port accepts connections.
// clear=true wipes the NV file first (fresh emulator).
func StartFWTPM(bin, dir string, port int, clear bool) (*FWTPM, error) {
	bin, _ = filepath.Abs(bin)
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("fwtpm_server not found at %s (build wolfTPM task-locally; see tools/pqtpm/README.md)", bin)
	}
	dir, _ = filepath.Abs(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	args := []string{"--port", strconv.Itoa(port), "--platform-port", strconv.Itoa(port + 1)}
	if clear {
		args = append(args, "--clear")
	}
	logf, err := os.Create(filepath.Join(dir, "log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	os.WriteFile(filepath.Join(dir, "pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	go cmd.Wait()
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return &FWTPM{Dir: dir, Port: port, PID: cmd.Process.Pid}, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	cmd.Process.Kill()
	return nil, errors.New("fwtpm_server did not open its command port")
}

// Stop kills the server process (pid file or recorded pid).
func (f *FWTPM) Stop() {
	pid := f.PID
	if b, err := os.ReadFile(filepath.Join(f.Dir, "pid")); err == nil {
		if p, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			pid = p
		}
	}
	if pid > 0 {
		if p, err := os.FindProcess(pid); err == nil {
			p.Kill()
		}
	}
	os.Remove(filepath.Join(f.Dir, "pid"))
}

// StopByDir kills a server by its pid file.
func StopByDir(dir string) { (&FWTPM{Dir: dir}).Stop() }

// CloneNV copies the emulator's complete state directory (the NV journal
// fwtpm_nv.bin AND its sibling HMAC key file; the firmware TPM authenticates the
// journal with that key and re-initializes when it is missing) into a new directory:
// the state-cloning capability control. Returns the copied byte count per file.
func CloneNV(srcDir, dstDir string) (map[string]int64, error) {
	es, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return nil, err
	}
	sizes := map[string]int64{}
	for _, e := range es {
		if e.IsDir() || e.Name() == "pid" || e.Name() == "log" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dstDir, e.Name()), b, 0o600); err != nil {
			return nil, err
		}
		sizes[e.Name()] = int64(len(b))
	}
	if _, ok := sizes["fwtpm_nv.bin"]; !ok {
		return nil, errors.New("no fwtpm_nv.bin in the source state directory")
	}
	return sizes, nil
}
