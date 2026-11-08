package tpmsig

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// SWTPM is one running swtpm instance (used by setup, the clone fixture and tests).
type SWTPM struct {
	Dir  string
	Sock string
	PID  int
}

// StartSWTPM starts `swtpm socket --tpm2` with its state in dir/state (created if
// missing; a pre-populated directory makes a clone). Socket paths must stay short
// (unix socket limit), so callers pass short dirs.
func StartSWTPM(dir string) (*SWTPM, error) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		return nil, fmt.Errorf("swtpm not installed: %w", err)
	}
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "tpm.sock")
	pidf := filepath.Join(dir, "pid")
	os.Remove(sock)
	os.Remove(pidf)
	cmd := exec.Command("swtpm", "socket", "--tpm2", "--tpmstate", "dir="+state,
		"--server", "type=unixio,path="+sock, "--ctrl", "type=unixio,path="+filepath.Join(dir, "ctrl.sock"),
		"--flags", "not-need-init,startup-clear", "--daemon", "--pid", "file="+pidf, "--log", "file="+filepath.Join(dir, "log")+",level=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("swtpm: %v %s", err, out)
	}
	for i := 0; i < 100; i++ {
		if st, err := os.Stat(sock); err == nil && st.Mode()&os.ModeSocket != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	b, err := os.ReadFile(pidf)
	if err != nil {
		return nil, errors.New("swtpm pid file missing")
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	// a connection round-trip confirms the emulator answers
	for i := 0; i < 50; i++ {
		c, err := Open(sock)
		if err == nil {
			c.Close()
			return &SWTPM{Dir: dir, Sock: sock, PID: pid}, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, errors.New("swtpm socket not answering")
}

// Stop kills the emulator process.
func (s *SWTPM) Stop() {
	if s == nil || s.PID <= 0 {
		return
	}
	if p, err := os.FindProcess(s.PID); err == nil {
		p.Kill()
	}
}

// CloneState copies a swtpm state directory (the emulator's NVRAM, including the
// persistent AK) into dst. This is exactly what a hardware TPM is supposed to make
// impossible; the fixture exists to show the emulator does not provide it.
func CloneState(srcDir, dstDir string) (map[string]int64, error) {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return nil, err
	}
	sizes := map[string]int64{}
	for _, e := range entries {
		if e.IsDir() {
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
	return sizes, nil
}
