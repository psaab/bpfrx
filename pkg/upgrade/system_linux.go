package upgrade

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
	"golang.org/x/sys/unix"
)

// realSystem is the production System backed by systemctl + the OS.
type realSystem struct {
	// systemdUnitDir is /etc/systemd/system (drop-ins go under
	// <unit>.service.d/). Overridable for tests.
	systemdUnitDir string
	// unit is the systemd unit name (without .service) the health probe
	// polls. Must match the Runner's Config.Unit (Codex r1 Medium: a
	// custom --unit must not be ignored by the health check).
	unit string
	// helperHealth is an optional hook the daemon wires to check its
	// running helper's reported version (set by the caller in xpfd, which
	// has the userspace manager). When nil, HelperHealthy degrades to a
	// fixed settle wait (the unit being active is the signal).
	helperHealth func(expectVersion string, deadline time.Duration) error
}

// NewSystem returns the production System implementation for the given
// systemd unit.
func NewSystem(unit string) System {
	if unit == "" {
		unit = DefaultUnit
	}
	return &realSystem{systemdUnitDir: "/etc/systemd/system", unit: unit}
}

// NewSystemWithHelperHealth returns the production System with a helper
// health probe (used by xpfd, which can query its own helper version).
func NewSystemWithHelperHealth(unit string, probe func(expectVersion string, deadline time.Duration) error) System {
	if unit == "" {
		unit = DefaultUnit
	}
	return &realSystem{systemdUnitDir: "/etc/systemd/system", unit: unit, helperHealth: probe}
}

func (s *realSystem) StopUnit(unit string) error {
	return runCmd("systemctl", "stop", unit+".service")
}

func (s *realSystem) StartUnit(unit string) error {
	return runCmd("systemctl", "start", unit+".service")
}

func (s *realSystem) DaemonReload() error {
	return runCmd("systemctl", "daemon-reload")
}

func (s *realSystem) WriteUnitDropin(unit, name, content string) error {
	dir := filepath.Join(s.systemdUnitDir, unit+".service.d")
	if err := fsatomic.MkdirAllDurable(dir, 0755); err != nil {
		return fmt.Errorf("create drop-in dir: %w", err)
	}
	return fsatomic.WriteFileDurable(filepath.Join(dir, name), []byte(content), 0644)
}

func (s *realSystem) FreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	// Stat the nearest existing ancestor so a not-yet-created versions dir
	// still yields the backing filesystem's free space.
	p := path
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	if err := unix.Statfs(p, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", p, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func (s *realSystem) VerifyDataplane(bin string, env []string) (bool, error) {
	cmd := exec.Command(bin, "verify-dataplane")
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		// exit 3 = REJECT (verifier rejected the shim). main.go contract.
		if ee.ExitCode() == 3 {
			return false, nil
		}
	}
	return false, fmt.Errorf("verify-dataplane exec failed: %w (output: %s)", err, strings.TrimSpace(out.String()))
}

func (s *realSystem) BinaryVersion(bin string) (string, error) {
	cmd := exec.Command(bin, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s version: %w (output: %s)", bin, err, strings.TrimSpace(out.String()))
	}
	// Output shape: "xpfd <version> (commit <c>, built <t>)".
	//
	// The extracted token keys the on-disk runtime layout (versions/<ver>/,
	// the `current` symlink target, the per-version DB-snapshot dotfile, the
	// unit drop-in ExecStart). A corrupt binary, an arch/lib mismatch that
	// still execs but prints garbage, or a benign future change to the
	// `version` output format must NOT yield a path-escaping or whitespace-
	// laden "version" that strands the cut or escapes VersionsDir (#1967 C1).
	// So validate the extracted token as a safe single path segment and hard-
	// fail otherwise — NEVER fall back to returning the whole trimmed output.
	trimmed := strings.TrimSpace(out.String())
	fields := strings.Fields(out.String())
	if len(fields) >= 2 && fields[0] == "xpfd" {
		if verr := ValidateVersionSegment(fields[1]); verr != nil {
			return "", fmt.Errorf("%s version: token %q is not a safe path "+
				"segment: %w (full output: %q)", bin, fields[1], verr, trimmed)
		}
		return fields[1], nil
	}
	return "", fmt.Errorf("%s version: unrecognized output format "+
		"(want \"xpfd <version> ...\"): %q", bin, trimmed)
}

func (s *realSystem) HelperHealthy(expectVersion string, deadline time.Duration) error {
	if s.helperHealth != nil {
		return s.helperHealth(expectVersion, deadline)
	}
	// Fallback: poll `systemctl is-active` until active or deadline. The
	// unit's own ExecStartPre verify gate + Restart=on-failure means an
	// active unit is a reasonable health proxy when no helper probe is
	// wired.
	end := time.Now().Add(deadline)
	for {
		out, _ := exec.Command("systemctl", "is-active", s.unit+".service").Output()
		if strings.TrimSpace(string(out)) == "active" {
			return nil
		}
		if time.Now().After(end) {
			return fmt.Errorf("unit %s did not become active within %s", s.unit, deadline)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (s *realSystem) Now() time.Time { return time.Now() }

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}
