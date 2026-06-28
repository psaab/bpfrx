package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// #3378: the flow-trace file was opened by raw "/var/log/"+name concatenation,
// with no path sanitization, mode 0644 (world-readable telemetry) and no
// symlink guard. These tests pin the hardened behavior.

func TestSanitizeTraceFilename_RejectsTraversal(t *testing.T) {
	bad := []string{
		"",
		".",
		"..",
		"../../etc/xpf-flow",
		"/etc/passwd",
		"sub/dir/trace",
		`sub\dir\trace`,
		"foo/..",
	}
	for _, name := range bad {
		if err := sanitizeTraceFilename(name); err == nil {
			t.Errorf("sanitizeTraceFilename(%q) = nil, want error (traversal must be rejected)", name)
		}
	}

	good := []string{"trace", "flow-trace.log", "trace_2026"}
	for _, name := range good {
		if err := sanitizeTraceFilename(name); err != nil {
			t.Errorf("sanitizeTraceFilename(%q) = %v, want nil (bare name)", name, err)
		}
	}
}

func TestHandleMonitorSecurityFlowFile_RejectsTraversalFilename(t *testing.T) {
	c := &CLI{}
	if err := c.handleMonitorSecurityFlowFile([]string{"../../etc/xpf-flow"}); err != nil {
		t.Fatalf("unexpected error return (should print + return nil): %v", err)
	}
	if c.monitorFlow == nil {
		t.Fatal("monitorFlow not initialized")
	}
	if c.monitorFlow.filename != "" {
		t.Fatalf("traversal filename was stored: %q (must be rejected)", c.monitorFlow.filename)
	}
}

func TestOpenTraceFile_Mode0600(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	f, path, err := openTraceFile("trace")
	if err != nil {
		t.Fatalf("openTraceFile error: %v", err)
	}
	defer f.Close()
	if path != filepath.Join(dir, "trace") {
		t.Fatalf("path = %q, want %q", path, filepath.Join(dir, "trace"))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("trace file perm = %o, want 0600 (must not be world-readable)", perm)
	}
}

func TestOpenTraceFile_RefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	// A pre-planted symlink under the log dir pointing at an attacker target.
	target := filepath.Join(dir, "secret-target")
	link := filepath.Join(dir, "trace")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	f, _, err := openTraceFile("trace")
	if err == nil {
		f.Close()
		t.Fatal("openTraceFile followed a symlink; O_NOFOLLOW must refuse it")
	}
	// The symlink target must NOT have been created/written.
	if _, statErr := os.Lstat(target); statErr == nil {
		t.Fatal("symlink target was created; the redirected write was not refused")
	}
}
