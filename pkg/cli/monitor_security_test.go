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

// #3379: size/files rotation params were parsed but the writer never rotated,
// allowing unbounded log growth. This pins enforcement: writing past `size`
// rotates and the file count is capped at `files` generations.
func TestTraceWriter_RotatesAndCapsFiles(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	const name = "trace"
	const maxFiles = 3
	f, _, err := openTraceFile(name)
	if err != nil {
		t.Fatalf("openTraceFile: %v", err)
	}
	// Small cap so a handful of ~25-byte lines forces several rotations.
	w := newTraceWriter(name, f, 40, maxFiles)
	for i := 0; i < 50; i++ {
		if err := w.writeLine("flow-trace-line-padding-xx"); err != nil {
			t.Fatalf("writeLine[%d]: %v", i, err)
		}
	}
	w.close()

	base := filepath.Join(dir, name)
	// The active file plus exactly (maxFiles-1) archives must exist.
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("active trace file missing: %v", err)
	}
	for i := 1; i <= maxFiles-1; i++ {
		if _, err := os.Stat(base + "." + itoa(i)); err != nil {
			t.Fatalf("expected archive %s.%d to exist: %v", base, i, err)
		}
	}
	// No generation beyond the cap may survive.
	if _, err := os.Stat(base + "." + itoa(maxFiles)); err == nil {
		t.Fatalf("generation %s.%d exists; files cap (%d) not enforced", base, maxFiles, maxFiles)
	}
	// The active file itself must respect the size cap.
	fi, err := os.Stat(base)
	if err != nil {
		t.Fatalf("stat active: %v", err)
	}
	if fi.Size() > 40 {
		t.Fatalf("active file size %d exceeds cap 40; rotation not triggered", fi.Size())
	}
}

func itoa(i int) string {
	return string(rune('0' + i))
}
