package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMonitorSecurityFlowFileRequiresControl is the #5038 fail-on-revert guard:
// the file-backed flow-trace verbs (`monitor security flow file|start`) drive a
// root-privileged on-disk write, so they must require PermControl, not the
// view-level permission the rest of `monitor` carries. Removing the gate drops
// them back to PermView → RED.
func TestMonitorSecurityFlowFileRequiresControl(t *testing.T) {
	controlCases := [][]string{
		{"monitor", "security", "flow", "file", "trace"},
		{"monitor", "security", "flow", "start"},
		// Abbreviated forms must gate identically (resolveCommand path). "sta"
		// is an unambiguous prefix of "start" among the flow verbs.
		{"monitor", "sec", "fl", "file", "trace"},
		{"monitor", "sec", "fl", "sta"},
	}
	for _, parts := range controlCases {
		if got := requiredPermission(parts); got != config.PermControl {
			t.Errorf("requiredPermission(%v) = %v, want PermControl", parts, got)
		}
	}

	viewCases := [][]string{
		{"monitor", "security", "flow"},                 // status
		{"monitor", "security", "flow", "filter", "f1"}, // filter edit (in-memory)
		{"monitor", "security", "flow", "stop"},         // stop
		{"monitor", "security", "packet-drop"},          // terminal-only stream
	}
	for _, parts := range viewCases {
		if got := requiredPermission(parts); got != config.PermView {
			t.Errorf("requiredPermission(%v) = %v, want PermView", parts, got)
		}
	}
}

// TestTraceDirIsDedicatedNamespace pins the #5038 confinement: the default
// trace directory is a dedicated subdirectory, NOT the shared /var/log, so a
// trace filename can never resolve onto — or rotate/rename — a system-log
// inode. openTraceFile also creates the directory on demand.
func TestTraceDirIsDedicatedNamespace(t *testing.T) {
	if traceLogDir == "/var/log" || !strings.HasPrefix(traceLogDir, "/var/log/") {
		t.Fatalf("traceLogDir = %q, want a dedicated subdirectory under /var/log (not /var/log itself)", traceLogDir)
	}

	// openTraceFile must create the (missing) dedicated dir and confine the file
	// strictly inside it. Simulate /var/log with base and the dedicated dir with
	// a not-yet-existing subdir.
	base := t.TempDir()
	sub := filepath.Join(base, "xpf-flow-trace")
	old := traceLogDir
	traceLogDir = sub
	defer func() { traceLogDir = old }()

	f, path, err := openTraceFile("auth.log")
	if err != nil {
		t.Fatalf("openTraceFile: %v", err)
	}
	defer f.Close()
	if path != filepath.Join(sub, "auth.log") {
		t.Fatalf("path = %q, want it confined under %q", path, sub)
	}
	if _, err := os.Stat(sub); err != nil {
		t.Fatalf("dedicated trace dir not created on demand: %v", err)
	}
	// The parent (standing in for /var/log) must NOT have gained an auth.log —
	// the name is confined to the dedicated dir, so a live system log is safe.
	if _, err := os.Stat(filepath.Join(base, "auth.log")); err == nil {
		t.Fatal("trace filename escaped the dedicated dir onto the parent (would clobber /var/log/auth.log)")
	}
}
