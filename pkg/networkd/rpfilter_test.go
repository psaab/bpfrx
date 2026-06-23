package networkd

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// captureWarn runs fn with slog routed to an in-memory text handler and
// returns everything logged. Used to assert the #2378 rp_filter warning fires
// (or stays quiet) without touching the live /proc tree.
func captureWarn(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

// setupProcRoot builds a fake /proc/sys/net/ipv4 tree with a given
// conf/all/rp_filter value and points procSysNetRoot at it for the duration of
// the test.
func setupProcRoot(t *testing.T, allValue string) {
	t.Helper()
	root := t.TempDir()
	allDir := filepath.Join(root, "conf", "all")
	if err := os.MkdirAll(allDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if allValue != "" {
		if err := os.WriteFile(filepath.Join(allDir, "rp_filter"), []byte(allValue), 0644); err != nil {
			t.Fatalf("write all rp_filter: %v", err)
		}
	}
	prev := procSysNetRoot
	procSysNetRoot = root
	t.Cleanup(func() { procSysNetRoot = prev })
}

// #2378 fail-on-revert: when conf/all/rp_filter is strict (1) or loose (2),
// the per-device 0 is overridden by the kernel (max(all, dev)) and slow-path
// reinjected IPv4 packets are silently dropped. warnIfAllRPFilterOverrides MUST
// emit a warning. If the all-rp_filter check is removed, this test fails.
func TestWarnIfAllRPFilterOverrides_Nonzero(t *testing.T) {
	for _, v := range []string{"1", "2", "1\n"} {
		setupProcRoot(t, v)
		out := captureWarn(t, func() { warnIfAllRPFilterOverrides("xpf-usp0") })
		if !bytes.Contains([]byte(out), []byte("SILENTLY DROPPED")) {
			t.Fatalf("all rp_filter=%q: expected a warning, got %q", v, out)
		}
		if !bytes.Contains([]byte(out), []byte("xpf-usp0")) {
			t.Fatalf("all rp_filter=%q: warning must name the TUN device, got %q", v, out)
		}
	}
}

// When conf/all/rp_filter is 0 the per-device 0 is effective; no warning.
func TestWarnIfAllRPFilterOverrides_Zero(t *testing.T) {
	setupProcRoot(t, "0\n")
	out := captureWarn(t, func() { warnIfAllRPFilterOverrides("xpf-usp0") })
	if bytes.Contains([]byte(out), []byte("SILENTLY DROPPED")) {
		t.Fatalf("all rp_filter=0 must not warn, got %q", out)
	}
}

// A missing or unparsable conf/all/rp_filter is "cannot determine" — stay
// quiet rather than emit a spurious warning.
func TestWarnIfAllRPFilterOverrides_MissingOrGarbage(t *testing.T) {
	// Missing file (no rp_filter written).
	setupProcRoot(t, "")
	out := captureWarn(t, func() { warnIfAllRPFilterOverrides("xpf-usp0") })
	if bytes.Contains([]byte(out), []byte("SILENTLY DROPPED")) {
		t.Fatalf("missing all rp_filter must not warn, got %q", out)
	}

	// Garbage contents.
	setupProcRoot(t, "garbage")
	out = captureWarn(t, func() { warnIfAllRPFilterOverrides("xpf-usp0") })
	if bytes.Contains([]byte(out), []byte("SILENTLY DROPPED")) {
		t.Fatalf("unparsable all rp_filter must not warn, got %q", out)
	}
}
