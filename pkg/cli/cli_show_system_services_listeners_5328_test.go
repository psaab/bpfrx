package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// newMinimalServicesStore builds a committed store with a trivial config so
// showSystemServices() gets a non-nil ActiveConfig.
func newMinimalServicesStore(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet("set system host-name test-fw"); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return &CLI{store: store}
}

// TestShowSystemServicesReportsEffectiveListeners_5328 is the #5328 (A10-b2-F5)
// RED-on-revert guard: with the daemon-wired listener state, `show system
// services` must report the EFFECTIVE gRPC address and mark HTTP REST disabled
// when --api-addr is empty — not a hardcoded 127.0.0.1:8080 (always on).
//
// FAIL-ON-REVERT: restore the unconditional hardcoded prints and the effective
// gRPC address / "HTTP REST: disabled" lines disappear (and "always on"
// reappears), turning every assertion RED.
func TestShowSystemServicesReportsEffectiveListeners_5328(t *testing.T) {
	c := newMinimalServicesStore(t)
	// Relocated gRPC listener, HTTP REST disabled (--api-addr "").
	c.SetServiceListeners("", "127.0.0.2:6000")

	out := captureStdout(t, func() {
		if err := c.showSystemServices(); err != nil {
			t.Fatalf("showSystemServices(): %v", err)
		}
	})

	if !strings.Contains(out, "127.0.0.2:6000") {
		t.Errorf("effective gRPC listener 127.0.0.2:6000 not reported:\n%s", out)
	}
	if !strings.Contains(out, "HTTP REST:      disabled") {
		t.Errorf("HTTP REST should read disabled when --api-addr is empty:\n%s", out)
	}
	if strings.Contains(out, "always on") {
		t.Errorf("hardcoded '(always on)' default reappeared despite wired listeners:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1:8080") || strings.Contains(out, "127.0.0.1:50051") {
		t.Errorf("hardcoded default listener address printed instead of effective state:\n%s", out)
	}
}

// TestShowSystemServicesUnwiredKeepsLegacyDisplay_5328 pins the fallback: a CLI
// spawned outside the daemon (SetServiceListeners never called) keeps the
// historical hardcoded display, bit-identical to pre-#5328.
func TestShowSystemServicesUnwiredKeepsLegacyDisplay_5328(t *testing.T) {
	c := newMinimalServicesStore(t)

	out := captureStdout(t, func() {
		if err := c.showSystemServices(); err != nil {
			t.Fatalf("showSystemServices(): %v", err)
		}
	})

	if !strings.Contains(out, "127.0.0.1:50051 (always on)") {
		t.Errorf("unwired CLI must keep the legacy gRPC display:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1:8080 (always on)") {
		t.Errorf("unwired CLI must keep the legacy HTTP REST display:\n%s", out)
	}
}
