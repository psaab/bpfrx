// RED-on-revert net for #6385: the REMOTE gRPC `show system services` renderer
// (server_show_system.go showSystemServices) — the path the remote `cli` binary
// reaches, and the one the dropped #6384 A10-b2-F5 attempt left hardcoded — must
// report the EFFECTIVE (post-clamp, post-bind) management-listener addresses
// from the shared daemon-owned snapshot (Config.ListenersFn ->
// Daemon.effectiveListeners), not the fixed `127.0.0.1:50051 (always on)` /
// `127.0.0.1:8080 (always on)` defaults it used to print unconditionally.
//
// Reverting the render substitution (restoring the two hardcoded Fprintln
// lines) makes this go RED: the relocated gRPC bind and the "disabled" HTTP
// state vanish and the hardcoded 8080/50051 defaults reappear.
package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/sysservices"
)

// newActiveConfigServer builds a Server whose store has a committed (non-nil)
// active config, so showSystemServices proceeds past its nil-config guard.
func newActiveConfigServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet("set system host-name xpf-test"); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return &Server{store: store}
}

// TestShowSystemServicesEffectiveListenersGRPC pins that the gRPC renderer
// reports the effective listener snapshot: a relocated gRPC bind and a disabled
// HTTP REST listener, never the hardcoded requested defaults.
func TestShowSystemServicesEffectiveListenersGRPC(t *testing.T) {
	s := newActiveConfigServer(t)
	// A relocated gRPC bind + an empty (disabled) HTTP REST listener — neither
	// of which the pre-#6385 hardcoded renderer could ever produce.
	s.listenersFn = func() sysservices.Listeners {
		return sysservices.Listeners{GRPC: "127.0.0.1:50055"}
	}

	var buf strings.Builder
	s.showSystemServices(&buf)
	out := buf.String()

	if !strings.Contains(out, "gRPC:           127.0.0.1:50055") {
		t.Errorf("gRPC listener not reported at its EFFECTIVE bind 127.0.0.1:50055:\n%s", out)
	}
	// An empty --api-addr disables the REST listener; it must render "disabled",
	// not the fixed `127.0.0.1:8080 (always on)`.
	if !strings.Contains(out, "HTTP REST:      disabled") {
		t.Errorf("disabled HTTP REST listener not reported as disabled:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1:8080") {
		t.Errorf("renderer still emits the hardcoded 127.0.0.1:8080 default:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1:50051") {
		t.Errorf("renderer still emits the hardcoded 127.0.0.1:50051 default:\n%s", out)
	}
	if strings.Contains(out, "always on") {
		t.Errorf("renderer still emits the stale (always on) suffix:\n%s", out)
	}
}

// TestShowSystemServicesListenersFnNilFallbackGRPC pins the no-daemon fallback:
// with no snapshot source wired (a bare Server / unit-test build), the renderer
// falls back to the documented loopback defaults so the output shape is
// preserved off-daemon.
func TestShowSystemServicesListenersFnNilFallbackGRPC(t *testing.T) {
	s := newActiveConfigServer(t) // listenersFn left nil
	var buf strings.Builder
	s.showSystemServices(&buf)
	out := buf.String()
	if !strings.Contains(out, "gRPC:           127.0.0.1:50051") {
		t.Errorf("nil-fn fallback dropped the default gRPC listener:\n%s", out)
	}
	if !strings.Contains(out, "HTTP REST:      127.0.0.1:8080") {
		t.Errorf("nil-fn fallback dropped the default HTTP REST listener:\n%s", out)
	}
}
