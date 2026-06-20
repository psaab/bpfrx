package userspace

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// fakeHelperSocket starts a one-shot unix-socket server that answers a single
// "status" request with the given status (or !ok when status is nil). It mimics
// the real helper's JSON request/response framing. Returns the socket path.
func fakeHelperSocket(t *testing.T, status *ProcessStatus, ok bool) string {
	t.Helper()
	// Keep the path short (<108 bytes for sun_path) — t.TempDir is under /tmp.
	sock := filepath.Join(t.TempDir(), "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req ControlRequest
		if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
			return
		}
		resp := ControlResponse{OK: ok, Status: status}
		_ = json.NewEncoder(conn).Encode(&resp)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return sock
}

func TestProbeForwardingArmedReportsLiveForwarding(t *testing.T) {
	sock := fakeHelperSocket(t, &ProcessStatus{Enabled: true, ForwardingArmed: true}, true)
	armed, err := ProbeForwardingArmed(sock, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !armed {
		t.Fatal("Enabled && ForwardingArmed must report armed=true")
	}
}

func TestProbeForwardingArmedEnabledButNotArmed(t *testing.T) {
	sock := fakeHelperSocket(t, &ProcessStatus{Enabled: true, ForwardingArmed: false}, true)
	armed, err := ProbeForwardingArmed(sock, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if armed {
		t.Fatal("ForwardingArmed=false must report armed=false (forwarding not live)")
	}
}

func TestProbeForwardingArmedArmedButNotEnabled(t *testing.T) {
	sock := fakeHelperSocket(t, &ProcessStatus{Enabled: false, ForwardingArmed: true}, true)
	armed, err := ProbeForwardingArmed(sock, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if armed {
		t.Fatal("Enabled=false must report armed=false (helper disabled)")
	}
}

func TestProbeForwardingArmedNotOK(t *testing.T) {
	sock := fakeHelperSocket(t, nil, false) // helper rejected the request
	armed, err := ProbeForwardingArmed(sock, time.Second)
	if err != nil {
		t.Fatalf("a !ok response is a clean armed=false, not an error: %v", err)
	}
	if armed {
		t.Fatal("a !ok / nil-status response must report armed=false")
	}
}

func TestProbeForwardingArmedSocketMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.sock")
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("test setup: socket must not exist")
	}
	armed, err := ProbeForwardingArmed(missing, time.Second)
	if err == nil {
		t.Fatal("a missing socket must surface a dial error")
	}
	if armed {
		t.Fatal("a missing socket must report armed=false")
	}
}

func TestProbeForwardingArmedEmptyPath(t *testing.T) {
	armed, err := ProbeForwardingArmed("", time.Second)
	if err == nil {
		t.Fatal("an empty control socket must surface a configuration error")
	}
	if armed {
		t.Fatal("an empty control socket must report armed=false")
	}
}

func TestDefaultControlSocketPathNilConfigUsesDefault(t *testing.T) {
	got := DefaultControlSocketPath(nil)
	want := deriveUserspaceConfig(nil).ControlSocket
	if got != want {
		t.Fatalf("nil config: got %q, want default %q", got, want)
	}
	if got == "" {
		t.Fatal("default control socket path must be non-empty")
	}
}

func TestDefaultControlSocketPathHonorsConfiguredOverride(t *testing.T) {
	custom := "/run/xpf/custom-control.sock"
	cfg := &config.Config{}
	cfg.System.UserspaceDataplane = &config.UserspaceConfig{ControlSocket: custom}
	if got := DefaultControlSocketPath(cfg); got != custom {
		t.Fatalf("configured override: got %q, want %q", got, custom)
	}
}
