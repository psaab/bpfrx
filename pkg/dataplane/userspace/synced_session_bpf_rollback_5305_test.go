package userspace

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/dataplane"
)

// newMirrorFailManager5305 builds a Manager whose helper session mirror FAILS:
// m.proc is set (so syncSession*Locked does not early-return nil) but no
// listener exists on the derived session socket, so the mirror connect fails.
// Real in-memory BPF session maps are injected so the pinned mirror can be read
// back to assert the transactional rollback (#5305).
func newMirrorFailManager5305(t *testing.T) *Manager {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	m := New()
	m.proc = &exec.Cmd{}
	// No listener at <dir>/userspace-dp-sessions.sock -> mirror connect fails.
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)
	return m
}

// newMirrorOKManager5305 builds a Manager with a live session helper socket
// that acknowledges every mirror request, so the mirror SUCCEEDS.
func newMirrorOKManager5305(t *testing.T) *Manager {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	ln, err := net.Listen("unix", sessionSock)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				_ = json.NewDecoder(conn).Decode(&req)
				_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
			}()
		}
	}()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)
	return m
}

func rollbackKeyV4() dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
}

func rollbackKeyV6() dataplane.SessionKeyV6 {
	var srcIP, dstIP [16]byte
	copy(srcIP[:], net.ParseIP("2001:db8:61::102").To16())
	copy(dstIP[:], net.ParseIP("2001:db8:80::200").To16())
	return dataplane.SessionKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
}

// TestSetClusterSyncedSessionV4RollsBackOrphanOnMirrorFailure pins the #5305
// transactional-install contract: when the helper mirror upsert fails, the
// forward cluster-synced install must leave the pinned BPF session map EXACTLY
// as it was — a previously-absent key stays absent (no orphan), a key with a
// prior value is restored to that prior value (not the failed install value).
//
// RED-on-revert: neutralize the compensation by deleting the
// `compErr := m.restoreBPFSessionV4Locked(...)` call in SetClusterSyncedSessionV4
// (return just the mirror error). The absent-key sub-case then finds the orphan
// installVal still present, and the prior-value sub-case finds it overwritten by
// installVal, so both assertions fail.
func TestSetClusterSyncedSessionV4RollsBackOrphanOnMirrorFailure(t *testing.T) {
	key := rollbackKeyV4()

	t.Run("absent-key-deleted", func(t *testing.T) {
		m := newMirrorFailManager5305(t)
		val := dataplane.SessionValue{IsReverse: 0, IngressZone: 1, EgressZone: 2}

		err := m.SetClusterSyncedSessionV4(key, val)
		if err == nil {
			t.Fatal("SetClusterSyncedSessionV4() = nil, want mirror failure")
		}
		// The orphan must not survive: the key was absent, so it must be gone.
		if _, getErr := m.bpfShim.GetSessionV4(key); !errors.Is(getErr, ebpf.ErrKeyNotExist) {
			t.Fatalf("BPF entry survived a failed install: GetSessionV4 err = %v, want ErrKeyNotExist", getErr)
		}
		// Health behavior preserved: takeover stays disarmed.
		if !m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = false, want true")
		}
		if m.sessionMirrorErr == "" {
			t.Fatal("sessionMirrorErr is empty, want non-empty")
		}
	})

	t.Run("prior-value-restored", func(t *testing.T) {
		m := newMirrorFailManager5305(t)
		// Seed a distinguishable prior value directly on the BPF mirror.
		prior := dataplane.SessionValue{IsReverse: 0, IngressZone: 7, EgressZone: 9, PolicyID: 111}
		if err := m.bpfShim.SetSessionV4(key, prior); err != nil {
			t.Fatalf("seed prior BPF entry: %v", err)
		}
		want, err := m.bpfShim.GetSessionV4(key) // canonical round-tripped prior
		if err != nil {
			t.Fatalf("read seeded prior: %v", err)
		}

		// A failing install with a DIFFERENT value must not survive.
		val := dataplane.SessionValue{IsReverse: 0, IngressZone: 1, EgressZone: 2, PolicyID: 222}
		if err := m.SetClusterSyncedSessionV4(key, val); err == nil {
			t.Fatal("SetClusterSyncedSessionV4() = nil, want mirror failure")
		}

		got, err := m.bpfShim.GetSessionV4(key)
		if err != nil {
			t.Fatalf("prior BPF entry vanished after failed install: %v", err)
		}
		if got != want {
			t.Fatalf("BPF entry not restored to prior value: got %+v, want %+v", got, want)
		}
	})
}

// TestSetClusterSyncedSessionV6RollsBackOrphanOnMirrorFailure is the IPv6
// analogue (#5305). Same RED-on-revert: drop restoreBPFSessionV6Locked.
func TestSetClusterSyncedSessionV6RollsBackOrphanOnMirrorFailure(t *testing.T) {
	key := rollbackKeyV6()

	t.Run("absent-key-deleted", func(t *testing.T) {
		m := newMirrorFailManager5305(t)
		val := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 1, EgressZone: 2}

		err := m.SetClusterSyncedSessionV6(key, val)
		if err == nil {
			t.Fatal("SetClusterSyncedSessionV6() = nil, want mirror failure")
		}
		if _, getErr := m.bpfShim.GetSessionV6(key); !errors.Is(getErr, ebpf.ErrKeyNotExist) {
			t.Fatalf("BPF entry survived a failed install: GetSessionV6 err = %v, want ErrKeyNotExist", getErr)
		}
		if !m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = false, want true")
		}
		if m.sessionMirrorErr == "" {
			t.Fatal("sessionMirrorErr is empty, want non-empty")
		}
	})

	t.Run("prior-value-restored", func(t *testing.T) {
		m := newMirrorFailManager5305(t)
		prior := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 7, EgressZone: 9, PolicyID: 111}
		if err := m.bpfShim.SetSessionV6(key, prior); err != nil {
			t.Fatalf("seed prior BPF entry: %v", err)
		}
		want, err := m.bpfShim.GetSessionV6(key)
		if err != nil {
			t.Fatalf("read seeded prior: %v", err)
		}

		val := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 1, EgressZone: 2, PolicyID: 222}
		if err := m.SetClusterSyncedSessionV6(key, val); err == nil {
			t.Fatal("SetClusterSyncedSessionV6() = nil, want mirror failure")
		}

		got, err := m.bpfShim.GetSessionV6(key)
		if err != nil {
			t.Fatalf("prior BPF entry vanished after failed install: %v", err)
		}
		if got != want {
			t.Fatalf("BPF entry not restored to prior value: got %+v, want %+v", got, want)
		}
	})
}

// TestSetClusterSyncedSessionRollbackSuccessPathUnregressed proves the fix does
// NOT regress the success path: a mirror that succeeds still installs the
// forward entry into the BPF map and clears the sticky mirror-failure flag
// (#5247). Both address families.
func TestSetClusterSyncedSessionRollbackSuccessPathUnregressed(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		m := newMirrorOKManager5305(t)
		// A prior transient failure latched the sticky flag.
		m.recordSessionMirrorFailureLocked(errors.New("transient control-socket failure"))

		key := rollbackKeyV4()
		val := dataplane.SessionValue{IsReverse: 0, IngressZone: 1, EgressZone: 2, PolicyID: 42}
		if err := m.SetClusterSyncedSessionV4(key, val); err != nil {
			t.Fatalf("SetClusterSyncedSessionV4: %v", err)
		}
		got, err := m.bpfShim.GetSessionV4(key)
		if err != nil {
			t.Fatalf("forward entry not installed on success path: %v", err)
		}
		if got.PolicyID != 42 || got.IngressZone != 1 || got.EgressZone != 2 {
			t.Fatalf("installed value = %+v, want PolicyID=42 zones 1/2", got)
		}
		if m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = true after successful mirror, want false (#5247)")
		}
		if m.sessionMirrorErr != "" {
			t.Fatalf("sessionMirrorErr = %q after successful mirror, want empty", m.sessionMirrorErr)
		}
	})

	t.Run("v6", func(t *testing.T) {
		m := newMirrorOKManager5305(t)
		m.recordSessionMirrorFailureLocked(errors.New("transient control-socket failure"))

		key := rollbackKeyV6()
		val := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 1, EgressZone: 2, PolicyID: 42}
		if err := m.SetClusterSyncedSessionV6(key, val); err != nil {
			t.Fatalf("SetClusterSyncedSessionV6: %v", err)
		}
		got, err := m.bpfShim.GetSessionV6(key)
		if err != nil {
			t.Fatalf("forward entry not installed on success path: %v", err)
		}
		if got.PolicyID != 42 || got.IngressZone != 1 || got.EgressZone != 2 {
			t.Fatalf("installed value = %+v, want PolicyID=42 zones 1/2", got)
		}
		if m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = true after successful mirror, want false (#5247)")
		}
		if m.sessionMirrorErr != "" {
			t.Fatalf("sessionMirrorErr = %q after successful mirror, want empty", m.sessionMirrorErr)
		}
	})
}
