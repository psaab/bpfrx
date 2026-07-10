package userspace

import (
	"encoding/binary"
	"net"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestClearAllSessionsDeliversEveryKeyToHelper5304 guards the bounded-memory
// wrapper clear (#5304): replacing the wrapper's own full-table key snapshot
// with the shim's per-chunk callback must still route an authoritative helper
// "delete" for EVERY mirror session. It seeds many distinct v4 + v6 forward
// sessions, runs the clear through the adapter (the real dispatch path), and
// asserts (a) the mirror is emptied and (b) the fake helper recorded a delete
// for every seeded key — no key dropped by the chunk plumbing.
//
// fail-on-revert: dropping the callbacks (passing nil,nil to
// ClearAllSessionsChunked) or reverting to a mirror-only clear leaves the fake
// helper missing deletes and fails RED — the #5096 forward-under-revoked-
// decision bypass on a bulk clear.
func TestClearAllSessionsDeliversEveryKeyToHelper5304(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	rec := startFakeHelperDeleteRecorder(t, sessionSock)

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = controlSock
	injectSessionMaps(t, m)
	adapter := NewLegacyDataPlaneAdapter(m)

	// Seed distinct v4 + v6 forward sessions in the mirror. injectSessionMaps
	// caps the maps at 1024 entries, so stay well under it.
	const n = 200
	v4Src := make([]string, n)
	v6Src := make([]string, n)
	const v4Dst = "172.16.80.200"
	const v6Dst = "2001:559:8585:80::200"
	var v6DstB [16]byte
	copy(v6DstB[:], net.ParseIP(v6Dst).To16())

	for i := 0; i < n; i++ {
		var s4 [4]byte
		binary.BigEndian.PutUint32(s4[:], 0x0a000000|uint32(i+1)) // 10.x.x.x, distinct
		k4 := dataplane.SessionKey{
			SrcIP:    s4,
			DstIP:    [4]byte{172, 16, 80, 200},
			SrcPort:  hostToNetwork16(uint16(20000 + i)),
			DstPort:  hostToNetwork16(443),
			Protocol: 6,
		}
		if err := m.bpfShim.SetSessionV4(k4, dataplane.SessionValue{}); err != nil {
			t.Fatalf("seed v4 %d: %v", i, err)
		}
		v4Src[i] = net.IP(s4[:]).String()

		var s6 [16]byte
		copy(s6[:], net.ParseIP("2001:559:8585:ef00::").To16())
		binary.BigEndian.PutUint32(s6[12:], uint32(i+1))
		k6 := dataplane.SessionKeyV6{
			SrcIP:    s6,
			DstIP:    v6DstB,
			SrcPort:  hostToNetwork16(uint16(30000 + i)),
			DstPort:  hostToNetwork16(443),
			Protocol: 6,
		}
		if err := m.bpfShim.SetSessionV6(k6, dataplane.SessionValueV6{}); err != nil {
			t.Fatalf("seed v6 %d: %v", i, err)
		}
		v6Src[i] = net.IP(s6[:]).String()
	}

	if v4, v6 := m.bpfShim.SessionCount(); v4 != n || v6 != n {
		t.Fatalf("pre-clear mirror count = (%d, %d), want (%d, %d)", v4, v6, n, n)
	}

	v4Deleted, v6Deleted, err := adapter.ClearAllSessions()
	if err != nil {
		t.Fatalf("ClearAllSessions: %v", err)
	}
	if v4Deleted != n || v6Deleted != n {
		t.Errorf("deleted = (%d, %d), want (%d, %d)", v4Deleted, v6Deleted, n, n)
	}

	// (a) mirror emptied.
	if v4, v6 := m.bpfShim.SessionCount(); v4 != 0 || v6 != 0 {
		t.Errorf("post-clear mirror count = (%d, %d), want (0, 0)", v4, v6)
	}

	// (b) every seeded key was delivered to the authoritative helper.
	missing := 0
	for i := 0; i < n; i++ {
		if !rec.deletedIP("delete", v4Src[i], v4Dst) {
			missing++
			if missing <= 5 {
				t.Errorf("v4 key %d (%s->%s) not delivered to helper", i, v4Src[i], v4Dst)
			}
		}
		if !rec.deletedIP("delete", v6Src[i], v6Dst) {
			missing++
			if missing <= 5 {
				t.Errorf("v6 key %d (%s->%s) not delivered to helper", i, v6Src[i], v6Dst)
			}
		}
	}
	if missing != 0 {
		t.Errorf("%d of %d keys were not delivered to the helper (chunk plumbing dropped keys?)", missing, 2*n)
	}
	if got := rec.count(); got != 2*n {
		t.Errorf("helper recorded %d delete requests, want %d (every seeded key exactly once)", got, 2*n)
	}
}
