package dataplane

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// newClearTestManager builds a Manager backed by real (in-kernel) v4/v6
// session hash maps. It skips the test when BPF map creation is unavailable
// (unprivileged CI), mirroring the pkg/dataplane/userspace test helpers.
func newClearTestManager(t *testing.T) *Manager {
	t.Helper()
	sessions, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(SessionKey{})),
		ValueSize:  ConntrackSessionValueSize,
		MaxEntries: 1 << 16,
	})
	if err != nil {
		skipIfBPFUnavailable(t, "new sessions map", err)
	}
	t.Cleanup(func() { sessions.Close() })

	sessionsV6, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(SessionKeyV6{})),
		ValueSize:  ConntrackSessionValueSizeV6,
		MaxEntries: 1 << 16,
	})
	if err != nil {
		skipIfBPFUnavailable(t, "new sessions_v6 map", err)
	}
	t.Cleanup(func() { sessionsV6.Close() })

	return &Manager{maps: map[string]*ebpf.Map{
		"sessions":    sessions,
		"sessions_v6": sessionsV6,
	}}
}

func skipIfBPFUnavailable(t *testing.T, ctx string, err error) {
	t.Helper()
	msg := strings.ToLower(err.Error())
	if errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES) ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "memlock") {
		t.Skipf("%s requires BPF map privileges: %v", ctx, err)
	}
	t.Fatalf("%s: %v", ctx, err)
}

// clearTestV4Key builds a unique v4 session key. n is encoded into SrcIP so
// every n is distinct, and reverse toggles DstPort so the forward and reverse
// conntrack entries occupy distinct map slots (as they do in production).
func clearTestV4Key(n uint32, reverse bool) SessionKey {
	var k SessionKey
	binary.BigEndian.PutUint32(k.SrcIP[:], n)
	k.DstIP = [4]byte{10, 0, 0, 1}
	k.SrcPort = 1024
	k.DstPort = 80
	k.Protocol = 6
	if reverse {
		k.DstPort = 8080
	}
	return k
}

func clearTestV6Key(n uint32, reverse bool) SessionKeyV6 {
	var k SessionKeyV6
	k.SrcIP = [16]byte{0x20, 0x01, 0x05, 0x59}
	binary.BigEndian.PutUint32(k.SrcIP[12:], n)
	k.DstIP = [16]byte{0x20, 0x01, 0x05, 0x59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	k.SrcPort = 1024
	k.DstPort = 80
	k.Protocol = 6
	if reverse {
		k.DstPort = 8080
	}
	return k
}

// countAllV4/countAllV6 count every entry in the session map (forward AND
// reverse), so a residual reverse companion after a clear is detected.
func countAllV4(t *testing.T, m *Manager) int {
	t.Helper()
	n := 0
	if err := m.IterateSessions(func(SessionKey, SessionValue) bool { n++; return true }); err != nil {
		t.Fatalf("iterate v4: %v", err)
	}
	return n
}

func countAllV6(t *testing.T, m *Manager) int {
	t.Helper()
	n := 0
	if err := m.IterateSessionsV6(func(SessionKeyV6, SessionValueV6) bool { n++; return true }); err != nil {
		t.Fatalf("iterate v6: %v", err)
	}
	return n
}

// TestClearAllSessionsBatchedRemovesEverything verifies that ClearAllSessions
// removes every v4 and v6 session — both the forward and the reverse conntrack
// entry — and that it does so through the chunked BPF_MAP_DELETE_BATCH path
// rather than one syscall per key (#4719).
//
// fail-on-revert: reverting ClearAllSessions to a per-key DeleteSession loop
// stops invoking sessionClearBatchObserver, so observedBatchKeys stays 0 and
// the "batched path" assertion fails. The all-cleared assertions guard the
// preserved semantics (no partial clear, no orphaned reverse entry).
func TestClearAllSessionsBatchedRemovesEverything(t *testing.T) {
	m := newClearTestManager(t)

	// Sessions per family, chosen to span several batch chunks
	// (sessionDeleteBatchSize == 64). Each session installs a forward AND a
	// reverse entry, so 2*flows map slots per family.
	const flows = 300
	fwdVal := SessionValue{State: 1, IsReverse: 0}
	revVal := SessionValue{State: 1, IsReverse: 1}
	for i := uint32(0); i < flows; i++ {
		if err := m.SetSessionV4(clearTestV4Key(i, false), fwdVal); err != nil {
			t.Fatalf("set v4 fwd %d: %v", i, err)
		}
		if err := m.SetSessionV4(clearTestV4Key(i, true), revVal); err != nil {
			t.Fatalf("set v4 rev %d: %v", i, err)
		}
		if err := m.SetSessionV6(clearTestV6Key(i, false), SessionValueV6{State: 1, IsReverse: 0}); err != nil {
			t.Fatalf("set v6 fwd %d: %v", i, err)
		}
		if err := m.SetSessionV6(clearTestV6Key(i, true), SessionValueV6{State: 1, IsReverse: 1}); err != nil {
			t.Fatalf("set v6 rev %d: %v", i, err)
		}
	}

	const wantEntries = 2 * flows
	if got := countAllV4(t, m); got != wantEntries {
		t.Fatalf("pre-clear v4 entries = %d, want %d", got, wantEntries)
	}
	if got := countAllV6(t, m); got != wantEntries {
		t.Fatalf("pre-clear v6 entries = %d, want %d", got, wantEntries)
	}

	// Batch-count seam: record every BPF_MAP_DELETE_BATCH syscall the clear
	// issues. A revert to per-key deletion never touches this observer.
	var observedBatchKeys, batchCalls int
	sessionClearBatchObserver = func(nKeys int) {
		observedBatchKeys += nKeys
		batchCalls++
		if nKeys > sessionDeleteBatchSize {
			t.Errorf("batch delete chunk %d exceeds sessionDeleteBatchSize %d", nKeys, sessionDeleteBatchSize)
		}
	}
	t.Cleanup(func() { sessionClearBatchObserver = nil })

	v4Deleted, v6Deleted, err := m.ClearAllSessions()
	if err != nil {
		t.Fatalf("ClearAllSessions: %v", err)
	}

	if v4Deleted != wantEntries {
		t.Errorf("v4Deleted = %d, want %d", v4Deleted, wantEntries)
	}
	if v6Deleted != wantEntries {
		t.Errorf("v6Deleted = %d, want %d", v6Deleted, wantEntries)
	}

	// ALL sessions cleared: forward AND reverse gone for both families.
	if got := countAllV4(t, m); got != 0 {
		t.Errorf("post-clear v4 entries = %d, want 0 (partial clear / orphaned reverse)", got)
	}
	if got := countAllV6(t, m); got != 0 {
		t.Errorf("post-clear v6 entries = %d, want 0 (partial clear / orphaned reverse)", got)
	}

	// Batched path taken: the observer fired, covering every key across
	// multiple chunks (v4 + v6 = 4*flows keys total).
	if batchCalls == 0 || observedBatchKeys == 0 {
		t.Errorf("batch delete path not taken (batchCalls=%d observedBatchKeys=%d) — per-key regression?", batchCalls, observedBatchKeys)
	}
	if wantKeys := 2 * wantEntries; observedBatchKeys != wantKeys {
		t.Errorf("observedBatchKeys = %d, want %d (all keys routed through batch delete)", observedBatchKeys, wantKeys)
	}
	if minCalls := (wantEntries + sessionDeleteBatchSize - 1) / sessionDeleteBatchSize; batchCalls < minCalls {
		t.Errorf("batchCalls = %d, want >= %d (chunked, not one giant call)", batchCalls, minCalls)
	}
}

// TestClearAllSessionsEmptyAndSmall guards the empty-table (no panic, no batch
// syscall) and single-session boundary cases.
func TestClearAllSessionsEmptyAndSmall(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		m := newClearTestManager(t)
		var calls int
		sessionClearBatchObserver = func(int) { calls++ }
		t.Cleanup(func() { sessionClearBatchObserver = nil })

		v4, v6, err := m.ClearAllSessions()
		if err != nil {
			t.Fatalf("ClearAllSessions on empty table: %v", err)
		}
		if v4 != 0 || v6 != 0 {
			t.Errorf("empty clear = (%d, %d), want (0, 0)", v4, v6)
		}
		if calls != 0 {
			t.Errorf("empty clear issued %d batch calls, want 0", calls)
		}
	})

	t.Run("single-session", func(t *testing.T) {
		m := newClearTestManager(t)
		if err := m.SetSessionV4(clearTestV4Key(1, false), SessionValue{IsReverse: 0}); err != nil {
			t.Fatalf("set v4 fwd: %v", err)
		}
		if err := m.SetSessionV4(clearTestV4Key(1, true), SessionValue{IsReverse: 1}); err != nil {
			t.Fatalf("set v4 rev: %v", err)
		}
		v4, _, err := m.ClearAllSessions()
		if err != nil {
			t.Fatalf("ClearAllSessions: %v", err)
		}
		if v4 != 2 {
			t.Errorf("v4Deleted = %d, want 2 (forward + reverse)", v4)
		}
		if got := countAllV4(t, m); got != 0 {
			t.Errorf("post-clear v4 entries = %d, want 0", got)
		}
	})
}
