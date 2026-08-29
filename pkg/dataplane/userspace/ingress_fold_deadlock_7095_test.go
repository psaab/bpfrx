package userspace

import (
	"os/exec"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #7095 regression: a non-zero IngressIfaceFold must not wedge the manager.
//
// `resolveIngressFold` took `m.mu` to read `ingressFoldResolver`. Both of its
// callers — `buildSessionSyncRequest{V4,V6}` — are reached with `m.mu` ALREADY
// held, from two directions:
//
//	SetClusterSyncedSessionV{4,6}  -> syncSessionV{4,6}Locked -> build...  (peer import)
//	mirrorSessionPairV{4,6}                                   -> build...  (local install)
//
// `m.mu` is a plain `sync.Mutex`, so that second acquire never returns. The
// manager mutex is then held forever and every other manager operation blocks
// behind it — session installs, status polls, snapshot publishes.
//
// It was armed by data, not by configuration: the guard `fold == 0` returns
// before the lock, so the deadlock fires exactly when a session carries a real
// fold. Since #7095 that is every peer-synced session whose ingress interface
// has a cluster-stable name. Note the lock was taken BEFORE reading the
// resolver, so leaving the resolver unwired did NOT avoid it.
//
// WHY THE TIMEOUT IS THE ASSERTION. A deadlock has no error value to compare —
// the only observable is that the call does not return. Each cell runs the call
// in its own goroutine and fails on a 5s watchdog. The `fold == 0` control is
// what makes a failure mean "the fold path deadlocks" rather than "this call
// path hangs for some unrelated reason"; without it a hang anywhere in the
// builder would read as this defect.
//
// The goroutine takes `m.mu` ITSELF before calling, rather than the test
// goroutine taking it — Go mutexes are not goroutine-owned, so locking in the
// test and calling from another goroutine would produce an ordinary
// cross-goroutine block and prove nothing about re-entrancy.

func runWithFold(t *testing.T, fold uint32, call func(*Manager, dataplane.SessionKey, *dataplane.SessionValue)) bool {
	t.Helper()
	m := New()
	m.proc = &exec.Cmd{}
	m.SetIngressFoldResolver(func(uint32) (uint32, uint16, bool) { return 42, 80, true })
	key := dataplane.SessionKey{Protocol: 6, SrcPort: 1111, DstPort: 2222}
	val := dataplane.SessionValue{
		IngressIfaceFold: fold,
		ReverseKey:       dataplane.SessionKey{Protocol: 6, SrcPort: 2222, DstPort: 1111},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		call(m, key, &val)
	}()
	select {
	case <-done:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

func TestPeerImportWithIngressFoldDoesNotDeadlock7095(t *testing.T) {
	// The peer-import shape: hold m.mu, then call the *Locked builder, exactly
	// as SetClusterSyncedSessionV4 does.
	peerImport := func(m *Manager, key dataplane.SessionKey, val *dataplane.SessionValue) {
		m.mu.Lock()
		defer m.mu.Unlock()
		_ = m.syncSessionV4Locked("upsert", key, val)
	}
	if !runWithFold(t, 0xABCD1234, peerImport) {
		t.Error("a peer-synced session carrying a non-zero IngressIfaceFold wedged " +
			"syncSessionV4Locked. m.mu is held for the whole import, so the manager " +
			"mutex is now stuck and every later session install, status poll and " +
			"snapshot publish blocks behind it (#7095)")
	}
	if !runWithFold(t, 0, peerImport) {
		t.Error("control: the fold==0 case must complete, or the cell above is not " +
			"isolating the fold")
	}
}

func TestLocalMirrorWithIngressFoldDoesNotDeadlock7095(t *testing.T) {
	localMirror := func(m *Manager, key dataplane.SessionKey, val *dataplane.SessionValue) {
		m.mirrorSessionPairV4(key, *val)
	}
	if !runWithFold(t, 0xABCD1234, localMirror) {
		t.Error("mirrorSessionPairV4 wedged on a session carrying a non-zero " +
			"IngressIfaceFold; it takes m.mu for the whole pair build (#7095)")
	}
	if !runWithFold(t, 0, localMirror) {
		t.Error("control: the fold==0 case must complete, or the cell above is not " +
			"isolating the fold")
	}
}

// The v6 twin exists because the two builders carry SEPARATE calls to the
// resolver: fixing one and not the other is a live possibility, and the v6
// import path is no less reachable than the v4 one.
func TestPeerImportV6WithIngressFoldDoesNotDeadlock7095(t *testing.T) {
	m := New()
	m.proc = &exec.Cmd{}
	m.SetIngressFoldResolver(func(uint32) (uint32, uint16, bool) { return 42, 80, true })
	key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1111, DstPort: 2222}
	val := dataplane.SessionValueV6{IngressIfaceFold: 0xABCD1234}
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.mu.Lock()
		defer m.mu.Unlock()
		_ = m.syncSessionV6Locked("upsert", key, &val)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the v6 peer-import path wedged on a non-zero IngressIfaceFold (#7095)")
	}
}
