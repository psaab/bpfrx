package userspace

import (
	"encoding/json"
	"net"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/dataplane"
)

// injectShimCompileResult sets the unexported dataplane.Manager.lastCompile
// field so zoneNameByID resolves zone IDs to names without a real compile.
func injectShimCompileResult(t *testing.T, bpfShim *dataplane.Manager, cr *dataplane.CompileResult) {
	t.Helper()
	if bpfShim == nil {
		t.Fatal("injectShimCompileResult: bpfShim manager is nil")
	}
	elem := reflect.ValueOf(bpfShim).Elem()
	rv := elem.FieldByName("lastCompile")
	if !rv.IsValid() {
		t.Fatal("injectShimCompileResult: dataplane.Manager has no field named \"lastCompile\"")
	}
	if !rv.CanAddr() {
		t.Fatal("injectShimCompileResult: lastCompile is not addressable")
	}
	reflect.NewAt(rv.Type(), unsafe.Pointer(rv.UnsafeAddr())).Elem().Set(reflect.ValueOf(cr))
}

// TestMirrorSessionPairV4ResolvedAgainstConsistentSnapshot_5007 pins the #5007
// fix: mirrorSessionPairV4 (driven by SetSessionV4) must resolve the forward
// session AND its reverse companion against ONE consistent config snapshot,
// even when a concurrent ApplyConfig swaps m.lastSnapshot mid-install.
//
// The reverse companion carries FibIfindex=0, so its only snapshot-derived
// field is OwnerRGID, resolved from the egress zone via
// resolveOwnerRGFromZone(m.lastSnapshot, ...). This test forces an
// ApplyConfig-style snapshot swap DURING the forward request's control-socket
// I/O (the deliberate m.mu drop in syncSessionRequestsLocked). With the fix
// both requests are BUILT before any socket I/O drops m.mu, so the reverse
// still reflects snapshot A. Reverting to the pre-#5007 shape — building the
// reverse AFTER the forward's socket round-trip — makes the reverse resolve
// against the swapped-in snapshot B and this test fails RED.
//
// It drives mirrorSessionPairV4 directly (not the SetSessionV4 wrapper) so it
// never touches m.bpfShim's kernel session map and needs no BPF privileges.
func TestMirrorSessionPairV4ResolvedAgainstConsistentSnapshot_5007(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")

	ln, err := net.Listen("unix", sessionSock)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	defer ln.Close()

	// Snapshot A: the "trust" egress zone maps to redundancy group 1.
	snapshotA := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{Name: "reth1.0", Ifindex: 6, Zone: "untrust", RedundancyGroup: 1},
			{Name: "reth0.80", Ifindex: 12, Zone: "trust", RedundancyGroup: 1},
		},
	}
	// Snapshot B is identical EXCEPT the "trust" zone now maps to group 2.
	// A reverse companion resolved against B would carry OwnerRGID=2.
	snapshotB := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{Name: "reth1.0", Ifindex: 6, Zone: "untrust", RedundancyGroup: 1},
			{Name: "reth0.80", Ifindex: 12, Zone: "trust", RedundancyGroup: 2},
		},
	}

	var mu sync.Mutex
	var received []*SessionSyncRequest
	forwardReceived := make(chan struct{}, 1)
	swapDone := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				if req.SessionSync != nil {
					mu.Lock()
					received = append(received, req.SessionSync)
					mu.Unlock()
					if !req.SessionSync.IsReverse {
						// Forward request in flight: trigger the concurrent
						// ApplyConfig snapshot swap and hold this response until
						// the swap has fully landed, so the pre-#5007 code path
						// would build the reverse against snapshot B.
						select {
						case forwardReceived <- struct{}{}:
						default:
						}
						<-swapDone
					}
				}
				_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
			}(conn)
		}
	}()

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = controlSock
	m.lastSnapshot = snapshotA
	// zoneNameByID needs a compile result to turn zone IDs into names; the
	// reverse's egress zone (id 1) must resolve to "trust".
	injectShimCompileResult(t, m.bpfShim, &dataplane.CompileResult{
		ZoneIDs: map[string]uint16{"trust": 1, "untrust": 2},
	})

	// Swap goroutine: mimics ApplyConfig publishing a new snapshot under m.mu
	// while the forward request is mid-socket-I/O.
	go func() {
		defer close(swapDone)
		select {
		case <-forwardReceived:
		case <-time.After(2 * time.Second):
			return
		}
		m.mu.Lock()
		m.lastSnapshot = snapshotB
		m.mu.Unlock()
	}()

	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		IsReverse:   0,
		IngressZone: 1, // trust
		EgressZone:  2, // untrust
		FibIfindex:  6, // forward egress resolves by ifindex; RG stays 1 in A and B
		ReverseKey: dataplane.SessionKey{
			SrcIP:    [4]byte{172, 16, 80, 200},
			DstIP:    [4]byte{10, 0, 61, 102},
			SrcPort:  hostToNetwork16(5201),
			DstPort:  hostToNetwork16(50952),
			Protocol: 6,
		},
	}

	m.mirrorSessionPairV4(key, val)

	mu.Lock()
	got := append([]*SessionSyncRequest(nil), received...)
	mu.Unlock()

	if len(got) != 2 {
		t.Fatalf("received %d session-sync requests, want 2 (forward + reverse): %+v", len(got), got)
	}
	var fwd, rev *SessionSyncRequest
	for _, r := range got {
		if r.IsReverse {
			rev = r
		} else {
			fwd = r
		}
	}
	if fwd == nil {
		t.Fatal("no forward session-sync request received")
	}
	if rev == nil {
		t.Fatal("no reverse session-sync request received")
	}
	// The forward was resolved against snapshot A (built before any socket
	// I/O). Its egress interface (ifindex 6) has RG 1 in both snapshots.
	if fwd.OwnerRGID != 1 {
		t.Fatalf("forward OwnerRGID = %d, want 1 (snapshot A)", fwd.OwnerRGID)
	}
	// The reverse companion MUST also reflect snapshot A. If it carries the
	// snapshot-B group (2), the forward/reverse pair drifted across the
	// mid-install ApplyConfig swap — the #5007 regression.
	if rev.OwnerRGID != 1 {
		t.Fatalf("reverse OwnerRGID = %d, want 1 (snapshot A) — forward/reverse "+
			"companion resolved against a different snapshot than the forward (#5007)", rev.OwnerRGID)
	}
}
