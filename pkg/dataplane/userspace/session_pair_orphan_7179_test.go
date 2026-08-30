package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #7179: the pair mirror discarded its transmit result entirely
// (`_ = m.syncSessionPairLocked(reqs...)`), so a partial helper mutation was
// not merely un-rolled-back, it was UNREPORTED.
//
// The direction that matters is the opposite of the one #7179 was filed
// describing, and that is why the classifier below is asymmetric. A forward
// that SUCCEEDS never leaves a half pair: the helper synthesizes and publishes
// the reverse companion itself on every non-reverse import, measured as
// entries=2 from a single forward upsert. A forward that fails at the TRANSPORT
// layer aborts the batch, so the reverse is never sent. The only way to publish
// a lone reverse is a forward the helper actively REFUSES — an application
// error such as a capacity rejection — after which the batch continues and the
// explicit reverse lands alone.

// orphanServer answers the FIRST session-sync request with an application-level
// error and every later one with success, reproducing exactly that shape: a
// healthy, reachable helper that refuses the forward.
type orphanServer struct {
	seen    atomic.Int64
	failIdx int64 // which arrival index gets the error reply (-1 = none)
	failAll bool  // refuse every request
}

func (o *orphanServer) serve(ln net.Listener) {
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
				idx := o.seen.Add(1) - 1
				resp := ControlResponse{OK: true}
				if o.failAll || idx == o.failIdx {
					// A REFUSAL from a healthy helper: ok=false with a reason.
					// Not a transport failure, so the batch continues.
					resp = ControlResponse{OK: false, Error: "synced import refused: capacity"}
				}
				_ = json.NewEncoder(conn).Encode(resp)
			}(conn)
		}
	}()
}

func newOrphanManager(t *testing.T, o *orphanServer) *Manager {
	t.Helper()
	dir, err := os.MkdirTemp("", "x7179")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "userspace-dp-sessions.sock"))
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	o.serve(ln)

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	m.lastSnapshot = &ConfigSnapshot{}
	return m
}

// TestMirrorSessionPairReportsOrphanedReverse binds the fix through the REAL
// mirror entry point, not the classifier. A test that only exercised
// sessionPairResult.orphanedReverse could not see mirrorSessionPair stop
// calling recordSessionPairResult, which is the wiring the fix consists of.
func TestMirrorSessionPairReportsOrphanedReverse(t *testing.T) {
	o := &orphanServer{failIdx: 0} // refuse the FORWARD, accept the reverse
	m := newOrphanManager(t, o)

	key := dataplane.SessionKey{Protocol: 6, SrcPort: 1234, DstPort: 80}
	val := dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		ReverseKey:  dataplane.SessionKey{Protocol: 6, SrcPort: 80, DstPort: 1234},
	}

	before := m.SessionPairOrphanedReverseTotal()
	m.mirrorSessionPairV4(key, val)

	if got := o.seen.Load(); got != 2 {
		t.Fatalf("helper saw %d requests, want 2 -- the fixture must send BOTH "+
			"halves or it cannot exercise a partial application", got)
	}
	if got := m.SessionPairOrphanedReverseTotal(); got != before+1 {
		t.Fatalf("orphaned-reverse total = %d, want %d: a refused forward with an "+
			"applied reverse left a reverse-only entry and was not reported", got, before+1)
	}
}

// TestMirrorSessionPairDoesNotReportWholeFailure is the negative control, and
// it carries as much weight as the positive one. A pair the helper never
// applied is benign -- the periodic session sync reconciles it -- so reporting
// it would fire on every transient hiccup and bury the case that matters. An
// implementation that counted ANY error would satisfy the positive test and
// fail here.
func TestMirrorSessionPairDoesNotReportWholeFailure(t *testing.T) {
	o := &orphanServer{failIdx: -1, failAll: true}
	m := newOrphanManager(t, o)

	key := dataplane.SessionKey{Protocol: 6, SrcPort: 1234, DstPort: 80}
	val := dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		ReverseKey:  dataplane.SessionKey{Protocol: 6, SrcPort: 80, DstPort: 1234},
	}
	before := m.SessionPairOrphanedReverseTotal()
	m.mirrorSessionPairV4(key, val)

	if got := o.seen.Load(); got != 2 {
		t.Fatalf("helper saw %d requests, want 2 -- an application-level refusal "+
			"must not abort the batch, or this control proves nothing", got)
	}
	if got := m.SessionPairOrphanedReverseTotal(); got != before {
		t.Fatalf("orphaned-reverse total advanced to %d on a wholly-refused pair; "+
			"nothing was applied, so nothing was stranded", got)
	}
}

// TestMirrorSessionPairDoesNotReportForwardOnlySuccess is the second negative
// control, aimed at the direction #7179 actually described. A forward that is
// APPLIED while the reverse is refused must not be reported: the helper
// synthesizes and publishes its own reverse companion on every non-reverse
// import, so that outcome is a COMPLETE pair, not a stranded half.
func TestMirrorSessionPairDoesNotReportForwardOnlySuccess(t *testing.T) {
	o := &orphanServer{failIdx: 1} // accept the forward, refuse the reverse
	m := newOrphanManager(t, o)

	key := dataplane.SessionKey{Protocol: 6, SrcPort: 1234, DstPort: 80}
	val := dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		ReverseKey:  dataplane.SessionKey{Protocol: 6, SrcPort: 80, DstPort: 1234},
	}
	before := m.SessionPairOrphanedReverseTotal()
	m.mirrorSessionPairV4(key, val)

	if got := m.SessionPairOrphanedReverseTotal(); got != before {
		t.Fatalf("orphaned-reverse total advanced to %d when the FORWARD was "+
			"applied; the helper builds its own reverse companion, so that is a "+
			"complete pair", got)
	}
}

// TestOrphanedReverseClassification pins the classifier itself across every
// shape the transmit can produce.
func TestOrphanedReverseClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  sessionPairResult
		want bool
	}{
		{"forward refused, reverse applied", sessionPairResult{total: 2, failed: []int{0}, applied: []int{1}}, true},
		{"forward applied, reverse failed", sessionPairResult{total: 2, failed: []int{1}, applied: []int{0}}, false},
		{"both failed", sessionPairResult{total: 2, failed: []int{0, 1}}, false},
		{"both applied", sessionPairResult{total: 2, applied: []int{0, 1}}, false},
		// A transport abort never SENDS the reverse, so it cannot appear in
		// `applied`. False here follows from the empty applied set, not from an
		// `aborted` guard -- there deliberately is none, because such a guard
		// would be unreachable by construction.
		{"aborted after forward", sessionPairResult{total: 2, failed: []int{0}, aborted: true}, false},
		// A lone forward with no companion is not a pair at all.
		{"single request refused", sessionPairResult{total: 1, failed: []int{0}}, false},
		{"empty", sessionPairResult{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.orphanedReverse(); got != tc.want {
				t.Errorf("orphanedReverse() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMirrorSessionPairV6ReportsOrphanedReverse binds the V6 wiring
// independently. The V4 test cannot see mirrorSessionPairV6 stop calling
// recordSessionPairResult -- the two are separate call sites, and a fix wired
// into only one of them is the asymmetry this campaign keeps finding (the V6
// half of the HA delta-drop logging was silent for exactly this reason).
func TestMirrorSessionPairV6ReportsOrphanedReverse(t *testing.T) {
	o := &orphanServer{failIdx: 0}
	m := newOrphanManager(t, o)

	key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1234, DstPort: 80}
	val := dataplane.SessionValueV6{
		IngressZone: 1,
		EgressZone:  2,
		ReverseKey:  dataplane.SessionKeyV6{Protocol: 6, SrcPort: 80, DstPort: 1234},
	}

	before := m.SessionPairOrphanedReverseTotal()
	m.mirrorSessionPairV6(key, val)

	if got := o.seen.Load(); got != 2 {
		t.Fatalf("helper saw %d requests, want 2", got)
	}
	if got := m.SessionPairOrphanedReverseTotal(); got != before+1 {
		t.Fatalf("v6 orphaned-reverse total = %d, want %d", got, before+1)
	}
}
