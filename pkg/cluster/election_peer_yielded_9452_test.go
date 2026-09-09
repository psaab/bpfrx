package cluster

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"
)

// #9452: a manual failover into a node that is still inside its bounded startup
// promotion hold must not leave the redundancy group owned by NEITHER node.
//
// WHAT WAS MEASURED, on the loss userspace cluster at origin/master with nothing
// applied. `make test-failover` crashes fw0, waits for it to rejoin as
// secondary, then runs `request chassis cluster failover redundancy-group N` on
// fw1 for N in 0,1,2. fw1 demoted all three immediately and fw0 became primary
// for NONE of them. fw0's journal named the reason at 5 Hz for 19 seconds:
//
//	cluster: election blocked by readiness gate rg=0 ready=false
//	  reasons="[session sync startup hold: bulk sync not yet complete]"
//
// and then promoted all three at the instant the #7162 hold hit its 30s
// timeout — "no-RETH sync hold timeout: bulk sync did not complete, releasing
// promotion hold in degraded mode". So the transfer was not refused, it was
// DEFERRED past the point of usefulness, and for the whole deferral the RG had
// no owner: nothing answered proxy-ARP for the pool-NAT address, which is the
// fourth red cell in the same run. (The iperf3 average also fell from 22.5 to
// 18.1 Gbit/s in that run, but the fix refuted the obvious attribution: with the
// gap closed to 0-1s, two runs came back at 18.9 and 20.3 against a
// [21.4, 23.6] band. A separate signal, tracked as #9484.)
//
// The 30s hold is IN CONTRACT — daemon_ha_noreth_hold.go states it releases on
// its own timer regardless of sync or peer state. So this is not a hold-duration
// bug that better NTP or a faster bulk sync would remove: with everything
// healthy, `request chassis cluster failover` issued within 30s of a peer
// restart still blackholes the RG for the remainder of the hold.
//
// WHY THESE CELLS DRIVE runElection AND NOT THE HELPER. The helper is a pure
// three-line predicate; a test that only calls it stays GREEN when the CALL SITE
// is reverted to the bare `continue`, which is the entire defect. Every
// behavioural cell below goes through m.runElection() with a peer heartbeat as
// the only input, and the wiring cell at the bottom asserts the call site by
// source.

// peerTransferredOutWhileNotReady builds the measured shape: peer alive on the
// control link, reporting SecondaryHold for RG0 (an explicit transfer-out), with
// the local RG NOT ready for exactly the reason the live node logged.
// preempt is a parameter because the LIVE cluster this was measured on runs
// `Preempt: no` on every RG, and the two settings reach the readiness gate by
// DIFFERENT electRG branches. With preempt the gate is reached through
// "Preempt: higher priority"; without it, through the peer-transfer-out branch
// (transfer-out and weight-0 are both checked BEFORE the preempt split, which is
// why the fix works identically in both). The controls below are the case where
// the two differ, and they are run in both modes for that reason.
func peerTransferredOutWhileNotReady(t *testing.T, peerState NodeState, peerWeight int, preempt bool) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, preempt, map[int]int{0: 200}))
	cfg.ControlInterface = "em0" // cluster mode: the readiness gate applies
	m.UpdateConfig(cfg)

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: uint8(peerWeight), State: uint8(peerState)},
		},
	})

	m.mu.Lock()
	rg := m.groups[0]
	rg.State = StateSecondary
	rg.Ready = false
	rg.ReadySince = time.Time{}
	rg.ReadinessReasons = []string{"session sync startup hold: bulk sync not yet complete"}
	m.mu.Unlock()
	return m
}

func TestPeerTransferOutPromotesDespiteStartupHold9452(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		t.Run(preemptName(preempt), func(t *testing.T) {
			peerTransferOutPromotes9452(t, preempt)
		})
	}
}

func preemptName(preempt bool) string {
	if preempt {
		return "preempt"
	}
	return "non-preempt" // the live cluster's setting
}

func peerTransferOutPromotes9452(t *testing.T, preempt bool) {
	m := peerTransferredOutWhileNotReady(t, StateSecondaryHold, 100, preempt)

	m.runElection()

	if !m.IsLocalPrimary(0) {
		t.Fatal("the peer has explicitly transferred out (secondary-hold) and this node is " +
			"the only other node: holding it secondary because a bounded startup hold has " +
			"not expired leaves RG0 owned by NEITHER node. Measured on the loss cluster as " +
			"19s of no owner, no proxy-ARP for the pool-NAT address, and a manual failover " +
			"the CLI had already reported as triggered (#9452)")
	}
	m.mu.RLock()
	degraded := m.groups[0].DegradedPromoted
	m.mu.RUnlock()
	if !degraded {
		t.Error("a promotion that happened while the RG was NOT ready must be MARKED " +
			"DegradedPromoted: it is forwarding without proven state and must not read as " +
			"a normal promotion in the event stream or in show chassis cluster status")
	}
}

// The promotion reason is the operator's only account of why a not-ready node is
// forwarding. sendEvent routes it into the RG event history, which is what
// `show chassis cluster status` renders under "Event history:" — a promotion
// that lands with the ordinary reason string is indistinguishable from a normal
// one.
func TestPeerTransferOutPromotionNamesItsReason9452(t *testing.T) {
	m := peerTransferredOutWhileNotReady(t, StateSecondaryHold, 100, false)

	m.runElection()

	var msg string
	for _, ev := range m.history.Events(EventRG) {
		if ev.GroupID == 0 && strings.Contains(ev.Message, "->primary") {
			msg = ev.Message
		}
	}
	if msg == "" {
		t.Fatal("no RG history entry recorded for the promotion to primary")
	}
	for _, want := range []string{
		"DEGRADED",
		"peer transferred out",
		"session sync startup hold",
		"owned by neither node",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("promotion history %q does not contain %q — this string is the only place "+
				"the operator learns that this node is forwarding without proven state and "+
				"why it promoted anyway", msg, want)
		}
	}
}

// The second way a live peer reports non-ownership. Weight 0 is a resignation
// and electRG forces a weight-0 node secondary unconditionally, so the peer
// cannot be primary — the same "nobody owns it" argument applies.
func TestPeerResignedWeightZeroPromotesDespiteStartupHold9452(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		t.Run(preemptName(preempt), func(t *testing.T) {
			peerResignedPromotes9452(t, preempt)
		})
	}
}

func peerResignedPromotes9452(t *testing.T, preempt bool) {
	m := peerTransferredOutWhileNotReady(t, StateSecondary, 0, preempt)

	m.runElection()

	if !m.IsLocalPrimary(0) {
		t.Fatal("the peer advertises weight 0, which election forces to SECONDARY " +
			"unconditionally, so it cannot be primary. Holding this node secondary because " +
			"a startup hold has not expired leaves the RG owned by neither node (#9452)")
	}
}

// CONTROL — the case the gate exists for, and the one an over-correction breaks.
//
// Both nodes secondary with the peer alive and healthy (weight > 0) is a COLD
// BOOT: nobody has yielded anything, there is no established forwarding to
// preserve, and a not-ready node that promotes forwards nothing while denying
// the peer a clean takeover. This must still HOLD.
//
// This cell is what distinguishes the fix from "promote whenever not ready".
// A peerYieldedOwnership that returned true unconditionally passes all three
// cells above and reds here.
func TestColdBootStillHoldsSecondary9452(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		t.Run(preemptName(preempt), func(t *testing.T) {
			coldBootHolds9452(t, preempt)
		})
	}
}

func coldBootHolds9452(t *testing.T, preempt bool) {
	m := peerTransferredOutWhileNotReady(t, StateSecondary, 100, preempt)

	m.runElection()

	if m.IsLocalPrimary(0) {
		t.Fatal("a not-ready RG whose peer is alive, healthy and has yielded NOTHING must " +
			"stay secondary — that is the cold-boot case the readiness gate exists for, and " +
			"promoting here claims VIPs this node cannot serve while denying the peer a " +
			"clean takeover (#7161 / #9452 control)")
	}
}

// CONTROL — the crash-failover half of make test-failover, which is GREEN today
// and must not be traded away.
//
// After fw0 reboots and rejoins, fw1 is PRIMARY with weight > 0. fw0 has the
// higher configured priority (200 vs 100) and non-preempt, so it must stay
// SECONDARY. If the fix made a not-ready node promote against a live primary it
// would auto-preempt here, red "fw0 rejoined as secondary for every redundancy
// group (no auto-preempt)" and "fw1 remains primary after fw0 rejoin", and reset
// every established flow.
func TestPeerPrimaryStillNoAutoPreempt9452(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		t.Run(preemptName(preempt), func(t *testing.T) {
			peerPrimaryNoAutoPreempt9452(t, preempt)
		})
	}
}

func peerPrimaryNoAutoPreempt9452(t *testing.T, preempt bool) {
	m := peerTransferredOutWhileNotReady(t, StatePrimary, 100, preempt)

	m.runElection()

	if m.IsLocalPrimary(0) {
		t.Fatal("the peer is PRIMARY and forwarding: a higher-priority non-preempt node must " +
			"stay secondary on rejoin. Promoting here is a dual-active and resets every " +
			"established flow (#9452 control for the green crash-failover cells)")
	}
}

// The predicate's own answers. Read the header on why this cell is not the
// binding one: reverting the call site leaves it green.
func TestPeerYieldedOwnershipVerdicts9452(t *testing.T) {
	for _, tc := range []struct {
		name string
		peer *PeerGroupState
		want bool
		frag string
	}{
		{"nil peer group is peer loss, not this case", nil, false, ""},
		{"explicit transfer-out", &PeerGroupState{State: StateSecondaryHold, Weight: 100}, true, "transferred out"},
		{"resigned with weight 0", &PeerGroupState{State: StateSecondary, Weight: 0}, true, "resigned"},
		{"healthy secondary is the cold-boot shape", &PeerGroupState{State: StateSecondary, Weight: 100}, false, ""},
		{"live primary has not yielded", &PeerGroupState{State: StatePrimary, Weight: 100}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, got := peerYieldedOwnership(tc.peer)
			if got != tc.want {
				t.Fatalf("peerYieldedOwnership = %v, want %v", got, tc.want)
			}
			if tc.frag != "" && !strings.Contains(reason, tc.frag) {
				t.Errorf("reason %q does not contain %q", reason, tc.frag)
			}
			if !tc.want && reason != "" {
				t.Errorf("a false verdict must carry no reason, got %q", reason)
			}
		})
	}
}

// WIRING. The behavioural cells above are the primary binding, but they cannot
// see a future refactor that keeps them green by consulting the predicate
// somewhere harmless. This asserts the call site itself: runElection's readiness
// gate must name peerYieldedOwnership, because a helper nothing on that path
// calls is the exact shape of the #7939 divergence one layer down.
func TestRunElectionGateConsultsPeerYieldedOwnership9452(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "election.go", nil, 0)
	if err != nil {
		t.Fatalf("parse election.go: %v", err)
	}
	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runElection" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "peerYieldedOwnership" {
				found = true
			}
			return true
		})
	}
	if !found {
		t.Error("runElection does not call peerYieldedOwnership, so the readiness gate has no " +
			"unowned-RG escape and a manual failover into a node inside its startup hold " +
			"leaves the redundancy group owned by neither node (#9452)")
	}
}
