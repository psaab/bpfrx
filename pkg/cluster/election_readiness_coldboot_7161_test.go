package cluster

import (
	"strings"
	"testing"
	"time"
)

// #7161: electSingleNode applied the per-RG takeover readiness gate only when
// `m.peerAlive`, so a node promoted while NOT READY on exactly the paths a cold
// boot and a peer loss take.
//
// The fix gates on cold boot and keeps the fail-open on genuine peer loss:
//
//	(m.peerAlive || !m.peerEverSeen)
//
// The two differ for a real reason. On peer LOSS an established cluster had a
// working primary and it died — a survivor refusing takeover is a total outage
// and it may be the only node that can forward. On COLD BOOT there is no
// established forwarding to preserve and a not-ready node that promotes forwards
// nothing anyway; it claims the VIPs while unable to serve them.
//
// WHY THIS TABLE HAS THREE ROWS AND NOT TWO. Two rows — peer-alive-not-ready and
// cold-boot-not-ready, both expecting secondary — are also satisfied by deleting
// the gate's peer condition entirely, i.e. by gating unconditionally and losing
// the peer-loss fail-open that the issue explicitly defends. Only the middle row
// distinguishes the intended change from that total flip.

func preemptColdBootManager7161(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	cfg.ControlInterface = "em0" // cluster mode: the election gates are armed
	m.UpdateConfig(cfg)
	// Preempt so the separate `!rg.Preempt && !peerEverSeen` non-preempt guard
	// two blocks above cannot mask the result — without this, the cold-boot row
	// would pass for the wrong reason.
	m.mu.Lock()
	m.groups[0].Preempt = true
	m.mu.Unlock()
	return m
}

// setNotReady drives the RG not-ready through the real setter, then asserts the
// precondition, so a cell can never measure a state it failed to establish.
func setNotReady7161(t *testing.T, m *Manager) {
	t.Helper()
	m.SetRGReady(0, true, nil)
	m.SetRGReady(0, false, []string{"interface ge-0/0/1 missing"})
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.groups[0].Ready {
		t.Fatal("precondition: the RG must be NOT ready or every assertion below " +
			"is about a different state than the one named")
	}
	m.groups[0].State = StateSecondary
}

func electState7161(m *Manager, peerAlive, peerEverSeen bool) NodeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerAlive = peerAlive
	m.peerEverSeen = peerEverSeen
	m.electSingleNode()
	return m.groups[0].State
}

func TestElectSingleNodeReadinessGateByPeerHistory7161(t *testing.T) {
	for _, tc := range []struct {
		name         string
		peerAlive    bool
		peerEverSeen bool
		want         NodeState
		why          string
	}{
		{
			name:      "peer alive, not ready -> secondary (unchanged)",
			peerAlive: true, peerEverSeen: true, want: StateSecondary,
			why: "the gate has always applied while the peer is alive; a regression " +
				"here means the fix widened the bypass instead of narrowing it",
		},
		{
			name:      "peer LOSS, not ready -> PRIMARY (fail-open preserved)",
			peerAlive: false, peerEverSeen: true, want: StatePrimary,
			why: "an established cluster lost its primary. A survivor that refuses " +
				"takeover is a TOTAL OUTAGE and may be the only node that can " +
				"forward. This row is what distinguishes the intended change from " +
				"gating unconditionally",
		},
		{
			name:      "COLD BOOT, not ready -> secondary (the change)",
			peerAlive: false, peerEverSeen: false, want: StateSecondary,
			why: "no established forwarding to preserve, and a not-ready node that " +
				"promotes forwards nothing anyway — it claims the VIPs while unable " +
				"to serve them and denies the peer a clean takeover (#103 criterion 1)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := preemptColdBootManager7161(t)
			setNotReady7161(t, m)
			if got := electState7161(m, tc.peerAlive, tc.peerEverSeen); got != tc.want {
				t.Errorf("peerAlive=%v peerEverSeen=%v: state=%v, want %v — %s",
					tc.peerAlive, tc.peerEverSeen, got, tc.want, tc.why)
			}
		})
	}
}

// The degraded fallback, in the shape #110 got wrong.
//
// #110's armSyncReadyTimer bails its callback on `!d.syncPeerConnected`, so its
// fallback never fires in exactly the peer-absent case it was written for. This
// cell therefore runs with NO PEER EVER SEEN — the case the fallback exists for
// — and would fail if the fallback were gated on any peer condition.
func TestDegradedTimeoutPromotesWithNoPeerEverSeen7161(t *testing.T) {
	m := preemptColdBootManager7161(t)
	setNotReady7161(t, m)

	m.mu.Lock()
	m.degradedPromoteTimeout = 40 * time.Millisecond
	m.mu.Unlock()

	// First election: the gate declines AND arms the fallback. Both halves are
	// at the decline site precisely because a cold-boot RG may never see a
	// readiness TRANSITION for SetRGReady to hook.
	if got := electState7161(m, false, false); got != StateSecondary {
		t.Fatalf("precondition: the cold-boot gate must decline first; got %v", got)
	}
	m.mu.Lock()
	armed := !m.groups[0].NotReadySince.IsZero()
	m.mu.Unlock()
	if !armed {
		t.Fatal("the decline did not stamp NotReadySince, so the fallback has no " +
			"window to measure and could never fire (#7161)")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		m.mu.Lock()
		state, degraded := m.groups[0].State, m.groups[0].DegradedPromoted
		m.mu.Unlock()
		if state == StatePrimary {
			if !degraded {
				t.Error("promoted without DegradedPromoted set: the operator cannot " +
					"tell a degraded promotion from a healthy one (#7161)")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the degraded fallback never fired with no peer ever seen. That " +
				"is #110's defect exactly: a fallback gated on the condition it " +
				"compensates for is not a fallback (#7161)")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Becoming ready must CANCEL the fallback and forget the window, so a later
// decline starts a fresh one. Without this a node that was briefly not-ready
// long ago would promote instantly on its next decline.
func TestReadyClearsTheDegradedWindow7161(t *testing.T) {
	m := preemptColdBootManager7161(t)
	setNotReady7161(t, m)
	if got := electState7161(m, false, false); got != StateSecondary {
		t.Fatalf("precondition: expected the gate to decline; got %v", got)
	}

	m.SetRGReady(0, true, nil)
	m.mu.Lock()
	cleared := m.groups[0].NotReadySince.IsZero() && m.groups[0].degradedTimer == nil
	m.mu.Unlock()
	if !cleared {
		t.Fatal("becoming ready left the not-ready window and/or the timer in place; " +
			"a later decline would inherit an already-satisfied window and promote " +
			"a not-ready RG immediately (#7161)")
	}
}

// The reason must name the readiness cause, not just the timeout — an operator
// reading `show chassis cluster` needs to know WHY it was not ready.
func TestDegradedReasonNamesTheReadinessCause7161(t *testing.T) {
	m := preemptColdBootManager7161(t)
	setNotReady7161(t, m)
	m.mu.Lock()
	m.degradedPromoteTimeout = time.Millisecond
	m.groups[0].NotReadySince = time.Now().Add(-time.Hour)
	reason, ok := m.degradedPromoteDueLocked(m.groups[0])
	m.mu.Unlock()
	if !ok {
		t.Fatal("the fallback did not report due after an hour not ready")
	}
	if !strings.Contains(reason, "ge-0/0/1") {
		t.Errorf("reason %q does not name the readiness cause; the operator is told "+
			"a timeout elapsed but not what was wrong (#7161)", reason)
	}
}
