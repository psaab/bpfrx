package cluster

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// TestHelperRefusalIsCountedAsDebtNotAsAnError6785 is a PAIRED test on the
// receiver's install accounting: the same call site, two error shapes, opposite
// classifications.
//
// A SEMANTIC refusal from the local userspace helper (#6785) means the helper
// answered correctly and the Go layer already rolled its BPF mirror row back.
// There is no split truth left and no sick socket, so it must NOT bump Errors or
// fire noteHelperMirrorResult's sticky "failed to mirror synced session" warning
// — that would make a standby whose PEER is oversubscribing it read as a flaky
// mirror. It must bump ImportsRefusedByHelper instead, because the peer still
// believes it synced a session this node does not hold and only the peer's next
// full sync closes that gap.
//
// Any OTHER install failure keeps the pre-#6785 behaviour exactly. Without that
// half, "a refusal does not bump Errors" would be satisfied by an implementation
// that stopped counting install errors altogether.
func TestHelperRefusalIsCountedAsDebtNotAsAnError6785(t *testing.T) {
	forward := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80}

	t.Run("semantic-refusal", func(t *testing.T) {
		dp := &mockSweepDP{
			v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
			failSetV4: map[dataplane.SessionKey]error{
				forward: dataplane.ErrSyncedImportRefused,
			},
		}
		ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
		ss.installClusterSyncedV4(forward, dataplane.SessionValue{State: dataplane.SessStateEstablished})

		if got := ss.stats.ImportsRefusedByHelper.Load(); got != 1 {
			t.Fatalf("ImportsRefusedByHelper = %d, want 1 — a helper refusal that "+
				"is counted nowhere is a silent divergence from the peer (#6785)", got)
		}
		if got := ss.stats.Errors.Load(); got != 0 {
			t.Fatalf("Errors = %d, want 0 — a semantic refusal is the correct "+
				"answer from a healthy helper, not a mirror error", got)
		}
		if got := ss.stats.SessionsInstalled.Load(); got != 0 {
			t.Fatalf("SessionsInstalled = %d, want 0 — the session was refused", got)
		}
	})

	t.Run("other-failure-keeps-the-error-accounting", func(t *testing.T) {
		dp := &mockSweepDP{
			v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
			failSetV4: map[dataplane.SessionKey]error{
				forward: errors.New("session table write failed"),
			},
		}
		ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
		ss.installClusterSyncedV4(forward, dataplane.SessionValue{State: dataplane.SessStateEstablished})

		if got := ss.stats.Errors.Load(); got != 1 {
			t.Fatalf("Errors = %d, want 1 — a non-refusal install failure must "+
				"still be counted as an error", got)
		}
		if got := ss.stats.ImportsRefusedByHelper.Load(); got != 0 {
			t.Fatalf("ImportsRefusedByHelper = %d, want 0 on a non-refusal failure", got)
		}
	})
}

// TestHelperRefusalIsCountedAsDebtNotAsAnErrorV6_6785 is the IPv6 twin. The two
// install paths carry independently written copies of the classify/count
// sequence, so a divergence between them is always a bug and binding only V4
// would leave the V6 receiver reporting refusals as mirror errors.
func TestHelperRefusalIsCountedAsDebtNotAsAnErrorV6_6785(t *testing.T) {
	forward := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1234, DstPort: 80}
	forward.SrcIP[15] = 1
	forward.DstIP[15] = 2

	dp := &mockSweepDP{
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
		failSetV6: map[dataplane.SessionKeyV6]error{
			forward: dataplane.ErrSyncedImportRefused,
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.installClusterSyncedV6(forward, dataplane.SessionValueV6{State: dataplane.SessStateEstablished})

	if got := ss.stats.ImportsRefusedByHelper.Load(); got != 1 {
		t.Fatalf("v6 ImportsRefusedByHelper = %d, want 1", got)
	}
	if got := ss.stats.Errors.Load(); got != 0 {
		t.Fatalf("v6 Errors = %d, want 0", got)
	}
}

// TestRefusalDebtIsRenderedOnlyWhenNonZero6785 pins the operator surface. The
// counter is health debt, so it has to reach `show chassis cluster information`
// — a counter nothing renders is a variable, not debt. It is rendered only when
// non-zero: zero is the ordinary state and a permanently-present "0" line is
// noise an operator learns to skip past.
func TestRefusalDebtIsRenderedOnlyWhenNonZero6785(t *testing.T) {
	const line = "Imports refused by helper:"

	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	cfg.ControlInterface = "em0"
	m.UpdateConfig(cfg)
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	m.SetSyncStats(ss)

	if got := m.FormatInformation(); strings.Contains(got, line) {
		t.Fatalf("the refusal line is rendered at zero:\n%s", got)
	}
	ss.stats.ImportsRefusedByHelper.Store(3)
	out := m.FormatInformation()
	if !strings.Contains(out, line+" 3") {
		t.Fatalf("a non-zero refusal count is not rendered anywhere an operator "+
			"can see it (want %q):\n%s", line+" 3", out)
	}
}
