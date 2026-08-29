package cluster

import (
	"testing"
	"time"
)

// #7942: DegradedPromoted must be CLEARED when the RG becomes ready again.
//
// It had two setters — electSingleNode and, since #7939, runElection — and no
// clearer, so an RG promoted while not ready reported that for the life of the
// process, including after it recovered and was re-promoted normally. The flag
// answers "is this RG forwarding while NOT ready", a statement about now, not a
// permanent record that it once was.
//
// WHY THE EXISTING #7161 CELL COULD NOT SEE THIS. It asserts the flag is SET on
// a degraded promotion and stops there. Nothing asserted it is ever cleared, so
// the sticky bug was invisible to the suite by construction — the same shape as
// an absence that is never checked. This cell walks the whole edge instead of
// one side of it: not-ready, promote degraded, become ready, assert cleared.
//
// Latent when found: no production surface renders the field yet, only tests.
// That is the reason to fix it rather than a reason to defer — a field with two
// setters and no reset is correct exactly until someone wires it into
// `show chassis cluster status`, and then it reads "degraded" on a healthy RG.

func TestDegradedPromotedIsClearedWhenReadyAgain7942(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	cfg.ControlInterface = "em0"
	m.UpdateConfig(cfg)

	m.mu.Lock()
	rg := m.groups[0]
	rg.State = StateSecondary
	rg.Ready = false
	rg.ReadySince = time.Time{}
	rg.ReadinessReasons = []string{"userspace XSK liveness not proven"}
	// Arrive at the state a degraded promotion leaves behind.
	rg.NotReadySince = time.Now().Add(-2 * m.degradedPromoteTimeout)
	rg.DegradedPromoted = true
	m.mu.Unlock()

	// Precondition: without this, a test on an RG that was never degraded would
	// pass trivially.
	m.mu.RLock()
	if !m.groups[0].DegradedPromoted {
		m.mu.RUnlock()
		t.Fatal("precondition: the fixture must start with DegradedPromoted set")
	}
	m.mu.RUnlock()

	// The become-ready edge.
	m.mu.Lock()
	m.clearDegradedStateLocked(m.groups[0])
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.groups[0].DegradedPromoted {
		t.Error("DegradedPromoted survived the RG becoming ready. The flag means " +
			"'forwarding while NOT ready' — left set, it reports a healthy RG as " +
			"degraded for the life of the process (#7942)")
	}
	if !m.groups[0].NotReadySince.IsZero() {
		t.Error("NotReadySince must also be cleared, or the degraded timer re-arms " +
			"against a stale start point")
	}
}
