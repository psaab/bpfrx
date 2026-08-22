package rpm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// rpmCarryCfg builds a one-probe/one-test RPM stanza. destIface, when set,
// makes the test's pin (and therefore its fwmark) depend on the RETH map.
func rpmCarryCfg(target, destIface string) *config.RPMConfig {
	return &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {
				Name:                 "t",
				Target:               target,
				DestinationInterface: destIface,
				NextHop:              "10.0.0.1",
				TestInterval:         3600,
			},
		}},
	}}
}

// newCarryManager returns a Manager whose prober BLOCKS until cleanup, so the
// probe goroutines Apply starts cannot race the assertions by writing a fresh
// verdict over the carried one. It returns on ctx.Done as well, so StopAll's
// wg.Wait() cannot hang.
func newCarryManager(t *testing.T) *Manager {
	t.Helper()
	m := New()
	release := make(chan struct{})
	m.probeFn = func(ctx context.Context, _ *config.RPMTest, _ string) (time.Duration, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return 0, fmt.Errorf("blocked test prober")
	}
	t.Cleanup(func() {
		close(release)
		m.StopAll()
	})
	return m
}

// setVerdict simulates a probe cycle having concluded FAIL for the given key.
func setVerdict(m *Manager, key, status string, succFail int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.results[key]; r != nil {
		r.LastStatus = status
		r.SuccFail = succFail
		r.TotalSent = 42
	}
}

func statusOf(m *Manager, key string) (string, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r := m.results[key]
	if r == nil {
		return "<absent>", 0
	}
	return r.LastStatus, r.SuccFail
}

// TestApplyCarriesVerdictAcrossUnrelatedCommit_6561 is the fail-on-revert gate.
//
// Manager.Apply rebuilt the whole results table from config and seeded every
// key LastStatus "unknown". ip-monitoring reads "unknown" as PASS
// (seedResultsLocked buckets it with pass via `r.LastStatus == "fail"`), so at
// the DEFAULT hold-down of 0 an ACTIVE failover route was withdrawn on the spot.
//
// The trigger is not exotic: reconcileRPM is hash-gated, but the hash covers
// cfg.RethToPhysical() as well as the RPM stanza, so an interface-stanza edit
// that never mentions `services rpm` restarts the probes and wiped every
// verdict. The reconcile is NOT skipped by this fix — what is preserved is the
// runtime half the config does not carry.
func TestApplyCarriesVerdictAcrossUnrelatedCommit_6561(t *testing.T) {
	const key = "WAN/t"
	ctx := context.Background()

	t.Run("an unchanged test keeps its verdict", func(t *testing.T) {
		m := newCarryManager(t)
		cfg := rpmCarryCfg("192.0.2.1", "reth0")
		m.SetRethMap(map[string]string{"reth0": "ge-0/0/2"})
		m.Apply(ctx, cfg)
		setVerdict(m, key, "fail", 3)

		// The re-apply an unrelated RETH edit produces: same RPM stanza, same
		// resolution for THIS test.
		m.Apply(ctx, cfg)

		if got, sf := statusOf(m, key); got != "fail" || sf != 3 {
			t.Fatalf("verdict after an unrelated commit = (%q, %d), want (\"fail\", 3) — "+
				"a wipe to \"unknown\" reads as PASS in ipmon and withdraws the active "+
				"failover route at the default hold-down of 0", got, sf)
		}
	})

	t.Run("an unrelated RETH-map edit keeps the verdict", func(t *testing.T) {
		// The issue's headline scenario. The RETH map changes — which is what
		// re-opens the reconcileRPM hash gate — but not for THIS test's
		// destination interface, so its pin and fwmark are unchanged and the
		// probe is still measuring the same path.
		m := newCarryManager(t)
		cfg := rpmCarryCfg("192.0.2.1", "reth0")
		m.SetRethMap(map[string]string{"reth0": "ge-0/0/2"})
		m.Apply(ctx, cfg)
		setVerdict(m, key, "fail", 3)

		m.SetRethMap(map[string]string{"reth0": "ge-0/0/2", "reth9": "ge-0/0/9"})
		m.Apply(ctx, cfg)

		if got, _ := statusOf(m, key); got != "fail" {
			t.Fatalf("verdict after an unrelated RETH-map edit = %q, want \"fail\"", got)
		}
	})

	t.Run("this test's own path moving DOES reseed", func(t *testing.T) {
		// The other half of the contract, and the reason the check is on the
		// fwmark rather than a plain field compare: the mark is derived from the
		// whole pin (routing-instance, destination-interface, next-hop, RETH
		// map), so a mark change means the probe's EGRESS PATH moved. A verdict
		// measured over the old path says nothing about the new one.
		m := newCarryManager(t)
		cfg := rpmCarryCfg("192.0.2.1", "reth0")
		m.SetRethMap(map[string]string{"reth0": "ge-0/0/2"})
		m.Apply(ctx, cfg)
		before := identityOf(m, key)
		setVerdict(m, key, "fail", 3)

		// The RETH map now moves THIS test's egress member.
		m.SetRethMap(map[string]string{"reth0": "ge-0/0/7"})
		m.Apply(ctx, cfg)

		// Hard failure, not a skip: if the identity stops moving here the
		// assertion below goes vacuous and would certify the carry-forward it
		// exists to disprove.
		if after := identityOf(m, key); before == after {
			t.Fatalf("setup: the measurement identity did not move (%q) — the discriminator is not exercised", before)
		}
		if got, _ := statusOf(m, key); got != "unknown" {
			t.Fatalf("verdict after THIS test's path moved = %q, want \"unknown\" — "+
				"a verdict measured over the old egress path must not be carried", got)
		}
	})

	t.Run("a retargeted test reseeds", func(t *testing.T) {
		m := newCarryManager(t)
		m.Apply(ctx, rpmCarryCfg("192.0.2.1", ""))
		setVerdict(m, key, "fail", 3)

		m.Apply(ctx, rpmCarryCfg("198.51.100.9", ""))

		if got, _ := statusOf(m, key); got != "unknown" {
			t.Fatalf("verdict after the target changed = %q, want \"unknown\" — "+
				"a test repointed at a new target has no history that means anything", got)
		}
	})

	t.Run("a removed test leaves no entry", func(t *testing.T) {
		// ABSENT must stay distinct from UNKNOWN: ip-monitoring treats an absent
		// key as "clear any stale FAIL" (#4423 M8), which is correct — no probe,
		// no protection. The carry-forward must never resurrect a dropped key.
		m := newCarryManager(t)
		m.Apply(ctx, rpmCarryCfg("192.0.2.1", ""))
		setVerdict(m, key, "fail", 3)

		m.Apply(ctx, &config.RPMConfig{Probes: map[string]*config.RPMProbe{
			"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
				"other": {Name: "other", Target: "192.0.2.1", TestInterval: 3600},
			}},
		}})

		if got, _ := statusOf(m, key); got != "<absent>" {
			t.Fatalf("removed test key = %q, want absent — a carried verdict must not "+
				"resurrect a probe the config dropped", got)
		}
	})
}

func identityOf(m *Manager, key string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if r := m.results[key]; r != nil {
		return r.identity
	}
	return ""
}

// TestProbeMeasurementIdentityVariesPerField_6561 binds EVERY component of the
// measurement identity. Without it a component could be deleted from
// probeMeasurementIdentity and every scenario test above would stay green,
// leaving a verdict carried across a change that invalidates it.
func TestProbeMeasurementIdentityVariesPerField_6561(t *testing.T) {
	base := &config.RPMTest{
		Name:                 "t",
		ProbeType:            "icmp-ping",
		Target:               "192.0.2.1",
		SourceAddress:        "10.0.0.9",
		RoutingInstance:      "vr1",
		DestinationInterface: "reth0",
		NextHop:              "10.0.0.1",
	}
	rethMap := map[string]string{"reth0": "ge-0/0/2"}
	want := probeMeasurementIdentity(base, rethMap)

	for name, mutate := range map[string]func(*config.RPMTest){
		"probe type":            func(t *config.RPMTest) { t.ProbeType = "tcp-ping" },
		"target":                func(t *config.RPMTest) { t.Target = "198.51.100.9" },
		"source address":        func(t *config.RPMTest) { t.SourceAddress = "10.0.0.10" },
		"routing instance":      func(t *config.RPMTest) { t.RoutingInstance = "vr2" },
		"next hop":              func(t *config.RPMTest) { t.NextHop = "10.0.0.2" },
		"destination interface": func(t *config.RPMTest) { t.DestinationInterface = "reth1" },
	} {
		t.Run(name, func(t *testing.T) {
			cp := *base
			mutate(&cp)
			if got := probeMeasurementIdentity(&cp, rethMap); got == want {
				t.Fatalf("changing the %s did not change the measurement identity — "+
					"a verdict would be carried across it", name)
			}
		})
	}

	t.Run("reth remap of this test's interface", func(t *testing.T) {
		// The issue's own trigger: the RETH map moves, and because it moves
		// THIS test's member the identity must move with it.
		if got := probeMeasurementIdentity(base, map[string]string{"reth0": "ge-0/0/7"}); got == want {
			t.Fatal("remapping this test's RETH member did not change the measurement identity")
		}
	})

	t.Run("reth remap of an unrelated interface", func(t *testing.T) {
		// And the converse, which is the case that must NOT reseed.
		m := map[string]string{"reth0": "ge-0/0/2", "reth9": "ge-0/0/9"}
		if got := probeMeasurementIdentity(base, m); got != want {
			t.Fatal("an unrelated RETH remap changed the measurement identity — the verdict would be wiped")
		}
	})
}
