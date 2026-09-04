package userspace

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #8447: applying a `persistent-nat` source pool on a chassis cluster STOPS
// transit, and until this test the stop was completely silent.
//
// # What actually happens, and why it presented as a mystery
//
// `capabilities.go` sets ForwardingSupported=false when
// `cfg.Chassis.Cluster != nil && userspaceConfigUsesPersistentSourceNAT(cfg)` —
// persistent-NAT leases are not HA-synchronized, so the dataplane declines to
// forward rather than forward with semantics it cannot honour. That is a
// DELIBERATE decision and this test does not change it.
//
// What was wrong is that nothing said so. `disarmBeforeUnsupportedPublishLocked`
// computed a `reason` and used it ONLY to decorate an error string on the
// failure path, so the SUCCESS path — the one that actually stops traffic —
// emitted nothing. The config commits cleanly, the reconcile then short-circuits
// silently every second because desired == actual, and the only surface left is
// `Forwarding supported: false` inside a `show` nobody runs when the symptom is
// "the link went down". #8447 was investigated across five rounds of cluster
// measurement — counter deltas, arm-order controls, log-line censuses — for a
// state the daemon already knew the reason for and threw away.
//
// # What these cells bind
//
// Not "a log line exists". The first binds the CAUSE end to end: a config with
// chassis cluster + a source rule pointing at a persistent-nat pool must reach
// the disarm at all, which is the #8447 mechanism stated as an executable
// claim. The second binds the DIAGNOSABILITY: the emitted record must name the
// persistent-NAT reason, because an operator greps the journal for why traffic
// stopped and a bare "disarming" tells them nothing they did not already know.
//
// RED ON REVERT: delete the `slog.Warn` from
// `disarmBeforeUnsupportedPublishLocked` and
// `the_disarm_says_why_it_stopped_forwarding_8447` fails; make the capability
// gate stop firing for persistent-nat and
// `a_persistent_nat_pool_on_a_cluster_disarms_forwarding_8447` fails.

// persistentNATClusterCfg is the #8447 configuration: a chassis cluster, a
// source pool carrying `persistent-nat`, and a source rule that points at it.
// All three are required — the predicate walks rules to pools, so a pool with
// persistent-nat that no rule references does NOT trip the gate.
func persistentNATClusterCfg() *config.Config {
	cfg := twoZonePolicyCfg(&config.Application{Name: "any", Protocol: "tcp"}, "any")
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0, ClusterID: 1}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p1": {
			Name:      "p1",
			Addresses: []string{"172.16.80.7/32"},
			PersistentNAT: &config.PersistentNATConfig{
				Permit:            config.PersistentNATPermitAnyRemoteHost,
				InactivityTimeout: 300,
			},
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "lan-to-wan",
		FromZone: "lan",
		ToZone:   "wan",
		Rules: []*config.NATRule{{
			Name: "pool-snat",
			Then: config.NATThen{PoolName: "p1"},
		}},
	}}
	return cfg
}

func newDisarmManager(t *testing.T) (*Manager, <-chan ControlRequest) {
	t.Helper()
	sock, reqCh := recordingControlServer(t)
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	m.lastStatus.ForwardingArmed = true
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	return m, reqCh
}

// The #8447 cause, as an executable claim rather than a cluster measurement.
func TestPersistentNATPoolOnAClusterDisarmsForwarding8447(t *testing.T) {
	m, reqCh := newDisarmManager(t)
	snap := snapForDisarm(t, persistentNATClusterCfg())

	if snap.Capabilities.ForwardingSupported {
		t.Fatal("a chassis cluster with a source rule pointing at a persistent-nat " +
			"pool must set ForwardingSupported=false — that is the #8447 mechanism")
	}
	// applyHelperStatusLocked touches a BPF map absent in a unit test, so the
	// call may return that local-bookkeeping error AFTER the wire disarm
	// succeeded. The request is the behaviour under test.
	_ = m.disarmBeforeUnsupportedPublishLocked(snap)

	select {
	case req := <-reqCh:
		if req.Type != "set_forwarding_state" || req.Forwarding == nil || req.Forwarding.Armed {
			t.Fatalf("got %+v, want set_forwarding_state{Armed:false}", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no disarm was issued: the #8447 outage would not reproduce, so " +
			"either the capability gate or the disarm path has moved and this " +
			"test no longer describes the defect")
	}
}

// The diagnosability half. An operator whose traffic stopped greps the journal.
func TestTheDisarmSaysWhyItStoppedForwarding8447(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	m, reqCh := newDisarmManager(t)
	_ = m.disarmBeforeUnsupportedPublishLocked(snapForDisarm(t, persistentNATClusterCfg()))
	select {
	case <-reqCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no disarm issued — precondition for the logging assertion")
	}

	got := buf.String()
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("the forwarding disarm did not log at WARN.\ngot: %s", got)
	}
	// The load-bearing assertion: the RECORD must carry the reason, not merely
	// announce a disarm. "Forwarding disarmed" alone tells an operator nothing
	// they cannot already see from the outage.
	for _, want := range []string{
		"persistent-nat", // the operator's own configuration keyword
		"HA-synchronized", // why it is refused
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the disarm record does not name %q, so an operator greping "+
				"the journal for why transit stopped learns nothing actionable.\ngot: %s",
				want, got)
		}
	}
	// And it must say that traffic STOPS. A record that reports a capability
	// verdict without its consequence reads as informational.
	if !strings.Contains(got, "STOP") {
		t.Errorf("the disarm record does not say transit will STOP — the whole "+
			"reason #8447 presented as a connectivity fault rather than a NAT "+
			"one.\ngot: %s", got)
	}
}

// ACCEPT-SIDE CONTROL. The gate is cluster-only ON PURPOSE — persistent-NAT
// leases are refused because they are not HA-SYNCHRONIZED, and a standalone
// node has nothing to synchronize them with. So a standalone box with the very
// same pool must keep forwarding.
//
// Without this, the two cells above are satisfied by a gate that disarms on
// persistent-nat unconditionally, and the obvious "fix" for #8447 — widen the
// condition — would turn a cluster-only outage into one that hits every
// standalone deployment using the feature. That mutation SURVIVED the first
// mutation table, which is why this cell exists.
//
// RED ON REVERT: drop `cfg.Chassis.Cluster != nil` from the capability gate in
// capabilities.go and this fails while every other #8447 cell stays green.
func TestStandalonePersistentNATKeepsForwarding8447(t *testing.T) {
	cfg := persistentNATClusterCfg()
	cfg.Chassis.Cluster = nil // the ONLY difference from the disarming fixture

	snap := snapForDisarm(t, cfg)
	if !snap.Capabilities.ForwardingSupported {
		t.Fatalf("a STANDALONE node with a persistent-nat source pool lost "+
			"ForwardingSupported — the gate exists because the leases are not "+
			"HA-synchronized, and standalone has no peer to synchronize with, "+
			"so this stops transit on a configuration that is fine. reasons: %v",
			snap.Capabilities.UnsupportedReasons)
	}

	m, reqCh := newDisarmManager(t)
	if err := m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
		t.Fatalf("disarmBeforeUnsupportedPublishLocked: %v", err)
	}
	select {
	case req := <-reqCh:
		t.Fatalf("a standalone persistent-nat config was disarmed: %+v", req)
	case <-time.After(200 * time.Millisecond):
	}
}
