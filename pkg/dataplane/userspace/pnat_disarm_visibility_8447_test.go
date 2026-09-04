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

// #8447/#8573: the persistent-NAT + chassis-cluster disarm, and its removal.
//
// WHAT #8447 WAS. Applying a `persistent-nat` source pool on a chassis cluster
// set ForwardingSupported=false and stopped transit entirely — and the stop was
// SILENT. The config committed cleanly, the reconcile short-circuited every
// second because desired == actual, and the only surface was
// `Forwarding supported: false` inside a `show` nobody runs when the symptom is
// "the link went down". #8447 was investigated across five rounds of cluster
// measurement for a state the daemon already knew the reason for and threw away.
//
// WHAT #8573 DID. Removed the disarm, after measuring on the loss userspace
// cluster that its stated reason — "persistent-NAT leases are not
// HA-synchronized" — was false. With the disarm lifted and a rule-referenced
// persistent-nat pool committed on both nodes: both armed and forwarded; a
// lease created on the active appeared on the STANDBY with an identical
// translated identity; it survived a manual RG0 failover; and after a failback
// the new active translated the SAME source identity to the SAME translated
// identity the other node had allocated. The imported lease was HONOURED, which
// is the whole of what persistent NAT promises.
//
// WHY THESE CELLS WERE INVERTED RATHER THAN DELETED. The disarm's cost is a
// total transit stop presenting as a link failure — the thing that took five
// rounds to identify. Deleting the cells would leave nothing to red if it came
// back. So the first now asserts a clustered persistent-NAT config KEEPS
// forwarding and issues NO disarm, and the standalone control is kept beside it
// so the pair still distinguishes "cluster-only gate removed" from "gate
// removed everywhere" if a future gate is added on a different predicate.
//
// The DIAGNOSABILITY cell is retargeted, not inverted: the disarm machinery is
// still live for the capability reasons that remain, and #8447's real finding —
// that a disarm must name its reason and say transit STOPS — outlives the
// particular trigger that motivated it. It now drives that machinery with a
// specimen reason that still exists.

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

// disarmingCfg8573 is a config that STILL disarms after #8573 removed the
// persistent-NAT gate: a color-AWARE three-color policer, which the userspace
// runtime lowers only in color-blind `then discard` form. It exists so the
// diagnosability cell below drives the real disarm path rather than a mock.
func disarmingCfg8573() *config.Config {
	cfg := twoZonePolicyCfg(&config.Application{Name: "any", Protocol: "tcp"}, "any")
	cfg.Firewall.ThreeColorPolicers = map[string]*config.ThreeColorPolicerConfig{
		"tcp1": {
			Name:                 "tcp1",
			ColorBlind:           false, // color-AWARE: the unsupported half
			ColorAwareConfigured: true,
			CIR:                  1250000,
			CBS:                  15000,
			ThenAction:           "discard",
		},
	}
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

// #8573 INVERTED: the clustered persistent-NAT config must KEEP forwarding.
//
// RED ON REVERT: restore the `cfg.Chassis.Cluster != nil &&
// userspaceConfigUsesPersistentSourceNAT(cfg)` disarm in capabilities.go and
// both halves of this fail — the capability verdict and the wire request.
func TestPersistentNATPoolOnAClusterKeepsForwarding8573(t *testing.T) {
	m, reqCh := newDisarmManager(t)
	snap := snapForDisarm(t, persistentNATClusterCfg())

	if !snap.Capabilities.ForwardingSupported {
		t.Fatalf("a chassis cluster with a source rule pointing at a persistent-nat "+
			"pool lost ForwardingSupported (reasons %v). #8573 removed that disarm "+
			"after measuring its premise false; re-adding it stops transit entirely "+
			"while the interfaces stay up and the config commits clean",
			snap.Capabilities.UnsupportedReasons)
	}
	for _, r := range snap.Capabilities.UnsupportedReasons {
		if strings.Contains(r, "persistent-nat") || strings.Contains(r, "HA-synchronized") {
			t.Errorf("a persistent-NAT disarm reason is back: %q", r)
		}
	}
	// The wire half: nothing may be disarmed for this config.
	if err := m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
		t.Fatalf("disarmBeforeUnsupportedPublishLocked: %v", err)
	}
	select {
	case req := <-reqCh:
		t.Fatalf("a clustered persistent-nat config was disarmed on the wire: %+v", req)
	case <-time.After(300 * time.Millisecond):
	}
}

// The diagnosability half. An operator whose traffic stopped greps the journal.
func TestTheDisarmSaysWhyItStoppedForwarding8447(t *testing.T) {
	// #8573: the trigger is now a still-live capability reason; see the header.
	var buf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	m, reqCh := newDisarmManager(t)
	_ = m.disarmBeforeUnsupportedPublishLocked(snapForDisarm(t, disarmingCfg8573()))
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
		"three-color", // the operator's own configuration keyword
		"color-blind", // why it is refused
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

// THE STANDALONE CONTROL, kept after #8573 removed the cluster gate.
//
// It no longer distinguishes cluster from standalone — neither disarms now — but
// it is the half that would catch a future gate added on a DIFFERENT predicate
// and applied too widely. Its original job was exactly that: the obvious "fix"
// for #8447 was to widen the condition, which would have turned a cluster-only
// outage into one hitting every standalone deployment, and that mutation
// survived the first mutation table.
func TestStandalonePersistentNATKeepsForwarding8447(t *testing.T) {
	cfg := persistentNATClusterCfg()
	cfg.Chassis.Cluster = nil // the ONLY difference from the disarming fixture

	snap := snapForDisarm(t, cfg)
	if !snap.Capabilities.ForwardingSupported {
		t.Fatalf("a STANDALONE node with a persistent-nat source pool lost "+
			"ForwardingSupported — no gate has ever refused this configuration "+
			"and #8573 removed the clustered one too, so this stops transit on a "+
			"configuration that is fine. reasons: %v",
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
