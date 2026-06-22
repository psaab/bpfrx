package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcprelay"
)

// relayCfg builds a *config.Config carrying a single dhcp-relay group bound to
// one interface, matching the shape the daemon hands reconcileDHCPRelay.
func relayCfg(iface string) *config.Config {
	c := &config.Config{}
	c.ForwardingOptions.DHCPRelay = &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {Name: "g", Interfaces: []string{iface}, ActiveServerGroup: "sg"},
		},
	}
	return c
}

// TestReconcileDHCPRelayNilManagerNoop proves the apply-path call is a safe
// no-op when the daemon was constructed without a relay Manager (#2348). A
// regression that dereferenced d.dhcpRelay unconditionally would panic here.
func TestReconcileDHCPRelayNilManagerNoop(t *testing.T) {
	d := &Daemon{daemonCtx: context.Background()}
	// Must not panic and must not create a Manager out of thin air.
	d.reconcileDHCPRelay(relayCfg("ge-0-0-0"))
	if d.dhcpRelay != nil {
		t.Fatal("reconcileDHCPRelay must not create a Manager when none exists")
	}
}

// TestReconcileDHCPRelayRemoveStopsAll is the headline #2348 wiring proof on the
// daemon seam: a relay running after boot is STOPPED when a day-2 commit removes
// the `forwarding-options dhcp-relay` block (a nil relay config). Before #2348
// the apply pipeline had no relay step, so the boot-started relay survived a
// delete forever. This path is socket-free (Apply(nil) only tears down), so it
// runs without root. It fails-on-revert: if reconcileDHCPRelay is removed from
// applyConfigLocked or stops forwarding the config, the relay would never stop.
func TestReconcileDHCPRelayRemoveStopsAll(t *testing.T) {
	d := &Daemon{
		daemonCtx: context.Background(),
		dhcpRelay: dhcprelay.NewManager(),
	}
	t.Cleanup(d.dhcpRelay.Stop)

	// Seed a running relay directly through the Manager (the boot path), using
	// a config whose interface never resolves an address so no client socket is
	// opened on :67 (the resolver retries forever in the background) — Stats()
	// still reports the relay as managed.
	d.dhcpRelay.Apply(context.Background(), relayCfg("xpf-test-nonexistent0").ForwardingOptions.DHCPRelay)
	if n := len(d.dhcpRelay.Stats()); n != 1 {
		t.Fatalf("expected 1 managed relay after seed, got %d", n)
	}

	// Day-2 commit removes the relay block. reconcileDHCPRelay must forward the
	// nil config to Apply, which stops every relay.
	cfgNoRelay := &config.Config{}
	d.reconcileDHCPRelay(cfgNoRelay)

	if n := len(d.dhcpRelay.Stats()); n != 0 {
		t.Fatalf("day-2 relay removal must stop all relays via the apply path, %d still managed", n)
	}
}

// TestReconcileDHCPRelayAddStartsRelay proves a relay ADDED on a day-2 commit is
// started through the apply seam (#2348). It uses a non-resolvable interface so
// the relay is registered/managed (Stats()==1) without opening a real :67
// socket — the resolver retry loop is ctx-cancelable and torn down by Stop().
func TestReconcileDHCPRelayAddStartsRelay(t *testing.T) {
	d := &Daemon{
		daemonCtx: context.Background(),
		dhcpRelay: dhcprelay.NewManager(),
	}
	t.Cleanup(d.dhcpRelay.Stop)

	// Boot had no relay configured.
	d.reconcileDHCPRelay(&config.Config{})
	if n := len(d.dhcpRelay.Stats()); n != 0 {
		t.Fatalf("expected no relays for empty config, got %d", n)
	}

	// Day-2 commit adds a relay group.
	d.reconcileDHCPRelay(relayCfg("xpf-test-nonexistent1"))
	if n := len(d.dhcpRelay.Stats()); n != 1 {
		t.Fatalf("day-2 relay add must start the relay via the apply path, got %d", n)
	}
}
