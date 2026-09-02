package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func proxyARPCfg8297(iface string, rg int) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		iface: {RedundancyGroup: rg},
	}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: iface + ".80", Addresses: []string{"172.16.80.7/32"}},
	}
	return cfg
}

// TestProxyARPStandbyIsFilteredOut8297 is the fail-on-revert cell.
//
// The defect is TWO answerers, so the assertion has to be that the non-owning
// node is EXCLUDED. Asserting that the owner is included passes on the broken
// code — both nodes were included — which is a green about nothing.
func TestProxyARPStandbyIsFilteredOut8297(t *testing.T) {
	cfg := proxyARPCfg8297("reth0", 1)

	owner := proxyARPOwnedEntries(cfg, func(string) bool { return true })
	if len(owner) != 1 {
		t.Fatalf("the RG owner must keep its proxy-arp entry; got %d", len(owner))
	}

	standby := proxyARPOwnedEntries(cfg, func(string) bool { return false })
	if len(standby) != 0 {
		t.Fatalf("a node that does NOT own the redundancy group must not answer "+
			"proxy-ARP for the pool address: both nodes then reply with their own RETH "+
			"virtual MAC, the upstream sees one IP at two MACs, and pool-mode return "+
			"traffic has no single destination (#8297). got %d retained entries", len(standby))
	}
}

// A box with NO redundancy groups must never be gated. This is the arm with the
// widest blast radius: gating it breaks pool-mode NAT on every standalone
// deployment — the larger population — while passing every cluster test.
func TestProxyARPStandaloneIsNeverGated8297(t *testing.T) {
	// d.cluster == nil is the standalone path; a nil *Daemon exercises the same
	// first branch without constructing one.
	var d *Daemon
	cfg := proxyARPCfg8297("reth0", 1) // RG present, but no cluster
	if !d.proxyARPOwnsInterface(cfg, "reth0.80") {
		t.Fatal("a standalone box must answer proxy-ARP for its pool address; gating " +
			"it here breaks pool-mode NAT everywhere that is not a cluster (#8297)")
	}
}

// An interface with no redundancy group is not a duplicate-responder hazard and
// must not be gated either, even on a clustered box.
func TestProxyARPNonRGInterfaceIsNeverGated8297(t *testing.T) {
	cfg := proxyARPCfg8297("ge-0-0-5", 0) // RedundancyGroup 0 == not RG-owned
	if got := proxyARPInterfaceRG(cfg, "ge-0-0-5.80"); got != 0 {
		t.Fatalf("an interface with no redundancy-group must resolve to RG 0; got %d", got)
	}
	// The unit suffix must be stripped before the lookup, or every VLAN
	// sub-interface resolves to 0 and the gate silently never engages —
	// which would look exactly like the fix working.
	if got := proxyARPInterfaceRG(proxyARPCfg8297("reth0", 3), "reth0.80"); got != 3 {
		t.Fatalf("reth0.80 must resolve through its base interface to RG 3; got %d "+
			"— a gate that resolves every sub-interface to 0 is inert", got)
	}
}

// The fingerprint must MOVE when ownership moves, or the reassert loop never
// notices a failover and the demoted node keeps answering until the 30s beat.
func TestProxyARPOwnershipFingerprintMoves8297(t *testing.T) {
	cfg := proxyARPCfg8297("reth0", 1)
	var d *Daemon // standalone: always owns
	standaloneFP := d.proxyARPOwnershipFingerprint(cfg)
	if standaloneFP == "" {
		t.Fatal("fingerprint must name the configured entries; an empty fingerprint " +
			"never changes and the loop never converges")
	}
	// A config with no proxy-arp entries fingerprints differently from one with
	// them, so adding or removing an entry is also seen.
	if d.proxyARPOwnershipFingerprint(&config.Config{}) == standaloneFP {
		t.Fatal("fingerprint does not distinguish a config with entries from one " +
			"without; a change the loop must act on would be invisible")
	}
}
