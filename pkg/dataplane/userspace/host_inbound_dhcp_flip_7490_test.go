package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7490 on the RUST AF_XDP plane.
//
// This plane has a hole the nft plane does not, and it is the reason this file
// exists rather than trusting the shared resolver. The Rust picker
// (host_inbound_admits_iface) consults the PER-INTERFACE table first and FALLS
// BACK to the zone-keyed table when the interface has no entry. Before #7490,
// buildInterfaceSnapshots stamped a per-interface set only for an interface
// that declared its own host-inbound stanza — so a withheld interface with no
// override would carry no entry, fall back to the zone table, and be admitted
// by the very zone-level token that was withheld from it.
//
// The nft plane cannot fail that way: it groups by resolved token signature and
// never falls back. A test written only against pkg/config would therefore have
// passed with this plane un-flipped.

func flip7490UserspaceCfg(t *testing.T, lines ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		tree.SetPath(path)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// TestWithheldInterfaceCarriesItsOwnHostInboundSet7490 — the withheld interface
// declares NO interface-level stanza, which is precisely the shape that used to
// carry no per-interface entry.
//
// RED on revert: restore the `ovr == nil` skip in buildInterfaceSnapshotsFrom
// and this interface stops carrying a set, so the Rust side falls back to the
// zone table and re-admits dhcp.
func TestWithheldInterfaceCarriesItsOwnHostInboundSet7490(t *testing.T) {
	cfg := flip7490UserspaceCfg(t,
		"set interfaces ge-0/0/5 unit 0 family inet address 10.0.5.1/24",
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
	if !cfg.Security.Zones["trust"].WithholdsZoneLevelDHCPFor("ge-0/0/5.0") {
		t.Fatal("fixture precondition: the interface must be withheld from, or this cell " +
			"cannot observe the fallback it exists to close")
	}
	if _, ok := cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/5.0"]; ok {
		t.Fatal("fixture precondition: the interface must declare NO interface-level " +
			"stanza — an interface that declares one was already carried before #7490, " +
			"so a fixture with one would pass with the plane un-flipped")
	}

	var found bool
	for _, snap := range buildInterfaceSnapshots(cfg) {
		if snap.Name != "ge-0/0/5.0" {
			continue
		}
		found = true
		if !snap.HostInboundConfigured {
			t.Fatalf("a withheld interface must carry HostInboundConfigured=true, or the "+
				"Rust picker falls back to the zone-keyed table and re-admits the token "+
				"that was withheld from it. snapshot = %+v", snap)
		}
		for _, s := range snap.HostInboundSystemServices {
			if s == "dhcp" || s == "bootp" {
				t.Errorf("the per-interface set shipped to the Rust dataplane still admits "+
					"%q on a withheld interface: %v", s, snap.HostInboundSystemServices)
			}
		}
		var sawSSH bool
		for _, s := range snap.HostInboundSystemServices {
			if s == "ssh" {
				sawSSH = true
			}
		}
		if !sawSSH {
			t.Errorf("the shipped set must still carry the zone's non-exception tokens, or "+
				"the withholding became a deny-most: %v", snap.HostInboundSystemServices)
		}
	}
	if !found {
		t.Fatal("no snapshot for ge-0/0/5.0 — the fixture never reached the builder")
	}
}

// TestUnwithheldInterfaceStillCarriesNothingExtra7490 is the OVER-REACH control
// for the change above: removing the `ovr == nil` skip entirely would stamp a
// per-interface set on EVERY interface in a zone, which silently converts the
// Rust zone-table path into dead code and changes what a stale peer/helper
// sees. Only a withheld interface, or one with its own stanza, may carry a set.
func TestUnwithheldInterfaceStillCarriesNothingExtra7490(t *testing.T) {
	cfg := flip7490UserspaceCfg(t,
		"set interfaces ge-0/0/9 unit 0 family inet address 10.0.9.1/24",
		"set security zones security-zone trust interfaces ge-0/0/9.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
	)
	for _, snap := range buildInterfaceSnapshots(cfg) {
		if snap.Name == "ge-0/0/9.0" && snap.HostInboundConfigured {
			t.Errorf("an interface with no override and nothing withheld must keep using "+
				"the zone-keyed table; stamping it would make the zone path dead code. "+
				"snapshot = %+v", snap)
		}
	}
}
