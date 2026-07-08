package config

import (
	"strings"
	"testing"
)

// hostInboundMulticastWarnings returns the #4455 (HI-1) commit-time advisories
// emitted by ValidateConfig for a zone that admits a multicast routing
// protocol. The advisory phrase ("admitted PACKET-WIDE") is unique to this
// check.
func hostInboundMulticastWarnings(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "admitted PACKET-WIDE") && strings.Contains(w, "#4455") {
			out = append(out, w)
		}
	}
	return out
}

// Test_4455_MulticastProtocolEmitsPacketWideAdvisory is the #4455 RED-on-revert
// guard for the commit-time advisory. A zone whose `host-inbound-traffic
// protocols` admits a MULTICAST routing protocol (ospf/pim/vrrp/rip/igmp/
// router-discovery) relies on the kernel input-chain `policy accept`
// fall-through to deliver that protocol's host-bound multicast packet-wide
// (buildHostInboundFilterPayload matches host-local unicast daddr only), which
// is broader than Junos's per-zone scoping. The zone must:
//
//   - COMPILE with NO error (valid Junos; the advisory is a WARNING, never a
//     reject — enforcement is deferred per #4455), and
//   - carry the packet-wide multicast advisory naming the zone AND the concrete
//     well-known group (e.g. OSPF 224.0.0.5).
//
// RED-on-revert: delete the validateHostInboundMulticastWarnings call in
// ValidateConfig (or the advise() emit) and every sub-test that expects an
// advisory turns RED.
func Test_4455_MulticastProtocolEmitsPacketWideAdvisory(t *testing.T) {
	cases := []struct {
		name  string
		token string
		group string // a well-known group the advisory must name
	}{
		{"ospf", "ospf", "224.0.0.5"},
		{"ospf3", "ospf3", "ff02::5"},
		{"rip", "rip", "224.0.0.9"},
		{"pim", "pim", "224.0.0.13"},
		{"vrrp", "vrrp", "224.0.0.18"},
		{"igmp", "igmp", "224.0.0.1"},
		{"router-discovery", "router-discovery", "224.0.0.2"},
	}
	for _, tc := range cases {
		t.Run("zone-level-"+tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
				"set security zones security-zone trust host-inbound-traffic protocols " + tc.token,
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig must accept protocols %s (valid Junos, warn-not-reject): %v", tc.token, err)
			}
			got := hostInboundMulticastWarnings(cfg)
			if len(got) != 1 {
				t.Fatalf("protocols %s: expected exactly one packet-wide multicast advisory, got %d: %v", tc.token, len(got), got)
			}
			if !strings.Contains(got[0], `zone "trust"`) {
				t.Errorf("advisory must name the zone, got: %q", got[0])
			}
			if !strings.Contains(got[0], tc.group) {
				t.Errorf("advisory must name the well-known group %q, got: %q", tc.group, got[0])
			}
		})
	}
}

// Test_4455_UnicastProtocolNoAdvisory pins the other half of the contract: a
// zone whose `host-inbound-traffic protocols` lists only UNICAST routing-control
// protocols (bgp is TCP/179 to a peer, ldp/msdp/bfd are unicast) rides no
// well-known multicast group and must draw NO #4455 advisory.
func Test_4455_UnicastProtocolNoAdvisory(t *testing.T) {
	for _, tok := range []string{"bgp", "ldp", "msdp", "bfd"} {
		t.Run(tok, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
				"set security zones security-zone trust host-inbound-traffic protocols " + tok,
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if got := hostInboundMulticastWarnings(cfg); len(got) != 0 {
				t.Fatalf("unicast protocol %q must NOT draw a multicast advisory, got: %v", tok, got)
			}
		})
	}
}

// Test_4455_NoProtocolsNoAdvisory pins that a zone with only system-services
// (no `protocols` stanza) and a zone with no host-inbound-traffic at all draw
// NO #4455 advisory — the check is scoped to multicast routing protocols.
func Test_4455_NoProtocolsNoAdvisory(t *testing.T) {
	t.Run("system-services-only", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set security zones security-zone trust host-inbound-traffic system-services ssh",
			"set security zones security-zone trust host-inbound-traffic system-services ping",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := hostInboundMulticastWarnings(cfg); len(got) != 0 {
			t.Fatalf("system-services-only zone must NOT draw a multicast advisory, got: %v", got)
		}
	})
	t.Run("no-host-inbound", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := hostInboundMulticastWarnings(cfg); len(got) != 0 {
			t.Fatalf("zone with no host-inbound-traffic must NOT draw a multicast advisory, got: %v", got)
		}
	})
}

// Test_4455_ProtocolsAllExpandsToMulticast pins that `protocols all` — which
// expands to the routing-protocol set (#3199) INCLUDING the multicast
// protocols — draws the advisory (the expansion is where the packet-wide
// multicast admission comes from under `all`).
func Test_4455_ProtocolsAllExpandsToMulticast(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic protocols all",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig must accept protocols all: %v", err)
	}
	got := hostInboundMulticastWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("protocols all must draw exactly one multicast advisory, got %d: %v", len(got), got)
	}
	// `all` expands to OSPF among others, so the OSPF group must appear.
	if !strings.Contains(got[0], "224.0.0.5") {
		t.Errorf("protocols all advisory must name an expanded multicast group (e.g. OSPF 224.0.0.5), got: %q", got[0])
	}
}

// Test_4455_PerInterfaceOverrideAdvisory covers the #3362 per-interface override
// path: a multicast `protocols` set only on one interface of a zone must warn
// and name BOTH the zone and the interface.
func Test_4455_PerInterfaceOverrideAdvisory(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic protocols ospf",
		// a sibling interface with a unicast protocol — must NOT warn.
		"set security zones security-zone wan interfaces ge-0/0/1.0 host-inbound-traffic protocols bgp",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig must accept a per-interface protocols override: %v", err)
	}
	got := hostInboundMulticastWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("expected exactly one per-interface multicast advisory, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], `zone "wan"`) || !strings.Contains(got[0], `interface "ge-0/0/0.0"`) {
		t.Errorf("per-interface advisory must name both zone and interface, got: %q", got[0])
	}
}

// Test_4455_CatalogSSOTShape guards the protocol->multicast-group catalog SSOT:
// every catalog token is a recognized host-inbound protocol, and none is a
// unicast-only or L2 protocol misfiled as multicast.
func Test_4455_CatalogSSOTShape(t *testing.T) {
	for _, tok := range HostInboundMulticastProtocolTokens() {
		if !KnownHostInboundProtocols[tok] {
			t.Errorf("catalog token %q is not a KnownHostInboundProtocols token", tok)
		}
		if HostInboundL2Protocols[tok] {
			t.Errorf("catalog token %q is an L2 protocol and rides no IP multicast group", tok)
		}
		g, ok := HostInboundMulticastProtocol(tok)
		if !ok {
			t.Errorf("HostInboundMulticastProtocol(%q) must report ok for a catalog token", tok)
		}
		if len(g.V4) == 0 && len(g.V6) == 0 {
			t.Errorf("catalog token %q has no multicast groups", tok)
		}
	}
	// bgp is unicast — must NOT be in the multicast catalog.
	if _, ok := HostInboundMulticastProtocol("bgp"); ok {
		t.Errorf("bgp is unicast and must not be a multicast-catalog protocol")
	}
}
