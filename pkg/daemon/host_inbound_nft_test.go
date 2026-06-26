package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// hostInboundTestConfig builds a config exercising the #3070 kernel-nftables
// host-inbound enforcement path end to end (config -> BuildZoneHostInboundViews
// -> buildHostInboundFilterPayload):
//   - wan: host-inbound { ssh; ping; } on reth0.50 (v4+v6 static addrs) — the
//     enforced zone.
//   - lan: NO host-inbound stanza on reth1.0 — must produce NO deny.
//   - control: host-inbound { all; } on em0 — em0 is a cluster-control lifeline,
//     its address must never be denied (and `all` would open it anyway).
//   - mgmt: host-inbound { ssh; } on fxp0 — fxp0 is the management lifeline
//     (DHCP, no static addr); must never be denied.
func hostInboundTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"}},
		}},
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
		"em0": {Name: "em0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.99.0.1/24"}},
		}},
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.50"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping"}},
		},
		"lan": {
			Name:       "lan",
			Interfaces: []string{"reth1.0"},
			// no HostInboundTraffic stanza
		},
		"control": {
			Name:               "control",
			Interfaces:         []string{"em0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"all"}},
		},
		"mgmt": {
			Name:               "mgmt",
			Interfaces:         []string{"fxp0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	return cfg
}

// TestHostInboundFilterAcceptsListedDeniesRest is the #3070 fail-on-revert
// proof: for a host-inbound-configured zone the generated `chain input`
// ACCEPTS each listed service to the zone's addresses and DROPs everything
// else to those addresses. Reverting the host-inbound nft emission (so no
// accept/drop are produced) turns this RED.
func TestHostInboundFilterAcceptsListedDeniesRest(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views)

	mustContain := []string{
		"table inet xpf_hostinbound",
		"ct state established,related accept",
		// wan allows ssh -> accept tcp/22 to the reth IP, both families gated.
		"ip daddr 172.16.50.8 tcp dport 22 accept",
		// wan allows ping -> accept icmp/icmpv6 echo-request.
		"ip daddr 172.16.50.8 icmp type echo-request accept",
		"ip6 daddr 2001:db8:50::8 icmpv6 type echo-request accept",
		// catch-all deny for the rest, per family.
		"ip daddr 172.16.50.8 drop",
		"ip6 daddr 2001:db8:50::8 drop",
	}
	for _, want := range mustContain {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing %q\n---\n%s", want, payload)
		}
	}

	// An unlisted service (telnet tcp/23) must NOT be accepted — it falls to the
	// catch-all drop.
	if strings.Contains(payload, "tcp dport 23") {
		t.Errorf("payload unexpectedly accepts telnet (tcp/23):\n%s", payload)
	}

	// Ordering: each accept for the wan v4 addr must precede that addr's drop.
	if idxDrop := strings.Index(payload, "ip daddr 172.16.50.8 drop"); idxDrop >= 0 {
		if idxAccept := strings.Index(payload, "ip daddr 172.16.50.8 tcp dport 22 accept"); idxAccept < 0 || idxAccept > idxDrop {
			t.Errorf("wan v4 ssh accept must precede the v4 catch-all drop:\n%s", payload)
		}
	}
}

// TestHostInboundFilterExemptsIPsecAndV6Errors verifies the global exemptions
// that must agree with the userspace stage_ipsec_passthrough_check: raw ESP/AH
// (proto 50/51) and v6 ND/error/PMTUD control are accepted BEFORE any per-zone
// drop, so an IPsec-terminating zone configured `host-inbound { ike; }` keeps
// its tunnel data plane and v6 error delivery is never gapped. The ESP/AH
// accept is fail-on-revert: removing it turns this RED.
func TestHostInboundFilterExemptsIPsecAndV6Errors(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views)

	espAH := "meta l4proto { 50, 51 } accept"
	if !strings.Contains(payload, espAH) {
		t.Errorf("payload missing raw ESP/AH exemption %q\n---\n%s", espAH, payload)
	}
	// icmpv6 error/PMTUD types 1-4 + ND 133-137 must be in the accepted set.
	if !strings.Contains(payload, "icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 } accept") {
		t.Errorf("payload missing icmpv6 error/PMTUD (1-4) + ND in the global accept:\n%s", payload)
	}
	// #3171: the ICMPv4 error/PMTUD set must agree with the userspace
	// host-inbound exemption (is_icmp_host_inbound_error) so the kernel chain and
	// the XSK LocalDelivery classifier admit the same ICMP errors on a ping-less
	// zone. Fail-on-revert: narrowing this back to bare destination-unreachable
	// turns this RED.
	if !strings.Contains(payload, "icmp type { destination-unreachable, time-exceeded, parameter-problem } accept") {
		t.Errorf("payload missing icmpv4 error/PMTUD (dest-unreachable/time-exceeded/parameter-problem) accept:\n%s", payload)
	}

	// The ESP/AH exemption MUST precede every per-zone scoped drop, otherwise a
	// zone's `daddr <wan-ip> drop` would catch outer ESP before XFRM decrypts.
	idxESP := strings.Index(payload, espAH)
	if idxESP < 0 {
		t.Fatalf("ESP/AH accept not found")
	}
	for _, drop := range []string{
		"ip daddr 172.16.50.8 drop",
		"ip6 daddr 2001:db8:50::8 drop",
	} {
		if idxDrop := strings.Index(payload, drop); idxDrop >= 0 && idxESP > idxDrop {
			t.Errorf("ESP/AH exemption must precede the per-zone drop %q", drop)
		}
	}
}

// TestHostInboundFilterNoStanzaNoDeny verifies a zone with NO
// host-inbound-traffic stanza (lan) emits no deny — admit-all preserved
// (zero-regression lifeline guarantee for unconfigured zones).
func TestHostInboundFilterNoStanzaNoDeny(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views)

	// lan's reth1 address must appear nowhere — no accept, no drop.
	if strings.Contains(payload, "10.0.61.1") {
		t.Errorf("lan (no host-inbound stanza) must not appear in payload:\n%s", payload)
	}
}

// TestHostInboundFilterLifelineNeverDenied verifies the management (fxp0) and
// cluster-control (em0) lifeline interfaces never get a host-inbound deny, even
// when their zone declares a host-inbound stanza.
func TestHostInboundFilterLifelineNeverDenied(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views)

	// em0's address (cluster control plane) must never be denied/scoped, even
	// though the control zone declares a host-inbound stanza.
	if strings.Contains(payload, "10.99.0.1") {
		t.Errorf("control/em0 lifeline address must never appear in host-inbound payload:\n%s", payload)
	}
	// fxp0 (management) has no static address and is a lifeline — it must not
	// be scoped either (there is no address to scope, and it is excluded).
	if strings.Contains(payload, "fxp0") {
		t.Errorf("management fxp0 must never appear in host-inbound payload:\n%s", payload)
	}
}

// TestHostInboundFilterAllOpensZoneNoDeny verifies `system-services { all }`
// fully opens a zone (accept all to its addresses, no deny). Uses a config
// whose `all` zone is NOT a lifeline so it actually emits a rule.
func TestHostInboundFilterAllOpensZoneNoDeny(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.1.1.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"all"}},
		},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views)
	if !strings.Contains(payload, "ip daddr 10.1.1.1 accept") {
		t.Errorf("`all` zone must accept everything to its addr:\n%s", payload)
	}
	if strings.Contains(payload, "ip daddr 10.1.1.1 drop") {
		t.Errorf("`all` zone must NOT emit a deny:\n%s", payload)
	}
}

// TestHostInboundFilterProtocolsAllScopedToRouting is the #3199 fail-on-revert
// proof for the kernel nft mirror: `host-inbound-traffic protocols all` admits
// the routing-protocol set (ospf/bgp/vrrp/...) but DOES NOT open
// system-services (SSH/HTTPS/SNMP), and still emits a catch-all drop for the
// rest. Restoring the old behaviour — hostInboundAllowsAll returning true for
// `protocols all` (a bare `<fam> daddr <addrs> accept` with no deny) — turns
// the "does not accept ssh" / "emits a drop" assertions RED.
func TestHostInboundFilterProtocolsAllScopedToRouting(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.2.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"routing": {
			Name:               "routing",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{Protocols: []string{"all"}},
		},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views)

	// Routing protocols must be accepted: ospf (proto 89), bgp (tcp/179),
	// vrrp (proto 112).
	mustAccept := []string{
		"ip daddr 10.2.2.1 meta l4proto 89 accept",
		"ip daddr 10.2.2.1 tcp dport 179 accept",
		"ip daddr 10.2.2.1 meta l4proto 112 accept",
	}
	for _, want := range mustAccept {
		if !strings.Contains(payload, want) {
			t.Errorf("protocols all must accept routing %q\n---\n%s", want, payload)
		}
	}

	// System-services must NOT be opened: no bare accept, no ssh/https accept.
	if strings.Contains(payload, "ip daddr 10.2.2.1 accept") {
		t.Errorf("protocols all must NOT emit a bare full-accept (opens all services):\n%s", payload)
	}
	if strings.Contains(payload, "tcp dport 22") {
		t.Errorf("protocols all must NOT accept ssh (tcp/22):\n%s", payload)
	}
	if strings.Contains(payload, "tcp dport 443") {
		t.Errorf("protocols all must NOT accept https (tcp/443):\n%s", payload)
	}
	if strings.Contains(payload, "udp dport 161") {
		t.Errorf("protocols all must NOT accept snmp (udp/161):\n%s", payload)
	}

	// A catch-all drop for everything else must be present (default-deny to
	// the host for non-routing traffic).
	if !strings.Contains(payload, "ip daddr 10.2.2.1 drop") {
		t.Errorf("protocols all must still emit the v4 catch-all drop:\n%s", payload)
	}
}

// TestHostInboundFilterExplicitSshStillAdmitted is the #3199 regression guard:
// an explicit `system-services ssh` zone still accepts ssh (the protocols-all
// scoping change must not affect explicit service lists).
func TestHostInboundFilterExplicitSshStillAdmitted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.3.3.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"mgmt": {
			Name:               "mgmt",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views)

	if !strings.Contains(payload, "ip daddr 10.3.3.1 tcp dport 22 accept") {
		t.Errorf("system-services ssh must accept tcp/22:\n%s", payload)
	}
	if !strings.Contains(payload, "ip daddr 10.3.3.1 drop") {
		t.Errorf("system-services ssh zone must emit a catch-all drop:\n%s", payload)
	}
}

// buildAndCheckViews resolves the per-zone views and asserts the table would be
// applied (at least one enforceable zone).
func buildAndCheckViews(t *testing.T, cfg *config.Config) []dpuserspace.ZoneHostInboundView {
	t.Helper()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	if !hostInboundHasEnforceableView(views) {
		t.Fatalf("expected at least one enforceable host-inbound view")
	}
	return views
}
