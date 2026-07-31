package userspace

import "testing"

// host_inbound_all_scoping_3226_test.go is the VERDICT guard for #3226: the
// scoping of `host-inbound-traffic system-services all` from a packet-wide
// admit to the union of the named system-services.
//
// Junos scopes `all` to "traffic from the defined system services available on
// the Routing Engine" (Juniper, `system-services (Security Zones Host Inbound
// Traffic)`), and its documented service list carries no raw IP protocol —
// GRE/ESP/OSPF/PIM/VRRP arrive through `protocols`, never through
// `system-services`. Before #3226 xpf short-circuited `all` to a full admit on
// both enforcement layers, so an `all` zone accepted EVERY IP protocol and port
// to its local addresses with no catch-all deny at all: a fail-OPEN relative to
// the Junos meaning that could mask a missing explicit `protocols` entry.
//
// These tests assert the ADMIT/DENY VERDICT for concrete packet tuples, not the
// shape of any intermediate structure — a structure-only assertion would pass
// straight through a policy widening.

// TestClassifyHostInboundSystemServicesAllScopedToNamedServices is the #3226
// RED-on-revert core: `system-services all` alone must ADMIT the named
// system-services and DENY every raw IP protocol the pre-#3226 blanket admit
// let through.
//
// FAIL-ON-REVERT: restore the full-admit short-circuit (teach
// config.HostInboundFullAdmitService to return true for "all", or drop the
// `case "all"` expansion from config.HostInboundServiceMatch) and every DENIED
// row below flips to admitted.
func TestClassifyHostInboundSystemServicesAllScopedToNamedServices(t *testing.T) {
	const (
		TCP = uint8(6)
		UDP = uint8(17)
	)
	cfg := cfgWithHostInbound("edge", []string{"all"}, nil)

	// --- ADMITTED: the named system-service union `all` now stands for. ------
	admitted := []struct {
		name  string
		proto uint8
		port  int
	}{
		{"ssh tcp/22", TCP, 22},
		{"https tcp/443", TCP, 443},
		{"telnet tcp/23", TCP, 23},
		{"snmp udp/161", UDP, 161},
		{"ntp udp/123", UDP, 123},
		{"dns udp/53", UDP, 53},
		{"ike udp/500", UDP, 500},
		{"netconf tcp/830", TCP, 830},
	}
	for _, tc := range admitted {
		got := ClassifyHostInbound(cfg, "edge", tc.proto, true, tc.port, nil, "ip")
		if got.Status != HostInboundTokenAdmit {
			t.Errorf("%s with system-services all: got %+v, want token-admit (`all` expands to the named service union)", tc.name, got)
		}
	}

	// --- DENIED: raw IP protocols Junos `all` never opens. -------------------
	// These are exactly the protocols the issue names. ESP (50) / AH (51) are
	// deliberately absent: they carry an unconditional global accept for
	// host-terminated IPsec (#3171) that is orthogonal to the host-inbound
	// token set, so they would be admitted regardless of this change and prove
	// nothing about the scoping.
	deniedProtos := []struct {
		name  string
		proto uint8
	}{
		{"ospf proto 89", 89},
		{"gre proto 47", 47},
		{"vrrp proto 112", 112},
		{"pim proto 103", 103},
		{"nhrp proto 54", 54},
		{"an unassigned future protocol 253", 253},
	}
	for _, tc := range deniedProtos {
		got := ClassifyHostInbound(cfg, "edge", tc.proto, true, 0, nil, "ip")
		if got.Status != HostInboundDenied {
			t.Errorf("%s with system-services all: got %+v, want DENIED — `all` is the union of named system-services, not a packet-wide admit (#3226)", tc.name, got)
		}
	}

	// --- DENIED: an unlisted TCP/UDP port. -----------------------------------
	// The catch-all deny is re-armed for the zone, so a port outside the named
	// service union is denied just as it is for any explicit service list.
	if got := ClassifyHostInbound(cfg, "edge", TCP, true, 9999, nil, "ip"); got.Status != HostInboundDenied {
		t.Errorf("tcp/9999 with system-services all: got %+v, want DENIED (unlisted port, #3226)", got)
	}
}

// TestClassifyHostInboundSystemServicesAllExcludesGRE pins the xpf-extension
// carve-out. `gre` is NOT a Junos system-service (Junos has no raw-IP-protocol
// service token); xpf accepts it because operator configs list it there. It is
// therefore excluded from the `all` expansion — otherwise `all` would silently
// open a protocol Junos's `all` never opens, which is the very over-admit
// #3226 closes. The token stays fully usable when listed EXPLICITLY.
//
// FAIL-ON-REVERT: drop "gre" from config.HostInboundNonJunosSystemServices and
// the first row (deny) flips to admitted.
func TestClassifyHostInboundSystemServicesAllExcludesGRE(t *testing.T) {
	const gre = uint8(47)

	if got := ClassifyHostInbound(cfgWithHostInbound("edge", []string{"all"}, nil),
		"edge", gre, true, 0, nil, "ip"); got.Status != HostInboundDenied {
		t.Errorf("gre proto 47 with system-services all: got %+v, want DENIED (gre is an xpf extension, excluded from the Junos `all` union)", got)
	}

	// Explicitly listed, it is admitted — the carve-out narrows `all`, it does
	// not remove the token.
	if got := ClassifyHostInbound(cfgWithHostInbound("edge", []string{"gre"}, nil),
		"edge", gre, true, 0, nil, "ip"); got.Status != HostInboundTokenAdmit || got.Token != "gre" {
		t.Errorf("gre proto 47 with an explicit system-services gre: got %+v, want token-admit gre", got)
	}
}

// TestClassifyHostInboundAnyServiceStillFullAdmit pins the other half of the
// #3226 contract: `any-service` REMAINS the packet-wide escape hatch. Junos
// defines it as "all system services on an entire port range including the
// system services that are not defined", so it is the documented way to admit
// what the named set does not cover — and the one-token migration for a config
// that relied on the pre-#3226 breadth of `all`.
//
// OVER-REACH GUARD: if the #3226 narrowing were applied to `any-service` too,
// every row here flips to denied.
func TestClassifyHostInboundAnyServiceStillFullAdmit(t *testing.T) {
	cfg := cfgWithHostInbound("edge", []string{"any-service"}, nil)

	for _, tc := range []struct {
		name  string
		proto uint8
		port  int
	}{
		{"ospf proto 89", 89, 0},
		{"gre proto 47", 47, 0},
		{"vrrp proto 112", 112, 0},
		{"an unlisted tcp/9999", 6, 9999},
	} {
		got := ClassifyHostInbound(cfg, "edge", tc.proto, true, tc.port, nil, "ip")
		if got.Status != HostInboundTokenAdmit || got.Token != "any-service" {
			t.Errorf("%s with system-services any-service: got %+v, want token-admit any-service (full-admit escape hatch retained)", tc.name, got)
		}
	}
}

// TestClassifyHostInboundSystemServicesAllPlusProtocols proves the two `all`
// tokens compose the way Junos means them to: `system-services all` supplies
// the service union and `protocols all` supplies the routing set, and a
// protocol reached ONLY through `protocols` (ospf) needs that explicit entry.
//
// This is the acceptance criterion stated in the issue: "`system-services all`
// admits SSH/HTTPS/SNMP but denies OSPF/GRE/VRRP unless a matching `protocols`
// entry exists".
func TestClassifyHostInboundSystemServicesAllPlusProtocols(t *testing.T) {
	const (
		TCP  = uint8(6)
		ospf = uint8(89)
	)

	// system-services all ALONE: ssh admitted, ospf denied.
	svcOnly := cfgWithHostInbound("edge", []string{"all"}, nil)
	if got := ClassifyHostInbound(svcOnly, "edge", TCP, true, 22, nil, "ip"); got.Status != HostInboundTokenAdmit {
		t.Fatalf("ssh tcp/22 with system-services all: got %+v, want token-admit", got)
	}
	if got := ClassifyHostInbound(svcOnly, "edge", ospf, true, 0, nil, "ip"); got.Status != HostInboundDenied {
		t.Fatalf("ospf proto 89 with system-services all only: got %+v, want DENIED", got)
	}

	// Add the matching `protocols ospf` entry and ospf is admitted — the
	// operator now says what they mean, which is the point of the narrowing.
	withProto := cfgWithHostInbound("edge", []string{"all"}, []string{"ospf"})
	if got := ClassifyHostInbound(withProto, "edge", ospf, true, 0, nil, "ip"); got.Status != HostInboundTokenAdmit || got.Kind != "protocols" {
		t.Fatalf("ospf proto 89 with system-services all + protocols ospf: got %+v, want token-admit via protocols", got)
	}
}
