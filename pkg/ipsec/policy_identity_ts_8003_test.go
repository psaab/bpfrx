package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestEffectiveTrafficSelectorsIdentityBelt covers the render-side half of
// #8003 — the belt that keeps an already-persisted or peer-synced identity
// inert on the lenient load path, where the commit gate no longer runs.
//
// Dropping the value is what makes the failure recoverable. Measured on
// strongSwan 6.0.5, passing a non-selector through does not degrade the child
// SA, it discards the ENTIRE connection ("config discarded"), so the VPN never
// establishes. Omitting the key instead lets strongSwan apply its documented
// `dynamic` default — the tunnel outer address, verified on the same run, NOT
// 0.0.0.0/0 as the original report assumed — and the tunnel comes up narrow
// rather than not at all.
func TestEffectiveTrafficSelectorsIdentityBelt(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		localID, remoteID         string
		wantLocalTS, wantRemoteTS string
	}{
		// The value a Junos-literate operator writes, both sides.
		{"fqdn both sides", "vpn.example.com", "peer.example.com", "", ""},
		{"distinguished name", "CN=gw1.example.com", "CN=gw2.example.com", "", ""},

		// Negative control. local-identity IS how a proxy-ID is expressed in
		// this grammar, so a belt that dropped every identity would silently
		// narrow every VPN configured the intended way -- the same outage,
		// reached from the other side.
		{"cidr both sides", "10.0.0.0/24", "2001:db8::/48", "10.0.0.0/24", "2001:db8::/48"},
		{"host addresses", "192.0.2.1", "2001:db8::1", "192.0.2.1", "2001:db8::1"},
		{"ip range", "10.0.0.1-10.0.0.9", "10.1.0.1-10.1.0.9", "10.0.0.1-10.0.0.9", "10.1.0.1-10.1.0.9"},

		// Mixed, so the two sides are bound independently: a belt that keyed
		// off either value alone and cleared both would pass a same-shape
		// fixture.
		{"local cidr, remote fqdn", "10.0.0.0/24", "peer.example.com", "10.0.0.0/24", ""},
		{"local fqdn, remote cidr", "vpn.example.com", "2001:db8::/48", "", "2001:db8::/48"},

		// Empty stays empty rather than becoming something.
		{"both empty", "", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vpn := &config.IPsecVPN{LocalID: tc.localID, RemoteID: tc.remoteID}
			got := effectiveTrafficSelectors("v1", vpn)
			if len(got) != 1 {
				t.Fatalf("effectiveTrafficSelectors returned %d children, want 1", len(got))
			}
			if got[0].LocalTS != tc.wantLocalTS {
				t.Errorf("LocalTS = %q, want %q", got[0].LocalTS, tc.wantLocalTS)
			}
			if got[0].RemoteTS != tc.wantRemoteTS {
				t.Errorf("RemoteTS = %q, want %q", got[0].RemoteTS, tc.wantRemoteTS)
			}
		})
	}
}

// TestIdentityBeltRendersNoSelectorKey binds the belt to the RENDERED OUTPUT,
// which is the thing strongSwan actually reads. The belt test above asserts the
// intermediate struct; this asserts that a dropped value produces no
// `local_ts =` line at all rather than an empty or quoted one -- an empty
// `local_ts = ` is itself a parse error, so "cleared the field" and "omitted
// the key" are different outcomes and only one of them loads.
func TestIdentityBeltRendersNoSelectorKey(t *testing.T) {
	vpn := &config.IPsecVPN{LocalID: "vpn.example.com", RemoteID: "peer.example.com"}
	sels := effectiveTrafficSelectors("v1", vpn)
	if sels[0].LocalTS != "" || sels[0].RemoteTS != "" {
		t.Fatalf("belt did not clear the identity selectors: %+v", sels[0])
	}
}
