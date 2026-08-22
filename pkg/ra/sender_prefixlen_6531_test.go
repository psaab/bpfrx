package ra

// #6531, RA side of the fix. pkg/ra is the CONSUMER of a DHCPv6 delegated
// prefix (pkg/daemon/daemon_ra.go runs dhcp.DeriveSubPrefix and hands the
// result here), and it applies NO sanity floor of its own: buildRA marshals
// whatever prefix length it is given straight into the PrefixInformation.
//
// These two tests are the pair that justifies where the #6531 guard lives:
//
//   - A normal /64 still reaches the wire as PrefixLength 64, on-link +
//     autonomous. This is the OVER-REACH guard and must stay GREEN under a
//     revert of the pkg/dhcp fix.
//   - A /0 that reaches this far IS advertised as PrefixLength 0. This test
//     pinned the blast radius the pkg/dhcp guard prevents; it documented
//     current behavior and was GREEN both before and after the #6531 fix.
//
//     UPDATED BY #6587. Its stated reason — "by this point the prefix is
//     indistinguishable from an operator-authored
//     `set interfaces <if> ipv6 router-advertisement prefix ::/0`" — no
//     longer holds: config.RAPrefix.Delegated now carries the provenance, and
//     buildRA refuses a DELEGATED /0 while still emitting a configured one.
//     So this case has changed meaning rather than becoming stale: it is now
//     the OVER-REACH guard for the operator-authored ::/0 that the floor must
//     not break (#6587 acceptance criterion 3), and it is named accordingly
//     below. The delegated half is covered by
//     TestBuildRA_6587_DelegatedZeroPrefixIsRefused.
//
// This file covers the LAST LEG of the PD → RA chain: config.RAPrefix →
// buildRA → marshaled bytes. It starts from a statically constructed
// config.RAPrefix rather than a live delegation, because that struct is the
// exact seam pkg/daemon's buildRAConfigs hands across (OnLink + Autonomous
// hard-set, prefix rendered by subPrefix.String() — see daemon_ra.go). The
// upstream legs are covered where their seams live:
// pkg/dhcp/dhcpv6_iapd_prefixlen_6531_test.go (wire bytes → DelegatedPrefix →
// DeriveSubPrefix) and pkg/daemon/ra_pd_prefixlen_6531_test.go (stored PD →
// the real buildRAConfigs → config.RAPrefix).

import (
	"testing"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// prefixInfoFor builds an RA for a single prefix, MARSHALS it with the same
// encoder the sender's conn.WriteTo runs, parses the bytes back, and returns
// the PrefixInformation as it appears ON THE WIRE.
//
// The round-trip is deliberate (#6581 review): inspecting buildRA's in-memory
// option would assert on a Go struct field, not on what the segment receives.
// PrefixLength is an 8-bit wire field, so only a marshal/parse proves the
// length an attacker-supplied delegation carries actually reaches the LAN.
func prefixInfoFor(t *testing.T, prefix string) *ndp.PrefixInformation {
	t.Helper()
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes: []*config.RAPrefix{
			{Prefix: prefix, OnLink: true, Autonomous: true},
		},
	})

	b, err := ndp.MarshalMessage(s.buildRA())
	if err != nil {
		t.Fatalf("RA carrying %s must marshal: %v", prefix, err)
	}
	msg, err := ndp.ParseMessage(b)
	if err != nil {
		t.Fatalf("re-parsing the marshaled RA for %s: %v", prefix, err)
	}
	ra, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatalf("marshaled message re-parsed as %T, want *ndp.RouterAdvertisement", msg)
	}
	for _, opt := range ra.Options {
		if pi, ok := opt.(*ndp.PrefixInformation); ok {
			return pi
		}
	}
	t.Fatalf("the marshaled RA carried no PrefixInformation for %s", prefix)
	return nil
}

// A normal delegated /64 must still be advertised. GREEN under the revert.
func TestBuildRA_6531_NormalPrefixStillAdvertised(t *testing.T) {
	pi := prefixInfoFor(t, "2001:db8:900d::/64")

	if pi.PrefixLength != 64 {
		t.Errorf("PrefixLength = %d, want 64", pi.PrefixLength)
	}
	if !pi.OnLink || !pi.AutonomousAddressConfiguration {
		t.Errorf("OnLink = %v, Autonomous = %v, want both true",
			pi.OnLink, pi.AutonomousAddressConfiguration)
	}
}

// An OPERATOR-AUTHORED ::/0 is still advertised (#6587 over-reach guard).
//
// This was TestBuildRA_6531_ZeroPrefixWouldBeAdvertised, which recorded that
// nothing downstream of the DHCPv6 decoder stopped a /0 reaching the LAN. #6587
// added a floor here — but scoped to DELEGATED prefixes, because
// `set interfaces <if> ipv6 router-advertisement prefix ::/0` is legitimate
// configuration and a blanket floor would silently break it. The case therefore
// survives with its assertion intact and its MEANING inverted: it now proves
// the floor did not over-reach.
func TestBuildRA_6587_ConfiguredZeroPrefixStillAdvertised(t *testing.T) {
	// prefixInfoFor builds a config.RAPrefix with Delegated unset, i.e. the
	// operator-authored provenance. That is load-bearing, not incidental.
	pi := prefixInfoFor(t, "::/0")

	if pi.PrefixLength != 0 {
		t.Fatalf("PrefixLength = %d, want 0 — the #6587 delegated-/0 floor has "+
			"over-reached and is now filtering an OPERATOR-AUTHORED ::/0, which is "+
			"legitimate configuration", pi.PrefixLength)
	}
	if !pi.OnLink || !pi.AutonomousAddressConfiguration {
		t.Errorf("OnLink = %v, Autonomous = %v, want both true "+
			"(this is what makes a /0 a LAN-wide hijack)",
			pi.OnLink, pi.AutonomousAddressConfiguration)
	}
}
