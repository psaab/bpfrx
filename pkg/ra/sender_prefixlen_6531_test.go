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
//     pins the blast radius the pkg/dhcp guard prevents; it documents current
//     behavior and is GREEN both before and after the fix. It is the reason
//     the /0 must be refused at the DHCPv6 decoder rather than filtered here:
//     by this point the prefix is indistinguishable from an operator-authored
//     `set interfaces <if> ipv6 router-advertisement prefix ::/0`.

import (
	"testing"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

func prefixInfoFor(t *testing.T, prefix string) *ndp.PrefixInformation {
	t.Helper()
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes: []*config.RAPrefix{
			{Prefix: prefix, OnLink: true, Autonomous: true},
		},
	})
	for _, opt := range s.buildRA().Options {
		if pi, ok := opt.(*ndp.PrefixInformation); ok {
			return pi
		}
	}
	t.Fatalf("buildRA emitted no PrefixInformation for %s", prefix)
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

// The blast radius #6531 prevents: nothing downstream of the DHCPv6 decoder
// stops a /0 from being advertised on-link + autonomous to the whole LAN.
func TestBuildRA_6531_ZeroPrefixWouldBeAdvertised(t *testing.T) {
	pi := prefixInfoFor(t, "::/0")

	if pi.PrefixLength != 0 {
		t.Fatalf("PrefixLength = %d, want 0 — pkg/ra gained a prefix-length "+
			"filter; re-check whether the #6531 guard in pkg/dhcp is still the "+
			"only thing keeping a delegated /0 off the wire", pi.PrefixLength)
	}
	if !pi.OnLink || !pi.AutonomousAddressConfiguration {
		t.Errorf("OnLink = %v, Autonomous = %v, want both true "+
			"(this is what makes a /0 a LAN-wide hijack)",
			pi.OnLink, pi.AutonomousAddressConfiguration)
	}
}
