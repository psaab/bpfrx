package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMatchRejectsV4SrcV6DstTuple pins codex-182 A10-b02-C1: the simulator must
// fail closed on an IPv4-source / IPv6-destination query. NAT46 is unsupported,
// so the forwarding path never produces that tuple and the runtime matcher
// rejects it (userspace-dp/src/policy.rs try_match_rule `_ => return false`).
// Before the gate, Match evaluated the two address sides independently and
// under a default-permit config returned a fabricated PERMIT for a packet shape
// the dataplane can never see.
//
// RED on revert: delete the up-front (V4 src, V6 dst) guard in Match and the
// mixed-family case returns the default PERMIT (UnsupportedTupleFamily false).
func TestMatchRejectsV4SrcV6DstTuple(t *testing.T) {
	// default-permit so a missing gate yields a fabricated PERMIT, not a
	// coincidental deny.
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
	}, config.ApplicationsConfig{})

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"),    // IPv4 source
		DstIP: net.ParseIP("2001:db8::1"), // IPv6 destination
	})
	if !res.UnsupportedTupleFamily {
		t.Fatalf("expected UnsupportedTupleFamily for (V4 src, V6 dst), got res=%+v", res)
	}
	if res.Matched || res.DefaultUsed {
		t.Fatalf("impossible tuple must not report a matched/default verdict, got res=%+v", res)
	}
	if res.Action != config.PolicyDeny {
		t.Fatalf("raw Action for an impossible tuple must be conservative deny, got %v", res.Action)
	}
	if got := res.DisplayAction(); got != UnsupportedTupleFamilyActionString {
		t.Fatalf("DisplayAction = %q, want the dedicated unsupported-tuple string", got)
	}
}

// TestMatchAllowsValidFamilyTuples guards that the gate does NOT over-reject:
// the reverse (V6 src, V4 dst) NAT64 arm and both same-family tuples fall
// through to normal evaluation (here, the default-permit).
func TestMatchAllowsValidFamilyTuples(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
	}, config.ApplicationsConfig{})

	cases := []struct {
		name     string
		src, dst string
	}{
		{"v4/v4 same family", "10.0.1.5", "10.0.2.7"},
		{"v6/v6 same family", "2001:db8::1", "2001:db8::2"},
		{"v6 src / v4 dst (NAT64 arm)", "2001:db8::1", "10.0.2.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(cfg, Query{
				FromZone: "trust", ToZone: "untrust",
				SrcIP: net.ParseIP(tc.src), DstIP: net.ParseIP(tc.dst),
			})
			if res.UnsupportedTupleFamily {
				t.Fatalf("%s must NOT be gated as unsupported, got res=%+v", tc.name, res)
			}
			if res.Action != config.PolicyPermit {
				t.Fatalf("%s should fall through to default-permit, got %v", tc.name, res.Action)
			}
		})
	}
}

// TestMatchUnspecifiedIPDoesNotTriggerGate guards that a nil (unspecified) src
// or dst — a legal wildcard query — is never mistaken for a mixed-family tuple.
func TestMatchUnspecifiedIPDoesNotTriggerGate(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
	}, config.ApplicationsConfig{})

	// v4 source, unspecified dst.
	if res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5")}); res.UnsupportedTupleFamily {
		t.Fatalf("v4 src with unspecified dst must not trigger the gate, got res=%+v", res)
	}
	// unspecified src, v6 dst.
	if res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust",
		DstIP: net.ParseIP("2001:db8::1")}); res.UnsupportedTupleFamily {
		t.Fatalf("unspecified src with v6 dst must not trigger the gate, got res=%+v", res)
	}
}
