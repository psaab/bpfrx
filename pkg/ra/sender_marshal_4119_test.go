package ra

// Regression tests for #4119: an explicit `default-lifetime 0` must marshal as
// RFC 4861 §6.2.1 Router Lifetime 0 ("this router is NOT a default router"),
// while an UNSET default-lifetime still defaults to 1800 and a configured value
// is passed through verbatim. Critically, a Router Lifetime of 0 withdraws only
// default-router duty — the on-link prefixes and the PREF64 / RDNSS options
// must still be advertised (with their own lifetimes), so a host can still use
// xpf for SLAAC / NAT64 / DNS while picking another router as its default.
//
// RED-on-revert: restore buildRA's `if lifetime <= 0 { lifetime =
// defaultRouterLifetime }` coercion and TestBuildRA_4119_ExplicitZero fails
// (RouterLifetime springs back to 1800). Point the RDNSS/PREF64 default back at
// the raw `lifetime` and TestBuildRA_4119_PrefixAndPref64StillAdvertised fails
// (their lifetimes collapse to 0).

import (
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// An explicit default-lifetime 0 must reach the wire as RouterLifetime 0.
func TestBuildRA_4119_ExplicitZero(t *testing.T) {
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface:          "trust0",
		DefaultLifetime:    0,
		DefaultLifetimeSet: true,
	})
	ra := s.buildRA()
	if ra.RouterLifetime != 0 {
		t.Fatalf("explicit default-lifetime 0 must marshal RouterLifetime 0; got %v", ra.RouterLifetime)
	}
}

// An UNSET default-lifetime still defaults to 1800 (unchanged behavior).
func TestBuildRA_4119_UnsetDefaults1800(t *testing.T) {
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface: "trust0",
		// DefaultLifetimeSet omitted -> false (unset).
	})
	ra := s.buildRA()
	if ra.RouterLifetime != 1800*time.Second {
		t.Fatalf("unset default-lifetime must default to 1800s; got %v", ra.RouterLifetime)
	}
}

// A configured non-zero value is passed through verbatim.
func TestBuildRA_4119_ExplicitValue(t *testing.T) {
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface:          "trust0",
		DefaultLifetime:    9000,
		DefaultLifetimeSet: true,
	})
	ra := s.buildRA()
	if ra.RouterLifetime != 9000*time.Second {
		t.Fatalf("explicit default-lifetime 9000 must marshal 9000s; got %v", ra.RouterLifetime)
	}
}

// With Router Lifetime 0 the prefix and PREF64 options must STILL be
// advertised: the RA marshals, the on-link prefix and PREF64 options are
// present, and the PREF64 lifetime does not collapse to 0 (it falls back to the
// standard default so hosts keep the NAT64 prefix while xpf declines
// default-router duty).
func TestBuildRA_4119_PrefixAndPref64StillAdvertised(t *testing.T) {
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface:          "trust0",
		DefaultLifetime:    0,
		DefaultLifetimeSet: true,
		NAT64Prefix:        "64:ff9b::/96",
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
	})

	ra := s.buildRA()
	if ra.RouterLifetime != 0 {
		t.Fatalf("RouterLifetime must be 0; got %v", ra.RouterLifetime)
	}
	if _, err := ndp.MarshalMessage(ra); err != nil {
		t.Fatalf("RA with lifetime 0 must still marshal; got %v", err)
	}

	var foundPrefix bool
	var pref64 *ndp.PREF64
	for _, opt := range ra.Options {
		switch o := opt.(type) {
		case *ndp.PrefixInformation:
			foundPrefix = true
		case *ndp.PREF64:
			pref64 = o
		}
	}
	if !foundPrefix {
		t.Error("on-link prefix must still be advertised when Router Lifetime is 0")
	}
	if pref64 == nil {
		t.Fatal("PREF64 must still be advertised when Router Lifetime is 0")
	}
	if pref64.Lifetime == 0 {
		t.Error("PREF64 lifetime must not collapse to 0 when the router lifetime is an explicit 0")
	}
}
