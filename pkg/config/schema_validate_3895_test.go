package config_test

// Regression tests for #3895: the router-advertisement lifetime leaves were
// typed by #2497 but left UNBOUNDED (ValidateIntegerMin(0) / min-only). An
// over-large lifetime commits, then the RA sender (pkg/ra/sender.go buildRA)
// hands it to an ndp option whose on-wire field cannot hold it:
//   - PREF64 (nat-prefix/nat64prefix) lifetime is a 13-bit scaled-by-8 field
//     (RFC 8781 §4, max 8191*8 = 65528s); an over-large value makes
//     ndp.PREF64.marshal FAIL, which — the whole RA is one WriteTo — aborts
//     the ENTIRE Router Advertisement and the segment stops getting RAs.
//   - the RA-header router lifetime is a 16-bit field (RFC 4861 §4.2); a
//     larger value silently wraps (65536 -> 0 = "not a default router").
//   - the Prefix Information valid/preferred lifetimes are 32-bit fields
//     (RFC 4861 §4.6.2); a larger value silently truncates.
// Each RejectsBad case FAILS to error before the bound (goes RED on revert)
// and errors after it; each AcceptsBoundary case guards against a false-reject
// of the exact maximum.

import (
	"strings"
	"testing"
)

// --- PREF64 (nat-prefix / nat64prefix) lifetime: RFC 8781 max 65528s -----

func TestSchema3895_PREF64Lifetime_RejectsOverlarge(t *testing.T) {
	for _, leaf := range []string{"nat-prefix", "nat64prefix"} {
		err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            `+leaf+` 64:ff9b::/96 {
                lifetime 100000;
            }
        }
    }
}`)
		if err == nil {
			t.Fatalf("expected error for %s lifetime 100000 (> RFC 8781 max 65528), got nil", leaf)
		}
		if !strings.Contains(err.Error(), "lifetime") {
			t.Fatalf("error should reference lifetime: %v", err)
		}
	}
}

func TestSchema3895_PREF64Lifetime_AcceptsMax(t *testing.T) {
	for _, leaf := range []string{"nat-prefix", "nat64prefix"} {
		// The exact RFC 8781 maximum (65528s) is representable and must pass;
		// 0 (= use router lifetime) must also pass.
		for _, life := range []string{"0", "1800", "65528"} {
			if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            `+leaf+` 64:ff9b::/96 {
                lifetime `+life+`;
            }
        }
    }
}`); err != nil {
				t.Fatalf("unexpected error for %s lifetime %s: %v", leaf, life, err)
			}
		}
	}
}

// --- router default-lifetime: RFC 4861 §4.2 16-bit max 65535s ------------

func TestSchema3895_DefaultLifetime_RejectsOverlarge(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            default-lifetime 65536;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for default-lifetime 65536 (> uint16 max 65535), got nil")
	}
	if !strings.Contains(err.Error(), "default-lifetime") {
		t.Fatalf("error should reference default-lifetime: %v", err)
	}
}

func TestSchema3895_DefaultLifetime_AcceptsMax(t *testing.T) {
	if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            default-lifetime 65535;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error for default-lifetime 65535: %v", err)
	}
}

// --- prefix valid/preferred lifetimes: RFC 4861 §4.6.2 32-bit max --------

func TestSchema3895_PrefixLifetimes_RejectOverlarge(t *testing.T) {
	for _, leaf := range []string{"valid-lifetime", "preferred-lifetime"} {
		err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            prefix 2001:db8::/64 {
                `+leaf+` 4294967296;
            }
        }
    }
}`)
		if err == nil {
			t.Fatalf("expected error for prefix %s 4294967296 (> uint32 max), got nil", leaf)
		}
		if !strings.Contains(err.Error(), leaf) {
			t.Fatalf("error should reference %s: %v", leaf, err)
		}
	}
}

func TestSchema3895_PrefixLifetimes_AcceptMax(t *testing.T) {
	for _, leaf := range []string{"valid-lifetime", "preferred-lifetime"} {
		// 4294967295 = 0xffffffff = RFC 4861 "infinity"; 0 = SLAAC default.
		for _, life := range []string{"0", "4294967295"} {
			if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            prefix 2001:db8::/64 {
                `+leaf+` `+life+`;
            }
        }
    }
}`); err != nil {
				t.Fatalf("unexpected error for prefix %s %s: %v", leaf, life, err)
			}
		}
	}
}
