package ddns

import (
	"strings"
	"testing"
)

// #8597 (muse-004 K49) — a provider name could forge a field boundary in the
// scope prefix, aliasing two scopes the reconciler must keep apart.
//
// The old encoding was `f4/if=%s/u=%d/ri=%s/rg=%d/pid=%s` plus an optional
// `/fqdn=%s`, and its comment asserted that "/fqdn=" could not alias an earlier
// field because "pid is the last fixed field and the value cannot contain
// /fqdn=". PolicyID is a RAW provider name from config
// (daemon_ddns_surface_a.go: `PolicyID: b.Provider`) and the `provider` schema
// leaf carries no validator. Measured before the fix:
//
//	{PolicyID: "p/fqdn=a.example"}       -> f4/if=ge-0-0-0/u=0/ri=/rg=0/pid=p/fqdn=a.example#
//	{PolicyID: "p", FQDN: "a.example"}   -> f4/if=ge-0-0-0/u=0/ri=/rg=0/pid=p/fqdn=a.example#
//
// Byte-identical. Two scopes sharing a prefix share their gating
// (`gatedScope`), their runtime state (`m.runtime`) and their owned-record
// keys — so a withdraw reasoned about one endpoint can act on the other's
// records, and one provider's backoff can suppress a healthy provider's
// publishes.

// TestScopePrefixCannotBeForgedByAFieldValue_8597 is the RED-on-revert core.
//
// It asserts DISTINCTNESS across a set of scopes that differ only in where a
// separator-looking substring sits, rather than pinning one encoding: the
// property is that no value can impersonate a boundary, and a pinned literal
// would go stale the next time the format changes for an unrelated reason.
func TestScopePrefixCannotBeForgedByAFieldValue_8597(t *testing.T) {
	scopes := map[string]ScopeKey{
		"fqdn injected via the provider name": {
			Family: FamilyV4, Interface: "ge-0-0-0", PolicyID: "p/fqdn=a.example",
		},
		"the real pairing it impersonates": {
			Family: FamilyV4, Interface: "ge-0-0-0", PolicyID: "p", FQDN: "a.example",
		},
		"separators injected via the interface": {
			Family: FamilyV4, Interface: "ge-0-0-0/u=9/ri=", Unit: 0,
		},
		"the real pairing the interface one impersonates": {
			Family: FamilyV4, Interface: "ge-0-0-0", Unit: 9,
		},
		"separators injected via the routing instance": {
			Family: FamilyV4, Interface: "ge", RoutingInstance: "vrf/rg=7/pid=",
		},
		"the real pairing the routing-instance one impersonates": {
			Family: FamilyV4, Interface: "ge", RGOwner: 7,
		},
		// Injection using the CURRENT separator, not only the old one. Without
		// these, dropping the length prefix while keeping "|" still passes this
		// cell — the mutation said so — because every other fixture forges the
		// PREVIOUS format's separators. A forgery cell has to attack the
		// encoding that is actually there.
		"pipe injected via the provider name": {
			Family: FamilyV4, Interface: "ge", PolicyID: "p|q", FQDN: "r",
		},
		"the real pairing the pipe one impersonates": {
			Family: FamilyV4, Interface: "ge", PolicyID: "p", FQDN: "q|r",
		},
		"empty fqdn": {
			Family: FamilyV4, Interface: "ge", PolicyID: "p",
		},
		"fqdn that is the empty-looking literal": {
			Family: FamilyV4, Interface: "ge", PolicyID: "p", FQDN: "0:",
		},
	}

	seen := map[string]string{}
	for name, k := range scopes {
		p := k.scopePrefix()
		if prev, dup := seen[p]; dup {
			t.Errorf("two distinct scopes share the prefix %q:\n  %s\n  %s\n"+
				"a value that can forge a field boundary makes the reconciler treat "+
				"two endpoints as one — shared gating, shared runtime state, shared "+
				"owned-record keys (#8597/K49)", p, prev, name)
			continue
		}
		seen[p] = name
	}
}

// TestScopePrefixLengthPrefixesEveryVariableField_8597 pins the MECHANISM, so
// a future change that restores distinctness by some fragile route (escaping,
// a denylist) still has to argue with the invariant.
//
// Length-prefixing is the property: each variable value is preceded by its byte
// length, which no value can forge because the length is computed, not typed.
func TestScopePrefixLengthPrefixesEveryVariableField_8597(t *testing.T) {
	k := ScopeKey{
		Family: FamilyV4, Interface: "eth0", Unit: 3, RoutingInstance: "vrf1",
		RGOwner: 2, PolicyID: "prov", FQDN: "host.example",
	}
	got := k.scopePrefix()
	for _, want := range []string{
		"4:eth0|", "4:vrf1|", "4:prov|", "12:host.example|",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing length-prefixed field %q in %q", want, got)
		}
	}
	if !strings.HasSuffix(got, "#") {
		t.Errorf("prefix %q does not end with the '#' that separates it from the "+
			"identity|address suffix", got)
	}
}

// TestZeroScopeStillYieldsTheEmptyPrefix_8597 is the OVER-BROAD control, and
// the one compat property that is genuinely load-bearing.
//
// ownedRecordKey's contract is that a ZERO scope yields the EXACT pre-P1b
// "identity|address" key, so a pre-P1b store (whose records decode to a zero
// ScopeKey) loads and reconciles unchanged. Changing the encoding must not
// touch that.
func TestZeroScopeStillYieldsTheEmptyPrefix_8597(t *testing.T) {
	if got := (ScopeKey{}).scopePrefix(); got != "" {
		t.Fatalf("the zero scope yields %q, want \"\" — a pre-P1b store's records "+
			"would re-key and the reconciler would see every one of them as new", got)
	}
	if got := ownedRecordKey(ScopeKey{}, "ident", "10.0.0.1"); got != "ident|10.0.0.1" {
		t.Fatalf("ownedRecordKey(zeroScope, ...) = %q, want the pre-P1b "+
			"\"ident|10.0.0.1\"", got)
	}
}

// TestNonZeroScopesStillDifferByEveryAxis_8597 is the other half of the
// over-broad control: an encoding change must not COLLAPSE axes either. Each
// field must still distinguish two otherwise-identical scopes.
func TestNonZeroScopesStillDifferByEveryAxis_8597(t *testing.T) {
	base := ScopeKey{
		Family: FamilyV4, Interface: "eth0", Unit: 1, RoutingInstance: "vrf",
		RGOwner: 1, PolicyID: "p", FQDN: "h.example",
	}
	variants := map[string]ScopeKey{}
	v := base
	v.Family = FamilyV6
	variants["family"] = v
	v = base
	v.Interface = "eth1"
	variants["interface"] = v
	v = base
	v.Unit = 2
	variants["unit"] = v
	v = base
	v.RoutingInstance = "vrf2"
	variants["routing-instance"] = v
	v = base
	v.RGOwner = 2
	variants["rg-owner"] = v
	v = base
	v.PolicyID = "q"
	variants["policy-id"] = v
	v = base
	v.FQDN = "i.example"
	variants["fqdn"] = v

	basePrefix := base.scopePrefix()
	for axis, k := range variants {
		if k.scopePrefix() == basePrefix {
			t.Errorf("changing %s did not change the prefix; the encoding has collapsed "+
				"an axis the reconciler keys on", axis)
		}
	}
}
