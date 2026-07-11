package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5225: a firewall-filter term that carries BOTH an UNRESOLVED positive
// prefix-list ref AND an `except` ref (unresolved OR resolved-empty), with no
// RESOLVED positive scope, must NOT compose to match-ALL on an `accept` term.
//
// The #4338 "any except X" compose (ResolveFilterPrefixListAddrs) fires on
// `hasExcept && !hasPositiveRef && addrsAllMatchAny(positive)` and lowers the
// direction to (exceptPrefixes, except=true, constrained=true) = match-ALL. That
// gate is correct only when the positive side is GENUINELY the match-any
// universe. An UNRESOLVED positive ref leaves `positive` empty WITHOUT the
// operator having written `any` — addrsAllMatchAny then returns a FALSE positive,
// the gate fires, and:
//   - `accept` term  -> match-ALL = ADMIT every packet  = fail-OPEN (the bug),
//   - `discard`/`reject` term -> match-ALL = DROP every packet = fail-CLOSED.
//
// hasPositiveRef is set only for RESOLVED positive refs (pl != nil), so an
// unresolved positive ref never sets it and the gate cannot see the intended
// specific scope. The fix records an UNRESOLVED positive ref separately
// (hasUnresolvedPositiveRef) and, when it is present, lowers the direction fail
// CLOSED BY ACTION: `accept` (and any non-deny action) -> match-NOTHING; only
// `discard`/`reject` keep match-ALL.
//
// This term shape is hard-rejected at strict commit TWICE — undefined prefix-list
// (validateFirewallPrefixListReferencesStrict) and mixed positive+except (#3359)
// — so it only reaches the runtime lowering on the tolerant / peer-sync /
// persisted-invalid load path (#1960 no-brick), same family as #5097/#5223.
//
// FAIL-ON-REVERT: drop the `hasUnresolvedPositiveRef && !firewallFilterActionDenies`
// branch from the compose gate in ResolveFilterPrefixListAddrs (so it always
// `return exceptPrefixes, true, true`) and the accept assertions below go RED —
// the accept term composes back to except=true = admit-ALL.
func TestResolvePrefixListAddrsUnresolvedPositivePlusExceptFailsClosedByAction_5225(t *testing.T) {
	// Empty config: BOTH referenced prefix-lists are undefined -> unresolved on
	// the tolerant path (pl == nil for each).
	cfg := &config.Config{}

	// refs order: positive first, then except (natural config order). The lowering
	// is order-independent, but pin the realistic ordering.
	refs4 := []config.PrefixListRef{
		{Name: "undef_pos4", Except: false},
		{Name: "undef_exc4", Except: true},
	}
	refs6 := []config.PrefixListRef{
		{Name: "undef_pos6", Except: false},
		{Name: "undef_exc6", Except: true},
	}

	acceptCases := []struct {
		name      string
		refs      []config.PrefixListRef
		direction string
		action    string
	}{
		{"accept-source-inet", refs4, "source", "accept"},
		{"accept-dest-inet", refs4, "destination", "accept"},
		{"accept-source-inet6", refs6, "source", "accept"},
		{"accept-dest-inet6", refs6, "destination", "accept"},
		// A modifier-only fall-through (Action == "") and a PBR redirect must ALSO
		// fail closed to match-NOTHING — an unresolvable positive set must never be
		// counted, logged, admitted, or redirected as a match.
		{"fallthrough-source-inet", refs4, "source", ""},
	}
	for _, tc := range acceptCases {
		t.Run(tc.name, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				nil, tc.refs, cfg, "f", "t", tc.direction, tc.action,
			)
			if !constrained {
				t.Fatalf("an unresolved positive+except term must stay constrained "+
					"(fail closed), got constrained=false addrs=%v", addrs)
			}
			if except {
				t.Fatalf("#5225 REGRESSION: an unresolved positive prefix-list ref + "+
					"except on a non-deny term (%q) must lower to match-NOTHING "+
					"(except=false), NOT the match-ALL compose (except=true = admit "+
					"every packet = fail-OPEN). got except=true addrs=%v", tc.action, addrs)
			}
			if len(addrs) != 0 {
				t.Fatalf("match-NOTHING contributes NO prefixes, got addrs=%v", addrs)
			}
		})
	}

	// Regression guard: a `discard`/`reject` term with the SAME shape must STAY
	// fail-closed = match-ALL (except=true, empty set). A deny that matched nothing
	// would fall through to a later permit term = fail-OPEN for the deny (#5097).
	denyCases := []struct {
		name   string
		action string
	}{
		{"discard", "discard"},
		{"reject", "reject"},
	}
	for _, tc := range denyCases {
		t.Run("deny-"+tc.name, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				nil, refs4, cfg, "f", "t", "source", tc.action,
			)
			if !except || !constrained {
				t.Fatalf("a %q term with unresolved positive+except must stay fail-closed "+
					"= match-ALL (except=true, constrained=true) so the deny drops "+
					"broadly; got except=%v constrained=%v addrs=%v",
					tc.action, except, constrained, addrs)
			}
			// The unresolved except ref contributes no prefixes, so the excepted set
			// is empty; inverted = match ALL.
			if len(addrs) != 0 {
				t.Fatalf("unresolved except contributes NO prefixes, got addrs=%v", addrs)
			}
		})
	}
}

// A RESOLVED positive prefix-list ref alongside an `except` ref is the mixed
// positive+except shape (#3359). It is NOT the #5225 case (hasPositiveRef=true, so
// the compose gate never fires) and must be UNCHANGED by the #5225 fix:
// POSITIVE-WINS — the except side is dropped and the term lowers to the resolved
// positive scope (except=false). This holds for EVERY action, so the action-gated
// #5225 branch must never touch it.
func TestResolvePrefixListAddrsResolvedPositivePlusExceptUnchanged_5225(t *testing.T) {
	cfg := &config.Config{
		PolicyOptions: config.PolicyOptionsConfig{
			PrefixLists: map[string]*config.PrefixList{
				"good": {Name: "good", Prefixes: []string{"10.0.0.0/8"}},
			},
		},
	}
	refs := []config.PrefixListRef{
		{Name: "good", Except: false},
		{Name: "undef_exc", Except: true},
	}
	for _, action := range []string{"accept", "discard", "reject", ""} {
		t.Run("action="+action, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				nil, refs, cfg, "f", "t", "source", action,
			)
			if except {
				t.Fatalf("resolved positive + except must stay positive-wins "+
					"(except=false), got except=true addrs=%v", addrs)
			}
			if !constrained {
				t.Fatalf("a resolved positive scope must stay constrained, got constrained=false")
			}
			if len(addrs) != 1 || addrs[0] != "10.0.0.0/8" {
				t.Fatalf("positive-wins must keep the resolved positive scope, got addrs=%v", addrs)
			}
		})
	}
}

// A GENUINE match-any positive (`0.0.0.0/0` literal, NO unresolved positive ref)
// alongside an unresolved except ref is the #4338/#5097 "any except X" lockdown
// idiom, X unresolved. The #5225 action-gate must NOT touch it — it composes to
// match-ALL (except=true) for EVERY action, including `accept` (admit any except
// the — here empty — unresolved set). This is the discriminator proving the fix
// keys off hasUnresolvedPositiveRef, not merely off "empty positive + except".
func TestResolvePrefixListAddrsGenuineMatchAnyPlusUnresolvedExceptUnchanged_5225(t *testing.T) {
	cfg := &config.Config{}
	for _, action := range []string{"accept", "discard", "reject", ""} {
		t.Run("action="+action, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				[]string{"0.0.0.0/0"},
				[]config.PrefixListRef{{Name: "undef_exc", Except: true}},
				cfg, "f", "t", "source", action,
			)
			if !except || !constrained {
				t.Fatalf("genuine match-any + unresolved except must compose to "+
					"except=true, constrained=true for action=%q; got except=%v "+
					"constrained=%v addrs=%v", action, except, constrained, addrs)
			}
			if len(addrs) != 0 {
				t.Fatalf("compose prefixes = %v, want empty (unresolved except set)", addrs)
			}
		})
	}
}
