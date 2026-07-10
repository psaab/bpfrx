package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5097: on the tolerant/peer-sync load path an UNRESOLVED sole `except`
// prefix-list reference must keep its inversion polarity. The strict commit
// gate rejects an undefined prefix-list, but a mixed-generation or
// persisted-invalid config reaches ResolveFilterPrefixListAddrs with the
// reference unresolved (pl == nil). The lowering must still emit the
// empty-set-complement triple (addrs=nil, except=true, constrained=true) so the
// Rust matcher reads it as "match every address NOT in {}" = match ALL — a
// `discard`/`reject` term then drops broadly (fail CLOSED).
//
// Pre-#5097 the loop skipped the unresolved reference with `continue` BEFORE the
// `ref.Except` check, so hasExcept stayed false and the term lowered to
// (nil, false, true) = "match addresses in {}" = match NOTHING. The Rust matcher
// returns match-none for that, so a discard/reject term matched no packet and
// traffic fell through to a later permit — fail OPEN for the deny it was written
// to enforce.
//
// FAIL-ON-REVERT: restore the pre-#5097 `continue` before the polarity check and
// `except` comes back false for every case below; the assertions go RED.
func TestResolvePrefixListAddrsUnresolvedSoleExceptFailsClosed_5097(t *testing.T) {
	// An empty config: the referenced prefix-list is undefined (unresolved on
	// the tolerant path).
	cfg := &config.Config{}

	cases := []struct {
		name      string
		literal   []string
		refName   string
		direction string
	}{
		{"source-inet", nil, "undefined4", "source"},
		{"dest-inet", nil, "undefined4", "destination"},
		{"source-inet6", nil, "undefined6", "source"},
		{"dest-inet6", nil, "undefined6", "destination"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				tc.literal,
				[]config.PrefixListRef{{Name: tc.refName, Except: true}},
				cfg, "f", "t", tc.direction,
			)
			if !constrained {
				t.Fatalf("an unresolved except reference must stay constrained "+
					"(fail closed), got constrained=false addrs=%v", addrs)
			}
			if !except {
				t.Fatalf("a SOLE unresolved except reference must lower to "+
					"except=true (empty-set complement = match ALL, fail CLOSED); "+
					"got except=false — this is the #5097 fail-OPEN regression "+
					"where a discard/reject term matched no packet. addrs=%v", addrs)
			}
			if len(addrs) != 0 {
				t.Fatalf("an unresolved except contributes NO prefixes, got addrs=%v", addrs)
			}
		})
	}
}

// A match-any positive literal (`0.0.0.0/0`) alongside an UNRESOLVED except
// reference is the #4338 "any except X" lockdown idiom with X unresolved. It
// must still compose to except=true (match ALL, minus the — here empty —
// unresolved set), i.e. fail CLOSED for a discard term rather than the
// pre-#5097 positive-wins-on-match-any that admitted everything.
func TestResolvePrefixListAddrsMatchAnyPlusUnresolvedExceptFailsClosed_5097(t *testing.T) {
	cfg := &config.Config{}
	addrs, except, constrained := resolvePrefixListAddrs(
		[]string{"0.0.0.0/0"},
		[]config.PrefixListRef{{Name: "undefined", Except: true}},
		cfg, "f", "t", "source",
	)
	if !except || !constrained {
		t.Fatalf("match-any + unresolved except must compose to except=true, "+
			"constrained=true (fail closed); got except=%v constrained=%v addrs=%v",
			except, constrained, addrs)
	}
	// The redundant match-any universe is dropped and the unresolved except set
	// contributes nothing, so the matched set is empty (inverted = match ALL).
	if len(addrs) != 0 {
		t.Fatalf("compose prefixes = %v, want empty (unresolved except set)", addrs)
	}
}

// A SPECIFIC positive literal alongside an UNRESOLVED except reference is NOT
// the compose case — the specific scope constrains the positive set, so it stays
// positive-wins (except dropped) and remains fail-safe (a discard drops at least
// the positive scope; an accept admits no more than it). This is the
// discriminator that the #5097 hasExcept recording does NOT widen the specific
// case.
func TestResolvePrefixListAddrsSpecificPlusUnresolvedExceptStaysPositiveWins_5097(t *testing.T) {
	cfg := &config.Config{}
	addrs, except, constrained := resolvePrefixListAddrs(
		[]string{"10.0.0.0/8"},
		[]config.PrefixListRef{{Name: "undefined", Except: true}},
		cfg, "f", "t", "source",
	)
	if except {
		t.Fatalf("specific positive + unresolved except must NOT compose "+
			"(positive-wins), got except=true addrs=%v", addrs)
	}
	if !constrained {
		t.Fatalf("a specific positive scope must stay constrained, got constrained=false")
	}
	if len(addrs) != 1 || addrs[0] != "10.0.0.0/8" {
		t.Fatalf("positive-wins must keep the literal scope, got addrs=%v", addrs)
	}
}
