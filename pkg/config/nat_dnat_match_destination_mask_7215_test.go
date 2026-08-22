package config

import (
	"reflect"
	"strings"
	"testing"
)

// #7215: destination-NAT `match destination-address` accepted an OUT-OF-RANGE
// MASK (`10.0.0.0/33`) that its own snapshot builder then silently discarded.
//
// MEASURED AT 353f09592 (the #7145 merge), over nat7145Base — the same base
// config #7145 swept — with `10.0.0.0/33`, `10.0.0.0/abc`, `10.0.0.0/` and
// `1.2.3.4/-1`:
//
//	kind         leaf                  master     here
//	source       source-address        rejected   rejected   (#7145, untouched)
//	source       destination-address   rejected   rejected   (#7145, untouched)
//	destination  source-address        rejected   rejected   (#7145, untouched)
//	destination  destination-address   ACCEPTED   rejected   <- #7215
//	static       source-address        rejected   rejected   (#7145, untouched)
//	static       destination-address   rejected   rejected   (#3206, untouched)
//
// After #7145 closed the four literal slots, this was the ONE slot of six that
// still took a mask the dataplane cannot use. #7145 did not reach it because
// #7145's probe value (`999.1.1.1/24`) is malformed in the ADDRESS text, which
// the old #3228 predicate did see; `10.0.0.0/33` is malformed only in the MASK
// text, which that predicate threw away before parsing.
//
// WHY IT WAS ACCEPTED. validateDestinationNATAddressesStrict split the token at
// the first `/` (natCIDRIPPart) and ran net.ParseIP on the address half only,
// so `10.0.0.0/33` read as the perfectly good `10.0.0.0`. Its consumer,
// dnatDestinationParts (pkg/dataplane/userspace/nat_destination.go), calls
// net.ParseCIDR on any token carrying a `/` and returns ok == false — the entry
// is SKIPPED and never reaches the wire. A validator that accepts what its own
// builder discards is the #2396(c) silent drop that gate was created to close.
// The gate's own doc comment claimed the two matched exactly; they did not.
//
// The predicate is now natMatchPrefixParses (#7145), which is extensionally
// EQUAL to dnatDestinationParts's ok — bound as a cross-package differential in
// pkg/dataplane/userspace/dnat_gate_builder_agreement_7215_test.go, so a
// comment is no longer what holds the two together.
//
// Per CLAUDE.md every flat-set case is built with ParseSetCommand + SetPath,
// never NewParser (which merges all set lines into one node).

// nat7215MaskValues is the value class #7215 covers: the ADDRESS half parses
// but the whole token is not a prefix the dataplane installs. The old #3228
// predicate accepted every one of these; net.ParseCIDR and Rust's
// IpNet::from_str refuse every one of them.
//
// It is deliberately not just `10.0.0.0/33`. A single probe would leave the
// class bound to one arithmetic check inside Go's mask parser; these five
// spellings fail in four different places (range, non-numeric, absent, signed,
// dotted-netmask), so a predicate that recovered any one of them fails here.
var nat7215MaskValues = []string{
	"10.0.0.0/33",            // v4 mask out of range
	"2001:db8::/129",         // v6 mask out of range
	"10.0.0.0/abc",           // mask not a number
	"10.0.0.0/",              // mask absent
	"10.0.0.1/255.255.255.0", // dotted netmask — Go and Rust both refuse it
}

// TestDNATMatchDestinationMask7215RejectsEverySlot is the ASYMMETRY guard: an
// out-of-range/malformed MASK must be refused in every (NAT kind x match leaf)
// slot, and the rejection must NAME the offending value, the rule-set and the
// rule.
//
// It is a full 3x2 census on purpose, exactly as #7145's is. Five of the six
// cells are pre-existing gates (#7145, #3206) asserted here as CONTROLS: they
// are in the table so a regression that silently removed one of them fails
// here too, and so the table reads as a complete (kind x leaf) census rather
// than a list of the one cell this change touched.
//
// RED-on-revert: restore the natCIDRIPPart + net.ParseIP predicate in
// validateDestinationNATAddressesStrict and the destination/destination-address
// cell fails at "committed CLEAN".
func TestDNATMatchDestinationMask7215RejectsEverySlot(t *testing.T) {
	for _, bad := range nat7215MaskValues {
		for _, k := range nat7145Kinds() {
			for _, leaf := range []string{"source-address", "destination-address"} {
				t.Run(bad+"/"+k.name+"/"+leaf, func(t *testing.T) {
					tree := nat7145Tree(t, nat7145Cmds(k, leaf, bad))
					_, err := CompileConfig(tree)
					if err == nil {
						t.Fatalf("`security nat %s rule-set %s rule R1 match %s %s` committed CLEAN. "+
							"The mask is one no NAT prefix parser accepts, so the entry is dropped "+
							"before it reaches the wire and the rule translates nothing it claims "+
							"to — visible only as a bounded NAT parse-error counter (#7215)",
							k.name, k.ruleSet, leaf, bad)
					}
					msg := err.Error()
					if !strings.Contains(msg, bad) {
						t.Errorf("the rejection must NAME the offending value %q so the operator can "+
							"find it in a long rule-set; got: %v", bad, msg)
					}
					if !strings.Contains(msg, k.ruleSet) || !strings.Contains(msg, "R1") {
						t.Errorf("the rejection must name the rule-set (%q) and rule (\"R1\"); got: %v",
							k.ruleSet, msg)
					}
					if !strings.Contains(msg, leaf) {
						t.Errorf("the rejection must name the match leaf (%q); got: %v", leaf, msg)
					}
				})
			}
		}
	}
}

// TestDNATMatchDestinationMask7215LenientWarnsAndKeeps is the #1960 no-brick
// half at the compiler for the ONE slot #7215 changes.
//
// The malformed value is authored SECOND, beside a good one, so this also pins
// that the widened gate walks the whole bracket list rather than only slot 0 —
// the #7143 slot-escape property, asserted here on the value class that gate's
// fixture does not carry.
//
// KEEPING THE VALUE IS LOAD-BEARING. The Rust `destination_constrained` flag is
// keyed on the snapshot list being NON-EMPTY, not on how many entries parsed.
// Dropping the entry Go-side would, for an all-malformed list, clear that flag
// and collapse the rule to MATCH-ANY — a fail-OPEN regression strictly worse
// than #7215. So the tolerant path warns, keeps the value, and lets the
// dataplane drop it per entry.
//
// RED-on-revert: remove the lenientDestNATAddresses downgrade at the
// runUniformGatesNAT call site and this fails at "the tolerant path REJECTED".
func TestDNATMatchDestinationMask7215LenientWarnsAndKeeps(t *testing.T) {
	const good = "198.51.100.0/24"
	for _, bad := range nat7215MaskValues {
		t.Run(bad, func(t *testing.T) {
			var k nat7145Kind
			for _, cand := range nat7145Kinds() {
				if cand.name == "destination" {
					k = cand
				}
			}
			tree := nat7145Tree(t, nat7145Cmds(k, "destination-address", good, bad))

			// Precondition: the SAME corpus is refused by the strict path.
			// Without it the tolerant assertion below could pass simply
			// because the corpus never tripped the gate at all.
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("precondition: the strict path must REJECT this corpus, else the "+
					"tolerant assertion is vacuous (bad=%q)", bad)
			}

			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("the tolerant path REJECTED a config carrying a malformed DNAT mask. "+
					"A config an older binary committed must still BOOT and still FORWARD "+
					"(#1960): a compile failure on Store.Load leaves ActiveConfig() nil, which "+
					"forces the daemon into the bootstrap/lifeline state — a worse outage than "+
					"the narrowed NAT rule it complains about: %v", err)
			}
			if cfg == nil {
				t.Fatal("the tolerant path returned a nil config; a silent nil is the same brick " +
					"as an error")
			}

			var warn string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, bad) {
					warn = w
					break
				}
			}
			if warn == "" {
				t.Fatalf("the tolerant path must WARN, naming the value — a silent tolerate is "+
					"the pre-#7215 behaviour, which is exactly the defect. warnings: %v", cfg.Warnings)
			}
			if !strings.Contains(warn, k.ruleSet) || !strings.Contains(warn, "R1") {
				t.Errorf("the warning must name the rule-set (%q) and rule (\"R1\"); got: %s",
					k.ruleSet, warn)
			}

			got := cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Match.DestinationAddresses
			want := []string{good, bad}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("tolerant-path match list = %q, want %q. The GOOD value must survive, "+
					"and so must the MALFORMED one: the Rust destination_constrained flag is "+
					"keyed on this list being non-empty, so dropping it here would collapse an "+
					"all-malformed rule to MATCH-ANY — a fail-OPEN regression worse than #7215",
					got, want)
			}
		})
	}
}

// TestDNATMatchDestinationMask7215AcceptsValidPrefixes is the OVER-REJECTION
// guard, and it is the half that makes the narrowing safe to ship: a widened
// validator that refuses a value the dataplane happily installs bricks the next
// commit on a box that was forwarding correctly (#1960).
//
// The values are the same census #7145 pins, re-asserted against the CHANGED
// predicate rather than assumed to carry over:
//
//   - `0.0.0.0/0` / `::/0` — the match-any spelling that ships in
//     docs/ha-cluster-userspace.conf and test/incus/xpf-cluster-fw0.conf today.
//   - a bare host IP — Rust's IpAddr::from_str promotes it to /32 / /128.
//   - a CIDR with host bits set — IpNet::from_str permits them.
//   - `1.2.3.4/024` — a ZERO-PADDED prefix length. Rust's u8::from_str reads
//     "024" as 24 and installs the prefix, and net.ParseCIDR agrees;
//     netip.ParsePrefix does NOT. This cell is why the new predicate is built
//     on net.ParseCIDR: swap natMatchPrefixParses to the netip form and this
//     goes RED. That is the point of the cell — #7215 narrows the gate, and the
//     one direction a narrowing must never take is past what Rust accepts.
//
// Asserted on every slot, not only the changed one, so the census stays whole.
func TestDNATMatchDestinationMask7215AcceptsValidPrefixes(t *testing.T) {
	for _, good := range []string{"0.0.0.0/0", "10.0.0.0/8", "192.0.2.5", "192.0.2.5/32", "1.2.3.4/024", "2001:db8::/32", "2001:db8::1"} {
		for _, k := range nat7145Kinds() {
			for _, leaf := range []string{"source-address", "destination-address"} {
				if k.name == "static" && leaf == "destination-address" {
					// Host-route-only slot; governed by #3206 / #3031.
					continue
				}
				if k.name == "static" && strings.HasPrefix(good, "2001:db8:") {
					// A v6 source-address against a v4 `then static-nat prefix`
					// is a family mismatch the static gates reject for their
					// own reasons.
					continue
				}
				t.Run(good+"/"+k.name+"/"+leaf, func(t *testing.T) {
					tree := nat7145Tree(t, nat7145Cmds(k, leaf, good))
					if _, err := CompileConfig(tree); err != nil {
						t.Fatalf("`match %s %s` on %s NAT was REJECTED, but the dataplane parses "+
							"and installs it (#1960 no-brick): %v", leaf, good, k.name, err)
					}
				})
			}
		}
	}
}
