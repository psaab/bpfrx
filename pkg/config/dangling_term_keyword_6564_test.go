package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// #6564 member 9 — a recognized `term` leaf keyword with NO value.
//
// parseApplicationTerms guards every value-taking arm with `if i+1 < len(keys)`
// and has no `else`. A keyword in the LAST position therefore falls through
// recording nothing at all: the `default:` arm that feeds UnknownTermLeaves is
// unreachable for a keyword the switch recognizes.
//
// The consequence is the exact fail-open the surrounding family was built to
// stop. `default:`'s own comment says it records the token "rather than
// silently dropping the constraint and widening the match", and #3348's says a
// dropped icmp-type "would leave the term UNCONSTRAINED ... a fail-open
// widening". A dangling keyword does precisely that and was the one shape none
// of #3320 / #3348 / #3352 / #6524 caught, because each of those instruments a
// MALFORMED value and this one has no value to be malformed.
//
// `term t1 protocol tcp destination-port` compiles to protocol-only, so an
// application the operator wrote to match ONE port matches EVERY TCP port —
// and a policy permitting it widens with it.
//
// POSTURE (#1960 no-brick): the repair records the keyword so the EXISTING
// validateApplicationSpecsStrict gate refuses it on the operator commit path,
// and the EXISTING lenientApplicationSpecs (#2142) downgrade keeps the tolerant
// Store.Load / Store.SyncApply path warning-only. Both directions are asserted.

func appTree6564(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestDanglingTermKeywordRejected6564 is the fail-on-revert case: every
// value-taking leaf, left dangling, must be refused at strict commit.
//
// FAIL-ON-REVERT: drop the incomplete-keyword record from parseApplicationTerms
// (restore the bare `if i+1 < len(keys)` with no else).
func TestDanglingTermKeywordRejected6564(t *testing.T) {
	for _, kw := range []string{
		"protocol",
		"destination-port",
		"source-port",
		"icmp-type",
		"icmp-code",
		"inactivity-timeout",
		"timeout",
		"alg",
	} {
		t.Run(kw, func(t *testing.T) {
			tree := appTree6564(t,
				"set applications application appA term t1 protocol tcp "+kw)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("#6564: `term t1 protocol tcp %s` (keyword with NO value) must be "+
					"REJECTED at strict commit — it records nothing, so the constraint is "+
					"dropped and the term WIDENS (protocol-only matches every TCP port), which "+
					"is the same fail-open #3348/#3352 exist to stop", kw)
			}
			if !strings.Contains(err.Error(), kw) {
				t.Fatalf("the rejection must name the dangling keyword %q; got %v", kw, err)
			}
			if !strings.Contains(err.Error(), "appA") {
				t.Fatalf("the rejection must name the application; got %v", err)
			}
		})
	}
}

// TestCompleteTermStillCompiles6564 is the over-rejection guard.
//
// The repair must fire ONLY on a keyword with no value. A well-formed term —
// and a term whose LAST leaf is a valid keyword/value pair, which is the
// boundary case the `i+1 < len(keys)` guard is actually about — must still
// compile and keep its constraints.
//
// FAIL-ON-REVERT: make the incomplete-keyword record unconditional (drop the
// `i+1 >= len(keys)` condition) and this reds immediately.
func TestCompleteTermStillCompiles6564(t *testing.T) {
	tree := appTree6564(t,
		"set applications application appA term t1 protocol tcp destination-port 80",
		"set applications application appB term t1 protocol udp source-port 53 destination-port 53",
		"set applications application appC term t1 protocol icmp icmp-type 8 icmp-code 0",
		"set applications application appD term t1 protocol tcp destination-port 22 inactivity-timeout 1800",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a well-formed term must still compile; got %v", err)
	}

	// The trailing constraint must actually be RETAINED, not merely accepted —
	// a repair that recorded nothing and also parsed nothing would pass a
	// compile-only assertion.
	// A term-bearing application is stored as synthesized per-term entries, so
	// look the constraint up by scanning rather than by guessing the key.
	findDPort := func(want string) bool {
		for _, a := range cfg.Applications.Applications {
			if a.DestinationPort == want {
				return true
			}
		}
		return false
	}
	if !findDPort("80") {
		t.Fatalf("a well-formed term must RETAIN destination-port 80 — it is the LAST leaf, "+
			"i.e. exactly the boundary the `i+1 < len(keys)` guard is about, so a repair that "+
			"mis-ordered the check would drop it; got %+v", cfg.Applications.Applications)
	}
	foundICMPCode := false
	for _, a := range cfg.Applications.Applications {
		if a.ICMPCode != nil && *a.ICMPCode == 0 && a.ICMPType != nil && *a.ICMPType == 8 {
			foundICMPCode = true
		}
	}
	if !foundICMPCode {
		t.Fatalf("a well-formed term must RETAIN icmp-type 8 / icmp-code 0 as its trailing "+
			"leaf; got %+v", cfg.Applications.Applications)
	}
}

// TestDanglingTermKeywordIsWarnOnlyOnTolerantPath6564 is the #1960 no-brick
// direction.
//
// A config an older binary accepted is already persisted and already arriving
// over HA config-sync. Refusing it on the tolerant path would blackout-boot the
// node or alarm-loop config sync during an upgrade. The existing
// lenientApplicationSpecs (#2142) downgrade must still apply to this new
// record, so the strict gate refuses while the tolerant path warns and
// continues.
//
// FAIL-ON-REVERT: reject the dangling keyword from a path the lenient opts
// cannot downgrade (e.g. a hard error inside parseApplicationTerms itself).
func TestDanglingTermKeywordIsWarnOnlyOnTolerantPath6564(t *testing.T) {
	tree := appTree6564(t, "set applications application appA term t1 protocol tcp destination-port")

	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("setup: the strict path must reject the dangling keyword")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("#1960 no-brick: the tolerant load / peer-sync path must still COMPILE a "+
			"dangling term keyword (warn, not refuse) — a hard failure here blackout-boots a "+
			"node whose persisted config an older binary accepted; got %v", err)
	}
	if cfg == nil {
		t.Fatal("#1960 no-brick: the tolerant path returned no config")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "destination-port") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("the tolerant path must WARN about the dropped constraint rather than "+
			"accepting it in silence — silence is the defect; got warnings %v", cfg.Warnings)
	}
}

// TestValueTakingTermLeavesCoversEveryConsumingArm6564 binds the
// valueTakingTermLeaves set to the switch it describes.
//
// The set is the arity contract for parseApplicationTerms: the dangling-keyword
// guard fires only for keywords listed in it, so a future value-taking leaf
// added to the switch WITHOUT being added to the set silently re-opens the
// fail-open — and every behavioural test above would still pass, because they
// can only exercise keywords someone remembered to list.
//
// The two are therefore bound textually, on the source of the function itself:
// every `case "<kw>":` arm whose body consumes `keys[i+1]` must be a member.
// This is the same discipline as the #6588 no-arg statement registry, which
// pins its map against the dispatch table it mirrors.
//
// FAIL-ON-REVERT: add a `case "foo":` arm to parseApplicationTerms that reads
// `keys[i+1]` without adding "foo" to valueTakingTermLeaves.
func TestValueTakingTermLeavesCoversEveryConsumingArm6564(t *testing.T) {
	src, err := os.ReadFile("compiler_applications.go")
	if err != nil {
		t.Fatalf("read compiler_applications.go: %v", err)
	}
	body := string(src)

	start := strings.Index(body, "func parseApplicationTerms")
	if start < 0 {
		t.Fatal("parseApplicationTerms not found — this gate is bound to that function " +
			"by name and must be re-pointed if it is renamed")
	}
	// End at the next top-level func so the scan cannot wander into unrelated
	// switches.
	rest := body[start+1:]
	end := strings.Index(rest, "\nfunc ")
	if end < 0 {
		t.Fatal("could not find the end of parseApplicationTerms")
	}
	fn := rest[:end]

	caseRe := regexp.MustCompile(`(?m)^\s*case ("(?:[^"]+)"(?:, "(?:[^"]+)")*):`)
	kwRe := regexp.MustCompile(`"([^"]+)"`)

	locs := caseRe.FindAllStringSubmatchIndex(fn, -1)
	if len(locs) == 0 {
		t.Fatal("no case arms found in parseApplicationTerms — the scan pattern has rotted, " +
			"which would make this gate vacuous")
	}

	checked := 0
	for i, loc := range locs {
		labels := fn[loc[2]:loc[3]]
		armStart := loc[1]
		armEnd := len(fn)
		if i+1 < len(locs) {
			armEnd = locs[i+1][0]
		}
		arm := fn[armStart:armEnd]
		// Only arms that actually consume the NEXT token are value-taking.
		if !strings.Contains(arm, "i+1 < len(keys)") {
			continue
		}
		for _, m := range kwRe.FindAllStringSubmatch(labels, -1) {
			kw := m[1]
			checked++
			if !valueTakingTermLeaves[kw] {
				t.Errorf("#6564: parseApplicationTerms has a value-consuming arm for %q "+
					"(its body reads keys[i+1]) but %q is NOT in valueTakingTermLeaves — a "+
					"dangling `%s` would fall through recording nothing, dropping the "+
					"constraint and widening the term, exactly the fail-open member 9 closed",
					kw, kw, kw)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the scan matched no value-consuming arms — the pattern has rotted and this " +
			"gate is vacuous")
	}
	// Every member of the set must correspond to a real arm, so the set cannot
	// accumulate entries for leaves that no longer exist.
	if checked != len(valueTakingTermLeaves) {
		t.Errorf("valueTakingTermLeaves has %d entries but %d value-consuming arms were found; "+
			"the set and the switch have drifted", len(valueTakingTermLeaves), checked)
	}
}
