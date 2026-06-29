package config

import (
	"strings"
	"testing"
)

// buildTree3294 compiles a set-command list into a ConfigTree using
// ParseSetCommand + SetPath (never NewParser, which merges newlines into one
// node — see CLAUDE.md "Testing flat set syntax").
func buildTree3294(t *testing.T, cmds []string) *ConfigTree {
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

// feedBase3294 is the shared prefix: a feed-server with a declared feed and an
// address-name binding to it, plus a concrete static address and two zones.
func feedBase3294() []string {
	return []string{
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name bad-actors profile feed-name malware",
		"set security address-book global address good-host 10.0.0.0/8",
		"set security zones security-zone lan interfaces ge-0-0-1.0",
		"set security zones security-zone wan interfaces ge-0-0-2.0",
	}
}

// TestDirectFeedRefCommitsStrict pins the #3294 #2008 one-liner: a security
// policy that names a dynamic-address binding DIRECTLY as a source/destination
// address must COMMIT under strict validation. The dataplane already resolves
// the binding via the feed overlay (#2049) and enforces the live prefixes;
// before this fix the documented feed-in-policy feature was un-committable
// because the binding name was absent from #2008's bookNames set.
//
// RED-on-revert: drop the AddressBindings loop in
// validatePolicyMatchAddressesStrict and this turns RED (strict rejects the
// direct feed token as an undefined address).
func TestDirectFeedRefCommitsStrict(t *testing.T) {
	cmds := append(feedBase3294(),
		"set security policies from-zone lan to-zone wan policy p1 match source-address bad-actors",
		"set security policies from-zone lan to-zone wan policy p1 match destination-address any",
		"set security policies from-zone lan to-zone wan policy p1 match application any",
		"set security policies from-zone lan to-zone wan policy p1 then deny",
	)
	tree := buildTree3294(t, cmds)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a DIRECT feed reference must commit under strict (#3294 #2008 one-liner), got: %v", err)
	}
}

// TestDirectFeedRefEmptyBindingCommitsStrict guards open-question 7: the #2008
// one-liner adds the binding NAME to bookNames regardless of live prefix count,
// so a declared-but-not-yet-fetched (empty) feed binding referenced directly
// still COMMITS (an empty feed is match-none by #2049 design, not a typo).
func TestDirectFeedRefEmptyBindingCommitsStrict(t *testing.T) {
	cmds := append(feedBase3294(),
		"set security policies from-zone lan to-zone wan policy p1 match destination-address bad-actors",
		"set security policies from-zone lan to-zone wan policy p1 match source-address any",
		"set security policies from-zone lan to-zone wan policy p1 match application any",
		"set security policies from-zone lan to-zone wan policy p1 then permit",
	)
	tree := buildTree3294(t, cmds)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a direct empty-feed binding reference must commit (match-none by #2049), got: %v", err)
	}
}

// TestFeedInSetStillRejectsStrict is the anti-Option-C regression pin: a feed
// binding nested as a MEMBER of an address-set must STILL be rejected at strict
// commit (#3149 policyMatchAddressBookResolves). The #3294 fix deliberately does
// NOT make the shared recursive resolver feed-aware — that would strict-accept
// feed-in-set and (without the dataplane merge present at commit-decision time)
// re-open the fail-open the #3261 family closes. Feed-in-set enforcement on the
// lenient path is handled by the dataplane set-row merge (Option A′), not by
// strict-accepting a fresh commit.
//
// RED-on-revert: if policyMatchAddressBookResolves were made feed-aware (or the
// #2008 loop leaked into isDefinedName), this turns RED.
func TestFeedInSetStillRejectsStrict(t *testing.T) {
	cmds := append(feedBase3294(),
		"set security address-book global address-set s address bad-actors",
		"set security address-book global address-set s address good-host",
		"set security policies from-zone lan to-zone wan policy p1 match source-address s",
		"set security policies from-zone lan to-zone wan policy p1 match destination-address any",
		"set security policies from-zone lan to-zone wan policy p1 match application any",
		"set security policies from-zone lan to-zone wan policy p1 then deny",
	)
	tree := buildTree3294(t, cmds)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("feed-in-set must STILL be rejected at strict commit (#3149 stays feed-unaware — anti-Option-C)")
	}
	if !strings.Contains(err.Error(), "bad-actors") {
		t.Fatalf("strict reject should name the feed member bad-actors, got: %v", err)
	}
}
