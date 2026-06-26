package config

import (
	"strings"
	"testing"
)

// Tests for #3149 (and the folded #3147): a security-policy source/destination
// address that names a DEFINED address-book entry whose members DANGLE (point at
// an undefined address/address-set), or that is a defined-but-EMPTY address-set,
// was only WARNED at commit (compiler_validate_warn.go). At runtime the userspace
// address resolver (resolveUserspaceAddressBookEntry) returns false for the same
// name — a dangling member fails the whole set, an empty set never sets
// resolvedAny — so userspaceSupportsSecurityPolicies returns false and the
// dataplane REFUSES to arm security policies. The operator got a green commit and
// a silently DISARMED allow/deny path: a commit/apply split, fail-open, and the
// address-book sibling of #3144/#3146 (the application gate). The fix
// hard-rejects at commit (strict CompileConfig) and warns on the tolerant load /
// peer-sync path (CompileConfigLenient).
//
// fail-on-revert: making validatePolicyMatchAddressSetMembersStrict `return nil`
// (or dropping its dispatch in compiler.go) turns every reject case GREEN and so
// RED here. Reusing buildAppMatchTree / zoneBoilerplate from the #3144 test
// (same package) for the flat-set tree builder + zone boilerplate.

// goodAddr defines one resolvable address-book address so a set can mix a good
// and a dangling member.
var goodAddr = []string{
	"set security address-book global address GOOD 10.0.0.0/24",
}

func TestPolicyMatchDanglingAddressSetMemberRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "zone-pair source dangling member",
			cmds: []string{
				"set security address-book global address-set BAD address MISSING",
				"set security policies from-zone trust to-zone untrust policy p match source-address BAD",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `policy "p" match source-address "BAD" does not fully resolve`,
		},
		{
			name: "zone-pair destination dangling member",
			cmds: []string{
				"set security address-book global address-set BAD address MISSING",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address BAD",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `policy "p" match destination-address "BAD" does not fully resolve`,
		},
		{
			name: "global source dangling member",
			cmds: []string{
				"set security address-book global address-set BAD address MISSING",
				"set security policies global policy g match source-address BAD",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any",
				"set security policies global policy g then permit",
			},
			want: `global policy "g" match source-address "BAD" does not fully resolve`,
		},
		{
			name: "dangling member alongside a good one still fails the whole set",
			cmds: append(append([]string{}, goodAddr...),
				"set security address-book global address-set BAD address GOOD",
				"set security address-book global address-set BAD address MISSING",
				"set security policies from-zone trust to-zone untrust policy p match source-address BAD",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
			want: `member "MISSING" is not a defined address or address-set`,
		},
		{
			name: "nested set with dangling leaf member",
			cmds: append(append([]string{}, goodAddr...),
				"set security address-book global address-set INNER address MISSING",
				"set security address-book global address-set OUTER address-set INNER",
				"set security policies from-zone trust to-zone untrust policy p match source-address OUTER",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
			want: `match source-address "OUTER" does not fully resolve`,
		},
		{
			name: "nested set referencing an undefined nested set",
			cmds: append(append([]string{}, goodAddr...),
				"set security address-book global address-set OUTER address GOOD",
				"set security address-book global address-set OUTER address-set NOSET",
				"set security policies from-zone trust to-zone untrust policy p match source-address OUTER",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
			want: `member "NOSET" is not a defined address or address-set`,
		},
		{
			name: "policy referencing an address with no configured prefix",
			cmds: []string{
				"set security address-book global address NOPREFIX description x",
				"set security policies from-zone trust to-zone untrust policy p match source-address NOPREFIX",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `match source-address "NOPREFIX" does not fully resolve`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...), tc.cmds...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig: expected reject for dangling address-set member, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestPolicyMatchEmptyAddressSetRejectedAtCommit proves the folded #3147: a
// policy referencing a DEFINED but EMPTY address-set is hard-rejected at commit.
// The set resolves by name but expands to zero addresses, so the runtime
// resolveUserspaceAddressBookEntry never sets resolvedAny → returns false → the
// dataplane refuses to arm — the same fail-open class as #3149.
func TestPolicyMatchEmptyAddressSetRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "zone-pair empty address-set",
			cmds: []string{
				"set security address-book global address-set EMPTY description x",
				"set security policies from-zone trust to-zone untrust policy p match source-address EMPTY",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `address-set "EMPTY" is empty`,
		},
		{
			name: "global empty address-set",
			cmds: []string{
				"set security address-book global address-set EMPTY description x",
				"set security policies global policy g match source-address EMPTY",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any",
				"set security policies global policy g then permit",
			},
			want: `global policy "g" match source-address "EMPTY" does not fully resolve`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...), tc.cmds...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig: expected reject for empty address-set, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestPolicyMatchEmptyExcludedAddressSetFailClosed is the #3147 excluded-
// inversion safety constraint: an EMPTY address-set referenced under
// `source-address-excluded` must NOT be allowed to commit — at the dataplane an
// empty excluded set inverts to MATCH-ALL (permit-all), the historic fail-open.
// Rejecting the empty set at commit (regardless of the excluded flag) is
// fail-CLOSED: the config can never reach the dataplane to invert. This test
// pins that an empty excluded set is rejected, not silently accepted.
func TestPolicyMatchEmptyExcludedAddressSetFailClosed(t *testing.T) {
	tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...),
		"set security address-book global address-set EMPTY description x",
		"set security policies from-zone trust to-zone untrust policy p match source-address EMPTY",
		"set security policies from-zone trust to-zone untrust policy p match source-address-excluded",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig: an empty EXCLUDED address-set must be rejected " +
			"(it would invert to match-all = fail-open), got nil")
	}
	if !strings.Contains(err.Error(), `match source-address "EMPTY" does not fully resolve`) {
		t.Fatalf("CompileConfig error = %q, want the empty-set reject", err.Error())
	}
}

// TestPolicyMatchResolvableAddressSetCommits proves a fully-resolvable address
// reference (set, nested set, defined address, `any`, literal CIDR) commits
// cleanly under the strict path.
func TestPolicyMatchResolvableAddressSetCommits(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "fully resolvable address-set",
			cmds: append(append([]string{}, goodAddr...),
				"set security address-book global address-set OK address GOOD",
				"set security policies from-zone trust to-zone untrust policy p match source-address OK",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
		},
		{
			name: "nested resolvable address-set",
			cmds: append(append([]string{}, goodAddr...),
				"set security address-book global address-set INNER address GOOD",
				"set security address-book global address-set OUTER address-set INNER",
				"set security policies from-zone trust to-zone untrust policy p match source-address OUTER",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
		},
		{
			name: "defined address by name",
			cmds: append(append([]string{}, goodAddr...),
				"set security policies from-zone trust to-zone untrust policy p match source-address GOOD",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
		},
		{
			name: "any and literal CIDR",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address 192.0.2.0/24",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
		},
		{
			name: "resolvable excluded set commits",
			cmds: append(append([]string{}, goodAddr...),
				"set security address-book global address-set OK address GOOD",
				"set security policies from-zone trust to-zone untrust policy p match source-address OK",
				"set security policies from-zone trust to-zone untrust policy p match source-address-excluded",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...), tc.cmds...)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig: expected clean commit for resolvable address, got %v", err)
			}
		})
	}
}

// TestPolicyMatchDanglingAddressSetLenientWarns proves the tolerant load /
// peer-sync path downgrades the reject to a warning so an already-persisted or
// peer-synced config still boots (#1960).
func TestPolicyMatchDanglingAddressSetLenientWarns(t *testing.T) {
	tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...),
		"set security address-book global address-set BAD address MISSING",
		"set security policies from-zone trust to-zone untrust policy p match source-address BAD",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: expected no error (warn-and-boot), got %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy match address-set members") && strings.Contains(w, "BAD") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want one mentioning the dangling address-set", cfg.Warnings)
	}
}
