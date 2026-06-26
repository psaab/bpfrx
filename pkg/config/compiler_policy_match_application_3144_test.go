package config

import (
	"strings"
	"testing"
)

// Tests for #3144: a security-policy `match application <name>` token that
// resolves to NONE of {predefined junos-* app, user-defined application,
// user-defined application-set} was only WARNED at commit
// (compiler_validate_warn.go). At runtime the userspace capability gate
// (resolveUserspaceApplicationNames) resolves the SAME name set and returns
// false for the unknown name → the dataplane REFUSES to arm security policies.
// The operator got a green commit and a silently DISARMED policy engine — a
// commit/apply split, fail-open. The fix hard-rejects the undefined reference
// at commit (strict CompileConfig) and warns on the tolerant load / peer-sync
// path (CompileConfigLenient).
//
// fail-on-revert: making validatePolicyMatchApplicationsStrict `return nil`
// (or dropping its dispatch in compiler.go) turns every reject case GREEN and
// so RED here.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath (handles the
// bracketed-list collapse for the list form), never NewParser.

func buildAppMatchTree(t *testing.T, cmds ...string) *ConfigTree {
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

// zoneBoilerplate defines the trust/untrust zones so the policy-under-test
// passes the #2401 zone-reference gate (which runs BEFORE this gate) and the
// undefined-application error is the one surfaced.
var zoneBoilerplate = []string{
	"set security zones security-zone trust",
	"set security zones security-zone untrust",
}

func TestPolicyMatchApplicationUndefinedRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string // substring expected in the commit error
	}{
		{
			name: "zone-pair undefined application",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application NO_SUCH_APP",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `policy "p" match application "NO_SUCH_APP" is not defined`,
		},
		{
			name: "global undefined application",
			cmds: []string{
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application BOGUS_APP",
				"set security policies global policy g then permit",
			},
			want: `global policy "g" match application "BOGUS_APP" is not defined`,
		},
		{
			name: "zone-pair list form one undefined member",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application [ junos-http NOPE ]",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `application "NOPE" is not defined`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...), tc.cmds...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig: expected reject for undefined application, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestPolicyMatchEmptyApplicationSetRejectedAtCommit proves #3146: a policy
// referencing a DEFINED but EMPTY application-set (it expands to zero members)
// is hard-rejected at commit. The set resolves by name, but the runtime
// resolveUserspaceApplicationNames calls ExpandApplicationSet, gets len==0, and
// returns false → the dataplane refuses to arm security policies — the same
// fail-open class as #3144. #2217's gate `continue`s on an empty set, so this
// gate is the one that catches it.
//
// fail-on-revert: dropping the `len(expanded) == 0` empty-set arm in appRefError
// (so a name-resolved set is accepted unconditionally) turns this GREEN and so
// RED here.
func TestPolicyMatchEmptyApplicationSetRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "zone-pair empty application-set",
			cmds: []string{
				"set applications application-set EMPTYSET description foo",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application EMPTYSET",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `match application "EMPTYSET" is a defined but EMPTY application-set`,
		},
		{
			name: "global empty application-set",
			cmds: []string{
				"set applications application-set EMPTYSET description foo",
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application EMPTYSET",
				"set security policies global policy g then permit",
			},
			want: `global policy "g" match application "EMPTYSET" is a defined but EMPTY application-set`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...), tc.cmds...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig: expected reject for empty application-set, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestPolicyMatchApplicationDefinedCommits proves a defined application
// (predefined junos-*, user-defined, application-set) and the `any` keyword all
// commit cleanly under the strict path.
func TestPolicyMatchApplicationDefinedCommits(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "predefined junos-http",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application junos-http",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
		},
		{
			name: "any keyword",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
		},
		{
			name: "user-defined application",
			cmds: []string{
				"set applications application MYAPP protocol tcp destination-port 8080",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application MYAPP",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
		},
		{
			name: "application-set",
			cmds: []string{
				"set applications application MYAPP protocol tcp destination-port 8080",
				"set applications application-set MYSET application MYAPP",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application MYSET",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
		},
		{
			name: "list of two defined apps",
			cmds: []string{
				"set applications application MYAPP protocol tcp destination-port 8080",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application [ junos-http MYAPP ]",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...), tc.cmds...)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig: expected clean commit for defined application, got %v", err)
			}
		})
	}
}

// TestPolicyMatchApplicationUndefinedLenientWarns proves the tolerant load /
// peer-sync path downgrades the undefined-application reject to a warning so an
// already-persisted or peer-synced config still boots (#1960).
func TestPolicyMatchApplicationUndefinedLenientWarns(t *testing.T) {
	tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...),
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application NO_SUCH_APP",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: expected no error (warn-and-boot), got %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy match application") && strings.Contains(w, "NO_SUCH_APP") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want one mentioning the undefined application", cfg.Warnings)
	}
}
