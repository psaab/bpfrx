package config

import (
	"strings"
	"testing"
)

// Tests for #3434 (Codex audit 095 H07/H08): a source- or destination-NAT
// rule's `match application <name>` token that resolves to NONE of {predefined
// junos-* app, user-defined application, non-empty user-defined
// application-set} was previously unvalidated. The DNAT snapshot builder then
// fell through to a wildcard match-all term (protocol="" + destination-port 0)
// and published the pool VIP for EVERY flow to the destination — a fail-open
// wildcard translation (the NAT analog of #3144/#3146). The fix hard-rejects
// the undefined reference at commit (strict CompileConfig) and warns on the
// tolerant load / peer-sync path (CompileConfigLenient).
//
// fail-on-revert: making validateNATMatchApplicationsStrict `return nil` (or
// dropping its dispatch in compiler.go) turns every reject case GREEN and so
// RED here.
//
// All trees are built from flat `set` commands via flatTreeFromSets (the only
// correct way to exercise the flat-set AST shape).

// H07: an undefined `match application` token is hard-rejected at commit, for
// both source and destination NAT.
func TestNATMatchApplicationUndefinedRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "source-nat undefined application",
			cmds: []string{
				"set security nat source rule-set rs1 from zone trust",
				"set security nat source rule-set rs1 to zone untrust",
				"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set rs1 rule r1 match application NO_SUCH_APP",
				"set security nat source rule-set rs1 rule r1 then source-nat interface",
			},
			want: `source NAT rule-set "rs1" rule "r1" match application "NO_SUCH_APP"`,
		},
		{
			name: "destination-nat undefined application",
			cmds: []string{
				"set security nat destination pool web1 address 10.0.30.100",
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
				"set security nat destination rule-set rs1 rule r1 match application NO_SUCH_APP",
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
			},
			want: `destination NAT rule-set "rs1" rule "r1" match application "NO_SUCH_APP"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig: expected reject for undefined NAT match application, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// H08: a defined-but-EMPTY application-set is hard-rejected at commit (it
// resolves by name but expands to zero members), for both source and
// destination NAT.
func TestNATMatchEmptyApplicationSetRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "source-nat empty application-set",
			cmds: []string{
				"set applications application-set EMPTYSET description foo",
				"set security nat source rule-set rs1 from zone trust",
				"set security nat source rule-set rs1 to zone untrust",
				"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set rs1 rule r1 match application EMPTYSET",
				"set security nat source rule-set rs1 rule r1 then source-nat interface",
			},
			want: `match application "EMPTYSET" is a defined but EMPTY application-set`,
		},
		{
			name: "destination-nat empty application-set",
			cmds: []string{
				"set applications application-set EMPTYSET description foo",
				"set security nat destination pool web1 address 10.0.30.100",
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
				"set security nat destination rule-set rs1 rule r1 match application EMPTYSET",
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
			},
			want: `destination NAT rule-set "rs1" rule "r1" match application "EMPTYSET" is a defined but EMPTY application-set`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig: expected reject for empty NAT match application-set, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// A defined application, a non-empty application-set, and the `any` keyword all
// commit cleanly under the strict path (non-tautological companion proving the
// rejects above are caused by the undefined/empty reference, not the
// surrounding NAT rule).
func TestNATMatchApplicationDefinedCommits(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "destination user-defined application",
			cmds: []string{
				"set applications application MYAPP protocol tcp destination-port 8080",
				"set security nat destination pool web1 address 10.0.30.100",
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
				"set security nat destination rule-set rs1 rule r1 match application MYAPP",
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
			},
		},
		{
			name: "destination predefined junos-http",
			cmds: []string{
				"set security nat destination pool web1 address 10.0.30.100",
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
				"set security nat destination rule-set rs1 rule r1 match application junos-http",
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
			},
		},
		{
			name: "destination non-empty application-set",
			cmds: []string{
				"set applications application MYAPP protocol tcp destination-port 8080",
				"set applications application-set MYSET application MYAPP",
				"set security nat destination pool web1 address 10.0.30.100",
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
				"set security nat destination rule-set rs1 rule r1 match application MYSET",
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
			},
		},
		{
			name: "source application any",
			cmds: []string{
				"set security nat source rule-set rs1 from zone trust",
				"set security nat source rule-set rs1 to zone untrust",
				"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set rs1 rule r1 match application any",
				"set security nat source rule-set rs1 rule r1 then source-nat interface",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.cmds...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig: expected clean commit for defined NAT match application, got %v", err)
			}
		})
	}
}

// The tolerant load / peer-sync path downgrades the undefined-application
// reject to a warning so an already-persisted or peer-synced config still
// boots (#1960).
func TestNATMatchApplicationUndefinedLenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security nat destination pool web1 address 10.0.30.100",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
		"set security nat destination rule-set rs1 rule r1 match application NO_SUCH_APP",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: expected no error (warn-and-boot), got %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "NAT match application") && strings.Contains(w, "NO_SUCH_APP") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want one mentioning the undefined NAT application", cfg.Warnings)
	}
}
