package config

import (
	"reflect"
	"strings"
	"testing"
)

// Tests for #4102: the standard Junos predefined application-SETS
// (junos-ms-rpc, junos-sun-rpc, junos-cifs, junos-routing-inbound) were absent.
// Only the protocol-split members (junos-ms-rpc-tcp/-udp, junos-sun-rpc-tcp/-udp)
// shipped as individual apps, and ResolveApplicationSet consulted ONLY
// user-defined sets — so a canonical vSRX policy `match application junos-ms-rpc`
// hard-failed at commit (validatePolicyMatchApplicationsStrict → appRefError:
// not an app, not a set) and, on the tolerant path, at runtime
// (resolveUserspaceApplicationNames → __unsupported__ → SnapshotIntegrityError).
//
// The fix adds PredefinedApplicationSets and has ResolveApplicationSet /
// ExpandApplicationSet fall back to it (user-then-predefined order).
//
// fail-on-revert: deleting the PredefinedApplicationSets entries (or dropping
// the predefined fallback in lookupApplicationSet) turns
// TestPredefinedApplicationSetsResolve RED (ExpandApplicationSet errors /
// ResolveApplicationSet misses) and TestPredefinedApplicationSetPolicyCommits
// RED (CompileConfig hard-rejects the reference).

// TestPredefinedApplicationSetsResolve pins the canonical Junos membership of
// each predefined application-set and proves it resolves with NO user config —
// the predefined table alone must satisfy both ResolveApplicationSet and the
// ExpandApplicationSet member walk. Member lists and order are verified against
// a real `show configuration groups junos-defaults` dump (SRX 15.1X49).
func TestPredefinedApplicationSetsResolve(t *testing.T) {
	cases := []struct {
		set  string
		want []string
	}{
		{"junos-ms-rpc", []string{"junos-ms-rpc-tcp", "junos-ms-rpc-udp"}},
		{"junos-sun-rpc", []string{"junos-sun-rpc-tcp", "junos-sun-rpc-udp"}},
		{"junos-cifs", []string{"junos-netbios-session", "junos-smb-session"}},
		{"junos-routing-inbound", []string{"junos-bgp", "junos-rip", "junos-ldp-tcp", "junos-ldp-udp"}},
	}
	// Empty ApplicationsConfig: no user apps, no user sets — resolution must
	// come entirely from the predefined tables.
	empty := &ApplicationsConfig{}
	for _, tc := range cases {
		t.Run(tc.set, func(t *testing.T) {
			if _, ok := ResolveApplicationSet(tc.set, nil); !ok {
				t.Fatalf("ResolveApplicationSet(%q, nil) = false, want true (predefined set)", tc.set)
			}
			got, err := ExpandApplicationSet(tc.set, empty)
			if err != nil {
				t.Fatalf("ExpandApplicationSet(%q): %v", tc.set, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ExpandApplicationSet(%q) = %v, want %v (config order)", tc.set, got, tc.want)
			}
			// Every expanded member must itself resolve as a predefined app —
			// otherwise the set would trip the empty/dangling-member gates.
			for _, m := range got {
				if _, ok := ResolveApplication(m, nil); !ok {
					t.Fatalf("predefined set %q member %q does not resolve as an application", tc.set, m)
				}
			}
		})
	}
}

// TestPredefinedApplicationSetPolicyCommits proves a stock vSRX policy that
// references each predefined application-set commits cleanly under the STRICT
// path (the exact surface that hard-failed before #4102). This is the primary
// fail-on-revert signal: removing the predefined set table makes appRefError
// reject the reference and CompileConfig returns an error, failing this test.
func TestPredefinedApplicationSetPolicyCommits(t *testing.T) {
	for _, set := range []string{"junos-ms-rpc", "junos-sun-rpc", "junos-cifs", "junos-routing-inbound"} {
		t.Run(set, func(t *testing.T) {
			cmds := append(append([]string{}, zoneBoilerplate...),
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application "+set,
				"set security policies from-zone trust to-zone untrust policy p then permit",
			)
			tree := buildAppMatchTree(t, cmds...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig: predefined application-set %q should commit clean, got %v", set, err)
			}
		})
	}
}

// TestUserDefinedApplicationSetShadowsPredefined proves the user-then-predefined
// precedence: a user-defined application-set whose name collides with a
// predefined bundle wins, and a plain user-defined set still resolves (the
// pre-#4102 behavior is preserved, not clobbered by the new fallback).
func TestUserDefinedApplicationSetShadowsPredefined(t *testing.T) {
	apps := &ApplicationsConfig{
		Applications: map[string]*Application{
			"MYAPP": {Name: "MYAPP", Protocol: "tcp", DestinationPort: "8080"},
		},
		ApplicationSets: map[string]*ApplicationSet{
			// Shadow the predefined junos-ms-rpc with a single custom member.
			"junos-ms-rpc": {Name: "junos-ms-rpc", Applications: []string{"MYAPP"}},
			// A plain user set (no predefined collision).
			"MYSET": {Name: "MYSET", Applications: []string{"MYAPP", "junos-http"}},
		},
	}

	// User definition wins over the predefined bundle (user-first order).
	got, err := ExpandApplicationSet("junos-ms-rpc", apps)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(shadowed junos-ms-rpc): %v", err)
	}
	if !reflect.DeepEqual(got, []string{"MYAPP"}) {
		t.Fatalf("shadowed junos-ms-rpc expanded to %v, want [MYAPP] (user def must win)", got)
	}

	// A plain user set still resolves.
	got, err = ExpandApplicationSet("MYSET", apps)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(MYSET): %v", err)
	}
	if !reflect.DeepEqual(got, []string{"MYAPP", "junos-http"}) {
		t.Fatalf("MYSET expanded to %v, want [MYAPP junos-http]", got)
	}

	// A predefined set NOT shadowed still resolves from the predefined table.
	got, err = ExpandApplicationSet("junos-sun-rpc", apps)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(junos-sun-rpc): %v", err)
	}
	if !reflect.DeepEqual(got, []string{"junos-sun-rpc-tcp", "junos-sun-rpc-udp"}) {
		t.Fatalf("junos-sun-rpc expanded to %v, want the predefined members", got)
	}
}

// TestUnknownApplicationSetStillRejected proves the predefined fallback did NOT
// weaken the definedness gate: an unknown application-set / application name
// still hard-fails at commit (no false-accept).
func TestUnknownApplicationSetStillRejected(t *testing.T) {
	cmds := append(append([]string{}, zoneBoilerplate...),
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application junos-no-such-set",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	tree := buildAppMatchTree(t, cmds...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig: expected reject for unknown application-set, got nil")
	}
	if !strings.Contains(err.Error(), `application "junos-no-such-set" is not defined`) {
		t.Fatalf("CompileConfig error = %q, want undefined-application reject", err.Error())
	}
}
