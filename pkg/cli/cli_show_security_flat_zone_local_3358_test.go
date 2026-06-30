package cli

import (
	"regexp"
	"strings"
	"testing"
)

// #3358 (flat-view guard): the CLI standard `show security policies` view
// (handleShowSecurity case "policies", non-brief/non-detail) joins a policy's
// match address tokens with joinDisplayAddressNames. A zone-local address book
// (#3061) is folded into the global book under zone-local/<zone>/<name>, so a
// raw strings.Join would leak that synthetic token. This is the fail-on-revert
// guard for that surface: replace joinDisplayAddressNames with a raw
// strings.Join and the assertions below go RED. (The detail view + the
// match-policies SSOT have their own guards; this pins the only one of the
// original five display sites that lacked a dedicated test.)

func zoneLocalFlatCLI(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, t.TempDir()+"/xpf.conf")
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security address-book global address external 198.51.100.0/24",
		"security zones security-zone trust address-book address web 10.0.1.100/32",
		"security zones security-zone untrust address-book address svc 192.0.2.5/32",
		"security policies from-zone trust to-zone untrust policy zl match source-address web",
		"security policies from-zone trust to-zone untrust policy zl match destination-address svc",
		"security policies from-zone trust to-zone untrust policy zl match application any",
		"security policies from-zone trust to-zone untrust policy zl then permit",
		"security policies from-zone trust to-zone untrust policy normal match source-address external",
		"security policies from-zone trust to-zone untrust policy normal match destination-address any",
		"security policies from-zone trust to-zone untrust policy normal match application any",
		"security policies from-zone trust to-zone untrust policy normal then permit",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &CLI{store: store}
}

// flatPolicyBlock returns the lines from a policy's "Policy: <name>" header up
// to (not including) the next "  Policy: " header in the standard flat view.
func flatPolicyBlock(t *testing.T, out, name string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	hdr := regexp.MustCompile(`Policy: ` + regexp.QuoteMeta(name) + `,`)
	start := -1
	for i, line := range lines {
		if hdr.MatchString(line) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("policy %q block not found in flat output:\n%s", name, out)
	}
	end := len(lines)
	next := regexp.MustCompile(`^\s*Policy: `)
	for i := start + 1; i < len(lines); i++ {
		if next.MatchString(lines[i]) {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

func Test_3358_FlatShowPoliciesUnqualifiesZoneLocalName(t *testing.T) {
	c := zoneLocalFlatCLI(t)

	out := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies"}); err != nil {
			t.Fatalf("handleShowSecurity(policies): %v", err)
		}
	})

	if strings.Contains(out, "zone-local/") {
		t.Fatalf("flat show security policies leaked the synthetic zone-local token:\n%s", out)
	}

	zl := flatPolicyBlock(t, out, "zl")
	if !strings.Contains(zl, "Source addresses: web") {
		t.Fatalf("zl flat block = %q, want \"Source addresses: web\" "+
			"(zone-local source name not unqualified — #3358 regression)", zl)
	}
	if !strings.Contains(zl, "Destination addresses: svc") {
		t.Fatalf("zl flat block = %q, want \"Destination addresses: svc\" "+
			"(zone-local destination name not unqualified — #3358 regression)", zl)
	}

	// Control: a global-book name passes through unchanged.
	normal := flatPolicyBlock(t, out, "normal")
	if !strings.Contains(normal, "Source addresses: external") {
		t.Fatalf("normal flat block = %q, want \"Source addresses: external\" (global name regressed)", normal)
	}
}
