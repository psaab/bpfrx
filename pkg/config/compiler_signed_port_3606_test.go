package config

import (
	"strings"
	"testing"
)

// #3606: a signed / non-canonical port string ("+80") must be rejected at
// commit, matching the userspace dataplane's port parsers. The historical
// commit gates used strconv.Atoi, which accepts a leading '+' ("+80" -> 80), so
// "+80" committed cleanly while the Go capability gate
// (userspacePortSpecRepresentable via strconv.ParseUint) rejected it (silently
// downgrading the application to unsupported at apply) and the simulator said it
// matched — a commit-vs-dataplane split on a security leaf.
//
// RED-on-revert: restore strconv.Atoi in place of parseCanonicalPort at any of
// the four port-parse sites and the corresponding case below flips to accepted.
// Note "-80" was already rejected before #3606 (Atoi("-80") = -80 fails the
// low-bound check), so the leading-'+' cases are the ones that demonstrate the
// regression.

func TestSignedPortRejectedAtCommit_3606(t *testing.T) {
	// The application-spec strict gate (validateApplicationSpecsStrict) only
	// engages for a REFERENCED application, so each application case is wired
	// into a policy match.
	refApp := func(portLeaf, spec string) []string {
		return []string{
			"set applications application a1 protocol tcp",
			"set applications application a1 " + portLeaf + " " + spec,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p match source-address any",
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application a1",
			"set security policies from-zone trust to-zone untrust policy p then permit",
		}
	}
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "application-destination-port-plus",
			cmds: refApp("destination-port", "+80"),
		},
		{
			name: "application-source-port-plus",
			cmds: refApp("source-port", "+80"),
		},
		{
			name: "application-destination-port-minus",
			cmds: refApp("destination-port", "-80"),
		},
		{
			name: "application-destination-port-range-signed-low",
			cmds: refApp("destination-port", "+80-90"),
		},
		{
			name: "application-destination-port-range-signed-high",
			cmds: refApp("destination-port", "80-+90"),
		},
		{
			name: "firewall-filter-destination-port-plus",
			cmds: []string{"set firewall family inet filter f1 term t1 from destination-port +80"},
		},
		{
			name: "firewall-filter-source-port-plus",
			cmds: []string{"set firewall family inet filter f1 term t1 from source-port +80"},
		},
		{
			name: "nat-match-destination-port-plus",
			cmds: []string{"set security nat destination rule-set RS rule R1 match destination-port +80"},
		},
		{
			name: "dnat-pool-port-plus",
			cmds: []string{
				"set security nat destination pool p1 address 192.168.1.10",
				"set security nat destination pool p1 port +80",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, tc.cmds)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted signed port for %q (want reject at commit)", tc.name)
			}
			// The tolerant load / peer-sync path must NOT brick: it downgrades
			// to a warning and still compiles (#1960 no-brick doctrine).
			if _, err := CompileConfigLenient(tree); err != nil {
				t.Fatalf("CompileConfigLenient rejected %q (want warn-and-compile): %v", tc.name, err)
			}
		})
	}
}

// The strict gate must not over-reject: canonical port forms still commit.
func TestCanonicalPortStillCompiles_3606(t *testing.T) {
	valid := [][]string{
		{"set applications application a1 protocol tcp", "set applications application a1 destination-port 80"},
		{"set applications application a1 protocol tcp", "set applications application a1 destination-port 8080-8090"},
		{"set applications application a1 protocol tcp", "set applications application a1 destination-port http"},
		{"set firewall family inet filter f1 term t1 from destination-port 22"},
		{"set firewall family inet filter f1 term t1 from destination-port 1024-2048"},
		{"set security nat destination rule-set RS rule R1 match destination-port 8080"},
		{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 port 8080",
		},
	}
	for _, cmds := range valid {
		tree := buildTreeFromSet(t, cmds)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected VALID port %q: %v", strings.Join(cmds, " ; "), err)
		}
	}
}

// parseCanonicalPort unit coverage: canonical forms parse, non-canonical
// (signed / whitespace / non-digit / empty) fail.
func TestParseCanonicalPort_3606(t *testing.T) {
	ok := map[string]int{"80": 80, "0": 0, "65535": 65535, "00080": 80}
	for in, want := range ok {
		got, err := parseCanonicalPort(in)
		if err != nil || got != want {
			t.Fatalf("parseCanonicalPort(%q) = %d, %v; want %d, nil", in, got, err, want)
		}
	}
	for _, in := range []string{"+80", "-80", " 80", "80 ", "0x50", "", "8-0", "http"} {
		if _, err := parseCanonicalPort(in); err == nil {
			t.Fatalf("parseCanonicalPort(%q) accepted a non-canonical token (want error)", in)
		}
	}
}
