package config

import (
	"strings"
	"testing"
)

// buildFilterTree compiles a flat-set firewall config the Junos way
// (ParseSetCommand + tree.SetPath, never NewParser — see CLAUDE.md).
func buildFilterTree(t *testing.T, cmds ...string) *ConfigTree {
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

func firstInetTerm(t *testing.T, cfg *Config, filter string) *FirewallFilterTerm {
	t.Helper()
	f := cfg.Firewall.FiltersInet[filter]
	if f == nil || len(f.Terms) == 0 {
		t.Fatalf("filter %q missing or has no terms", filter)
	}
	return f.Terms[0]
}

// #3205 (agy-070 #07): a symbolic icmp-type name must resolve to its numeric
// type, not be silently dropped (a dropped icmp-type set matches ALL ICMP).
//
// FAIL-ON-REVERT: restore the old `strconv.Atoi(v); if err == nil` silent-drop
// in compileFilterFrom and this test goes RED — ICMPTypes is empty (the
// constraint was dropped) instead of [8].
func TestFilterICMPTypeNameResolvesV4_3205(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter ping term allow from protocol icmp",
		"set firewall family inet filter ping term allow from icmp-type echo-request",
		"set firewall family inet filter ping term allow then accept",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := firstInetTerm(t, cfg, "ping")
	if len(term.ICMPTypes) != 1 || term.ICMPTypes[0] != 8 {
		t.Fatalf("icmp-type echo-request => ICMPTypes %v, want [8] "+
			"(symbolic name silently dropped = matches ALL ICMP, #3205)", term.ICMPTypes)
	}
	if len(term.UnknownICMPTypes) != 0 {
		t.Fatalf("echo-request must resolve, got UnknownICMPTypes %v", term.UnknownICMPTypes)
	}
}

// #3205: the ICMPv6 table is family-selected — echo-request is 128 on inet6.
func TestFilterICMPTypeNameResolvesV6_3205(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet6 filter ping6 term allow from next-header icmp6",
		"set firewall family inet6 filter ping6 term allow from icmp-type echo-request",
		"set firewall family inet6 filter ping6 term allow then accept",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	f := cfg.Firewall.FiltersInet6["ping6"]
	if f == nil || len(f.Terms) == 0 {
		t.Fatal("inet6 filter ping6 missing")
	}
	term := f.Terms[0]
	if len(term.ICMPTypes) != 1 || term.ICMPTypes[0] != 128 {
		t.Fatalf("inet6 icmp-type echo-request => ICMPTypes %v, want [128] (#3205)", term.ICMPTypes)
	}
}

// #3205 (agy-070 #07): an unknown icmp-type name is REJECTED at commit with a
// clear error, not silently compiled to match-all.
func TestFilterUnknownICMPTypeRejected_3205(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter bad term t from protocol icmp",
		"set firewall family inet filter bad term t from icmp-type frobnicate",
		"set firewall family inet filter bad term t then accept",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("unknown icmp-type frobnicate must be rejected at commit (#3205)")
	}
	if !strings.Contains(err.Error(), "icmp-type") || !strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("error %q must name the offending icmp-type token", err)
	}
	// Tolerant path downgrades to a warning so a persisted/peer-synced config
	// still boots (#1960 no-brick).
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on unknown icmp-type: %v", lerr)
	}
}

// #3205 (agy-070 #08): a named port (Junos `domain` = 53) must resolve to its
// numeric value so the dataplane never sees an unparseable token (which makes a
// *-port-except term match ALL ports — fail open).
//
// FAIL-ON-REVERT: drop the resolveFilterPortTokens rewrite (keep the raw name)
// and DestPortsExcept stays ["domain"] instead of ["53"].
func TestFilterNamedPortExceptResolves_3205(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol udp",
		"set firewall family inet filter f term t from destination-port-except domain",
		"set firewall family inet filter f term t then accept",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := firstInetTerm(t, cfg, "f")
	if len(term.DestPortsExcept) != 1 || term.DestPortsExcept[0] != "53" {
		t.Fatalf("destination-port-except domain => %v, want [53] (#3205 fail-open)", term.DestPortsExcept)
	}
	if len(term.UnknownPorts) != 0 {
		t.Fatalf("domain must resolve, got UnknownPorts %v", term.UnknownPorts)
	}
}

// #3205: a named port in a positive match resolves too, and a numeric port
// passes through unchanged.
func TestFilterNamedPortResolves_3205(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t from destination-port ssh",
		"set firewall family inet filter f term t from source-port 1024-65535",
		"set firewall family inet filter f term t then accept",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := firstInetTerm(t, cfg, "f")
	if len(term.DestinationPorts) != 1 || term.DestinationPorts[0] != "22" {
		t.Fatalf("destination-port ssh => %v, want [22]", term.DestinationPorts)
	}
	if len(term.SourcePorts) != 1 || term.SourcePorts[0] != "1024-65535" {
		t.Fatalf("source-port range => %v, want [1024-65535]", term.SourcePorts)
	}
}

// #3205 (agy-070 #08): an unknown port name is REJECTED at commit, not silently
// dropped (which makes a *-port-except term fail open).
func TestFilterUnknownPortRejected_3205(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter bad term t from protocol tcp",
		"set firewall family inet filter bad term t from destination-port-except notaport",
		"set firewall family inet filter bad term t then accept",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("unknown port notaport must be rejected at commit (#3205)")
	}
	if !strings.Contains(err.Error(), "port") || !strings.Contains(err.Error(), "notaport") {
		t.Fatalf("error %q must name the offending port token", err)
	}
	// Unresolved token is kept verbatim so the dataplane fails CLOSED on the
	// tolerant path (it must NOT be silently dropped to an empty list).
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient path must not hard-fail on unknown port: %v", lerr)
	}
	term := firstInetTerm(t, cfg, "bad")
	if len(term.DestPortsExcept) != 1 || term.DestPortsExcept[0] != "notaport" {
		t.Fatalf("unresolved except port must be KEPT verbatim for fail-closed dataplane, got %v", term.DestPortsExcept)
	}
}

// #3397: a HYPHENATED catalog service name (kerberos-sec, ftp-data, tacacs-ds)
// resolves to its single port on a firewall-filter source/destination-port.
// FAIL-ON-REVERT: restore the old split-on-'-'-first order in resolveFilterPort
// and these names misparse as malformed low-high ranges (e.g. kerberos / sec)
// and are rejected, leaving them on UnknownPorts.
func TestFilterHyphenatedServiceNameResolves_3397(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t from destination-port kerberos-sec",
		"set firewall family inet filter f term t from source-port ftp-data",
		"set firewall family inet filter f term t then accept",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := firstInetTerm(t, cfg, "f")
	if len(term.DestinationPorts) != 1 || term.DestinationPorts[0] != "88" {
		t.Fatalf("destination-port kerberos-sec => %v, want [88] (#3397)", term.DestinationPorts)
	}
	if len(term.SourcePorts) != 1 || term.SourcePorts[0] != "20" {
		t.Fatalf("source-port ftp-data => %v, want [20] (#3397)", term.SourcePorts)
	}
	if len(term.UnknownPorts) != 0 {
		t.Fatalf("hyphenated catalog names must resolve, got UnknownPorts %v", term.UnknownPorts)
	}
}

// #3397: a hyphenated name also resolves on the *-port-except path.
func TestFilterHyphenatedServiceNameExceptResolves_3397(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t from destination-port-except tacacs-ds",
		"set firewall family inet filter f term t then accept",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := firstInetTerm(t, cfg, "f")
	if len(term.DestPortsExcept) != 1 || term.DestPortsExcept[0] != "65" {
		t.Fatalf("destination-port-except tacacs-ds => %v, want [65] (#3397)", term.DestPortsExcept)
	}
	if len(term.UnknownPorts) != 0 {
		t.Fatalf("tacacs-ds must resolve, got UnknownPorts %v", term.UnknownPorts)
	}
}

// #3397: a two-token spec that is NOT a catalog name (http-https) still resolves
// as a low-high range — the whole-spec lookup falls through to the range path.
func TestFilterServiceNameRangeStillResolves_3397(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t from destination-port http-https",
		"set firewall family inet filter f term t then accept",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := firstInetTerm(t, cfg, "f")
	if len(term.DestinationPorts) != 1 || term.DestinationPorts[0] != "80-443" {
		t.Fatalf("destination-port http-https => %v, want [80-443] (#3397)", term.DestinationPorts)
	}
	if len(term.UnknownPorts) != 0 {
		t.Fatalf("http-https range must resolve, got UnknownPorts %v", term.UnknownPorts)
	}
}

// #3397: a numeric port still passes through and an unknown name is still
// rejected — the new whole-spec-first order does not weaken either behavior.
func TestFilterNumericAndUnknownUnaffected_3397(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t from destination-port 8080",
		"set firewall family inet filter f term t then accept",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := firstInetTerm(t, cfg, "f")
	if len(term.DestinationPorts) != 1 || term.DestinationPorts[0] != "8080" {
		t.Fatalf("numeric destination-port => %v, want [8080]", term.DestinationPorts)
	}

	bad := buildFilterTree(t,
		"set firewall family inet filter b term t from protocol tcp",
		"set firewall family inet filter b term t from destination-port not-a-service",
		"set firewall family inet filter b term t then accept",
	)
	if _, err := CompileConfig(bad); err == nil {
		t.Fatal("unknown hyphenated name not-a-service must be rejected at commit (#3397)")
	}
}

// #3205: an out-of-range numeric icmp-type is rejected (defense against a
// silently-truncated u8 cast).
func TestFilterICMPTypeOutOfRangeRejected_3205(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter bad term t from protocol icmp",
		"set firewall family inet filter bad term t from icmp-type 300",
		"set firewall family inet filter bad term t then accept",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("icmp-type 300 (>255) must be rejected at commit (#3205)")
	}
}
