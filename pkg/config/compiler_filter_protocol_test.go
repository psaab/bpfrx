package config

import (
	"strings"
	"testing"
)

// #2175 review fold: a firewall-filter `from protocol <token>` whose protocol is
// not resolvable by the centralized appid.ProtocolNumber SSOT was caught ONLY by
// the dataplane compiler (compileFirewallFilters → validateFilterProtocols),
// whose error the daemon swallows (compileErrorMustAbortApply == false). Commit
// reported SUCCESS, the config was promoted, and the term silently programmed no
// protocol match (the pre-#2175 "match protocol 0" surprise). These tests drive
// the real strict commit path (CompileConfig) and the tolerant load path
// (CompileConfigLenient) through validateFilterProtocolsStrict so an invalid
// token now REFUSES the operator commit while a persisted/synced config still
// boots.
//
// All trees are built from flat `set` commands via flatTreeFromSets (defined in
// compiler_interfaces_unsupported_test.go) — the only correct way to exercise
// the flat-set AST shape.

func filterWithProtocol(family, proto string) []string {
	return []string{
		"set firewall family " + family + " filter f1 term t1 from protocol " + proto,
		"set firewall family " + family + " filter f1 term t1 then accept",
	}
}

func TestFilterProtocol_UnknownName_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithProtocol("inet", "bogus-proto")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject firewall filter f1 term t1 with protocol bogus-proto")
	}
	if !strings.Contains(err.Error(), "bogus-proto") ||
		!strings.Contains(err.Error(), "f1") ||
		!strings.Contains(err.Error(), "t1") {
		t.Fatalf("error %q must name the family/filter/term and the offending protocol", err.Error())
	}
}

// An unknown junos-* alias must be rejected too: validateProtocol blanket-accepts
// any "junos-" prefix, but the filter gate mirrors appid.ProtocolNumber, which
// resolves only the specific junos-* aliases. A token the dataplane SSOT cannot
// resolve must not slip past commit only to be dropped (swallowed) at the
// dataplane.
func TestFilterProtocol_UnknownJunosAlias_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithProtocol("inet", "junos-foobar")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject firewall filter with protocol junos-foobar")
	}
}

func TestFilterProtocol_OutOfRangeNumeric_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithProtocol("inet", "256")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject firewall filter with protocol 256 (out of 0-255)")
	}
}

func TestFilterProtocol_Inet6UnknownName_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithProtocol("inet6", "nope")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject inet6 firewall filter with protocol nope")
	}
}

// Valid protocols across the full SSOT acceptance set must still commit: the L4
// subset, a #2124-added name (sctp/esp), a junos-* alias, the deliberate
// numeric 0 (HOPOPT), and a numeric bound.
func TestFilterProtocol_ValidProtocols_Commit(t *testing.T) {
	for _, proto := range []string{
		"tcp", "udp", "icmp", "icmpv6", "icmp6",
		"sctp", "esp", "ah", "gre", "ospf", "vrrp", "igmp", "pim",
		"junos-tcp-any", "junos-icmp6-all",
		"0", "47", "132", "255",
	} {
		t.Run(proto, func(t *testing.T) {
			tree := flatTreeFromSets(t, filterWithProtocol("inet", proto)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("valid filter protocol %q must commit, got %v", proto, err)
			}
		})
	}
}

// No-brick (#1960 doctrine): a config persisted/synced with a firewall filter
// carrying an unrepresentable protocol token must still LOAD on the tolerant
// path (CompileConfigLenient) — downgraded to a warning — so an upgraded or
// receiving node does not fail closed on boot. The dataplane drops the protocol
// constraint independently, so the leniently-loaded term is inert (it matches
// without a protocol constraint, never silently "protocol 0").
func TestFilterProtocol_Unknown_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithProtocol("inet", "bogus-proto")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a bad filter protocol must not fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "firewall filter protocol") && strings.Contains(w, "bogus-proto") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient path to record a firewall-filter-protocol downgrade warning, got %v", cfg.Warnings)
	}
}
