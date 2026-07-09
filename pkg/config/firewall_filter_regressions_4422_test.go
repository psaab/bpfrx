package config

import (
	"strings"
	"testing"
)

// #4422 (audit test-coverage follow-up): pin the firewall-FILTER (family
// inet|inet6 filter, NOT security policy) compile + commit-check behavior for
// three edge cells the audit flagged as regression-prone but that no existing
// test locks down. These are TEST-ONLY: they assert the ACTUAL behavior of the
// current compiler (they do not change it), so a future edit that silently
// weakens a fail-closed rejection into a fail-open silent-drop flips the assert.
//
// Coverage already in the tree (verified, NOT duplicated here):
//   - port on a non-port protocol (icmp/gre/esp/numeric/mixed-list/inet6/except),
//     tcp-flags on non-TCP, icmp-type/icmp-code on non-ICMP, icmp-code without
//     icmp-type, and the port-with-no-protocol / tcp-flags-with-no-protocol
//     positive controls: firewall_crossfield_3723_test.go.
//   - icmp-type/named-port SYMBOLIC resolution to numeric on a VALID
//     icmp/tcp/udp term: firewall_symbolic_match_3205_test.go.
//   - tcp-flags parse + compiled term.TCPFlags value: tcp_flags_test.go,
//     parser_security_test.go.
//   - generic unenforced `from` leaves (ttl/source-mac-address/ip-options/
//     fragment-offset/hop-limit): firewall_from_unenforced_3307_test.go.
//
// The cells below are the genuinely-missing ones, each named in the #4422 slice:
// the bare Junos `from port` keyword, the `tcp-established` / `tcp-initial`
// shorthands, and the source-port variant of the port-on-portless-protocol
// reject.

// firstInet6Term returns the first term of an inet6 filter (the inet sibling
// firstInetTerm lives in firewall_symbolic_match_3205_test.go).
func firstInet6Term(t *testing.T, cfg *Config, filter string) *FirewallFilterTerm {
	t.Helper()
	f := cfg.Firewall.FiltersInet6[filter]
	if f == nil || len(f.Terms) == 0 {
		t.Fatalf("inet6 filter %q missing or has no terms", filter)
	}
	return f.Terms[0]
}

// The bare Junos `from port <x>` keyword (match source OR destination port) is
// NOT modeled by xpf — only the explicit `source-port` / `destination-port`
// leaves are. An unmodeled `port` leaf hits compileFilterFrom's default arm and
// is recorded on term.UnknownFrom, so validateFilterFromMatchStrict rejects it
// at commit rather than silently dropping the port constraint (which would let
// a `then discard`/`reject` match more broadly than authored — over-drop — or a
// `then accept` over-permit). This is distinct from the #3307 generic-leaf set
// (ttl/mac/ip-options): `port` looks supportable, so a vSRX/SRX config import
// carrying `from port 80` must fail CLOSED with a clear error, not compile with
// the constraint quietly gone.
//
// FAIL-ON-REVERT: add a `case "port":` that maps to SourcePorts/DestinationPorts
// (a plausible "support it" change) without also wiring the matcher, and the
// UnknownFrom pin + reject assert both go RED — the constraint would then be
// dropped or half-enforced silently.
func TestFilterBarePortKeywordRejected_4422(t *testing.T) {
	cases := []struct {
		name, family, filter string
		cmds                 []string
	}{
		{
			name:   "inet",
			family: "inet",
			filter: "f",
			cmds: []string{
				"set firewall family inet filter f term t from protocol tcp",
				"set firewall family inet filter f term t from port 80",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name:   "inet6",
			family: "inet6",
			filter: "f6",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from next-header tcp",
				"set firewall family inet6 filter f6 term t from port 443",
				"set firewall family inet6 filter f6 term t then discard",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatal("bare `from port` (not modeled by xpf) must be rejected at " +
					"commit — silently dropping it would over-match (#4422/#3307)")
			}
			if !strings.Contains(err.Error(), "from port") ||
				!strings.Contains(err.Error(), "not enforced") {
				t.Fatalf("error %q must name the unenforced `from port` leaf", err)
			}
			if !strings.Contains(err.Error(), tc.family) {
				t.Fatalf("error %q must name family %s", err, tc.family)
			}
			// Tolerant path downgrades to a warning so a persisted/peer-synced
			// config still boots (#1960 no-brick), and the token is recorded on
			// UnknownFrom (the mechanism that makes the strict gate fire).
			cfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient path must not hard-fail on bare `from port`: %v", lerr)
			}
			var term *FirewallFilterTerm
			if tc.family == "inet6" {
				term = firstInet6Term(t, cfg, tc.filter)
			} else {
				term = firstInetTerm(t, cfg, tc.filter)
			}
			foundPort := false
			for _, u := range term.UnknownFrom {
				if u == "port" {
					foundPort = true
				}
			}
			if !foundPort {
				t.Fatalf("bare `port` must be recorded on UnknownFrom, got %v", term.UnknownFrom)
			}
		})
	}
}

// The Junos filter shorthands `tcp-established` (match TCP with ACK|RST — an
// established connection) and `tcp-initial` (match the SYN-without-ACK opening
// segment) are NOT modeled as tcp-flags predicates by xpf. Each hits
// compileFilterFrom's default arm → term.UnknownFrom → validateFilterFromMatchStrict
// rejects it at commit. This is the fail-CLOSED-correct outcome: silently
// dropping the shorthand would turn a TCP-only established/initial match into a
// match on ALL TCP (a `then accept` over-permit, a `then discard`/`reject`
// over-drop). These shorthands are common in real SRX/vSRX filters, so a config
// import must be refused with a clear error rather than compiled wrong.
//
// The protocol constraint (`from protocol tcp`) is unaffected — only the
// shorthand is flagged — so term.Protocols still carries tcp on the lenient
// path, proving the gate is scoped to the unmodeled leaf, not the whole term.
//
// FAIL-ON-REVERT: map tcp-established/tcp-initial to an empty tcp-flags set (a
// plausible "accept the keyword" change) without a real flags expression, and
// the UnknownFrom pin + reject assert go RED — the term would then match ALL
// TCP, a silent fail-open.
func TestFilterTCPEstablishedInitialRejected_4422(t *testing.T) {
	cases := []struct {
		name, family, filter, leaf string
		cmds                       []string
	}{
		{
			name: "inet_tcp_established", family: "inet", filter: "f", leaf: "tcp-established",
			cmds: []string{
				"set firewall family inet filter f term t from protocol tcp",
				"set firewall family inet filter f term t from tcp-established",
				"set firewall family inet filter f term t then accept",
			},
		},
		{
			name: "inet_tcp_initial", family: "inet", filter: "f", leaf: "tcp-initial",
			cmds: []string{
				"set firewall family inet filter f term t from protocol tcp",
				"set firewall family inet filter f term t from tcp-initial",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "inet6_tcp_established", family: "inet6", filter: "f6", leaf: "tcp-established",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from next-header tcp",
				"set firewall family inet6 filter f6 term t from tcp-established",
				"set firewall family inet6 filter f6 term t then discard",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("`from %s` (not modeled) must be rejected at commit — "+
					"silently dropping it matches ALL TCP, a fail-open (#4422/#3307)", tc.leaf)
			}
			if !strings.Contains(err.Error(), tc.leaf) ||
				!strings.Contains(err.Error(), "not enforced") {
				t.Fatalf("error %q must name the unenforced `from %s` leaf", err, tc.leaf)
			}
			// Tolerant path downgrades to a warning; the token lands on
			// UnknownFrom and the protocol constraint survives intact.
			cfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient path must not hard-fail on `from %s`: %v", tc.leaf, lerr)
			}
			var term *FirewallFilterTerm
			if tc.family == "inet6" {
				term = firstInet6Term(t, cfg, tc.filter)
			} else {
				term = firstInetTerm(t, cfg, tc.filter)
			}
			foundLeaf := false
			for _, u := range term.UnknownFrom {
				if u == tc.leaf {
					foundLeaf = true
				}
			}
			if !foundLeaf {
				t.Fatalf("`%s` must be recorded on UnknownFrom, got %v", tc.leaf, term.UnknownFrom)
			}
			if len(term.Protocols) != 1 || term.Protocols[0] != "tcp" {
				t.Fatalf("the `protocol tcp` constraint must survive (only the shorthand "+
					"is flagged), got Protocols %v", term.Protocols)
			}
		})
	}
}

// The source-port variant of the port-on-a-non-port-protocol reject. #3723
// covers destination-port + icmp and source-port + esp, but not the exact
// source-port + icmp cell the #4422 slice names ("a `from port`/`source-port`/
// `destination-port` match combined with a `from protocol icmp`"). The
// cross-field gate keys on any port match in the term (source or destination),
// so source-port + icmp is a never-match — the dataplane extracts port 0 for
// ICMP — and a `then discard`/`reject` would fail OPEN. It must be rejected at
// commit for BOTH families.
//
// FAIL-ON-REVERT: drop the source-port arm from the validateFilterCrossFieldStrict
// hasPorts test and these asserts go RED.
func TestFilterSourcePortOnICMPRejected_4422(t *testing.T) {
	cases := []struct {
		name  string
		cmds  []string
		proto string
	}{
		{
			name:  "inet_sport_icmp",
			proto: "icmp",
			cmds: []string{
				"set firewall family inet filter g term t from protocol icmp",
				"set firewall family inet filter g term t from source-port 80",
				"set firewall family inet filter g term t then discard",
			},
		},
		{
			name:  "inet6_sport_icmp6",
			proto: "icmp6",
			cmds: []string{
				"set firewall family inet6 filter g6 term t from next-header icmp6",
				"set firewall family inet6 filter g6 term t from source-port 80",
				"set firewall family inet6 filter g6 term t then discard",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("source-port on non-port protocol %q must be rejected at "+
					"commit (never-match → fail-open on discard/reject) (#4422/#3723)", tc.proto)
			}
			if !strings.Contains(err.Error(), tc.proto) ||
				!strings.Contains(err.Error(), "port") {
				t.Fatalf("error %q must name the port match and protocol %q", err, tc.proto)
			}
			// Tolerant path downgrades to a warning (#1960 no-brick).
			if _, lerr := CompileConfigLenient(tree); lerr != nil {
				t.Fatalf("lenient path must not hard-fail on the cross-field term: %v", lerr)
			}
		})
	}
}
