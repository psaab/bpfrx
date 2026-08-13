package nat

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6812 B2 — the deterministic-NAT expander is the THIRD consumer of the
// source-NAT pool grammar, and the one where a network-base drift stops being
// "wrong addresses" and becomes a Go/Rust divergence.
//
// expandPoolV4 enumerates a pool CIDR from net.ParseCIDR's ipnet.IP, which is
// already masked to the network base, and lookupForwardInPool INDEXES that
// slice (p.poolV4[ipIdx]) to answer the operator-facing question "which
// external address does this subscriber translate to?". The Rust expander
// (expand_pool_address, userspace-dp/src/nat/source.rs) computes its own base
// with a hand-rolled mask that #6812 round 3 wrote to replace IpNet::network().
//
// If those two bases disagree, the CLI/gRPC/REST deterministic mapping names a
// different external address than the dataplane actually translates to —
// off by exactly the host bits — which is the #5794 invariant-8 forensic
// failure (the reverse map attributing a tuple to the wrong subscriber), and
// it is a divergence of precisely the kind this PR exists to close, on a line
// this PR authored.
//
// Nothing bound it: the shared fixture asserted verdict and host COUNT, and a
// missing mask changes WHICH addresses are produced and never HOW MANY.
// (`10.0.0.1/24` still yields 256 addresses unmasked — it just walks
// 10.0.0.1 .. 10.0.1.0, one address into the NEIGHBOURING prefix.) This test
// reads the SAME fixture the Rust expander and the Go grammar predicate read,
// so all three consumers are pinned to one table.
type poolGrammarFixtureNAT struct {
	Cases []struct {
		Addr     string   `json:"addr"`
		OK       bool     `json:"ok"`
		Hosts    uint64   `json:"hosts"`
		First    string   `json:"first"`
		Last     string   `json:"last"`
		Expanded []string `json:"expanded"`
		Note     string   `json:"note"`
	} `json:"cases"`
}

func TestDeterministicPoolExpansionMatchesSharedGrammarFixture_6812(t *testing.T) {
	path := filepath.Join("..", "..", "userspace-dp", "tests", "fixtures", "snat_pool_grammar_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared fixture %s: %v", path, err)
	}
	var fx poolGrammarFixtureNAT
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	checked, hostBitsRows := 0, 0
	for _, c := range fx.Cases {
		// Only IPv4 rows with a pinned expansion: expandPoolV4 is the v4
		// (mode-1) path, and a row without first/expanded pins no identity.
		if !c.OK || (c.First == "" && len(c.Expanded) == 0) {
			continue
		}
		if ip := netParseV4(c.Addr); !ip {
			continue
		}
		wantFirst := c.First
		if wantFirst == "" {
			wantFirst = c.Expanded[0]
		}

		pool := &config.NATPool{Name: "p", Addresses: []string{c.Addr}}
		got, lerr := expandPoolV4(pool, ModeV4)
		if lerr != nil {
			t.Errorf("expandPoolV4(%q) = %v; the shared fixture says this member expands",
				c.Addr, lerr)
			continue
		}
		checked++
		if uint64(len(got)) != c.Hosts {
			t.Errorf("expandPoolV4(%q) produced %d addresses, want %d",
				c.Addr, len(got), c.Hosts)
			continue
		}
		if got[0].String() != wantFirst {
			t.Errorf("expandPoolV4(%q) starts at %s, want %s — the Go deterministic "+
				"expander and the Rust dataplane expander disagree on the network base, "+
				"so lookupForwardInPool would name a different external address than the "+
				"dataplane translates to", c.Addr, got[0], wantFirst)
		}
		if c.Last != "" && got[len(got)-1].String() != c.Last {
			t.Errorf("expandPoolV4(%q) ends at %s, want %s", c.Addr, got[len(got)-1], c.Last)
		}
		if len(c.Expanded) > 0 {
			for i, want := range c.Expanded {
				if got[i].String() != want {
					t.Errorf("expandPoolV4(%q)[%d] = %s, want %s", c.Addr, i, got[i], want)
					break
				}
			}
		}
		// A row whose address is ALREADY the network base proves nothing about
		// the mask: count how many rows actually have host bits set.
		if hasHostBitsV4(c.Addr) {
			hostBitsRows++
		}
	}

	if checked < 5 {
		t.Fatalf("only %d IPv4 fixture rows carried a pinned expansion; the cross-language "+
			"base agreement has too little to stand on", checked)
	}
	if hostBitsRows < 2 {
		t.Fatalf("only %d fixture rows have HOST BITS SET; a network-aligned row is a "+
			"no-op under a missing mask, so those are the only rows that bind this",
			hostBitsRows)
	}

	// The REJECT half (#6812 F-C). The loop above walks only accepted rows with
	// a pinned expansion — 7 of 58 — so "all three consumers are pinned to one
	// table" was true of the ACCEPT half only. Driving the rejects found two
	// genuine v4 divergences: net.ParseCIDR takes `10.0.0.0/016` as `/16` and
	// `198.51.100.1/032` as `/32`, where netip.ParsePrefix and the dataplane's
	// parse_canonical_prefix_len both refuse the leading-zero mask. That made
	// the deterministic surface answer a forward-mapping query with a
	// 65,536-address pool for a member every other layer rejects.
	rejected := 0
	for _, c := range fx.Cases {
		if c.OK || c.Addr == "" {
			continue
		}
		// Only v4 members reach the v4 index space; expandPoolV4 deliberately
		// SKIPS a colon-bearing member (mode-1) rather than rejecting it, so a
		// v6 row proves nothing here and must not be counted as agreement.
		if config.NATAddrFamily(config.NATCIDRIPPart(c.Addr)) != "v4" {
			continue
		}
		rejected++
		pool := &config.NATPool{Name: "p", Addresses: []string{c.Addr}}
		got, lerr := expandPoolV4(pool, ModeV4)
		if lerr == nil && len(got) > 0 {
			t.Errorf("expandPoolV4(%q) ACCEPTED %d addresses, but the shared fixture — and "+
				"therefore the commit gate and the dataplane — reject this member. The pool "+
				"translates nothing while show/gRPC/REST report a confident mapping for it",
				c.Addr, len(got))
		}
	}
	if rejected < 8 {
		t.Fatalf("only %d rejected v4 rows exercised; the reject half needs enough shapes "+
			"to be worth asserting", rejected)
	}
}

// netParseV4 reports whether the member is an IPv4 CIDR expandPoolV4 handles.
func netParseV4(addr string) bool {
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' {
			return false
		}
		if addr[i] == '/' {
			return true
		}
	}
	return false
}

// hasHostBitsV4 reports whether an IPv4 CIDR sets any bit below its prefix —
// the only shape under which a missing network-base mask changes the answer.
func hasHostBitsV4(addr string) bool {
	ip, ipnet, err := net.ParseCIDR(addr)
	if err != nil || ipnet == nil {
		return false
	}
	return !ip.Mask(ipnet.Mask).Equal(ip)
}
