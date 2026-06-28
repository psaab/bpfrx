package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestHostInboundNftMatchesKnownTokens asserts the nftables kernel mirror
// recognizes EXACTLY the recognized-token SSOT in
// config.KnownHostInboundSystemServices / config.KnownHostInboundProtocols
// (#3200). Commit-time validation rejects any token outside this SSOT, so this
// is the "both layers agree on a known token" guard: every SSOT token must be
// classifiable by the nft builder (either fully-admitted via hostInboundAllowsAll
// or producing at least one match fragment), and a token outside the SSOT must
// be classified by NEITHER layer (fail-closed default). If the nft matcher and
// the SSOT diverge, a known token could enforce on one layer and not the other —
// the split-brain this issue fixes.
func TestHostInboundNftMatchesKnownTokens(t *testing.T) {
	// Every known system-service must be recognized by the nft builder.
	for tok := range config.KnownHostInboundSystemServices {
		if tok == "all" || tok == "any-service" {
			// Full-admit tokens are handled by hostInboundAllowsAll, not the
			// per-token match switch (which returns nil for them by design).
			v := dpuserspace.ZoneHostInboundView{SystemServices: []string{tok}}
			if !hostInboundAllowsAll(v) {
				t.Errorf("known full-admit system-service %q not recognized by hostInboundAllowsAll", tok)
			}
			continue
		}
		if len(hostInboundServiceMatches(tok, "ip")) == 0 &&
			len(hostInboundServiceMatches(tok, "ip6")) == 0 {
			t.Errorf("known system-service %q produces no nft match in either family — "+
				"nft builder and config SSOT diverge", tok)
		}
	}

	// Every known protocol must be recognized by the nft builder in AT LEAST
	// one family. Some routing protocols are family-specific (#3225): ospf3 /
	// ripng admit only on IPv6 (return nil for ip), ospf / rip / igmp only on
	// IPv4 (nil for ip6); igmp/router-discovery v6 map to the always-accepted ND
	// set. So a token recognized by the SSOT must classify in ip OR ip6.
	for tok := range config.KnownHostInboundProtocols {
		if config.HostInboundL2Protocols[tok] {
			// #3311: L2/non-IP routing protocols (IS-IS rides OSI/CLNP over LLC,
			// not IP) are recognized-but-no-op host-inbound tokens. They CANNOT
			// be expressed as an ip/ip6 match on either surface, so the
			// every-token-produces-a-match rule does not apply; instead BOTH
			// surfaces must produce NO IP match (the kernel hands IS-IS PDUs to
			// FRR's isisd via an LLC socket, outside this filter). Assert the no-op
			// so the two surfaces stay consistent. Fail-on-revert: emit any nft
			// match from the isis arm in hostInboundProtocolMatches and this RED.
			if len(hostInboundProtocolMatches(tok, "ip")) != 0 ||
				len(hostInboundProtocolMatches(tok, "ip6")) != 0 {
				t.Errorf("L2 host-inbound protocol %q produced an IP nft match — it must be "+
					"a no-op on the IP filter (handled by FRR over L2)", tok)
			}
			continue
		}
		if len(hostInboundProtocolMatches(tok, "ip")) == 0 &&
			len(hostInboundProtocolMatches(tok, "ip6")) == 0 {
			t.Errorf("known protocol %q produces no nft match in either family — "+
				"nft builder and config SSOT diverge", tok)
		}
	}

	// A token outside the SSOT must be classified by NEITHER the service nor the
	// protocol matcher (fail-closed) — this is what makes commit-time rejection
	// of unknown tokens sufficient to guarantee both-layer agreement.
	for _, bad := range []string{"sssh", "ospff", "notathing"} {
		if config.KnownHostInboundSystemServices[bad] || config.KnownHostInboundProtocols[bad] {
			t.Fatalf("test bug: %q is unexpectedly in the SSOT", bad)
		}
		if len(hostInboundServiceMatches(bad, "ip")) != 0 ||
			len(hostInboundServiceMatches(bad, "ip6")) != 0 {
			t.Errorf("unknown service token %q produced an nft match — nft path not fail-closed", bad)
		}
		if len(hostInboundProtocolMatches(bad, "ip")) != 0 {
			t.Errorf("unknown protocol token %q produced an nft match — nft path not fail-closed", bad)
		}
	}
}

// TestHostInboundBfdAdmitsMultiHop asserts the nft host-inbound rule for
// `protocols bfd` admits multi-hop BFD control (UDP 4784, RFC 5883) in addition
// to single-hop control (3784) + echo (3785). Operators running BFD-assisted
// multi-hop BGP (or BFD over multi-hop static routes) to the firewall depend on
// 4784 reaching the host (#3299). This must stay in lockstep with the AF_XDP
// host_inbound classifier ("bfd" arm in host_inbound.rs). Fail-on-revert:
// dropping 4784 from the dport set turns this RED.
func TestHostInboundBfdAdmitsMultiHop(t *testing.T) {
	matches := hostInboundProtocolMatches("bfd", "ip")
	if len(matches) == 0 {
		t.Fatalf("bfd produced no nft match for ip family")
	}
	joined := strings.Join(matches, " ; ")
	for _, port := range []string{"3784", "3785", "4784"} {
		if !strings.Contains(joined, port) {
			t.Errorf("bfd nft match %q missing UDP dport %s (single-hop 3784/echo 3785 + multi-hop 4784 RFC 5883)", joined, port)
		}
	}
}

// TestHostInboundProtocolsAllExcludesL2Isis asserts that the nft `protocols all`
// expansion EXCLUDES the L2/non-IP protocol IS-IS (#3311). The nft `all` case
// derives its expansion from config.HostInboundAllExpansionProtocols()
// (KnownHostInboundProtocols minus the L2 set), so this is the load-bearing
// daemon-side use of config.HostInboundL2Protocols. The previous
// arm-existence assertion (`isis produces no nft match`) was FALSE-GREEN — the
// default switch arm returns nil too, so deleting the explicit isis case did
// not turn it RED.
//
// Fail-on-revert: remove "isis" from config.HostInboundL2Protocols and — because
// isis stays in config.KnownHostInboundProtocols — it reappears in the SSOT
// expansion, turning the "excluded" assertion RED. (Its per-token nft match is
// still nil, so the emitted nft rule set is unchanged; the token-list guard is
// what catches the SSOT regression.)
func TestHostInboundProtocolsAllExcludesL2Isis(t *testing.T) {
	expansion := config.HostInboundAllExpansionProtocols()
	for _, p := range expansion {
		if p == "isis" {
			t.Fatalf("isis (L2) must be excluded from the nft `protocols all` expansion; got %v", expansion)
		}
	}
	// Sanity: a real IP routing protocol is still in the expansion AND the nft
	// `all` case emits its match (proves the expansion is actually consumed).
	allMatches := strings.Join(hostInboundProtocolMatches("all", "ip"), " ; ")
	if !strings.Contains(allMatches, "179") { // bgp tcp/179
		t.Errorf("nft `protocols all` (ip) missing BGP tcp/179 — expansion not consumed: %q", allMatches)
	}
}

// TestHostInboundEmptyStanzaFailsClosed asserts that a host-inbound-CONFIGURED
// zone whose stanza yields zero recognized matches (an empty
// `host-inbound-traffic { }`, or — on the tolerant load path — a zone whose
// every token was a downgraded-to-warning typo) emits a catch-all DROP rather
// than a bare accept (#3200). This matches the Rust classifier, which fails
// CLOSED for a configured-but-empty zone (host_inbound_admits returns deny).
// Before the fix emitHostInboundZone emitted NOTHING for a zero-match zone —
// failing OPEN and disagreeing with Rust. Make the zero-match branch emit no
// drop again and this test catches the regression.
func TestHostInboundEmptyStanzaFailsClosed(t *testing.T) {
	v := dpuserspace.ZoneHostInboundView{
		Zone:    "untrust",
		V4Addrs: []string{"203.0.113.1"},
		V6Addrs: []string{"2001:db8::1"},
		// No SystemServices, no Protocols → zero matches.
	}
	var rules []string
	emitHostInboundZone(&rules, v, "ip", v.V4Addrs)
	emitHostInboundZone(&rules, v, "ip6", v.V6Addrs)

	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "ip daddr 203.0.113.1 drop") {
		t.Errorf("empty-stanza v4 zone did not fail closed (no catch-all drop):\n%s", joined)
	}
	if !strings.Contains(joined, "ip6 daddr 2001:db8::1 drop") {
		t.Errorf("empty-stanza v6 zone did not fail closed (no catch-all drop):\n%s", joined)
	}
	for _, r := range rules {
		// A bare "<daddr> accept" with no match fragment would fail OPEN.
		if strings.HasSuffix(r, " accept") && !strings.Contains(r, " dport ") &&
			!strings.Contains(r, " type ") && !strings.Contains(r, " l4proto ") {
			t.Errorf("empty-stanza zone emitted a bare-accept rule (fail open): %q", r)
		}
	}
}
