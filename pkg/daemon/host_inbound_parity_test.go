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

	// Every known protocol must be recognized by the nft builder. Family "ip"
	// is exercised because a few routing protocols (igmp, router-discovery) map
	// to the always-accepted ND set in v6 and intentionally return nil for ip6.
	for tok := range config.KnownHostInboundProtocols {
		if len(hostInboundProtocolMatches(tok, "ip")) == 0 {
			t.Errorf("known protocol %q produces no nft match for family ip — "+
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
