package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func bgpNeighborConfig6796(addr string) *Config {
	cfg := &Config{}
	cfg.Protocols.BGP = &BGPConfig{
		LocalAS:  65001,
		RouterID: "10.0.0.1",
		Neighbors: []*BGPNeighbor{
			{Address: addr, PeerAS: 65000},
		},
	}
	return cfg
}

// TestMultiTokenNeighborIsRejectedAtCommit6796 is the strict half, PAIRED: the
// same gate, an injecting identity and a legitimate one, opposite verdicts.
//
// The accept leg is not decoration. FRR's grammar is
// `neighbor <A.B.C.D|X:X::X:X|WORD>`, and this tree already commits configs
// whose neighbor is a hostname — the first version of this fix required a bare
// IP and was caught by a PRE-EXISTING parser test peering with
// `peer.example.com`. Over-rejection in routing config is an outage, so the
// accepting rows are the ones that keep the gate honest.
func TestMultiTokenNeighborIsRejectedAtCommit6796(t *testing.T) {
	rejected := []string{
		"1.1.1.1 remote-as 65000",
		"1.1.1.1\n neighbor 2.2.2.2",
		"1.1.1.1\tremote-as 65000",
		"",
	}
	for _, addr := range rejected {
		if err := validateBGPNeighborAddressStrict(bgpNeighborConfig6796(addr)); err == nil {
			t.Errorf("commit ACCEPTED a neighbor identity spanning more than one "+
				"FRR token (%q) — it renders as multiple frr.conf statements and "+
				"injects configuration the operator never wrote (#6796)", addr)
		}
	}

	accepted := []string{
		"10.0.0.2",
		"2001:db8::2",
		"peer.example.com",
		"UPSTREAM-GROUP",
	}
	for _, addr := range accepted {
		if err := validateBGPNeighborAddressStrict(bgpNeighborConfig6796(addr)); err != nil {
			t.Errorf("commit REJECTED the legitimate single-token neighbor %q: %v "+
				"— dropping a working peering is an outage, and it is the "+
				"direction a fail-closed gate gets wrong", addr, err)
		}
	}
}

// TestMultiTokenNeighborGateNamesTheNeighbor6796 pins the operator-facing half.
// A gate that rejects without saying WHICH neighbor leaves an operator grepping
// a large BGP config; the sibling peer-as gate names it, and so must this one.
func TestMultiTokenNeighborGateNamesTheNeighbor6796(t *testing.T) {
	cfg := bgpNeighborConfig6796("1.1.1.1 remote-as 65000")
	cfg.Protocols.BGP.Neighbors[0].GroupName = "upstream"

	err := validateBGPNeighborAddressStrict(cfg)
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if !strings.Contains(err.Error(), "upstream") {
		t.Fatalf("the error does not name the GROUP, so an operator cannot "+
			"locate the offending stanza: %v", err)
	}
	if !strings.Contains(err.Error(), "1.1.1.1") {
		t.Fatalf("the error does not quote the offending identity: %v", err)
	}
}

// TestMultiTokenNeighborGateIsLenientOnTheTolerantPath6796 pins #1960. A
// strict gate that also fired on the tolerant load / peer-sync path would brick
// a node whose already-persisted config carries such a neighbor — turning a
// render-time defect into a boot failure, which is strictly worse.
//
// RED-on-revert: unregister lenientBGPNeighborAddress from the tolerant opt set
// and the lenient compile returns an error instead of a warning.
func TestMultiTokenNeighborGateIsLenientOnTheTolerantPath6796(t *testing.T) {
	cfg := bgpNeighborConfig6796("1.1.1.1 remote-as 65000")
	if err := validateBGPNeighborAddressStrict(cfg); err == nil {
		t.Fatal("precondition: the fixture must be rejected by the STRICT gate, " +
			"or the lenient assertion below is vacuous")
	}
	if !lenientCompileOpts().lenientBGPNeighborAddress {
		t.Fatal("lenientBGPNeighborAddress is NOT registered in the tolerant " +
			"opt set — a leniently-loaded or peer-synced config carrying such a " +
			"neighbor would fail to compile and the node would not boot, turning " +
			"a render-time defect into a boot failure (#1960)")
	}
}

// rustlessTokenRe extracts the render-side belt's body so the two spellings of
// "one FRR token" can be compared rather than each pinned to a literal.
var renderBeltRe = regexp.MustCompile(`(?s)func validBGPNeighborAddress\(s string\) bool \{(.*?)\n\}`)
var commitGateRe = regexp.MustCompile(`(?s)func isSingleFRRToken\(s string\) bool \{(.*?)\n\}`)

// TestNeighborTokenGateAgreesWithTheRenderBelt6796 asserts the AGREEMENT
// between the commit gate and the render belt, by reading BOTH bodies rather
// than pinning either to a literal.
//
// The two must accept exactly the same set. If the commit gate were stricter,
// operators would be told a working config is invalid; if the render belt were
// stricter, a committed config would silently lose a peering at render time —
// and neither divergence produces an error anywhere, so nothing else would
// notice. Pinning one side to a literal would encode which side is trusted, and
// here neither is: the first version of this fix had BOTH wrong in the same
// direction (requiring an IP), and only a pre-existing test caught it.
//
// Comments are stripped before comparison: both bodies are introduced by doc
// comments describing the byte set, and a gate satisfiable by its own
// documentation proves nothing.
func TestNeighborTokenGateAgreesWithTheRenderBelt6796(t *testing.T) {
	strip := func(src string) string {
		var b strings.Builder
		for _, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			b.WriteString(strings.TrimSpace(line))
			b.WriteString("\n")
		}
		return b.String()
	}

	beltSrc, err := os.ReadFile("../frr/render_validate.go")
	if err != nil {
		t.Fatalf("read the render belt: %v", err)
	}
	gateSrc, err := os.ReadFile("compiler_validate_strict_routing.go")
	if err != nil {
		t.Fatalf("read the commit gate: %v", err)
	}

	belt := renderBeltRe.FindStringSubmatch(strip(string(beltSrc)))
	if belt == nil {
		t.Fatal("validBGPNeighborAddress not found in pkg/frr — the render belt " +
			"was renamed or removed, so a committed multi-token neighbor would " +
			"reach frr.conf (#6796)")
	}
	gate := commitGateRe.FindStringSubmatch(strip(string(gateSrc)))
	if gate == nil {
		t.Fatal("isSingleFRRToken not found in pkg/config — the commit gate was " +
			"renamed or removed")
	}
	if strings.TrimSpace(belt[1]) != strings.TrimSpace(gate[1]) {
		t.Fatalf("the commit gate and the render belt disagree about what one "+
			"FRR token is. A stricter commit gate rejects working configs; a "+
			"stricter belt silently drops a committed peering. Neither "+
			"divergence errors anywhere.\n--- render belt ---\n%s\n--- commit "+
			"gate ---\n%s", belt[1], gate[1])
	}
}
