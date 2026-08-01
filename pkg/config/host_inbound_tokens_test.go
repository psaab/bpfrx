package config

import (
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestHostInboundUnknownTokenFailsCommit asserts that an unknown / typo'd
// `host-inbound-traffic system-services` / `protocols` token is HARD-REJECTED at
// commit (#3200).
//
// This is the fail-on-revert guard for the split-brain bug: before the fix the
// schema modeled system-services / protocols as untyped containers and the
// compiler copied every child token verbatim with NO validation, so a typo such
// as `system-services sssh` committed cleanly. At runtime the two enforcement
// layers then DISAGREED — the nftables kernel mirror emitted no match (and, for
// an all-unknown stanza, fell OPEN) while the Rust AF_XDP classifier ignored the
// token and denied everything else (fail CLOSED). Remove
// validateHostInboundTokensStrict (or its dispatch in compiler.go) and the
// reject subtests go green on the BAD config, which is exactly the regression
// this test exists to catch.
func TestHostInboundUnknownTokenFailsCommit(t *testing.T) {
	cases := []struct {
		name    string
		cmds    []string
		wantSub string
	}{
		{
			name: "unknown system-service",
			cmds: []string{
				"set security zones security-zone untrust host-inbound-traffic system-services sssh",
			},
			wantSub: `system-services "sssh"`,
		},
		{
			name: "unknown protocol",
			cmds: []string{
				"set security zones security-zone trust host-inbound-traffic protocols ospff",
			},
			wantSub: `protocols "ospff"`,
		},
		{
			name: "wrong-case system-service (rejected at commit for typo-hygiene)",
			cmds: []string{
				"set security zones security-zone trust host-inbound-traffic system-services SSH",
			},
			wantSub: `system-services "SSH"`,
		},
		{
			name: "good token mixed with a typo still rejects",
			cmds: []string{
				"set security zones security-zone trust host-inbound-traffic system-services ssh",
				"set security zones security-zone trust host-inbound-traffic system-services htp",
			},
			wantSub: `system-services "htp"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject an unknown host-inbound token, got nil error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not name the bad token (want substring %q)", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestHostInboundKnownTokensCommit asserts the strict validator does NOT reject
// legitimate host-inbound tokens — including the full-admit tokens, the
// routing-scoped `protocols all` (#3199), aliases, and a representative spread
// of services/protocols (#3200 anti-over-reject). A regression here would break
// valid operator configs.
func TestHostInboundKnownTokensCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services ping",
		"set security zones security-zone trust host-inbound-traffic system-services https",
		"set security zones security-zone trust host-inbound-traffic system-services dhcpv6",
		"set security zones security-zone trust host-inbound-traffic system-services netconf-ssh",
		"set security zones security-zone trust host-inbound-traffic protocols ospf",
		"set security zones security-zone trust host-inbound-traffic protocols bgp",
		"set security zones security-zone untrust host-inbound-traffic system-services all",
		"set security zones security-zone wan host-inbound-traffic protocols all",
		"set security zones security-zone dmz host-inbound-traffic system-services any-service",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected legitimate host-inbound tokens: %v", err)
	}
}

// TestHostInboundRoutingProtocolTokensCommit asserts the #3341 routing-control
// tokens (rsvp/pgm/sap/dvmrp) are ACCEPTED at commit and carry the correct
// address-family scoping. Before #3341 they were absent from
// KnownHostInboundProtocols, so since #3200 made tokens typed a valid vSRX
// config naming them was HARD-REJECTED at commit. Fail-on-revert: remove any of
// these from KnownHostInboundProtocols and the commit subtest goes RED.
func TestHostInboundRoutingProtocolTokensCommit(t *testing.T) {
	for _, tok := range []string{"rsvp", "pgm", "sap", "dvmrp"} {
		t.Run(tok, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone wan host-inbound-traffic protocols " + tok,
			})
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict commit rejected `host-inbound-traffic protocols %s` (vSRX parity, #3341): %v", tok, err)
			}
			if !KnownHostInboundProtocols[tok] {
				t.Fatalf("%s must be in KnownHostInboundProtocols so commit accepts it", tok)
			}
			if HostInboundL2Protocols[tok] {
				t.Fatalf("%s rides IP, it must NOT be in HostInboundL2Protocols", tok)
			}
		})
	}
	// rsvp/pgm/sap are dual-family (absent from the family map); dvmrp is
	// IPv4-only (IGMP-encapsulated), like igmp.
	for _, dual := range []string{"rsvp", "pgm", "sap"} {
		if _, scoped := HostInboundProtocolFamily[dual]; scoped {
			t.Errorf("%s must be dual-family (absent from HostInboundProtocolFamily)", dual)
		}
	}
	if HostInboundProtocolFamily["dvmrp"] != "ip" {
		t.Errorf("dvmrp must be IPv4-only (HostInboundProtocolFamily[\"dvmrp\"]=%q, want \"ip\")",
			HostInboundProtocolFamily["dvmrp"])
	}
}

// The Junos `system-services` oracle: Juniper's PUBLISHED YANG MODULE, vendored
// whole and PARSED at test time.
//
// This union was wrong three times while the oracle was a list hand-copied out
// of Juniper's prose reference pages, which are individually incomplete and
// mutually inconsistent. A fourth revision replaced that with a hand-copied list
// of tokens EXTRACTED from the YANG — which was no better in kind: it was still
// a literal nobody could check, and deleting a token from it (and from the
// implementation) stayed green.
//
// So the module itself is vendored, gzipped, and the test does the extraction.
// Three gates make the derivation real rather than asserted:
//
//  1. SHA-256 of the DECOMPRESSED module is pinned to the byte-identical hash of
//     the file Juniper publishes. Any edit to the vendored copy — including
//     deleting one `enum` — changes it and REDS. Anyone can check the pin by
//     hand against upstream; see the regeneration recipe below.
//  2. The enumeration is extracted by brace-matching the grouping and reading
//     its `enum` statements. Nothing is transcribed.
//  3. The token COUNT is pinned, so a deletion still REDS even if the hash pin
//     were re-baselined along with the edit.
//
// Regenerate (network required; verified to reproduce the pinned hash):
//
//	U=https://raw.githubusercontent.com/Juniper/yang/master/24.4/24.4R2
//	U=$U/native/conf-and-rpcs/junos-es/conf/models
//	curl -sSL "$U/junos-es-conf-security%402024-01-01.yang" |
//	  tee >(sha256sum) | gzip -9 -n > \
//	  pkg/config/testdata/junos-es-conf-security@2024-01-01.yang.gz
//
// `gzip -n` omits the mtime, so the vendored file is byte-reproducible: running
// the recipe again yields an identical blob rather than a spurious diff.
const (
	// junosSchemaModule is the vendored module: junos-es (the SRX/vSRX platform
	// family) security configuration, revision 2024-01-01, whose revision
	// description reads "Junos: 24.4R2.25" — the target release.
	junosSchemaModule = "testdata/junos-es-conf-security@2024-01-01.yang.gz"

	// junosSchemaModuleSHA256 is the SHA-256 of the DECOMPRESSED module, equal to
	// the hash of the file published at the URL in the recipe above. It is the
	// tamper gate: it makes the vendored copy checkable against upstream by hand,
	// and makes any local edit fail loudly instead of silently redefining what
	// "Juniper documents".
	junosSchemaModuleSHA256 = "3d03d81b1ac2041c070610c9708f74c3bc67c6d26790d4fe2509b63d5d3bd70e"

	// junosSchemaZoneGrouping is the zone-level stanza
	// (`security zones security-zone <z> host-inbound-traffic system-services`).
	junosSchemaZoneGrouping = "zone-system-services-object-type"
	// junosSchemaIfaceGrouping is the per-interface override
	// (`... security-zone <z> interfaces <i> host-inbound-traffic
	// system-services`). The two must enumerate the same tokens; the test
	// ENFORCES that rather than recording it as a comment.
	junosSchemaIfaceGrouping = "interface-system-services-object-type"

	// junosSchemaTokenCount is the size of the 24.4R2 enumeration: 35 concrete
	// services plus the two meta tokens `all` and `any-service`. Pinned as a
	// second, independent guard so a token deletion REDS even if the hash pin is
	// re-baselined in the same edit. Bumping this is a deliberate act that must
	// come with a re-vendored module and a new hash.
	junosSchemaTokenCount = 37
)

// junosSchemaModuleSource decompresses the vendored YANG module and gates it on
// the pinned SHA-256.
func junosSchemaModuleSource(t *testing.T) string {
	t.Helper()
	f, err := os.Open(junosSchemaModule)
	if err != nil {
		t.Fatalf("opening the vendored Junos schema module %s: %v", junosSchemaModule, err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip %s: %v", junosSchemaModule, err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("reading %s: %v", junosSchemaModule, err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != junosSchemaModuleSHA256 {
		t.Fatalf("vendored Junos schema module %s has SHA-256 %s, want %s.\n"+
			"The module is the ORACLE for a security allowlist: it must be Juniper's "+
			"published bytes, not a locally edited copy. If you are intentionally moving to "+
			"a new target release, re-vendor from upstream and update the pin (and "+
			"junosSchemaTokenCount) in the same commit.",
			junosSchemaModule, got, junosSchemaModuleSHA256)
	}
	return string(raw)
}

// junosSchemaGroupingEnums extracts the `enum` values of a YANG grouping's
// `leaf name { type enumeration { ... } }` by brace-matching the grouping body,
// so an `enum` belonging to some later grouping can never leak in.
func junosSchemaGroupingEnums(t *testing.T, src, grouping string) []string {
	t.Helper()
	lines := strings.Split(src, "\n")
	head := regexp.MustCompile(`^\s*grouping ` + regexp.QuoteMeta(grouping) + `\s*\{`)
	start := -1
	for i, l := range lines {
		if head.MatchString(l) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("grouping %q not found in %s — the module moved or was replaced; "+
			"the oracle cannot be derived", grouping, junosSchemaModule)
	}
	depth, end := 0, -1
	for i := start; i < len(lines); i++ {
		depth += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		if depth == 0 && i > start {
			end = i
			break
		}
	}
	if end < 0 {
		t.Fatalf("grouping %q in %s is unterminated — parser or module is broken", grouping, junosSchemaModule)
	}
	enumRe := regexp.MustCompile(`^\s*enum "([^"]+)"`)
	var out []string
	for _, l := range lines[start : end+1] {
		if m := enumRe.FindStringSubmatch(l); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// junosSchemaSystemServices parses the vendored module and returns the CONCRETE
// `system-services` tokens — the enumeration minus the two meta tokens `all` and
// `any-service`, which name no single service.
//
// It also ENFORCES the zone-level / per-interface agreement that earlier
// revisions merely asserted in a comment: both groupings must enumerate exactly
// the same tokens, so one oracle legitimately governs both surfaces.
func junosSchemaSystemServices(t *testing.T) []string {
	t.Helper()
	src := junosSchemaModuleSource(t)

	zone := junosSchemaGroupingEnums(t, src, junosSchemaZoneGrouping)
	iface := junosSchemaGroupingEnums(t, src, junosSchemaIfaceGrouping)

	if len(zone) != junosSchemaTokenCount {
		t.Fatalf("grouping %s enumerates %d tokens, want %d (%v).\n"+
			"A changed count means the vendored module is not the pinned 24.4R2 enumeration "+
			"— re-vendor and update junosSchemaTokenCount deliberately, never to make a test pass.",
			junosSchemaZoneGrouping, len(zone), junosSchemaTokenCount, zone)
	}
	zoneSet, ifaceSet := map[string]bool{}, map[string]bool{}
	for _, tok := range zone {
		zoneSet[tok] = true
	}
	for _, tok := range iface {
		ifaceSet[tok] = true
	}
	missing, extra := diffSets(zoneSet, ifaceSet)
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("the zone-level (%s) and per-interface (%s) groupings enumerate DIFFERENT "+
			"tokens (only-in-zone %v, only-in-interface %v) — one oracle cannot govern both "+
			"surfaces; xpf models them with a single token set",
			junosSchemaZoneGrouping, junosSchemaIfaceGrouping, missing, extra)
	}

	var concrete []string
	meta := map[string]bool{}
	for _, tok := range zone {
		if tok == "all" || tok == "any-service" {
			meta[tok] = true
			continue
		}
		concrete = append(concrete, tok)
	}
	for _, m := range []string{"all", "any-service"} {
		if !meta[m] {
			t.Fatalf("grouping %s is missing the meta token %q — this is not the "+
				"host-inbound system-services enumeration", junosSchemaZoneGrouping, m)
		}
	}
	return concrete
}

// hiOpeningKeys decomposes one L4Match into the ATOMIC openings it grants — one
// key per (proto, port), per (proto, icmp-type), or the bare protocol number —
// so two token sets can be compared by WHAT THEY OPEN rather than by token
// spelling or by how the matches happen to be grouped.
//
// Decomposition is what makes the comparison correct as well as rename-proof.
// An alias may bundle openings differently from the tokens it aliases:
// `ssh-netconf` emits ONE tcp match carrying {22, 830}, while `ssh` and
// `netconf` emit two matches of one port each. Compared as whole matches those
// look like a tuple no Junos token opens; compared as atomic openings they are
// exactly tcp/22 ∪ tcp/830, which is the truth. Grouping is an nft-rendering
// detail; the security-relevant question is only which (proto, port) pairs
// become reachable.
func hiOpeningKeys(m L4Match) []string {
	prefix := ""
	if m.Reject {
		prefix = "reject:"
	}
	proto := strconv.Itoa(int(m.Proto))
	if m.ICMPType != nil {
		return []string{prefix + proto + "/type" + strconv.Itoa(int(*m.ICMPType))}
	}
	if len(m.Ports) == 0 {
		// A bare IP protocol number (gre=47, ospf=89, ...): the protocol itself
		// is the opening.
		return []string{prefix + proto}
	}
	var out []string
	for _, p := range m.Ports {
		for port := int(p.Lo); port <= int(p.Hi); port++ {
			out = append(out, prefix+proto+"/"+strconv.Itoa(port))
		}
	}
	return out
}

// TestHostInboundAllUnionMatchesJunosSchema_3226 is the bidirectional statement
// of the `system-services all` contract, with BOTH directions derived from
// Juniper's published schema rather than from a hand-typed list:
//
//	fail-CLOSED direction — every concrete service in Juniper's enumeration must
//	be recognized at commit AND be in the `all` union. A service missing from
//	the union is denied by `all` and (because strict validation rejects any
//	token outside the allowlist) cannot be restored by naming it either, so its
//	traffic has no in-grammar escape short of the packet-wide `any-service`.
//	This is the #3200-class parity gap that recurred three times.
//
//	fail-OPEN direction — the union may open no (proto, port) tuple that
//	Juniper's own set does not already open. Stated over TUPLES, not names, so
//	it cannot be satisfied by renaming a token, and so a future xpf-only service
//	with a port of its own is caught automatically.
//
// The second direction is what keeps `r-exec`/`rexec` (tcp/512) and `gre` (IP
// protocol 47) out: Juniper's enumeration has neither, and unlike the
// port-neutral xpf spellings (`webapi-clear-text`/`webapi-ssl` resolve to the
// http/https ports, `ssh-netconf`/`netconf-ssh` to ssh ∪ netconf, `ipsec` to
// ike's) each opens something no Junos token opens.
//
// FAIL-ON-REVERT: drop a schema token from KnownHostInboundSystemServices and
// the fail-closed direction names it; put `r-exec` or `gre` back in the
// expansion and the fail-open direction names the exact tuple it added.
func TestHostInboundAllUnionMatchesJunosSchema_3226(t *testing.T) {
	schema := junosSchemaSystemServices(t)

	inExpansion := map[string]bool{}
	for _, tok := range HostInboundAllExpansionServices() {
		inExpansion[tok] = true
	}

	// --- fail-CLOSED: Juniper's set ⊆ recognized, and ⊆ the `all` union. -----
	for _, tok := range schema {
		if !KnownHostInboundSystemServices[tok] {
			t.Errorf("Junos schema service %q is not recognized at commit — a valid vSRX "+
				"`system-services %s` is HARD-REJECTED (#3200 parity gap)", tok, tok)
			continue
		}
		if !inExpansion[tok] {
			t.Errorf("Junos schema service %q is missing from the `system-services all` union — "+
				"`all` must cover the services Juniper defines (#3226)", tok)
		}
		if HostInboundNonJunosSystemServices[tok] {
			t.Errorf("%q is in Juniper's schema, so it is NOT an xpf-only extension; "+
				"HostInboundNonJunosSystemServices must not exclude it from `all`", tok)
		}
	}

	// --- fail-OPEN: the union opens no tuple Juniper's set does not. ---------
	for _, family := range []string{"ip", "ip6"} {
		schemaOpens := map[string]string{} // opening -> the token that grants it
		for _, tok := range schema {
			for _, m := range HostInboundServiceMatch(tok, family) {
				for _, k := range hiOpeningKeys(m) {
					schemaOpens[k] = tok
				}
			}
		}
		if len(schemaOpens) == 0 {
			t.Fatalf("(%s) Juniper's schema set opens ZERO tuples — the subset check below "+
				"would pass vacuously", family)
		}
		for _, m := range HostInboundServiceMatch("all", family) {
			for _, k := range hiOpeningKeys(m) {
				if _, ok := schemaOpens[k]; !ok {
					t.Errorf("`system-services all` (%s) opens %s (from %+v), which NO service in "+
						"Juniper's enumeration opens — the union is wider than Junos's `all` (#3226)",
						family, k, m)
				}
			}
		}
	}

	// The two known-excluded tokens stay RECOGNIZED: the carve-out narrows
	// `all`, it does not remove the service. (Stated by name because this is a
	// claim about the tokens themselves, not about ports.)
	for _, tok := range []string{"r-exec", "rexec", "gre"} {
		if !KnownHostInboundSystemServices[tok] {
			t.Errorf("%q must stay a recognized token — listing it explicitly must still work", tok)
		}
		if inExpansion[tok] {
			t.Errorf("%q is absent from Juniper's schema and opens a tuple no Junos token opens; "+
				"it must be excluded from the `all` union (HostInboundNonJunosSystemServices)", tok)
		}
	}
	// Port-level restatement of the rexec exclusion, which survives a rename.
	for _, family := range []string{"ip", "ip6"} {
		for _, m := range HostInboundServiceMatch("all", family) {
			if m.Proto != HostInboundProtoTCP {
				continue
			}
			for _, p := range m.Ports {
				if p.Lo <= 512 && 512 <= p.Hi {
					t.Errorf("`system-services all` (%s) opens tcp/512 via %+v — Junos's `all` never opens the rexec port (#3226)", family, m)
				}
			}
		}
	}
}

// TestHostInboundFixedPortJunosServicesCommit_3226 pins the Junos services this
// fold added that have a port Juniper actually FIXES: they commit, and they
// carry exactly that tuple on both families.
//
//	reverse-telnet TCP/2900, reverse-ssh TCP/2901 — junos-es-conf-system 24.4R2
//	  `[edit system services reverse telnet|ssh] port` carry explicit YANG
//	  `default` statements. This is the strongest evidence class available: a
//	  machine-readable platform default in the schema the CLI validates against.
//	lsselfping UDP/8503 — RFC 7746 §3 ("The UDP Destination Port MUST be
//	  lsp-self-ping (8503)") and §6 (IANA assignment). Deliberately NOT 3503:
//	  that is `lsping` (MPLS echo), a different protocol with a similar name,
//	  and conflating them would open the wrong port for both.
//
// FAIL-ON-REVERT: drop one from KnownHostInboundSystemServices and its commit
// subtest goes RED; move a port and the tuple assertion names the drift.
func TestHostInboundFixedPortJunosServicesCommit_3226(t *testing.T) {
	want := map[string][]L4Match{
		"reverse-telnet": {{Proto: HostInboundProtoTCP, Ports: []PortRange{{Lo: 2900, Hi: 2900}}}},
		"reverse-ssh":    {{Proto: HostInboundProtoTCP, Ports: []PortRange{{Lo: 2901, Hi: 2901}}}},
		"lsselfping":     {{Proto: HostInboundProtoUDP, Ports: []PortRange{{Lo: 8503, Hi: 8503}}}},
	}
	for tok, tuples := range want {
		t.Run(tok, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone mgmt host-inbound-traffic system-services " + tok,
			})
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict commit rejected `host-inbound-traffic system-services %s` (Junos schema service, #3226): %v", tok, err)
			}
			if !KnownHostInboundSystemServices[tok] {
				t.Fatalf("%s must be in KnownHostInboundSystemServices so commit accepts it", tok)
			}
			if HostInboundUnportedSystemServices[tok] {
				t.Fatalf("%s has an authoritative fixed port; it must NOT be in HostInboundUnportedSystemServices", tok)
			}
			// Dual-family (absent from the family map), like ssh/telnet.
			if fam, scoped := HostInboundServiceFamily[tok]; scoped {
				t.Errorf("%s must be dual-family (HostInboundServiceFamily[%q]=%q)", tok, tok, fam)
			}
			for _, family := range []string{"ip", "ip6"} {
				got := HostInboundServiceMatch(tok, family)
				if len(got) != len(tuples) {
					t.Fatalf("%s (%s): got %d match tuples, want %d (%+v)", tok, family, len(got), len(tuples), got)
				}
				for i, w := range tuples {
					if got[i].Proto != w.Proto || len(got[i].Ports) != len(w.Ports) ||
						got[i].Ports[0] != w.Ports[0] || got[i].Reject {
						t.Errorf("%s (%s) tuple %d: got %+v, want %+v (admit)", tok, family, i, got[i], w)
					}
				}
			}
		})
	}
	// lsping and lsselfping are different protocols on different ports; a fold
	// of one into the other would silently open the wrong port for both.
	a := hiOpeningKeys(HostInboundServiceMatch("lsping", "ip")[0])
	b := hiOpeningKeys(HostInboundServiceMatch("lsselfping", "ip")[0])
	if len(a) != 1 || len(b) != 1 || a[0] == b[0] {
		t.Errorf("lsping (%v) and lsselfping (%v) must open exactly one, DIFFERENT port each: "+
			"lsping is MPLS echo udp/3503, lsselfping is RFC 7746 udp/8503", a, b)
	}
}

// TestHostInboundUnportedJunosServicesCommit_3226 pins the other half: the Junos
// services for which Juniper fixes NO listening port. They must COMMIT (they are
// real vSRX services — rejecting them is the #3200 gap) and must synthesize NO
// admission tuple on either family (any port would be a guess).
//
// Two of these carried a synthesized port in an earlier revision of this fold:
//
//	r2cp udp/28762 — draft-dubois-r2cp-00 calls 28762 a value prototypes
//	  "suggested"; Juniper adopts it nowhere. `[edit protocols r2cp] server-port`
//	  is range 1..65535 with NO YANG default.
//	rpm tcp+udp/7  — 7 is the FLOOR of the `[edit services rpm probe-server]
//	  port` range ("Port number 7 through 65535"), not a default, and the
//	  probe-server container is presence-gated so nothing listens without
//	  explicit configuration.
//
// The basis is a deliberate CHOICE under uncertainty, NOT an inference from the
// schema. An earlier revision argued that the absence of a YANG `default` proved
// no fixed port existed; that generalization is false — `[edit system services
// telnet]` has no port leaf either, yet telnet is TCP/23 — and has been
// withdrawn. What holds is narrower: no authoritative host-inbound tuple was
// found for these tokens, and under that gap opening nothing fails in one
// direction and visibly, whereas a guessed port fails in both directions and
// silently. See config.HostInboundUnportedSystemServices for per-token evidence
// and for what is explicitly NOT sourced.
//
// FAIL-ON-REVERT: give any of these a tuple (add a case arm, or drop it from
// HostInboundUnportedSystemServices) and the no-tuple assertion goes RED naming
// the port that reappeared.
func TestHostInboundUnportedJunosServicesCommit_3226(t *testing.T) {
	schema := map[string]bool{}
	for _, tok := range junosSchemaSystemServices(t) {
		schema[tok] = true
	}
	if len(HostInboundUnportedSystemServices) == 0 {
		t.Fatal("HostInboundUnportedSystemServices is empty — the subtests below would be vacuous")
	}
	// BIJECTION with the reason map: a token cannot be given a no-admit mapping
	// without stating WHY, and a reason cannot name a token that is not actually
	// unported. The two classes are epistemically different — an
	// operator-configured port is a positive fact about how Junos defines the
	// service, an unsourced one is an admission about the limits of our sourcing
	// — and conflating them is the overstatement pattern this fold keeps having
	// to correct.
	for tok := range HostInboundUnportedSystemServices {
		reason, ok := HostInboundNoAdmitReason[tok]
		if !ok {
			t.Errorf("%q has no HostInboundNoAdmitReason — every no-admit token must state "+
				"whether its port is operator-configured or simply unsourced", tok)
			continue
		}
		if reason != HostInboundNoPortOperatorConfigured && reason != HostInboundNoPortUnsourced {
			t.Errorf("%q has reason %q, which is neither %q nor %q", tok, reason,
				HostInboundNoPortOperatorConfigured, HostInboundNoPortUnsourced)
		}
	}
	for tok := range HostInboundNoAdmitReason {
		if !HostInboundUnportedSystemServices[tok] {
			t.Errorf("%q has a no-admit REASON but is not in HostInboundUnportedSystemServices — "+
				"the reason map must not claim a token xpf actually admits", tok)
		}
	}
	// Both classes must be populated, or the distinction is decorative.
	classes := map[string]int{}
	for _, r := range HostInboundNoAdmitReason {
		classes[r]++
	}
	for _, want := range []string{HostInboundNoPortOperatorConfigured, HostInboundNoPortUnsourced} {
		if classes[want] == 0 {
			t.Errorf("no token carries reason %q — if a class is empty, delete it rather than "+
				"keeping a distinction nothing uses", want)
		}
	}
	for tok := range HostInboundUnportedSystemServices {
		t.Run(tok, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone mgmt host-inbound-traffic system-services " + tok,
			})
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict commit rejected `host-inbound-traffic system-services %s` — it is a "+
					"Junos service, so rejecting it is the #3200 parity gap: %v", tok, err)
			}
			if !KnownHostInboundSystemServices[tok] {
				t.Fatalf("%s must stay recognized — the no-port model narrows what it admits, "+
					"it does not remove the token", tok)
			}
			// It is a genuine Junos service, so it must be in the schema oracle
			// and must NOT be treated as an xpf-only extension.
			if !schema[tok] {
				t.Errorf("%s is not in the Junos schema oracle — an unported token must still be a "+
					"real Junos service, otherwise it belongs in HostInboundNonJunosSystemServices", tok)
			}
			if HostInboundNonJunosSystemServices[tok] {
				t.Errorf("%s is a Junos service, not an xpf extension — it must stay in the `all` union", tok)
			}
			// The load-bearing assertion: NO tuple, either family.
			for _, family := range []string{"ip", "ip6"} {
				if got := HostInboundServiceMatch(tok, family); len(got) != 0 {
					t.Errorf("%s (%s) synthesized %d admission tuple(s) %+v — xpf has no "+
						"authoritative listening port for this service, so any port here is a guess "+
						"that opens an unused port while still denying the one actually in use (#3226)",
						tok, family, len(got), got)
				}
			}
		})
	}
	// The two historical guesses, restated at the union level: `all` must not
	// open them. This is the precise RED-on-revert for a literal revert of the
	// previous revision of this fold.
	for _, family := range []string{"ip", "ip6"} {
		for _, m := range HostInboundServiceMatch("all", family) {
			for _, p := range m.Ports {
				if m.Proto == HostInboundProtoUDP && p.Lo <= 28762 && 28762 <= p.Hi {
					t.Errorf("`system-services all` (%s) opens udp/28762 — the r2cp port is a draft "+
						"SUGGESTION, not a Junos default (#3226)", family)
				}
				if p.Lo <= 7 && 7 <= p.Hi {
					t.Errorf("`system-services all` (%s) opens proto %d port 7 — the RPM probe-server "+
						"range FLOOR is not a platform default (#3226)", family, m.Proto)
				}
			}
		}
	}
}

// TestHostInboundIsisCommitsAsL2NoOp asserts that
// `host-inbound-traffic protocols isis` is ACCEPTED at commit (#3311). IS-IS
// routing is supported via FRR, but before #3311 `isis` was absent from
// KnownHostInboundProtocols, so the stanza was HARD-REJECTED at commit even
// though Junos/vSRX accepts it — a fail-closed parity gap (the operator could
// not even author the stanza). IS-IS rides OSI/CLNP over L2 (not IP), so it is
// modeled as a recognized-but-no-op host-inbound token: it admits at commit but
// produces no IP host-inbound match on either enforcement surface (the kernel
// delivers IS-IS PDUs to FRR's isisd via an LLC socket, outside the IP filter).
//
// Fail-on-revert: remove `"isis"` from KnownHostInboundProtocols and commit
// rejects the stanza again, turning this RED. The companion membership check
// keeps `isis` in the HostInboundL2Protocols SSOT that the nft parity test and
// the Rust classifier rely on to stay consistent.
func TestHostInboundIsisCommitsAsL2NoOp(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone core host-inbound-traffic protocols isis",
		"set security zones security-zone core host-inbound-traffic protocols bgp",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected `host-inbound-traffic protocols isis` (vSRX parity gap, #3311): %v", err)
	}
	if !KnownHostInboundProtocols["isis"] {
		t.Fatal("isis must be in KnownHostInboundProtocols so commit accepts it")
	}
	if !HostInboundL2Protocols["isis"] {
		t.Fatal("isis must be in HostInboundL2Protocols (the L2/no-op SSOT the nft + Rust surfaces consult)")
	}
}

// TestHostInboundProtocolsAllExcludesL2 asserts that the SSOT-derived
// `protocols all` expansion (HostInboundAllExpansionProtocols) EXCLUDES every
// L2/non-IP protocol (HostInboundL2Protocols) while still including the IP
// routing protocols (#3311). This is the load-bearing use of
// HostInboundL2Protocols: the nft `all` case (pkg/daemon) and the Rust `all`
// arm both derive their expansion from this exclusion, so adding a new L2
// protocol to the SSOT automatically keeps it out of the IP expansion on both
// surfaces with no other edit.
//
// Fail-on-revert: remove "isis" from HostInboundL2Protocols and — because isis
// stays in KnownHostInboundProtocols — it reappears in the expansion, turning
// the "isis excluded" assertion RED. This is the genuine SSOT guard (the old
// arm-existence tests were false-green: the catch-all/default no-op masked a
// deleted explicit arm).
func TestHostInboundProtocolsAllExcludesL2(t *testing.T) {
	expansion := HostInboundAllExpansionProtocols()
	inExpansion := make(map[string]bool, len(expansion))
	for _, p := range expansion {
		inExpansion[p] = true
	}

	// The `all` meta-token never expands to itself.
	if inExpansion["all"] {
		t.Error("HostInboundAllExpansionProtocols must not contain the `all` meta-token")
	}
	// Every L2 protocol is excluded from the IP expansion.
	for l2 := range HostInboundL2Protocols {
		if inExpansion[l2] {
			t.Errorf("L2 protocol %q must be excluded from the `protocols all` IP expansion", l2)
		}
	}
	// IS-IS specifically: it IS a recognized routing token (so the exclusion is
	// meaningful) but must NOT appear in the IP expansion (because it is L2).
	if !KnownHostInboundProtocols["isis"] {
		t.Fatal("isis must be a recognized protocol for the exclusion to be meaningful")
	}
	if inExpansion["isis"] {
		t.Error("isis (L2) must not appear in the `protocols all` IP expansion")
	}
	// Sanity: real IP routing protocols still expand.
	for _, p := range []string{"ospf", "ospf3", "bgp", "bfd", "router-discovery"} {
		if !inExpansion[p] {
			t.Errorf("IP routing protocol %q must remain in the `protocols all` expansion", p)
		}
	}
}

// TestHostInboundUnknownTokenLenientDowngradesToWarning asserts the tolerant
// load / peer-sync path downgrades the unknown-token reject to a warning instead
// of failing the compile, so an already-persisted or peer-synced config carrying
// a stale token still boots (#3200 / #1960 no-brick). Both enforcement layers
// ignore the unknown token (Rust ignores it; nft now fails CLOSED on a
// zero-match zone), so the leniently-loaded config is inert and consistent.
func TestHostInboundUnknownTokenLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust host-inbound-traffic system-services sssh",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on an unknown host-inbound token: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "host-inbound-traffic token (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded host-inbound-token warning, got warnings: %v", cfg.Warnings)
	}
}
