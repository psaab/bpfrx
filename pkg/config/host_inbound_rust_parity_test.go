package config

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/webmgmt"
)

// host_inbound_rust_parity_test.go closes the Go<->Rust drift gap for the
// host-inbound `system-services` / `protocols` token ALLOWLISTS (#3486).
//
// The recognized-token set is a SECURITY allowlist: it decides which Junos
// host-inbound tokens are meaningful, and (since #3200) commit-time validation
// hard-rejects any token outside it. Three enforcement layers must agree on the
// set:
//
//  1. commit-time validation (this package, config.KnownHostInbound*),
//  2. the nftables KERNEL mirror (pkg/daemon hostInbound*Matches), guarded by
//     TestHostInboundNftMatchesKnownTokens, and
//  3. the Rust AF_XDP classifier
//     (userspace-dp/src/afxdp/forwarding/host_inbound.rs
//     classify_system_service / classify_protocol).
//
// Before #3486 layer 3 was a HAND-MIRRORED copy with NO build-time parity
// check: a token added to the Go SSOT but not the Rust match (or vice versa)
// silently diverged — commit accepts a service the dataplane never admits, or
// the dataplane admits one the control plane rejects. That is the exact
// fail-open / fail-closed split-brain #3200 set out to prevent, reopened on the
// Rust surface.
//
// This test parses the Rust source (the established repo pattern — see
// pkg/dataplane/retirement_boundary_canary_test.go, which os.ReadFiles the
// userspace-xdp Rust tree) and asserts the Rust token sets EXACTLY equal the Go
// SSOT. Add a token to one side only and a subtest goes RED.

const hostInboundRustSource = "../../userspace-dp/src/afxdp/forwarding/host_inbound.rs"

// rustLineComment strips a trailing `// ...` from a Rust source line so a `=>`
// or a quoted word inside a comment can never be mistaken for a match arm or a
// token. The Rust file uses only `//` / `//!` / `///` line comments (no block
// comments) in the regions we parse, so line-stripping is sufficient. We do not
// attempt to honor `//` inside a string literal: the token regions contain no
// such literals, and a spurious strip there would only DROP a token, turning
// the parity assertion RED (fail-safe) rather than silently passing.
func rustStripComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// rustSection returns the substring of src between the first occurrence of
// startAnchor and the first occurrence of endAnchor that follows it. It fails
// the test if either anchor is missing so a refactor that renames a Rust fn /
// const cannot silently turn this contract into a no-op.
func rustSection(t *testing.T, src, startAnchor, endAnchor string) string {
	t.Helper()
	start := strings.Index(src, startAnchor)
	if start < 0 {
		t.Fatalf("anchor %q not found in %s — Rust source moved/renamed; update the parity test", startAnchor, hostInboundRustSource)
	}
	rest := src[start+len(startAnchor):]
	end := strings.Index(rest, endAnchor)
	if end < 0 {
		t.Fatalf("end anchor %q not found after %q in %s — Rust source moved/renamed; update the parity test", endAnchor, startAnchor, hostInboundRustSource)
	}
	return rest[:end]
}

var (
	// Captures a match-arm pattern of one-or-more string literals joined by
	// `|`, immediately before `=>`: `"a"` or `"a" | "b" | "c"` in `... =>`.
	rustMatchArmRe = regexp.MustCompile(`((?:"[^"]+"\s*\|\s*)*"[^"]+")\s*=>`)
	rustStringRe   = regexp.MustCompile(`"([^"]+)"`)
)

// rustMatchArmTokens extracts every string literal that appears in a match-arm
// PATTERN (left of `=>`) within section. The catch-all `_ => {}` carries no
// literal and is correctly ignored. Literals inside arm BODIES are not before a
// `=>` and so are never captured.
func rustMatchArmTokens(section string) map[string]bool {
	out := map[string]bool{}
	for _, arm := range rustMatchArmRe.FindAllStringSubmatch(section, -1) {
		for _, lit := range rustStringRe.FindAllStringSubmatch(arm[1], -1) {
			out[lit[1]] = true
		}
	}
	return out
}

// rustArrayTokens extracts the string literals from a `&[ ... ]` slice literal
// section (e.g. the body of KNOWN_ROUTING_PROTOCOL_TOKENS).
func rustArrayTokens(section string) map[string]bool {
	out := map[string]bool{}
	for _, lit := range rustStringRe.FindAllStringSubmatch(section, -1) {
		out[lit[1]] = true
	}
	return out
}

func goKeySet(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// diffSets returns the elements in want missing from got, and the extras in got
// not in want.
func diffSets(want, got map[string]bool) (missing, extra []string) {
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return
}

func assertSameSet(t *testing.T, name string, goSet, rustSet map[string]bool) {
	t.Helper()
	if len(rustSet) == 0 {
		t.Fatalf("%s: parsed ZERO tokens from the Rust source — parser/anchor broke, contract would be a no-op", name)
	}
	missing, extra := diffSets(goSet, rustSet)
	if len(missing) == 0 && len(extra) == 0 {
		return
	}
	t.Errorf("%s: Go SSOT and Rust classifier token sets DRIFTED (#3486 split-brain risk).\n"+
		"  in Go SSOT but MISSING from Rust: %v\n"+
		"  in Rust but NOT in Go SSOT:       %v\n"+
		"  Go set:   %v\n"+
		"  Rust set: %v",
		name, missing, extra, sortedKeys(goSet), sortedKeys(rustSet))
}

// TestHostInboundRustClassifierMatchesGoSSOT is the Go<->Rust drift guard
// (#3486). It parses the Rust AF_XDP classifier and asserts each of its
// host-inbound token sets EXACTLY equals the corresponding Go SSOT set:
//
//   - classify_system_service arms  == config.KnownHostInboundSystemServices
//   - classify_protocol arms        == config.KnownHostInboundProtocols
//   - KNOWN_ROUTING_PROTOCOL_TOKENS == config.KnownHostInboundProtocols \ {all}
//   - HOST_INBOUND_L2_PROTOCOLS     == config.HostInboundL2Protocols
//
// Fail-on-revert: add a service/protocol to one side only (or drop one) and the
// corresponding subtest reports the precise missing/extra token. This is a real
// contract, not a tautology — both sides are derived independently (Go from the
// in-package maps, Rust from its source text).
func TestHostInboundRustClassifierMatchesGoSSOT(t *testing.T) {
	raw, err := os.ReadFile(hostInboundRustSource)
	if err != nil {
		t.Fatalf("reading Rust host-inbound classifier %s: %v", hostInboundRustSource, err)
	}
	src := rustStripComments(string(raw))

	// system-services: classify_system_service { match token { ... } }.
	svcSection := rustSection(t, src,
		"fn classify_system_service(", "fn classify_protocol(")
	rustServices := rustMatchArmTokens(svcSection)
	assertSameSet(t, "system-services (classify_system_service vs KnownHostInboundSystemServices)",
		goKeySet(KnownHostInboundSystemServices), rustServices)

	// protocols: classify_protocol { match token { ... } }.
	protoSection := rustSection(t, src,
		"fn classify_protocol(", "fn is_icmp_host_inbound_global_accept(")
	rustProtocols := rustMatchArmTokens(protoSection)
	assertSameSet(t, "protocols (classify_protocol vs KnownHostInboundProtocols)",
		goKeySet(KnownHostInboundProtocols), rustProtocols)

	// KNOWN_ROUTING_PROTOCOL_TOKENS = KnownHostInboundProtocols minus the `all`
	// meta-token (the Rust const lists each concrete routing protocol; `all` is
	// the recursion entry handled by the classify_protocol arm above).
	knownRoutingSection := rustSection(t, src,
		"KNOWN_ROUTING_PROTOCOL_TOKENS: &[&str] = &[", "];")
	rustKnownRouting := rustArrayTokens(knownRoutingSection)
	wantRouting := goKeySet(KnownHostInboundProtocols)
	delete(wantRouting, "all")
	assertSameSet(t, "routing tokens (KNOWN_ROUTING_PROTOCOL_TOKENS vs KnownHostInboundProtocols\\{all})",
		wantRouting, rustKnownRouting)

	// HOST_INBOUND_L2_PROTOCOLS = config.HostInboundL2Protocols (the L2/non-IP
	// set whose `protocols all` exclusion is load-bearing on both surfaces).
	l2Section := rustSection(t, src,
		"HOST_INBOUND_L2_PROTOCOLS: &[&str] = &[", "];")
	rustL2 := rustArrayTokens(l2Section)
	assertSameSet(t, "L2 protocols (HOST_INBOUND_L2_PROTOCOLS vs HostInboundL2Protocols)",
		goKeySet(HostInboundL2Protocols), rustL2)

	// #3226: KNOWN_SYSTEM_SERVICE_TOKENS = KnownHostInboundSystemServices minus
	// the two meta tokens (`all` is the recursion entry handled by the
	// classify_system_service arm; `any-service` is the full-admit
	// short-circuit). This list is what the Rust `system-services all`
	// expansion is derived FROM, so a token present on only one side would make
	// the two enforcement layers expand `all` differently — a split-brain that
	// the arm-set assertion above cannot see, because both sides still
	// RECOGNIZE the token.
	knownSvcSection := rustSection(t, src,
		"KNOWN_SYSTEM_SERVICE_TOKENS: &[&str] = &[", "];")
	rustKnownSvc := rustArrayTokens(knownSvcSection)
	wantSvc := goKeySet(KnownHostInboundSystemServices)
	delete(wantSvc, "all")
	delete(wantSvc, "any-service")
	assertSameSet(t, "system-service tokens (KNOWN_SYSTEM_SERVICE_TOKENS vs KnownHostInboundSystemServices\\{all,any-service})",
		wantSvc, rustKnownSvc)

	// #3226: HOST_INBOUND_NON_JUNOS_SERVICES = config.HostInboundNonJunosSystem
	// Services — the xpf-only extension set EXCLUDED from the `system-services
	// all` expansion. Drift here means one layer's `all` opens a raw IP protocol
	// the other's does not.
	nonJunosSection := rustSection(t, src,
		"HOST_INBOUND_NON_JUNOS_SERVICES: &[&str] = &[", "];")
	rustNonJunos := rustArrayTokens(nonJunosSection)
	assertSameSet(t, "non-Junos services (HOST_INBOUND_NON_JUNOS_SERVICES vs HostInboundNonJunosSystemServices)",
		goKeySet(HostInboundNonJunosSystemServices), rustNonJunos)
}

// TestHostInboundAllExpansionMatchesRust_3226 is the BEHAVIOURAL half of the
// `system-services all` parity contract. TestHostInboundRustClassifierMatchesGo
// SSOT proves the two layers recognize the same TOKENS; this proves they expand
// `all` to the same SET. Without it, one layer could exclude a token from the
// expansion (or fail to) while both still list it, so an `all` zone would admit
// a service on the kernel path that the AF_XDP path denies — exactly the
// split-brain #3200 exists to prevent, on the surface #3226 created.
//
// The Rust expansion is recomputed from its own source text
// (KNOWN_SYSTEM_SERVICE_TOKENS minus HOST_INBOUND_NON_JUNOS_SERVICES, the
// definition of `system_service_all_expansion`), so the two sides are derived
// independently.
func TestHostInboundAllExpansionMatchesRust_3226(t *testing.T) {
	raw, err := os.ReadFile(hostInboundRustSource)
	if err != nil {
		t.Fatalf("reading Rust host-inbound classifier %s: %v", hostInboundRustSource, err)
	}
	src := rustStripComments(string(raw))

	rustKnown := rustArrayTokens(rustSection(t, src,
		"KNOWN_SYSTEM_SERVICE_TOKENS: &[&str] = &[", "];"))
	rustNonJunos := rustArrayTokens(rustSection(t, src,
		"HOST_INBOUND_NON_JUNOS_SERVICES: &[&str] = &[", "];"))
	rustExpansion := map[string]bool{}
	for tok := range rustKnown {
		if !rustNonJunos[tok] {
			rustExpansion[tok] = true
		}
	}

	goExpansion := map[string]bool{}
	for _, tok := range HostInboundAllExpansionServices() {
		goExpansion[tok] = true
	}

	assertSameSet(t, "`system-services all` expansion (Rust system_service_all_expansion vs Go HostInboundAllExpansionServices)",
		goExpansion, rustExpansion)

	// The expansion must be non-trivial and must exclude the meta tokens, or
	// the equality above could hold vacuously / recurse forever.
	if len(goExpansion) < 10 {
		t.Fatalf("`all` expansion has only %d tokens — contract looks vacuous: %v", len(goExpansion), sortedKeys(goExpansion))
	}
	for _, meta := range []string{"all", "any-service"} {
		if goExpansion[meta] {
			t.Errorf("`all` expansion must not contain the meta token %q", meta)
		}
	}
	// gre is recognized on BOTH sides yet excluded from BOTH expansions — the
	// property that makes the non-Junos set load-bearing rather than decorative.
	if !KnownHostInboundSystemServices["gre"] || !rustKnown["gre"] {
		t.Errorf("gre must stay a recognized system-service on both sides (so the exclusion is meaningful)")
	}
	if goExpansion["gre"] || rustExpansion["gre"] {
		t.Errorf("gre must be excluded from the `all` expansion on BOTH sides (#3226)")
	}
}

// rustArmInsertPortRe captures the tcp-port the classify_system_service arm
// starting at a given token inserts: from the token to the FIRST
// `hi.tcp_ports.insert(<N>)` within the same `{ ... }` arm body (the `[^}]`
// class stops the match at the arm's closing brace so it cannot leak into a
// later arm). Tolerant of whitespace / newlines and the alias order inside the
// pattern (`"http" | "webapi-clear-text"`).
func rustArmInsertPort(t *testing.T, section, token string) uint16 {
	t.Helper()
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(token) + `"[^}]*?hi\.tcp_ports\.insert\((\d+)\)`)
	m := re.FindStringSubmatch(section)
	if m == nil {
		t.Fatalf("could not find `hi.tcp_ports.insert(N)` for the %q arm in classify_system_service — "+
			"Rust web-management admit moved/renamed; update the #5715 port-parity test", token)
	}
	n, err := strconv.ParseUint(m[1], 10, 16)
	if err != nil {
		t.Fatalf("Rust %q arm inserts a non-uint16 port %q: %v", token, m[1], err)
	}
	return uint16(n)
}

// TestHostInboundRustWebPortsMatchSSOT_5715 is the cross-LANGUAGE PORT contract
// the #5715 research flagged as missing: TestHostInboundRustClassifierMatchesGoSSOT
// proves Go and Rust know the same http/https TOKENS, but NOT that they admit the
// same PORTS. This asserts the Rust classifier inserts EXACTLY the webmgmt SSOT
// ports (80/443) for the http and https arms — the same constants the Go catalog
// (config.HostInboundServiceMatch) and the daemon listener bind derive from.
//
// FAIL-ON-REVERT: change the Rust `http` arm to `insert(8080)` (or the SSOT
// constant) and this goes RED, naming the mismatch. It fails LOUDLY (never a
// zero-match pass) if the Rust arm moves — rustArmInsertPort t.Fatals on no match.
func TestHostInboundRustWebPortsMatchSSOT_5715(t *testing.T) {
	raw, err := os.ReadFile(hostInboundRustSource)
	if err != nil {
		t.Fatalf("reading Rust host-inbound classifier %s: %v", hostInboundRustSource, err)
	}
	src := rustStripComments(string(raw))
	svcSection := rustSection(t, src, "fn classify_system_service(", "fn classify_protocol(")

	if got := rustArmInsertPort(t, svcSection, "http"); got != webmgmt.HTTPPort {
		t.Errorf("Rust `http` admits TCP/%d, but the webmgmt SSOT (and Go catalog + listener) use %d — port drift",
			got, webmgmt.HTTPPort)
	}
	if got := rustArmInsertPort(t, svcSection, "https"); got != webmgmt.HTTPSPort {
		t.Errorf("Rust `https` admits TCP/%d, but the webmgmt SSOT (and Go catalog + listener) use %d — port drift",
			got, webmgmt.HTTPSPort)
	}
}
