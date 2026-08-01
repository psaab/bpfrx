package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// hostInboundFullAdmitWarnings returns the commit-time advisories emitted by
// ValidateConfig for a `system-services any-service` packet-wide full-admit.
// The advisory phrase is unique to this check.
func hostInboundFullAdmitWarnings(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "broad packet-wide full-admit") {
			out = append(out, w)
		}
	}
	return out
}

// hostInboundAllScopingWarnings returns the #3226 commit-time UPGRADE advisories
// emitted for a `system-services all` stanza on an enforcing (non-lifeline)
// zone/interface. The advisory phrase is unique to this check.
func hostInboundAllScopingWarnings(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "expands to the union of the") {
			out = append(out, w)
		}
	}
	return out
}

// Test_3226_SystemServicesAllEmitsFullAdmitAdvisory is the RED-on-revert guard
// for the commit-time advisories the issue's Direction asks for ("document it
// as such with an explicit commit warning"). Since #3226 the two tokens carry
// DIFFERENT advisories because they now have different semantics:
//
//   - `any-service` is still the packet-wide full admit -> the breadth advisory;
//   - `all` is the named-service union -> the SCOPING advisory, an upgrade
//     notice for a deploy that leaned on the old packet-wide breadth.
//
// Both must COMPILE with NO error (each is valid Junos; the advisory is a
// WARNING, never a reject).
//
// RED-on-revert: delete the advisory loops in compiler_validate_warn.go and
// both cases stop warning. Restoring `all` to HostInboundFullAdmitService makes
// it emit the FULL-ADMIT advisory instead of the scoping one, which this test
// also catches (each subtest asserts the OTHER advisory is absent).
func Test_3226_SystemServicesAllEmitsFullAdmitAdvisory(t *testing.T) {
	compileZone := func(t *testing.T, tok string) *Config {
		t.Helper()
		tree := buildTree(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set security zones security-zone trust host-inbound-traffic system-services " + tok,
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig must accept system-services %s (valid Junos, warn-not-reject): %v", tok, err)
		}
		return cfg
	}

	t.Run("zone-level-any-service", func(t *testing.T) {
		cfg := compileZone(t, "any-service")
		got := hostInboundFullAdmitWarnings(cfg)
		if len(got) != 1 {
			t.Fatalf("system-services any-service: expected exactly one full-admit advisory, got %d: %v", len(got), got)
		}
		if !strings.Contains(got[0], `zone "trust"`) {
			t.Errorf("advisory must name the zone, got: %q", got[0])
		}
		if !strings.Contains(got[0], "any-service") {
			t.Errorf("advisory must name the offending token, got: %q", got[0])
		}
		if extra := hostInboundAllScopingWarnings(cfg); len(extra) != 0 {
			t.Errorf("any-service must NOT draw the `all` scoping advisory, got: %v", extra)
		}
	})

	t.Run("zone-level-all", func(t *testing.T) {
		cfg := compileZone(t, "all")
		// #3226: `all` is no longer packet-wide, so it must NOT draw the
		// full-admit advisory. Reverting the narrowing turns this RED.
		if got := hostInboundFullAdmitWarnings(cfg); len(got) != 0 {
			t.Errorf("system-services all must NOT draw the packet-wide full-admit advisory (#3226), got: %v", got)
		}
		got := hostInboundAllScopingWarnings(cfg)
		if len(got) != 1 {
			t.Fatalf("system-services all: expected exactly one scoping advisory, got %d: %v", len(got), got)
		}
		if !strings.Contains(got[0], `zone "trust"`) {
			t.Errorf("scoping advisory must name the zone, got: %q", got[0])
		}
		if !strings.Contains(got[0], "any-service") {
			t.Errorf("scoping advisory must point at the `any-service` escape hatch, got: %q", got[0])
		}
	})
}

// Test_3226_AllScopingAdvisorySilentOnLifelineOnlyZone pins the advisory's
// noise gate: a zone whose every interface is a LIFELINE (fxp0 + the configured
// cluster control / fabric interfaces, #3277) is excluded from the host-inbound
// deny address sets by BuildZoneHostInboundViews, so it emits no rules at all
// and the #3226 narrowing cannot change its enforcement. Every shipped HA
// config puts `system-services all` on exactly such a zone (the lifeline-only
// `control` zone — docs/ha-cluster-userspace.conf), so an ungated advisory would
// fire on every cluster commit forever while flagging a guaranteed no-op.
//
// RED-on-revert: drop the `zoneEnforces` gate in compiler_validate_warn.go and
// this test goes RED with a spurious advisory.
func Test_3226_AllScopingAdvisorySilentOnLifelineOnlyZone(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set security zones security-zone control interfaces em0.0",
		"set security zones security-zone control host-inbound-traffic system-services all",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := hostInboundAllScopingWarnings(cfg); len(got) != 0 {
		t.Errorf("a lifeline-only zone must draw NO #3226 scoping advisory (the narrowing is a no-op there), got: %v", got)
	}
}

// Test_3226_SpecificServiceNoAdvisory pins the other half of the contract: a
// zone that lists only named/specific system-services (ssh, ping) is NOT a
// packet-wide full-admit and must draw NO #3226 advisory.
func Test_3226_SpecificServiceNoAdvisory(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services ping",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := hostInboundFullAdmitWarnings(cfg); len(got) != 0 {
		t.Fatalf("specific services (ssh/ping) must NOT draw a full-admit advisory, got: %v", got)
	}
}

// Test_3226_PerInterfaceFullAdmitAdvisory covers the #3362 per-interface
// override path: a full-admit / `all` set on only one interface of a zone must
// warn and name BOTH the zone and the interface. Both advisory flavours are
// exercised so the per-interface path cannot drift from the zone-level one.
func Test_3226_PerInterfaceFullAdmitAdvisory(t *testing.T) {
	compileIface := func(t *testing.T, tok string) *Config {
		t.Helper()
		tree := buildTree(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services " + tok,
			// a sibling interface with a specific service — must NOT warn.
			"set security zones security-zone wan interfaces ge-0/0/1.0 host-inbound-traffic system-services ssh",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig must accept a per-interface system-services %s: %v", tok, err)
		}
		return cfg
	}

	got := hostInboundFullAdmitWarnings(compileIface(t, "any-service"))
	if len(got) != 1 {
		t.Fatalf("expected exactly one per-interface full-admit advisory, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], `zone "wan"`) || !strings.Contains(got[0], `interface "ge-0/0/0.0"`) {
		t.Errorf("per-interface advisory must name both zone and interface, got: %q", got[0])
	}

	got = hostInboundAllScopingWarnings(compileIface(t, "all"))
	if len(got) != 1 {
		t.Fatalf("expected exactly one per-interface scoping advisory, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], `zone "wan"`) || !strings.Contains(got[0], `interface "ge-0/0/0.0"`) {
		t.Errorf("per-interface scoping advisory must name both zone and interface, got: %q", got[0])
	}
}

// hostInboundUnportedWarnings filters the #3226-fold advisory for Junos
// services xpf has no authoritative listening port for.
func hostInboundUnportedWarnings(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "accepted but NOT enforced") {
			out = append(out, w)
		}
	}
	return out
}

// Test_3226_UnportedSystemServiceEmitsAdvisory is the operator-visibility guard
// for the unverified-port half of the #3226 fold.
//
// r2cp / rpm / tcp-encap / appqoe / high-availability are real Junos services,
// so they must COMMIT (rejecting them is the #3200 parity gap this fold closes).
// But xpf has no authoritative listening port to admit for any of them — for
// rpm/r2cp because Junos documents the port as operator-chosen, for the rest
// because we could not find it — and refuses to invent one, since an invented
// port opens a port with no listener while still denying the port actually in
// use. The resulting behaviour is a deliberate fail-CLOSED
// divergence from Junos, and an operator who explicitly NAMED the service
// plainly expects it to work, so the divergence must be announced at commit
// rather than discovered as a silent blackhole in production.
//
// FAIL-ON-REVERT: drop the unportedAdvice call (or empty
// HostInboundUnportedSystemServices) and the advisory disappears, turning this
// RED. The negative case pins that a fully-ported stanza stays quiet, so the
// advisory cannot degrade into noise on every commit.
func Test_3226_UnportedSystemServiceEmitsAdvisory(t *testing.T) {
	// The expected reason class per token, recorded INDEPENDENTLY of
	// config.HostInboundNoAdmitReason. Reading that map to decide what the
	// advisory should say would be a tautology: the production wording is
	// derived from the same map, so any reclassification would be self-
	// consistent and invisible. Pinning the judgement here means silently
	// moving a token between classes — e.g. relabelling `rpm`, whose port Junos
	// documents as operator-configured, as merely unfound — goes RED.
	wantNoAdmitClass := map[string]string{
		// Junos DOCUMENTS these ports as operator-chosen over a range.
		"rpm":  HostInboundNoPortOperatorConfigured,
		"r2cp": HostInboundNoPortOperatorConfigured,
		// xpf could not find an authoritative tuple for these.
		"tcp-encap":         HostInboundNoPortUnsourced,
		"appqoe":            HostInboundNoPortUnsourced,
		"high-availability": HostInboundNoPortUnsourced,
	}
	for tok := range wantNoAdmitClass {
		if !HostInboundUnportedSystemServices[tok] {
			t.Fatalf("wantNoAdmitClass names %q, which is not in HostInboundUnportedSystemServices "+
				"— the expectation table is stale", tok)
		}
		if got := HostInboundNoAdmitReason[tok]; got != wantNoAdmitClass[tok] {
			t.Errorf("%q is classified %q but should be %q — a token's reason class is a "+
				"human judgement about the EVIDENCE, not a free parameter: "+
				"%q means Junos documents the port as operator-chosen, %q means xpf simply "+
				"could not find it, and telling an operator the wrong one is a lie either way",
				tok, got, wantNoAdmitClass[tok],
				HostInboundNoPortOperatorConfigured, HostInboundNoPortUnsourced)
		}
	}

	compile := func(t *testing.T, cmds ...string) *Config {
		t.Helper()
		cfg, err := CompileConfig(buildTree(t, cmds))
		if err != nil {
			t.Fatalf("CompileConfig must ACCEPT the stanza (these are real Junos services): %v", err)
		}
		return cfg
	}

	// Every unported token draws the advisory when named explicitly.
	for tok := range HostInboundUnportedSystemServices {
		if _, ok := wantNoAdmitClass[tok]; !ok {
			t.Fatalf("no expected reason class recorded for %q in wantNoAdmitClass — add it "+
				"deliberately; the expectation must be INDEPENDENT of the map under test", tok)
		}
		t.Run(tok, func(t *testing.T) {
			cfg := compile(t,
				"set security zones security-zone wan host-inbound-traffic system-services "+tok)
			got := hostInboundUnportedWarnings(cfg)
			if len(got) != 1 {
				t.Fatalf("expected exactly one unported-service advisory for %q, got %d: %v", tok, len(got), got)
			}
			if !strings.Contains(got[0], tok) {
				t.Errorf("advisory must NAME the service %q, got: %q", tok, got[0])
			}
			if !strings.Contains(got[0], `zone "wan"`) {
				t.Errorf("advisory must name the zone, got: %q", got[0])
			}
			// It must point at a remedy that ACTUALLY WORKS, or it is worse than
			// noise. `any-service` is the ONLY remedy on either enforcement
			// path; an lo0 filter rescues nothing (see the refuted-remedy guard
			// below for why). So the advisory must name any-service.
			if !strings.Contains(got[0], "any-service") {
				t.Errorf("advisory must name the escape that works on BOTH surfaces (any-service), got: %q", got[0])
			}
			// The wording must match the token's REASON CLASS. Telling an operator
			// their port "is configurable" when in truth xpf simply could not find
			// it would be a lie, and telling them xpf "could not find" a port that
			// Junos documents as operator-chosen would be a different lie. The
			// bijection between the sets is asserted in
			// TestHostInboundUnportedJunosServicesCommit_3226; this pins that the
			// classification actually reaches the operator.
			switch wantNoAdmitClass[tok] {
			case HostInboundNoPortOperatorConfigured:
				if !strings.Contains(got[0], "operator-configured port") {
					t.Errorf("%q has an operator-configured port; the advisory must say so "+
						"rather than claiming xpf could not find one, got: %q", tok, got[0])
				}
			case HostInboundNoPortUnsourced:
				if !strings.Contains(got[0], "could not find an authoritative listening port") {
					t.Errorf("%q is unsourced; the advisory must say xpf could not find the port "+
						"rather than implying the operator configured it, got: %q", tok, got[0])
				}
			default:
				t.Errorf("%q carries no recognized no-admit reason class", tok)
			}
			// REGRESSION GUARD on a REFUTED remedy. Two earlier revisions told
			// operators to fix this with an lo0 firewall filter — first
			// unconditionally, then "on the kernel path only". Both are false. On
			// AF_XDP, #3485 runs host-inbound first and never reaches the filter
			// after a deny. On the kernel path the priorities (xpf_lo0 0 <
			// xpf_hostinbound 10) are right but the inference is wrong: nftables
			// `accept` ends the current BASE CHAIN, not the hook — "The packet
			// advances to the next base chain" — so it still traverses
			// xpf_hostinbound and still hits the catch-all drop. Only `drop` ends
			// the whole ruleset.
			//
			// This asserts the false statement is ABSENT, which is a different
			// (and sound) thing from asserting a sentence is true: it cannot
			// validate wording, it just stops a known-wrong remedy coming back.
			// The remedy the advisory DOES name is bound behaviourally below.
			for _, refuted := range []string{"firewall filter", "kernel path"} {
				if strings.Contains(got[0], refuted) {
					t.Errorf("advisory names the REFUTED lo0-filter remedy (%q): an lo0 accept "+
						"cannot rescue a host-inbound deny on EITHER path — nftables `accept` "+
						"ends the base chain, not the hook, so the packet still reaches "+
						"xpf_hostinbound's catch-all drop. got: %q", refuted, got[0])
				}
			}
		})
	}

	// The remedy the advisory NAMES must actually work — otherwise this is the
	// same defect as before, just with different words. `any-service` is a
	// full-admit token, which is what makes it a real escape: the nft builder
	// emits a bare accept and NO catch-all drop for the zone, and the AF_XDP
	// classifier short-circuits admits() to true. Assert that property directly
	// rather than trusting the sentence.
	for tok := range HostInboundUnportedSystemServices {
		if !HostInboundFullAdmitService("any-service") {
			t.Fatal("the advised remedy \"any-service\" is not a full-admit token — the " +
				"advisory would be recommending something that does not lift the deny")
		}
		// The unported token itself admits nothing on either family (the deny the
		// advisory is warning about is real)...
		for _, family := range []string{"ip", "ip6"} {
			if got := HostInboundServiceMatch(tok, family); len(got) != 0 {
				t.Errorf("%s (%s) admits %+v — the advisory claims its traffic is DENIED; "+
					"if that premise is false the whole warning is wrong", tok, family, got)
			}
		}
	}

	// ...and naming `any-service` alongside SUPPRESSES the advisory entirely,
	// because with it present nothing is denied. Before this gate the two
	// advisory passes ran independently and a stanza with both emitted a
	// self-contradicting pair: one warning that `any-service` admits everything,
	// another that rpm is DENIED and the operator should add `any-service`.
	cfgBoth := compile(t,
		"set security zones security-zone wan host-inbound-traffic system-services rpm",
		"set security zones security-zone wan host-inbound-traffic system-services any-service")
	if got := hostInboundUnportedWarnings(cfgBoth); len(got) != 0 {
		t.Errorf("a stanza that already carries \"any-service\" must NOT also be told its "+
			"unported services are DENIED and to add \"any-service\" — nothing is denied "+
			"and the advice is already taken, got: %v", got)
	}
	// The full-admit advisory still fires for that stanza, so suppressing the
	// unported one loses no signal.
	if got := hostInboundFullAdmitWarnings(cfgBoth); len(got) != 1 {
		t.Errorf("the any-service full-admit advisory must still fire, got %d: %v", len(got), got)
	}

	// Several named at once collapse into ONE advisory listing all of them,
	// rather than N separate lines.
	cfg := compile(t,
		"set security zones security-zone wan host-inbound-traffic system-services rpm",
		"set security zones security-zone wan host-inbound-traffic system-services r2cp",
		"set security zones security-zone wan host-inbound-traffic system-services ssh")
	got := hostInboundUnportedWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("expected ONE combined advisory for two unported services, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "r2cp") || !strings.Contains(got[0], "rpm") {
		t.Errorf("combined advisory must name every unported service in the stanza, got: %q", got[0])
	}

	// Negative: a fully-ported stanza — including `all`, which COVERS the
	// unported services but does not name them — stays quiet. Warning on `all`
	// would fire on a large fraction of commits (every lifeline-only HA control
	// zone included) while telling the operator nothing they asked about.
	for _, quiet := range []string{"ssh", "all", "any-service"} {
		cfg := compile(t,
			"set security zones security-zone wan host-inbound-traffic system-services "+quiet)
		if got := hostInboundUnportedWarnings(cfg); len(got) != 0 {
			t.Errorf("`system-services %s` must NOT draw an unported-service advisory, got: %v", quiet, got)
		}
	}

	// Per-interface overrides carry the same grammar, so they warn too and must
	// name BOTH the zone and the interface (#3362 shape).
	cfg = compile(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services appqoe")
	got = hostInboundUnportedWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("expected one per-interface unported advisory, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], `zone "wan"`) || !strings.Contains(got[0], `interface "ge-0/0/0.0"`) {
		t.Errorf("per-interface unported advisory must name both zone and interface, got: %q", got[0])
	}
}

// hostInboundMatrixDoc is the operator-facing host-inbound reference.
const hostInboundMatrixDoc = "../../docs/host-inbound-service-matrix.md"

// TestHostInboundMatrixDocDoesNotAdviseTheRefutedRemedy widens the
// refuted-remedy guard from the commit advisory to the OPERATOR DOC.
//
// The lo0-filter remedy was withdrawn from the advisory, and a negative string
// guard stops it returning there. But that guard is scoped to the advisory
// string, and the claim is not: the operator guide kept telling people to
// "admit it with an explicit firewall filter on the real port" — and to read
// the advisory as saying so — for a full review round after the advisory itself
// had stopped. A guard narrower than the claim it protects is how the same
// error survives a withdrawal, which has now happened twice.
//
// The doc legitimately DESCRIBES the remedy in order to refute it (the
// revision-history table, the nftables quotes, the bypass-mechanism note), so a
// blanket grep would be a false positive. Instead the refutational material is
// fenced with REFUTED-REMEDY:BEGIN/END and this asserts the phrasing appears
// ONLY inside the fence. Live operator guidance outside it must name
// `any-service`, which is the only remedy that works on either enforcement
// path.
//
// FAIL-ON-REVERT: move any refuted phrasing outside the fence — or drop the
// fence — and this goes RED naming the line.
func TestHostInboundMatrixDocDoesNotAdviseTheRefutedRemedy(t *testing.T) {
	raw, err := os.ReadFile(hostInboundMatrixDoc)
	if err != nil {
		t.Fatalf("reading %s: %v", hostInboundMatrixDoc, err)
	}
	lines := strings.Split(string(raw), "\n")

	begin, end := -1, -1
	for i, l := range lines {
		if strings.Contains(l, "REFUTED-REMEDY:BEGIN") {
			begin = i
		}
		if strings.Contains(l, "REFUTED-REMEDY:END") {
			end = i
		}
	}
	if begin < 0 || end < 0 || end <= begin {
		t.Fatalf("%s is missing a well-formed REFUTED-REMEDY:BEGIN/END fence (begin=%d end=%d) — "+
			"without it this guard cannot tell refutation from live advice, and would either "+
			"pass vacuously or reject the refutation itself", hostInboundMatrixDoc, begin, end)
	}

	// Phrases that only make sense as ADVICE to use an lo0 filter. Kept narrow
	// on purpose: the goal is to catch the remedy coming back, not to police
	// every mention of the word "filter" (the doc discusses input filters
	// legitimately elsewhere, e.g. the appqoe udp/36000 discard guidance).
	refuted := []string{
		"firewall filter on the real port",
		"admit the real port with a firewall filter",
		"lo0 input-filter accept fixes",
		"kernel path only",
	}
	var offences []string
	for i, l := range lines {
		if i >= begin && i <= end {
			continue // inside the fence: this is the refutation itself
		}
		for _, bad := range refuted {
			if strings.Contains(l, bad) {
				offences = append(offences, fmt.Sprintf("%s:%d contains %q: %s",
					hostInboundMatrixDoc, i+1, bad, strings.TrimSpace(l)))
			}
		}
	}
	if len(offences) > 0 {
		t.Errorf("the operator doc advises the REFUTED lo0-filter remedy OUTSIDE the "+
			"REFUTED-REMEDY fence. An lo0 accept cannot rescue a host-inbound deny on "+
			"EITHER path — nftables `accept` ends the base chain, not the hook, so the "+
			"packet still reaches xpf_hostinbound's catch-all drop; and #3485 means AF_XDP "+
			"never evaluates the filter after a deny. `any-service` is the only remedy.\n  %s",
			strings.Join(offences, "\n  "))
	}

	// Anti-vacuity: the fence must actually contain the refutation, or the
	// exclusion above would be protecting nothing.
	fenced := strings.Join(lines[begin:end+1], "\n")
	if !strings.Contains(fenced, "kernel path only") {
		t.Errorf("the REFUTED-REMEDY fence does not contain the refutation it exists to "+
			"delimit — either it moved (and is now unguarded outside the fence) or the "+
			"fence is in the wrong place in %s", hostInboundMatrixDoc)
	}
	// And live guidance must still name the remedy that works.
	if !strings.Contains(string(raw), "any-service") {
		t.Errorf("%s no longer names `any-service` — withdrawing the false remedy must not "+
			"leave the operator with no remedy at all", hostInboundMatrixDoc)
	}
}

// Test_3226_AdvisoriesReasonAboutTheEffectiveTokenSet pins the STRUCTURAL fix
// for a family of self-contradicting advisory pairs.
//
// Junos host-inbound is ADDITIVE across the zone and interface levels: an
// interface admits a service when EITHER level lists it, and the dataplane
// enforcement view is built from that union. The commit advisories used to run
// per RAW STANZA, so they reasoned about a different object than the enforcer
// and emitted advice that contradicted it — and contradicted each other in the
// same commit output. Three shapes, all closed here:
//
//	any-service + all in ONE stanza      -> "everything is admitted" together
//	                                        with "ports are now DENIED".
//	zone any-service + interface rpm     -> "rpm is DENIED, add any-service"
//	                                        when the union already full-admits.
//	zone rpm + interface any-service     -> same, in the other direction.
//
// Fixing those case by case would have left the two views diverging, so the
// advisories now consume config.UnionHostInboundTokens — the same union the
// dataplane builder uses — and suppress the scoping / unported notices whenever
// the EFFECTIVE set full-admits.
//
// FAIL-ON-REVERT: drop the effectiveFullAdmits gates, or go back to passing the
// raw per-stanza token lists, and the contradicting pair reappears.
func Test_3226_AdvisoriesReasonAboutTheEffectiveTokenSet(t *testing.T) {
	compile := func(t *testing.T, cmds ...string) *Config {
		t.Helper()
		cfg, err := CompileConfig(buildTree(t, cmds))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return cfg
	}

	t.Run("any-service and all in one stanza", func(t *testing.T) {
		cfg := compile(t,
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone wan interfaces ge-0/0/0.0",
			"set security zones security-zone wan host-inbound-traffic system-services any-service",
			"set security zones security-zone wan host-inbound-traffic system-services all")
		if got := hostInboundAllScopingWarnings(cfg); len(got) != 0 {
			t.Errorf("`all` alongside `any-service` must NOT draw the scoping advisory — "+
				"any-service full-admits, so nothing `all` would have narrowed is actually "+
				"denied, and saying so contradicts the full-admit advisory in the same "+
				"output, got: %v", got)
		}
		// The full-admit notice still fires: suppressing the contradiction must
		// not lose the signal that this zone accepts everything.
		if got := hostInboundFullAdmitWarnings(cfg); len(got) != 1 {
			t.Errorf("the any-service full-admit advisory must still fire, got %d: %v", len(got), got)
		}
	})

	t.Run("zone any-service with interface rpm", func(t *testing.T) {
		cfg := compile(t,
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone wan interfaces ge-0/0/0.0",
			"set security zones security-zone wan host-inbound-traffic system-services any-service",
			"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services rpm")
		if got := hostInboundUnportedWarnings(cfg); len(got) != 0 {
			t.Errorf("the interface's EFFECTIVE set is zone{any-service} + iface{rpm}, which "+
				"full-admits — rpm traffic is NOT denied there, so the unported advisory must "+
				"not fire, got: %v", got)
		}
	})

	t.Run("zone rpm with interface any-service", func(t *testing.T) {
		cfg := compile(t,
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone wan interfaces ge-0/0/0.0",
			"set security zones security-zone wan host-inbound-traffic system-services rpm",
			"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services any-service")
		// The zone's ONLY interface overrides with a full-admit, so the
		// zone-level `rpm` is unobservable everywhere in this zone.
		if got := hostInboundUnportedWarnings(cfg); len(got) != 0 {
			t.Errorf("every interface in the zone overrides with `any-service`, so the "+
				"zone-level `rpm` is denied NOWHERE — the advisory must not claim it is, "+
				"got: %v", got)
		}
	})

	// ANTI-VACUITY: without a full-admit anywhere, the advisory still fires.
	// Otherwise the three suppressions above could be satisfied by an advisory
	// that never fires at all.
	t.Run("still fires when nothing full-admits", func(t *testing.T) {
		cfg := compile(t,
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone wan interfaces ge-0/0/0.0",
			"set security zones security-zone wan host-inbound-traffic system-services rpm")
		if got := hostInboundUnportedWarnings(cfg); len(got) != 1 {
			t.Fatalf("a zone naming `rpm` with no full-admit anywhere MUST still draw the "+
				"unported advisory, got %d: %v", len(got), got)
		}
		// And a second interface WITHOUT a full-admit override keeps the
		// zone-level advisory alive even when another interface has one.
		cfg = compile(t,
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone wan interfaces ge-0/0/0.0",
			"set security zones security-zone wan interfaces ge-0/0/1.0",
			"set security zones security-zone wan host-inbound-traffic system-services rpm",
			"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services any-service")
		if got := hostInboundUnportedWarnings(cfg); len(got) != 1 {
			t.Errorf("ge-0/0/1.0 has no override, so the zone-level `rpm` IS denied there and "+
				"the advisory must still fire, got %d: %v", len(got), got)
		}
	})
}

// Test_3226_AdvisoryUnionIsTheEnforcementUnion binds the advisory's notion of
// "effective token set" to the enforcer's. The contradiction class above existed
// because the two computed it separately; a shared helper only removes the class
// while it actually stays shared.
//
// config.UnionHostInboundTokens is the SSOT. The dataplane builder
// (pkg/dataplane/userspace unionHostInboundTokens) delegates to it, differing
// only by lower-casing for map keying — which cannot change MEMBERSHIP, because
// every predicate the advisories apply to the union is case-insensitive.
//
// FAIL-ON-REVERT: give either side its own union and the additive/order/dedup
// properties asserted here stop matching.
func Test_3226_AdvisoryUnionIsTheEnforcementUnion(t *testing.T) {
	cases := []struct {
		name        string
		zone, iface []string
		want        []string
	}{
		{"additive across levels", []string{"ssh"}, []string{"rpm"}, []string{"ssh", "rpm"}},
		{"zone tokens keep authored order first", []string{"ping", "ssh"}, []string{"rpm"}, []string{"ping", "ssh", "rpm"}},
		{"exact duplicates collapse", []string{"ssh"}, []string{"ssh", "rpm"}, []string{"ssh", "rpm"}},
		{"empties skipped", []string{"ssh", ""}, []string{" "}, []string{"ssh"}},
		{"nil override is the zone set", []string{"ssh"}, nil, []string{"ssh"}},
		{"nil zone is the override set", nil, []string{"rpm"}, []string{"rpm"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := UnionHostInboundTokens(tc.zone, tc.iface)
			if len(got) != len(tc.want) {
				t.Fatalf("UnionHostInboundTokens(%v,%v) = %v, want %v", tc.zone, tc.iface, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("UnionHostInboundTokens(%v,%v)[%d] = %q, want %q",
						tc.zone, tc.iface, i, got[i], tc.want[i])
				}
			}
		})
	}
	// The property the advisories actually depend on: a full-admit token
	// anywhere in EITHER level is a full-admit in the union, whatever its case.
	for _, tc := range []struct{ zone, iface []string }{
		{[]string{"any-service"}, []string{"rpm"}},
		{[]string{"rpm"}, []string{"any-service"}},
		{[]string{"rpm"}, []string{"ANY-SERVICE"}},
	} {
		full := false
		for _, svc := range UnionHostInboundTokens(tc.zone, tc.iface) {
			if HostInboundFullAdmitService(svc) {
				full = true
			}
		}
		if !full {
			t.Errorf("union of zone %v + iface %v must be recognized as full-admit — the "+
				"advisory suppression and the dataplane short-circuit both key on this",
				tc.zone, tc.iface)
		}
	}
}
