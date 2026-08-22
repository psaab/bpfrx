package userspace

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// junos_host_residual_6612_test.go is the coverage lock for the #4146 junos-host
// DENY projection's WARN-ONLY REMAINDER — the classes #6612 enumerates as
// un-representable in the kernel `xpf_hostinbound` chain.
//
// #6612 closes on a single claim: "each item above is documented … and each
// affected policy emits the #4168 commit warning naming itself." That claim was
// prose. This file makes it a contract, because the remainder has exactly the
// failure mode that is worst here — a policy that commits clean, renders no
// kernel rule, and says nothing — and one member of the enumeration was in that
// state (a destination-scoped `permit`; see the row below).
//
// Every row asserts BOTH halves, because either alone is satisfiable by a bug:
//
//   1. NO kernel rule is rendered. "No partial / coarsened kernel rule is ever
//      emitted for the remainder" — a silently-narrower-than-authored kernel
//      deny would be a new parity gap, so zero rules is the requirement, not an
//      accident of the fixture.
//   2. The #4168 commit warning fires and NAMES the policy. Without this the
//      operator's only signal that the policy is unenforced is its absence from
//      a ruleset they have no reason to read.
//
// And every row carries its own FLIP — the same fixture with the residual
// attribute neutralised — asserting that the pair actually changes state. That
// is what pins WHICH property drove the row: a fixture that failed to compile
// its scheduler, or named an address book entry that does not exist, would also
// render zero rules and would also warn, and would be indistinguishable from a
// working row without the flip.

// residualBase is the minimal zone/interface/address-book scaffolding. `untrust`
// is the ingress zone under test and owns a non-lifeline interface, so it
// resolves to a real iifname scope — without that every row would render zero
// rules for the uninteresting reason that the zone is unenforceable.
var residualBase = []string{
	"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	"set security zones security-zone untrust interfaces ge-0/0/1.0",
	"set security zones security-zone untrust host-inbound-traffic system-services ssh",
	"set security zones security-zone trust interfaces ge-0/0/0.0",
	"set security address-book global address bad-host 10.0.0.5/32",
	"set security address-book global address fw-mgmt 10.0.1.1/32",
	"set security address-book global address mgmt-net 10.10.0.0/24",
}

// feedScaffolding binds an address-book name to a dynamic feed, which is the
// "not commit-stable" taint the projection refuses to render.
var feedScaffolding = []string{
	"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
	"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
	"set security dynamic-address address-name feed-bad profile feed-name malware",
}

// schedulerScaffolding defines the scheduler a scheduler-gated policy names —
// without it CompileConfig rejects the reference and the row would exercise the
// undefined-scheduler error rather than the time-window residual.
var schedulerScaffolding = []string{
	"set schedulers scheduler workhours daily start-time 09:00:00",
	"set schedulers scheduler workhours daily stop-time 17:00:00",
}

func residualCfg(t *testing.T, cmds ...[]string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, group := range cmds {
		for _, cmd := range group {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// residualRuleCount is the number of kernel DROP rules the daemon would render
// for this config — the real consumer path (BuildJunosHostPrograms wraps
// config.BuildJunosHostDenyProjection and is what pkg/daemon feeds to the
// nftables renderer).
func residualRuleCount(cfg *config.Config) int {
	n := 0
	for _, p := range BuildJunosHostPrograms(cfg) {
		n += len(p.RulesV4) + len(p.RulesV6)
	}
	return n
}

// residualWarnings returns the #4146/#4168 junos-host parity warnings naming the
// given policy. Filtering by policy NAME (not merely counting) is what makes the
// assertion "the warning names itself" rather than "some warning fired".
func residualWarnings(cfg *config.Config, policy string) []string {
	var out []string
	want := fmt.Sprintf("security policy %q", policy)
	for _, w := range config.ValidateConfig(cfg) {
		if strings.Contains(w, "to-zone junos-host") && strings.Contains(w, "#4146") &&
			strings.Contains(w, want) {
			out = append(out, w)
		}
	}
	return out
}

// policy builds the four set lines of one `from-zone untrust to-zone junos-host`
// policy, so a row differs from its flip in exactly the field under test.
func policy(name, src, dst, app, action string) []string {
	p := "set security policies from-zone untrust to-zone junos-host policy " + name + " "
	return []string{
		p + "match source-address " + src,
		p + "match destination-address " + dst,
		p + "match application " + app,
		p + "then " + action,
	}
}

// TestJunosHostResidualIsUnrenderedAndWarned6612 walks the #6612 remainder.
//
// FAIL-ON-REVERT: each row's residual attribute is the only difference from its
// flip, so removing a representability gate in junosHostProjectTerm /
// junosHostProjectProgram makes that row render rules (half 1 RED) and lose its
// warning through RenderedPolicyKeys (half 2 RED); narrowing
// junosHostPolicyStricterThanCoarseGate makes the permit rows lose their warning
// while still rendering nothing (half 2 RED alone).
func TestJunosHostResidualIsUnrenderedAndWarned6612(t *testing.T) {
	rows := []struct {
		name string
		// policyName is the policy the warning must name.
		policyName string
		// cmds is the residual variant: no kernel rule, and a warning.
		cmds []string
		// flip is the same fixture with the residual attribute neutralised.
		flip []string
		// flipRules is whether the neutralised variant renders kernel rules. It
		// is false for the permit rows: a permit is projected only as a source
		// subtraction of LATER denies, so a lone permit renders nothing either
		// way and its flip is about the WARNING, not the rules.
		flipRules bool
	}{
		{
			name:       "scheduler-gated deny (time-windowed, cannot be a static rule)",
			policyName: "sched-deny",
			cmds: concat(residualBase, schedulerScaffolding,
				policy("sched-deny", "bad-host", "any", "any", "deny"),
				[]string{"set security policies from-zone untrust to-zone junos-host policy sched-deny scheduler-name workhours"}),
			flip:      concat(residualBase, schedulerScaffolding, policy("sched-deny", "bad-host", "any", "any", "deny")),
			flipRules: true,
		},
		{
			name:       "feed-bound SOURCE deny (not commit-stable)",
			policyName: "feed-src",
			cmds: concat(residualBase, feedScaffolding,
				policy("feed-src", "feed-bad", "any", "any", "deny")),
			flip:      concat(residualBase, feedScaffolding, policy("feed-src", "bad-host", "any", "any", "deny")),
			flipRules: true,
		},
		{
			name:       "feed-bound DESTINATION deny (not commit-stable)",
			policyName: "feed-dst",
			cmds: concat(residualBase, feedScaffolding,
				policy("feed-dst", "any", "feed-bad", "any", "deny")),
			flip:      concat(residualBase, feedScaffolding, policy("feed-dst", "any", "fw-mgmt", "any", "deny")),
			flipRules: true,
		},
		{
			name:       "then reject (a silent kernel drop diverges from the RST/ICMP verdict class)",
			policyName: "rej",
			cmds:       concat(residualBase, policy("rej", "bad-host", "any", "any", "reject")),
			flip:       concat(residualBase, policy("rej", "bad-host", "any", "any", "deny")),
			flipRules:  true,
		},
		{
			name:       "deny in a tcp-rst ingress zone (every deny in the zone answers with a RST)",
			policyName: "rst-zone",
			cmds: concat(residualBase,
				[]string{"set security zones security-zone untrust tcp-rst"},
				policy("rst-zone", "bad-host", "any", "any", "deny")),
			flip:      concat(residualBase, policy("rst-zone", "bad-host", "any", "any", "deny")),
			flipRules: true,
		},
		{
			name:       "ALG-bearing application deny (the ALG path owns the tuple)",
			policyName: "alg-deny",
			cmds: concat(residualBase,
				[]string{
					"set applications application my-ftp protocol tcp",
					"set applications application my-ftp destination-port 21",
					"set applications application my-ftp alg ftp",
				},
				policy("alg-deny", "bad-host", "any", "my-ftp", "deny")),
			flip: concat(residualBase,
				[]string{
					"set applications application my-ftp protocol tcp",
					"set applications application my-ftp destination-port 21",
				},
				policy("alg-deny", "bad-host", "any", "my-ftp", "deny")),
			flipRules: true,
		},
		{
			name:       "application scoped to an IKE exempt tuple (the IPsec passthrough path owns it)",
			policyName: "ike-deny",
			cmds: concat(residualBase,
				[]string{
					"set applications application my-ike protocol udp",
					"set applications application my-ike destination-port 500",
				},
				policy("ike-deny", "bad-host", "any", "my-ike", "deny")),
			flip: concat(residualBase,
				[]string{
					"set applications application my-ike protocol udp",
					"set applications application my-ike destination-port 4444",
				},
				policy("ike-deny", "bad-host", "any", "my-ike", "deny")),
			flipRules: true,
		},
		{
			name:       "source-restricted permit (its implied deny-non-permitted half is unenforced)",
			policyName: "src-permit",
			cmds:       concat(residualBase, policy("src-permit", "bad-host", "any", "any", "permit")),
			flip:       concat(residualBase, policy("src-permit", "any", "any", "any", "permit")),
			flipRules:  false,
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			cfg := residualCfg(t, row.cmds)
			if n := residualRuleCount(cfg); n != 0 {
				t.Errorf("residual variant rendered %d kernel DROP rule(s); the remainder must emit NOTHING — a partial or coarsened kernel rule is a new parity gap", n)
			}
			if got := residualWarnings(cfg, row.policyName); len(got) != 1 {
				t.Errorf("residual variant produced %d #4168 warnings naming %q, want exactly 1 — an unenforced junos-host policy that says nothing at commit is the silent-failure case this projection exists to avoid; got %v",
					len(got), row.policyName, got)
			}

			flip := residualCfg(t, row.flip)
			flipRules := residualRuleCount(flip)
			if row.flipRules && flipRules == 0 {
				t.Errorf("flip variant rendered no kernel rule, so the row proves nothing: the residual attribute is not what suppressed rendering (the fixture is un-representable for some other reason)")
			}
			if !row.flipRules && flipRules != 0 {
				t.Errorf("flip variant rendered %d rule(s); a lone permit must render none on a DROP-only projection", flipRules)
			}
			if got := residualWarnings(flip, row.policyName); len(got) != 0 {
				t.Errorf("flip variant still warns for %q (%d), so the row proves nothing: the warning is not driven by the residual attribute; got %v",
					row.policyName, len(got), got)
			}
		})
	}
}

// TestJunosHostRepresentableDenyRendersAndIsSuppressed6612 is the positive
// control for the whole file. Without it, a projection that returned nothing for
// EVERY config and a warning generator that fired on EVERY junos-host policy
// would satisfy every assertion above.
func TestJunosHostRepresentableDenyRendersAndIsSuppressed6612(t *testing.T) {
	cfg := residualCfg(t, residualBase, policy("plain-deny", "bad-host", "any", "any", "deny"))
	if n := residualRuleCount(cfg); n == 0 {
		t.Fatalf("a representable junos-host deny must render a kernel DROP rule; got 0")
	}
	if got := residualWarnings(cfg, "plain-deny"); len(got) != 0 {
		t.Errorf("a deny that IS enforced on the direct host-bound path must have its #4168 warning suppressed; got %v", got)
	}
}

func concat(groups ...[]string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// TestJunosHostMultiTermApplicationIsFullyExpanded6612 corrects the record on
// one member of #6612's enumeration and locks the correction.
//
// #6612 item 7 and the "Un-representable remainder" paragraph both list
// "multi-term … applications" as un-representable. Measured, that is not what
// the projection does: a pure `term`-bearing application compiles to an implicit
// application-SET (`compiler_applications.go` — the parent struct is discarded
// and each term is stored as its own application), so
// junosHostResolveApplications takes the set branch and OR-expands it, exactly
// as the issue's own "Representable subset" says application-sets are handled.
// What is genuinely un-representable is a MIXED direct+term application
// (`MixedDirectTermApps`), and that is hard-rejected at commit by the strict
// structure gate before it can reach here.
//
// So the deny IS enforced — which makes the real hazard the opposite of the one
// documented: a PARTIAL expansion would render a kernel deny SILENTLY NARROWER
// than authored (the udp/53 term dropped, its traffic admitted), which is the
// one outcome the projection's "no partial / coarsened kernel rule" rule forbids.
// This asserts every term survives.
//
// FAIL-ON-REVERT: drop the `ExpandApplicationSet` loop's accumulation (keep only
// the first member) and the udp/53 fragment disappears — RED. Make the whole
// app un-representable instead and the rule count goes to 0 — also RED.
func TestJunosHostMultiTermApplicationIsFullyExpanded6612(t *testing.T) {
	cfg := residualCfg(t, residualBase,
		[]string{
			"set applications application multi term t1 protocol tcp destination-port 22",
			"set applications application multi term t2 protocol udp destination-port 53",
		},
		policy("mt-deny", "bad-host", "any", "multi", "deny"))

	progs := BuildJunosHostPrograms(cfg)
	if len(progs) != 1 {
		t.Fatalf("multi-term application deny must render one ingress-zone program; got %d", len(progs))
	}
	var frags []config.JunosHostDenyL4
	for _, r := range progs[0].RulesV4 {
		frags = append(frags, r.L4...)
	}
	// Both authored terms must appear. Asserting the SET (not the count) is what
	// distinguishes "expanded" from "expanded to the same term twice".
	want := map[string]bool{"tcp/22": false, "udp/53": false}
	for _, f := range frags {
		for _, p := range f.Ports {
			switch {
			case f.Proto == config.HostInboundProtoTCP && p.Lo == 22 && p.Hi == 22:
				want["tcp/22"] = true
			case f.Proto == config.HostInboundProtoUDP && p.Lo == 53 && p.Hi == 53:
				want["udp/53"] = true
			}
		}
	}
	for term, seen := range want {
		if !seen {
			t.Errorf("term %s is missing from the projected deny — a partially-expanded multi-term application renders a kernel deny SILENTLY NARROWER than authored; got %+v", term, frags)
		}
	}
	// And, being enforced, it must NOT carry the #4168 unenforced-parity warning.
	if got := residualWarnings(cfg, "mt-deny"); len(got) != 0 {
		t.Errorf("an enforced multi-term deny must have its #4168 warning suppressed; got %v", got)
	}
}

// TestJunosHostDestinationScopedPermitDoesNotWidenALaterDeny6612 locks the half
// of the destination-scoped-permit contract that HOLDS today, and names the half
// that does not.
//
// A `to-zone junos-host` permit narrowed on DESTINATION (or carrying
// `destination-address-excluded`) is un-representable: a permit is projected only
// as a `saddr !=` SUBTRACTION of later denies, which cannot express a carve that
// is also destination-scoped. junosHostProjectTerm marks it so, and the whole
// zone program then emits nothing.
//
// The fixture deliberately places a DENY after the permit, because that is the
// only shape in which the gate changes a packet verdict. A lone
// destination-scoped permit renders nothing whether or not the gate exists — the
// projection is DROP-only — so a test built on one would assert a property that
// holds for an unrelated reason and would stay green with the gate deleted. With
// a following deny, dropping the gate renders `saddr != <permit source>` on that
// deny, which stops denying the permitted source to firewall addresses the
// permit never covered: an under-deny, and exactly the fail-open the gate exists
// to prevent.
//
// **The warning half is a KNOWN OPEN DEFECT and is deliberately NOT asserted
// here.** Measured on this fixture, ValidateConfig emits ZERO warnings of any
// kind for the permit: junosHostPolicyStricterThanCoarseGate
// (pkg/config/compiler_validate_warn_host_inbound.go) admits a permit as
// stricter-than-coarse only through junosHostPolicySourceScoped, which inspects
// the SOURCE dimension alone, so a destination-narrowed permit never reaches the
// test. The policy commits clean, renders nothing, and says nothing — the exact
// silent state #4168 exists to prevent, and the reason #6612's closing claim
// ("each affected policy emits the #4168 commit warning naming itself") is false
// as written.
//
// The fix is one clause, binding the warning to the SAME predicate the
// projection already uses in junosHostProjectTerm so the two halves cannot drift:
//
//	if junosHostAddrScoped(m.DestinationAddresses) || m.DestinationAddressExcluded {
//	    return true, "destination-restricted permit"
//	}
//
// It lands in pkg/config, outside this lane's file surface, and is tracked on
// #6612. When it lands, this test folds back into the table above as two rows
// asserting both halves — they were written and measured, and they pass with
// that clause.
//
// FAIL-ON-REVERT: delete the `p.Action != PolicyDeny && (junosHostAddrScoped(...)
// || DestinationAddressExcluded)` gate in junosHostProjectTerm and the following
// deny renders a widened rule — RED here.
func TestJunosHostDestinationScopedPermitDoesNotWidenALaterDeny6612(t *testing.T) {
	followingDeny := policy("blk", "any", "any", "any", "deny")
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{
			name: "destination-scoped permit ahead of a deny",
			cmds: concat(residualBase,
				policy("dst-permit", "mgmt-net", "fw-mgmt", "any", "permit"),
				followingDeny),
		},
		{
			name: "destination-EXCLUDED permit ahead of a deny",
			cmds: concat(residualBase,
				policy("dstx-permit", "mgmt-net", "fw-mgmt", "any", "permit"),
				[]string{"set security policies from-zone untrust to-zone junos-host policy dstx-permit match destination-address-excluded"},
				followingDeny),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := residualCfg(t, tc.cmds)
			if n := residualRuleCount(cfg); n != 0 {
				t.Errorf("rendered %d kernel DROP rule(s); a destination-scoped permit ahead of a deny must leave the zone program EMPTY — projecting the permit as a bare `saddr !=` subtraction drops its destination scope and under-denies the permitted source to every other firewall address", n)
			}
			// The deny that follows DOES warn (a deny always does), which is what
			// keeps the zone's other policies visible. The permit does not — the
			// open half named above.
			if got := residualWarnings(cfg, "blk"); len(got) != 1 {
				t.Errorf("the following deny must keep its #4168 warning (%d), otherwise the whole zone is silent, not just the permit; got %v", len(got), got)
			}
		})
	}
	// Non-vacuity: the same builder and fixture DO render a rule for that deny
	// when no un-representable permit precedes it, so the zero above is the gate
	// and not an inert fixture.
	if n := residualRuleCount(residualCfg(t, residualBase, followingDeny)); n == 0 {
		t.Fatalf("control: a lone representable deny must render a kernel rule on this fixture; got 0")
	}
}
