package config

// nat_lenient_terminal_visibility_7640_test.go — #7640.
//
// The strict terminal-action cardinality gate (#5628) rejects a NAT rule whose
// `then` carries anything other than exactly one translation action. The
// tolerant load / peer-sync / rollback path downgrades that to a cfg.Warnings
// entry (#1960 no-brick) — correctly, since the alternative is a brick.
//
// But cfg.Warnings reaches an operator only through the commit RESPONSE
// (pkg/api, pkg/grpcapi) and an apply-time log line (pkg/daemon), and a
// tolerant LOAD has no commit response. Boot, peer-sync and rollback are
// exactly the paths on which such a rule survives, so the node then runs
// indefinitely carrying a rule a commit would refuse, with no live signal.
//
// These cells bind the record the gauge and the operator annotation read.

import (
	"strings"
	"testing"
)

// actionlessSourceRuleSet builds a rule-set whose rule carries NO terminal
// action — the shape a pre-#5628 config can still carry through a tolerant
// load.
func actionlessSourceRuleSet7640(rsName, ruleName string) *NATRuleSet {
	return &NATRuleSet{
		Name:  rsName,
		Rules: []*NATRule{{Name: ruleName}}, // Then zero-valued: no action at all
	}
}

// TestLenientPathRecordsTheAdmittedRule7640 is the core: a rule the strict gate
// rejects, admitted by the tolerant path, must leave a durable record on the
// compiled config — not only a warning string.
//
// FAIL-ON-REVERT: drop the LenientNATTerminalActionRules assignment in
// compiler_uniformgates_firewall_nat2.go and the record is empty while the
// warning still fires, which is precisely the pre-#7640 invisibility.
func TestLenientPathRecordsTheAdmittedRule7640(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Source = []*NATRuleSet{actionlessSourceRuleSet7640("rs1", "actionless")}

	opts := compileOpts{lenientNATTerminalAction: true}
	if err := runUniformGatesFirewallNAT2(nil, cfg, opts); err != nil {
		t.Fatalf("the tolerant path must not reject: %v", err)
	}

	// Precondition: the warning fired, so this cell is about the RECORD being
	// missing rather than about the gate not firing at all.
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "NAT terminal-action cardinality") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the tolerant path did not warn, so the fixture never reached "+
			"the downgrade this cell is about: %v", cfg.Warnings)
	}

	if len(cfg.LenientNATTerminalActionRules) != 1 {
		t.Fatalf("LenientNATTerminalActionRules = %v, want exactly the one "+
			"admitted rule — without the record the surviving rule is invisible "+
			"to the gauge and to `show ... rule detail`, and a tolerant load has "+
			"no commit response to carry the warning (#7640)",
			cfg.LenientNATTerminalActionRules)
	}
	got := cfg.LenientNATTerminalActionRules[0]
	if got.Kind != "source" || got.RuleSet != "rs1" || got.Rule != "actionless" || got.Actions != 0 {
		t.Fatalf("recorded rule = %+v, want {source rs1 actionless 0} — the "+
			"identity must be enough to find the stanza", got)
	}
	if s := got.String(); !strings.Contains(s, "rs1") || !strings.Contains(s, "actionless") {
		t.Fatalf("String() = %q, must name the rule-set and rule", s)
	}
}

// TestStrictPathRecordsNothing7640 is the PAIRED control. The record means
// "admitted leniently"; on the strict path the config is REJECTED, so a
// recorded rule there would make the gauge report a violation on a node that
// refused to run one.
func TestStrictPathRecordsNothing7640(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Source = []*NATRuleSet{actionlessSourceRuleSet7640("rs1", "actionless")}

	if err := runUniformGatesFirewallNAT2(nil, cfg, compileOpts{}); err == nil {
		t.Fatal("the strict path must REJECT an actionless rule (#5628)")
	}
	if len(cfg.LenientNATTerminalActionRules) != 0 {
		t.Fatalf("the strict path recorded %v — the record must mean "+
			"'admitted leniently', and a rejected config admitted nothing",
			cfg.LenientNATTerminalActionRules)
	}
}

// TestHealthyConfigRecordsNothing7640 is the other half of the pairing: a
// well-formed rule must leave the record empty, or the gauge reports a
// violation on every node and the alert is worthless.
func TestHealthyConfigRecordsNothing7640(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Source = []*NATRuleSet{{
		Name:  "rs1",
		Rules: []*NATRule{{Name: "ok", Then: NATThen{Interface: true}}},
	}}
	if err := runUniformGatesFirewallNAT2(nil, cfg, compileOpts{lenientNATTerminalAction: true}); err != nil {
		t.Fatalf("a well-formed rule must compile: %v", err)
	}
	if len(cfg.LenientNATTerminalActionRules) != 0 {
		t.Fatalf("a healthy config recorded %v", cfg.LenientNATTerminalActionRules)
	}
}

// TestLenientNATOffendersMatchTheGate_7640 binds the AGREEMENT between the
// enumerator and the gate, which is the property that actually matters.
//
// They are separate functions on purpose — the gate reports the FIRST offender
// and stops (one deterministic, actionable commit error), while the record needs
// ALL of them. Separate walks are exactly how a count and a rejection drift
// apart, so this asserts they cannot: for every shape, the gate rejects iff the
// enumerator finds something.
//
// FAIL-ON-REVERT: change either side's predicate (e.g. make the enumerator
// count `n == 0` only) and a row here reds.
func TestLenientNATOffendersMatchTheGate_7640(t *testing.T) {
	for _, tc := range []struct {
		name     string
		then     NATThen
		offender bool
	}{
		{"actionless", NATThen{}, true},
		{"interface-only", NATThen{Interface: true}, false},
		{"off-only", NATThen{Off: true}, false},
		{"pool-only", NATThen{PoolName: "p"}, false},
		{"interface+pool", NATThen{Interface: true, PoolName: "p"}, true},
		{"off+interface", NATThen{Off: true, Interface: true}, true},
		{"all-three", NATThen{Off: true, Interface: true, PoolName: "p"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Security.NAT.Source = []*NATRuleSet{{
				Name:  "rs1",
				Rules: []*NATRule{{Name: "r", Then: tc.then}},
			}}
			gateRejects := validateNATTerminalActionCardinalityStrict(cfg) != nil
			found := len(natTerminalActionCardinalityOffenders(cfg)) > 0
			if gateRejects != tc.offender {
				t.Fatalf("gate rejects = %v, want %v", gateRejects, tc.offender)
			}
			if found != gateRejects {
				t.Fatalf("the enumerator and the gate DISAGREE (enumerator found=%v, "+
					"gate rejects=%v). They must share one predicate, or the gauge "+
					"counts rules a commit would accept, or misses ones it would "+
					"refuse", found, gateRejects)
			}
		})
	}
}

// TestOffendersCoverBothKinds7640 pins that destination NAT is walked too. The
// gate checks both kinds; an enumerator that walked only source would report a
// healthy node for a config whose destination rules a commit would refuse.
func TestOffendersCoverBothKinds7640(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Source = []*NATRuleSet{actionlessSourceRuleSet7640("srs", "s-actionless")}
	cfg.Security.NAT.Destination = &DestinationNATConfig{
		RuleSets: []*NATRuleSet{actionlessSourceRuleSet7640("drs", "d-actionless")},
	}
	got := natTerminalActionCardinalityOffenders(cfg)
	if len(got) != 2 {
		t.Fatalf("offenders = %v, want one source and one destination", got)
	}
	kinds := map[string]bool{}
	for _, r := range got {
		kinds[r.Kind] = true
	}
	if !kinds["source"] || !kinds["destination"] {
		t.Fatalf("offenders cover only %v; the gate checks BOTH kinds", kinds)
	}
}
