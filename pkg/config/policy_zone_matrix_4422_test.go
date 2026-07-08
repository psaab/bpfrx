package config

import "testing"

// TestPolicyZoneMatrixCompilesActionsIndependently is the #4422 policy
// zone-matrix composition guard: permit / deny / reject policies that COEXIST
// in one config each compile to their own terminal action, in config order,
// with no cross-contamination between policies or between contexts (a transit
// zone-pair vs a to-junos-host host-inbound zone-pair), and the no-match
// default-policy scope is independent of the per-policy actions.
//
// The per-action gates are each covered in isolation (compiler_policy_then_*,
// policy_terminal_action_3043, compiler_default_policy_3065). What NONE of them
// exercises is the COMPOSITION: multiple policies of DIFFERENT actions in the
// SAME zone-pair, plus a second (host-inbound) zone-pair, in one CompileConfig.
// compilePolicy resolves each policy's Action from its own `then` block and
// appends to a per-policy terminalActions slice; a regression that shared state
// across policies (e.g. a package-level or zone-pair-scoped "last action", or a
// reused/leaked terminalActions slice) would make a later policy's action bleed
// onto an earlier one, or the transit reject bleed onto the host-inbound permit.
// This test pins that each compiled Policy.Action is exactly the one authored,
// in order, per context.
//
// FAIL-ON-REVERT: make compilePolicy resolve actions non-independently (e.g.
// carry the previous policy's Action forward when a policy's own `then` is read,
// or key the action off the zone-pair rather than the policy) and the ordered
// per-policy assertions below go RED.
func TestPolicyZoneMatrixCompilesActionsIndependently(t *testing.T) {
	cmds := []string{
		"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces eth1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone untrust interfaces eth1",
		// Transit zone-pair trust->untrust: three policies, three DIFFERENT
		// terminal actions, authored in the order permit, deny, reject.
		"set security policies from-zone trust to-zone untrust policy t-permit match source-address any",
		"set security policies from-zone trust to-zone untrust policy t-permit match destination-address any",
		"set security policies from-zone trust to-zone untrust policy t-permit match application any",
		"set security policies from-zone trust to-zone untrust policy t-permit then permit",
		"set security policies from-zone trust to-zone untrust policy t-deny match source-address any",
		"set security policies from-zone trust to-zone untrust policy t-deny match destination-address any",
		"set security policies from-zone trust to-zone untrust policy t-deny match application any",
		"set security policies from-zone trust to-zone untrust policy t-deny then deny",
		"set security policies from-zone trust to-zone untrust policy t-reject match source-address any",
		"set security policies from-zone trust to-zone untrust policy t-reject match destination-address any",
		"set security policies from-zone trust to-zone untrust policy t-reject match application any",
		"set security policies from-zone trust to-zone untrust policy t-reject then reject",
		// Host-inbound context untrust->junos-host: a plain permit-any (which
		// mirrors the coarse host-inbound gate, so it draws NO #4146 advisory
		// warning) — its action must stay permit, isolated from the transit
		// reject above.
		"set security policies from-zone untrust to-zone junos-host policy h-permit match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy h-permit match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy h-permit match application any",
		"set security policies from-zone untrust to-zone junos-host policy h-permit then permit",
		// A deny no-match default, independent of the per-policy actions.
		"set security policies default-policy deny-all",
	}

	tree := buildPolicyTree(t, cmds)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a well-formed mixed-action policy matrix: %v", err)
	}

	// The transit zone-pair must carry exactly the three authored policies, in
	// order, each with its own action.
	transit := findZonePair(cfg.Security.Policies, "trust→untrust")
	if transit == nil {
		t.Fatal("transit zone-pair trust→untrust missing from compiled config")
	}
	wantTransit := []struct {
		name string
		act  PolicyAction
	}{
		{"t-permit", PolicyPermit},
		{"t-deny", PolicyDeny},
		{"t-reject", PolicyReject},
	}
	if len(transit.Policies) != len(wantTransit) {
		t.Fatalf("transit zone-pair has %d policies, want %d", len(transit.Policies), len(wantTransit))
	}
	for i, w := range wantTransit {
		got := transit.Policies[i]
		if got.Name != w.name {
			t.Fatalf("transit policy[%d] name = %q, want %q (config order not preserved)", i, got.Name, w.name)
		}
		if got.Action != w.act {
			t.Errorf("transit policy %q action = %s, want %s (mixed-action cross-contamination)",
				got.Name, policyActionName(got.Action), policyActionName(w.act))
		}
	}

	// The host-inbound context is a SEPARATE zone-pair; its permit must not be
	// contaminated by the transit reject.
	host := findZonePair(cfg.Security.Policies, "untrust→junos-host")
	if host == nil {
		t.Fatal("junos-host zone-pair untrust→junos-host missing from compiled config")
	}
	if len(host.Policies) != 1 {
		t.Fatalf("junos-host zone-pair has %d policies, want 1", len(host.Policies))
	}
	if hp := host.Policies[0]; hp.Name != "h-permit" || hp.Action != PolicyPermit {
		t.Errorf("junos-host policy = %q/%s, want h-permit/permit (host-inbound context not isolated)",
			hp.Name, policyActionName(hp.Action))
	}

	// The no-match default is deny, orthogonal to the explicit-policy actions
	// (a permit policy in the transit pair must not flip the default open).
	if cfg.Security.DefaultPolicy != PolicyDeny {
		t.Errorf("default-policy = %s, want deny (default scope leaked from a per-policy action)",
			policyActionName(cfg.Security.DefaultPolicy))
	}
}
