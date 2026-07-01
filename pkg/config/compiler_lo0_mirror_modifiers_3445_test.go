package config

import (
	"strings"
	"testing"
)

// TestLo0FilterKernelMirrorWarns proves #3445: a firewall filter bound to lo0
// input that carries a `then` modifier the kernel nftables lo0 mirror cannot
// faithfully honor (policer / dscp-rewrite / forwarding-class) commits
// successfully but emits a commit WARNING naming the family/filter/term/modifier
// — it is NOT silently dropped from the kernel mirror (the M04/M05/M06 gap).
//
// Fail-on-revert: removing the validateLo0FilterKernelMirrorWarnings call (or any
// of its per-modifier appends) removes the warning(s) and this test fails.
func TestLo0FilterKernelMirrorWarns(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall policer p1 if-exceeding bandwidth-limit 1m",
		"set firewall policer p1 if-exceeding burst-size-limit 15k",
		"set firewall policer p1 then discard",
		"set firewall family inet filter lo0in term rate from protocol tcp",
		"set firewall family inet filter lo0in term rate then policer p1",
		"set firewall family inet filter lo0in term mark from protocol udp",
		"set firewall family inet filter lo0in term mark then dscp ef",
		"set firewall family inet filter lo0in term mark then accept",
		"set firewall family inet filter lo0in term fc from protocol tcp",
		"set firewall family inet filter lo0in term fc then forwarding-class my-fc",
		"set firewall family inet filter lo0in term fc then accept",
		"set interfaces lo0 unit 0 family inet filter input lo0in",
	})

	warnings := ValidateConfig(cfg)

	// modifier substring -> the term carrying it.
	want := map[string]string{
		"policer":          "rate",
		"dscp":             "mark",
		"forwarding-class": "fc",
	}
	for mod, term := range want {
		found := false
		for _, w := range warnings {
			if strings.Contains(w, "kernel lo0 input mirror") &&
				strings.Contains(w, "\""+term+"\"") && strings.Contains(w, mod) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected lo0 kernel-mirror warning for modifier %q on term %q, got: %v", mod, term, warnings)
		}
	}
}

// TestLo0FilterKernelMirrorRoutingInstanceWarns pins #3724 M04: a
// routing-instance (policy-based routing) term on an lo0 input filter commits
// successfully and terminates as accept on the kernel mirror (daemon_nft.go
// terminate-as-accept), but the kernel `hook input` chain cannot perform the
// route selection. It must emit a commit WARNING naming the term and the
// routing-instance so the operator knows the PBR route selection is silently not
// honored on the PRIMARY host-bound path.
//
// Fail-on-revert: removing the M04 routing-instance append in
// validateLo0FilterKernelMirrorWarnings removes the warning and this test fails.
func TestLo0FilterKernelMirrorRoutingInstanceWarns(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set routing-instances mgmt-ri instance-type forwarding",
		"set firewall family inet filter lo0in term pbr from protocol tcp",
		"set firewall family inet filter lo0in term pbr then routing-instance mgmt-ri",
		"set interfaces lo0 unit 0 family inet filter input lo0in",
	})

	found := false
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "kernel lo0 input mirror") &&
			strings.Contains(w, `"pbr"`) &&
			strings.Contains(w, "routing-instance mgmt-ri") &&
			strings.Contains(w, "route selection") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected lo0 kernel-mirror routing-instance warning for term %q, got: %v", "pbr", ValidateConfig(cfg))
	}
}

// TestLo0FilterKernelMirrorCommitSucceeds confirms the warning never fail-closes
// the commit: these modifiers are valid Junos and must be accepted (warn, never
// reject) so a previously-committed config is never bricked.
func TestLo0FilterKernelMirrorCommitSucceeds(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set system dataplane-type userspace",
		"set firewall policer p1 if-exceeding bandwidth-limit 1m",
		"set firewall policer p1 if-exceeding burst-size-limit 15k",
		"set firewall policer p1 then discard",
		"set firewall family inet filter lo0in term rate from protocol tcp",
		"set firewall family inet filter lo0in term rate then policer p1",
		"set interfaces lo0 unit 0 family inet filter input lo0in",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("lo0 filter with a policer must commit (warn, not reject): %v", err)
	}
	if cfg.System.Lo0FilterInputV4 != "lo0in" {
		t.Fatalf("expected lo0 input v4 filter binding, got %q", cfg.System.Lo0FilterInputV4)
	}
}

// TestLo0FilterKernelMirrorNoFalsePositive confirms the warning is SCOPED to the
// lo0 input filter: the same modifiers on a library filter NOT bound to lo0 input
// (userspace remains the enforcement path there) emit no kernel-mirror warning.
func TestLo0FilterKernelMirrorNoFalsePositive(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall policer p1 if-exceeding bandwidth-limit 1m",
		"set firewall policer p1 if-exceeding burst-size-limit 15k",
		"set firewall policer p1 then discard",
		"set firewall family inet filter notlo0 term rate from protocol tcp",
		"set firewall family inet filter notlo0 term rate then policer p1",
	})
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "kernel lo0 input mirror") {
			t.Fatalf("unexpected lo0 kernel-mirror warning for a filter not bound to lo0 input: %q", w)
		}
	}
}

// TestLo0FilterKernelMirrorHonoredModifiersNoWarn confirms the modifiers the
// kernel mirror DOES honor (then count / then log) do not produce a
// cannot-honor warning when present on an lo0 input filter.
func TestLo0FilterKernelMirrorHonoredModifiersNoWarn(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter lo0in term t from protocol tcp",
		"set firewall family inet filter lo0in term t then count c1",
		"set firewall family inet filter lo0in term t then log",
		"set firewall family inet filter lo0in term t then accept",
		"set interfaces lo0 unit 0 family inet filter input lo0in",
	})
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "kernel lo0 input mirror") {
			t.Fatalf("count/log are honored on the kernel mirror and must not warn: %q", w)
		}
	}
}
