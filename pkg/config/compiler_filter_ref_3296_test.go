package config

import (
	"strings"
	"testing"
)

// #3296: an interface/unit (or lo0) `family inet|inet6 filter input|output
// <name>` reference naming a filter not defined under `firewall family
// inet|inet6 filter` must be hard-rejected at commit
// (validateFirewallFilterReferencesStrict). A dangling reference otherwise
// compiled with only a warning and the userspace filter compiler left the
// per-interface fast-path map empty for the missing key, so the hot path
// returned the default Accept — the security hook was silently disarmed and
// the interface forwarded unfiltered (fail-OPEN on a typo'd firewall hook).
// Mirrors the #2217 policer / #2506 prefix-list reference gates.
//
// Each direction asserts the reject (fail-on-revert: delete the validator and
// the reject disappears) and a defined reference asserts no false reject; the
// lenient path asserts the downgrade-to-warning (#1960).

func TestFilterRefUndefinedInputV4Rejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet filter input WAN-BLOCK",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for undefined inet input filter, got nil")
	}
	if !strings.Contains(err.Error(), "undefined filter") ||
		!strings.Contains(err.Error(), "WAN-BLOCK") ||
		!strings.Contains(err.Error(), "input") {
		t.Fatalf("error = %v, want it to name the undefined inet input filter", err)
	}
}

func TestFilterRefUndefinedInputV6Rejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet6 filter input v6-ghost",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for undefined inet6 input filter, got nil")
	}
	if !strings.Contains(err.Error(), "undefined filter") ||
		!strings.Contains(err.Error(), "v6-ghost") ||
		!strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error = %v, want it to name the undefined inet6 input filter", err)
	}
}

func TestFilterRefUndefinedOutputV4Rejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet filter output egress-ghost",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for undefined inet output filter, got nil")
	}
	if !strings.Contains(err.Error(), "undefined filter") ||
		!strings.Contains(err.Error(), "egress-ghost") ||
		!strings.Contains(err.Error(), "output") {
		t.Fatalf("error = %v, want it to name the undefined inet output filter", err)
	}
}

func TestFilterRefUndefinedOutputV6Rejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet6 filter output egress6-ghost",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for undefined inet6 output filter, got nil")
	}
	if !strings.Contains(err.Error(), "undefined filter") ||
		!strings.Contains(err.Error(), "egress6-ghost") {
		t.Fatalf("error = %v, want it to name the undefined inet6 output filter", err)
	}
}

// lo0 is stored as an ordinary interface (cfg.Interfaces.Interfaces["lo0"]),
// so the strict gate covers the host-bound lo0 input/output hooks too — the
// canonical "protect-RE lockout" filter must not silently fail open on a typo.
func TestFilterRefUndefinedLo0InputV4Rejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces lo0 unit 0 family inet filter input protect-re-typo",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for undefined lo0 inet input filter, got nil")
	}
	if !strings.Contains(err.Error(), "undefined filter") ||
		!strings.Contains(err.Error(), "protect-re-typo") ||
		!strings.Contains(err.Error(), "lo0") {
		t.Fatalf("error = %v, want it to name the undefined lo0 inet input filter", err)
	}
}

func TestFilterRefUndefinedLo0InputV6Rejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces lo0 unit 0 family inet6 filter input protect-re6-typo",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for undefined lo0 inet6 input filter, got nil")
	}
	if !strings.Contains(err.Error(), "undefined filter") ||
		!strings.Contains(err.Error(), "protect-re6-typo") ||
		!strings.Contains(err.Error(), "lo0") {
		t.Fatalf("error = %v, want it to name the undefined lo0 inet6 input filter", err)
	}
}

// A reference whose target filter IS defined must commit cleanly, in all four
// interface directions plus lo0.
func TestFilterRefDefinedCommitsCleanly(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet filter in4 term t1 then accept",
		"set firewall family inet filter out4 term t1 then accept",
		"set firewall family inet6 filter in6 term t1 then accept",
		"set firewall family inet6 filter out6 term t1 then accept",
		"set firewall family inet filter lo4 term t1 then accept",
		"set interfaces ge-0/0/0 unit 0 family inet filter input in4",
		"set interfaces ge-0/0/0 unit 0 family inet filter output out4",
		"set interfaces ge-0/0/0 unit 0 family inet6 filter input in6",
		"set interfaces ge-0/0/0 unit 0 family inet6 filter output out6",
		"set interfaces lo0 unit 0 family inet filter input lo4",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("defined filter references must commit cleanly, got: %v", err)
	}
	u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if u.FilterInputV4 != "in4" || u.FilterOutputV4 != "out4" ||
		u.FilterInputV6 != "in6" || u.FilterOutputV6 != "out6" {
		t.Fatalf("filter refs lost: %+v", u)
	}
	if cfg.System.Lo0FilterInputV4 != "lo4" {
		t.Fatalf("lo0 input ref lost: %q", cfg.System.Lo0FilterInputV4)
	}
}

// The strict reject is downgraded to a warning on the tolerant load / peer-sync
// path so an already-persisted or peer-synced config carrying the typo still
// boots (#1960 fail-closed-on-load class). The dataplane's snapshot-integrity
// backstop then refuses to publish the broken snapshot (fail-closed), so the
// hook never degrades to Accept.
func TestFilterRefUndefinedLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet filter input WAN-BLOCK",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must boot through undefined filter ref, got: %v", err)
	}
	if !warningsContain(cfg.Warnings, "firewall filter reference") {
		t.Fatalf("expected a downgraded filter-reference warning, got: %v", cfg.Warnings)
	}
}
