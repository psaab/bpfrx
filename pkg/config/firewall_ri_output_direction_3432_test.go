package config

import (
	"strings"
	"testing"
)

// #3432: an OUTPUT-attached firewall filter whose term carries `then
// routing-instance <x>` (filter-based-forwarding) compiled cleanly but was a
// silent no-op — the userspace route-override path only consults the INPUT
// filter's affects_route_lookup flag (the Rust filter compiler sets it only on
// the input attach branch), so the configured steering never influenced the
// route lookup. validateFilterRoutingInstanceDirectionStrict makes the
// unsupported direction an operator-visible commit error.
//
// FAIL-ON-REVERT: remove the validateFilterRoutingInstanceDirectionStrict
// invocation (or the function's reject) and the reject tests go RED —
// CompileConfig accepts the dead output-FBF attachment.

func TestOutputFBFRejected_3432(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances blue instance-type forwarding",
		"set firewall family inet filter steer term t then routing-instance blue",
		"set firewall family inet filter steer term t then accept",
		"set interfaces ge-0/0/0 unit 0 family inet filter output steer",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("output-attached filter with `then routing-instance` must be " +
			"rejected at commit (#3432 — FBF route override is ingress-only, " +
			"so the steering would silently no-op)")
	}
	if !strings.Contains(err.Error(), "routing-instance") ||
		!strings.Contains(err.Error(), "input") {
		t.Fatalf("error %q must name routing-instance and the input-only restriction", err)
	}
	if !strings.Contains(err.Error(), `filter output "steer"`) ||
		!strings.Contains(err.Error(), "ge-0/0/0") {
		t.Fatalf("error %q must name the offending interface and output filter", err)
	}
}

// inet6 must be gated identically (the validator walks both families).
func TestOutputFBFRejectedV6_3432(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances blue6 instance-type forwarding",
		"set firewall family inet6 filter steer6 term t then routing-instance blue6",
		"set interfaces ge-0/0/0 unit 0 family inet6 filter output steer6",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("inet6 output-attached FBF filter must be rejected (#3432)")
	}
	if !strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error %q must name the inet6 family", err)
	}
}

// The SAME filter attached on INPUT is the legitimate FBF case and must
// compile cleanly — the gate is strictly about the output direction.
func TestInputFBFAllowed_3432(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances blue instance-type forwarding",
		"set firewall family inet filter steer term t then routing-instance blue",
		"set firewall family inet filter steer term t then accept",
		"set interfaces ge-0/0/0 unit 0 family inet filter input steer",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("input-attached FBF (valid PBR) must compile: %v", err)
	}
}

// An OUTPUT-attached filter that does NOT carry a routing-instance action
// (e.g. a plain count/accept egress filter) must still compile — the gate must
// not reject ordinary output filters.
func TestOutputNonFBFAllowed_3432(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet filter egress term t then accept",
		"set interfaces ge-0/0/0 unit 0 family inet filter output egress",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("ordinary output filter (no routing-instance) must compile: %v", err)
	}
}

// The strict reject downgrades to a warning on the tolerant load / peer-sync
// path so an already-persisted or peer-synced config still boots (#1960). The
// runtime already treats the output steering term as inert.
func TestOutputFBFLenientWarns_3432(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances blue instance-type forwarding",
		"set firewall family inet filter steer term t then routing-instance blue",
		"set interfaces ge-0/0/0 unit 0 family inet filter output steer",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must boot through output-FBF attach, got: %v", err)
	}
	if !warningsContain(cfg.Warnings, "routing-instance direction") {
		t.Fatalf("expected a downgraded routing-instance-direction warning, got: %v", cfg.Warnings)
	}
}
