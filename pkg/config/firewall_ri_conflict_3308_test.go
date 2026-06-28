package config

import (
	"strings"
	"testing"
)

// #3308: a firewall-filter term that co-locates `then routing-instance <x>`
// with a terminating `then discard` / `then reject` is contradictory. The PBR
// runtime (ingress_route_table_override) logs the deny/reject but
// unconditionally returns the routing table, so the packet is ROUTED while the
// audit stream records it as denied (the audit trail lies; fail-open PBR).
// validateFilterRoutingInstanceConflictStrict makes it an operator-visible
// commit error.
//
// FAIL-ON-REVERT: remove the validateFilterRoutingInstanceConflictStrict
// invocation (or the function's reject) and these strict-path tests go RED —
// CompileConfig accepts the contradictory term.

func TestFilterRoutingInstanceDiscardConflict_3308(t *testing.T) {
	tree := buildFilterTree(t,
		"set routing-instances blue instance-type forwarding",
		"set firewall family inet filter f term t then routing-instance blue",
		"set firewall family inet filter f term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with both routing-instance and discard must be rejected " +
			"at commit (#3308 — would route while logging deny)")
	}
	if !strings.Contains(err.Error(), "routing-instance") ||
		!strings.Contains(err.Error(), "discard") ||
		!strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error %q must name the routing-instance/discard conflict", err)
	}
	if !strings.Contains(err.Error(), `filter "f"`) ||
		!strings.Contains(err.Error(), `term "t"`) {
		t.Fatalf("error %q must name the offending filter and term", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the RI/discard conflict: %v", lerr)
	}
}

func TestFilterRoutingInstanceRejectConflict_3308(t *testing.T) {
	tree := buildFilterTree(t,
		"set routing-instances red instance-type forwarding",
		"set firewall family inet filter f term t then routing-instance red",
		"set firewall family inet filter f term t then reject",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with both routing-instance and reject must be rejected " +
			"at commit (#3308)")
	}
	if !strings.Contains(err.Error(), "routing-instance") ||
		!strings.Contains(err.Error(), "reject") {
		t.Fatalf("error %q must name the routing-instance/reject conflict", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the RI/reject conflict: %v", lerr)
	}
}

// inet6 must be gated identically (the validator walks both families).
func TestFilterRoutingInstanceConflictV6_3308(t *testing.T) {
	tree := buildFilterTree(t,
		"set routing-instances blue6 instance-type forwarding",
		"set firewall family inet6 filter f6 term t then routing-instance blue6",
		"set firewall family inet6 filter f6 term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("inet6 term with routing-instance + discard must be rejected (#3308)")
	}
	if !strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error %q must name the inet6 family", err)
	}
}

// A routing-instance term with `then accept` (or no terminal action) is the
// legitimate filter-based-forwarding case and must compile cleanly.
func TestFilterRoutingInstanceAcceptAllowed_3308(t *testing.T) {
	accept := buildFilterTree(t,
		"set routing-instances blue instance-type forwarding",
		"set firewall family inet filter ok term t then routing-instance blue",
		"set firewall family inet filter ok term t then accept",
	)
	if _, err := CompileConfig(accept); err != nil {
		t.Fatalf("routing-instance + accept (valid PBR) must compile: %v", err)
	}
	bare := buildFilterTree(t,
		"set routing-instances blue instance-type forwarding",
		"set firewall family inet filter ok2 term t then routing-instance blue",
	)
	if _, err := CompileConfig(bare); err != nil {
		t.Fatalf("routing-instance with no terminal action (valid PBR) must compile: %v", err)
	}
}
