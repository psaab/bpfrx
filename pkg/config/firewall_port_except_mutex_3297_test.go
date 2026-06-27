package config

import (
	"strings"
	"testing"
)

// #3297: a single firewall-filter term may carry BOTH a positive port match
// (source-port / destination-port) AND the negated *-port-except list in the
// same direction. Junos treats these as mutually exclusive match families and
// rejects the term at commit. xpf's parser lands the positive list and the
// except list on separate term fields, so both coexist; the Rust matcher then
// silently resolves the conflict as positive-wins and drops the except side
// (fail-safe at runtime, but a Junos-invalid config accepted with one side of
// the operator's intent lost). validateFilterPortExceptStrict makes the
// conflict an operator-visible commit error instead.
//
// FAIL-ON-REVERT: remove the validateFilterPortExceptStrict invocation (or the
// function's reject) and these strict-path tests go RED — CompileConfig accepts
// the ambiguous term instead of erroring.

func TestFilterSourcePortPositiveAndExceptRejected_3297(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from source-port 80",
		"set firewall family inet filter f term t from source-port-except 443",
		"set firewall family inet filter f term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with both source-port and source-port-except must be " +
			"rejected at commit (Junos-invalid, #3297)")
	}
	if !strings.Contains(err.Error(), "source-port") ||
		!strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error %q must name the source-port conflict", err)
	}
	if !strings.Contains(err.Error(), `filter "f"`) ||
		!strings.Contains(err.Error(), `term "t"`) {
		t.Fatalf("error %q must name the offending filter and term", err)
	}
	// Tolerant path downgrades to a warning so a persisted/peer-synced config
	// still boots (#1960 no-brick); the dataplane positive-wins fallback keeps
	// the direction fail-safe.
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the port-except conflict: %v", lerr)
	}
}

func TestFilterDestPortPositiveAndExceptRejected_3297(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from destination-port 22",
		"set firewall family inet filter f term t from destination-port-except 22",
		"set firewall family inet filter f term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with both destination-port and destination-port-except " +
			"must be rejected at commit (Junos-invalid, #3297)")
	}
	if !strings.Contains(err.Error(), "destination-port") ||
		!strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error %q must name the destination-port conflict", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the port-except conflict: %v", lerr)
	}
}

// inet6 family must be gated identically (the validator walks both families).
func TestFilterDestPortPositiveAndExceptRejectedV6_3297(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet6 filter f6 term t from destination-port 22",
		"set firewall family inet6 filter f6 term t from destination-port-except 22",
		"set firewall family inet6 filter f6 term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("inet6 term with both destination-port and " +
			"destination-port-except must be rejected at commit (#3297)")
	}
	if !strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error %q must name the inet6 family", err)
	}
}

// A term with ONLY a positive port match, or ONLY an except list, must still
// compile cleanly — the gate fires only when both are present in one direction.
func TestFilterPortExceptOnlyOneSideAccepted_3297(t *testing.T) {
	posOnly := buildFilterTree(t,
		"set firewall family inet filter pos term t from source-port 80",
		"set firewall family inet filter pos term t then discard",
	)
	if _, err := CompileConfig(posOnly); err != nil {
		t.Fatalf("source-port alone must compile: %v", err)
	}
	exceptOnly := buildFilterTree(t,
		"set firewall family inet filter exc term t from destination-port-except 22",
		"set firewall family inet filter exc term t then discard",
	)
	if _, err := CompileConfig(exceptOnly); err != nil {
		t.Fatalf("destination-port-except alone must compile: %v", err)
	}
	// Positive source + except destination (different directions) is allowed.
	crossDir := buildFilterTree(t,
		"set firewall family inet filter cross term t from source-port 80",
		"set firewall family inet filter cross term t from destination-port-except 22",
		"set firewall family inet filter cross term t then discard",
	)
	if _, err := CompileConfig(crossDir); err != nil {
		t.Fatalf("source-port + destination-port-except (different directions) must compile: %v", err)
	}
}
