package config

import (
	"strings"
	"testing"
)

// #3359: a single firewall-filter term may carry BOTH a positive address match
// (a literal source-address / destination-address OR a non-except prefix-list)
// AND an `except` prefix-list in the same direction. Junos treats these as
// mutually exclusive and rejects the term at commit. xpf's parser lands the
// literal addresses and the prefix-list references (positive AND except) on
// separate term fields, so both coexist; the userspace lowering then FOLDED the
// except prefixes into the positive set (dropping the except modifier) — a
// silent fail-OPEN for a discard/reject term (traffic the operator carved out
// via `except` was no longer dropped). validateFilterAddressExceptStrict makes
// the conflict an operator-visible commit error instead; the runtime fold is
// now positive-wins (fail-safe) for any leniently-loaded term.
//
// FAIL-ON-REVERT: remove the validateFilterAddressExceptStrict invocation (or
// the function's reject) and these strict-path tests go RED — CompileConfig
// accepts the ambiguous term instead of erroring.

func TestFilterSourceAddrPositiveAndExceptRejected_3359(t *testing.T) {
	tree := buildFilterTree(t,
		"set policy-options prefix-list trusted 10.1.0.0/16",
		"set firewall family inet filter f term t from source-address 10.0.0.0/8",
		"set firewall family inet filter f term t from source-prefix-list trusted except",
		"set firewall family inet filter f term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with both a positive source-address and an except " +
			"source-prefix-list must be rejected at commit (Junos-invalid, #3359)")
	}
	if !strings.Contains(err.Error(), "source") ||
		!strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error %q must name the source-address conflict", err)
	}
	if !strings.Contains(err.Error(), `filter "f"`) ||
		!strings.Contains(err.Error(), `term "t"`) {
		t.Fatalf("error %q must name the offending filter and term", err)
	}
	// Tolerant path downgrades to a warning so a persisted/peer-synced config
	// still boots (#1960 no-brick); the dataplane positive-wins fallback keeps
	// the direction fail-safe.
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the address-except conflict: %v", lerr)
	}
}

// A positive PREFIX-LIST (not a literal address) mixed with an except
// prefix-list in the same direction must also be rejected.
func TestFilterDestPrefixListPositiveAndExceptRejected_3359(t *testing.T) {
	tree := buildFilterTree(t,
		"set policy-options prefix-list servers 192.168.0.0/16",
		"set policy-options prefix-list mgmt 192.168.1.0/24",
		"set firewall family inet filter f term t from destination-prefix-list servers",
		"set firewall family inet filter f term t from destination-prefix-list mgmt except",
		"set firewall family inet filter f term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with both a positive destination-prefix-list and an except " +
			"destination-prefix-list must be rejected at commit (#3359)")
	}
	if !strings.Contains(err.Error(), "destination") ||
		!strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error %q must name the destination-address conflict", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the address-except conflict: %v", lerr)
	}
}

// inet6 family must be gated identically (the validator walks both families).
func TestFilterSourceAddrPositiveAndExceptRejectedV6_3359(t *testing.T) {
	tree := buildFilterTree(t,
		"set policy-options prefix-list trusted6 2001:db8:1::/48",
		"set firewall family inet6 filter f6 term t from source-address 2001:db8::/32",
		"set firewall family inet6 filter f6 term t from source-prefix-list trusted6 except",
		"set firewall family inet6 filter f6 term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("inet6 term with both a positive source-address and an except " +
			"source-prefix-list must be rejected at commit (#3359)")
	}
	if !strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error %q must name the inet6 family", err)
	}
}

// A term with ONLY positive addresses, or ONLY an except prefix-list, must
// still compile cleanly — the gate fires only when both shapes are present in
// one direction. A positive source + except destination (different directions)
// is also allowed.
func TestFilterAddressExceptOnlyOneSideAccepted_3359(t *testing.T) {
	posOnly := buildFilterTree(t,
		"set policy-options prefix-list pl 10.2.0.0/16",
		"set firewall family inet filter pos term t from source-address 10.0.0.0/8",
		"set firewall family inet filter pos term t from source-prefix-list pl",
		"set firewall family inet filter pos term t then discard",
	)
	if _, err := CompileConfig(posOnly); err != nil {
		t.Fatalf("positive source-address + positive prefix-list must compile: %v", err)
	}
	exceptOnly := buildFilterTree(t,
		"set policy-options prefix-list trusted 10.1.0.0/16",
		"set firewall family inet filter exc term t from source-prefix-list trusted except",
		"set firewall family inet filter exc term t then discard",
	)
	if _, err := CompileConfig(exceptOnly); err != nil {
		t.Fatalf("except prefix-list alone must compile: %v", err)
	}
	// Positive source + except destination (different directions) is allowed —
	// the conflict is per-direction.
	crossDir := buildFilterTree(t,
		"set policy-options prefix-list trusted 10.1.0.0/16",
		"set firewall family inet filter cross term t from source-address 10.0.0.0/8",
		"set firewall family inet filter cross term t from destination-prefix-list trusted except",
		"set firewall family inet filter cross term t then discard",
	)
	if _, err := CompileConfig(crossDir); err != nil {
		t.Fatalf("source-address + destination-prefix-list except (different directions) must compile: %v", err)
	}
}
