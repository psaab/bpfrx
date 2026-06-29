package config

import (
	"strings"
	"testing"
)

// #3433 (codex audit 094 H02/H09): firewall-filter literal source/destination
// addresses were untyped at commit — validateFilterMatchValuesStrict checks only
// icmp-type/icmp-code/named-ports and validateFilterFromMatchStrict only rejects
// unimplemented `from` leaves, so a malformed CIDR or a wrong-family literal
// reached the kernel lo0 nft mirror verbatim and either failed the atomic
// `nft -f -` load (breaking a legitimate commit) or, on the lenient/peer-sync
// path, left the kernel mirror absent while userspace stayed armed.
// validateFilterAddressLiteralsStrict makes the bad literal an operator-visible
// commit error.
//
// FAIL-ON-REVERT: remove the validateFilterAddressLiteralsStrict invocation (or
// its reject) and these strict-path tests go RED — CompileConfig accepts the bad
// literal instead of erroring.

func TestFilterMalformedSourceAddressRejected_3433(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from source-address 10.0.0.0/99",
		"set firewall family inet filter f term t then accept",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("malformed source-address /99 must be rejected at commit (#3433 H09)")
	}
	if !strings.Contains(err.Error(), "malformed") ||
		!strings.Contains(err.Error(), "source-address") {
		t.Fatalf("error %q must name the malformed source-address", err)
	}
	if !strings.Contains(err.Error(), `filter "f"`) || !strings.Contains(err.Error(), `term "t"`) {
		t.Fatalf("error %q must name the offending filter and term", err)
	}
	// Tolerant path downgrades to a warning so a persisted/peer-synced config
	// still boots (#1960 no-brick); the lowering + userspace matcher fail closed
	// for the bad token independently.
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on a malformed address: %v", lerr)
	}
}

func TestFilterWrongFamilySourceAddressRejected_3433(t *testing.T) {
	// A v4 CIDR under `family inet6`.
	tree := buildFilterTree(t,
		"set firewall family inet6 filter f6 term t from source-address 10.0.1.0/24",
		"set firewall family inet6 filter f6 term t then accept",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a v4 source-address in an inet6 filter must be rejected at commit (#3433 H02)")
	}
	if !strings.Contains(err.Error(), "wrong address family") || !strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error %q must name the wrong-family inet6 conflict", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on a wrong-family address: %v", lerr)
	}

	// Symmetric: a v6 CIDR under `family inet`.
	tree4 := buildFilterTree(t,
		"set firewall family inet filter f term t from destination-address 2001:db8::/32",
		"set firewall family inet filter f term t then accept",
	)
	if _, err := CompileConfig(tree4); err == nil {
		t.Fatal("a v6 destination-address in an inet filter must be rejected at commit (#3433 H02)")
	}
}

// `any` is a NO-CONSTRAINT placeholder, not a malformed token — it must compile
// cleanly (the dataplane treats it as match-all, #3433 H01). Valid same-family
// literals and bare host IPs must also compile.
func TestFilterAddressLiteralsAcceptValid_3433(t *testing.T) {
	ok := buildFilterTree(t,
		"set firewall family inet filter f term any from source-address any",
		"set firewall family inet filter f term any then accept",
		"set firewall family inet filter f term cidr from source-address 10.0.0.0/8",
		"set firewall family inet filter f term cidr then accept",
		"set firewall family inet filter f term host from destination-address 192.168.1.1",
		"set firewall family inet filter f term host then accept",
		"set firewall family inet6 filter f6 term v6 from source-address 2001:db8::/32",
		"set firewall family inet6 filter f6 term v6 then accept",
	)
	if _, err := CompileConfig(ok); err != nil {
		t.Fatalf("valid / `any` / bare-host address literals must compile: %v", err)
	}
}
