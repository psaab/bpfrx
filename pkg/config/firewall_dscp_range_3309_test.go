package config

import (
	"strings"
	"testing"
)

// #3309: `from dscp <token>`, `from traffic-class <token>`, and `then dscp
// <token>` accepted any raw string at commit. Invalid names (`not-a-code`) and
// out-of-range numbers (`64`, `-1`) committed cleanly, then were SILENTLY
// DROPPED by the snapshot builder — a dropped `from dscp` value left the term
// with NO DSCP constraint (matches all DSCPs — a policy widening) and a dropped
// `then dscp` rewrite did nothing. validateFilterDSCPStrict rejects out-of-range
// / unknown tokens at commit, naming the token.
//
// FAIL-ON-REVERT: remove the validateFilterDSCPStrict invocation (or the
// function's reject) and these strict-path tests go RED — CompileConfig accepts
// the bad token.

func TestFilterFromDSCPInvalidNameRejected_3309(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from dscp not-a-code",
		"set firewall family inet filter f term t then accept",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("`from dscp not-a-code` must be rejected at commit (#3309 — " +
			"the value would be dropped, leaving the term matching all DSCPs)")
	}
	if !strings.Contains(err.Error(), "not-a-code") ||
		!strings.Contains(err.Error(), "dscp") {
		t.Fatalf("error %q must name the bad dscp token", err)
	}
	if !strings.Contains(err.Error(), `filter "f"`) ||
		!strings.Contains(err.Error(), `term "t"`) {
		t.Fatalf("error %q must name the offending filter and term", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the bad dscp: %v", lerr)
	}
}

func TestFilterFromDSCPOutOfRangeRejected_3309(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from dscp 64",
		"set firewall family inet filter f term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("`from dscp 64` (out of 0-63) must be rejected at commit (#3309)")
	}
	if !strings.Contains(err.Error(), "64") {
		t.Fatalf("error %q must name the out-of-range value", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the out-of-range dscp: %v", lerr)
	}
}

func TestFilterThenDSCPRewriteInvalidRejected_3309(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t then dscp typo",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("`then dscp typo` rewrite must be rejected at commit (#3309 — " +
			"the rewrite would silently do nothing)")
	}
	if !strings.Contains(err.Error(), "typo") ||
		!strings.Contains(err.Error(), "rewrite") {
		t.Fatalf("error %q must name the bad rewrite token", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the bad rewrite: %v", lerr)
	}
}

// IPv6 `from traffic-class` shares the typed field and the 0..63 range; an
// out-of-range traffic-class must be rejected too.
func TestFilterFromTrafficClassOutOfRangeRejectedV6_3309(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet6 filter f6 term t from traffic-class 99",
		"set firewall family inet6 filter f6 term t then accept",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("inet6 `from traffic-class 99` must be rejected at commit (#3309)")
	}
	if !strings.Contains(err.Error(), "inet6") ||
		!strings.Contains(err.Error(), "99") {
		t.Fatalf("error %q must name the inet6 out-of-range traffic-class", err)
	}
}

// Valid DSCP code-point names and in-range numbers must compile cleanly — the
// gate must not over-reject the supported set (ef / af43 / be / 0 / 63).
func TestFilterDSCPValidAccepted_3309(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter ok term ef from dscp ef",
		"set firewall family inet filter ok term ef then accept",
		"set firewall family inet filter ok term af from dscp af43",
		"set firewall family inet filter ok term af then dscp be",
		"set firewall family inet filter ok term num from dscp 0",
		"set firewall family inet filter ok term num then dscp 63",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("valid dscp names/numbers must compile: %v", err)
	}
}

// FilterDSCPResolvable acceptance set sanity (the drift-guard against
// dataplane.DSCPValues lives in firewall_dscp_drift_3309_test.go, external pkg).
func TestFilterDSCPResolvableBasics_3309(t *testing.T) {
	for _, ok := range []string{"ef", "EF", "af43", "be", "cs7", "0", "63"} {
		if !FilterDSCPResolvable(ok) {
			t.Errorf("FilterDSCPResolvable(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"not-a-code", "64", "-1", "256", ""} {
		if FilterDSCPResolvable(bad) {
			t.Errorf("FilterDSCPResolvable(%q) = true, want false", bad)
		}
	}
}
