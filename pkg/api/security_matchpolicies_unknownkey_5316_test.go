package api

import (
	"strings"
	"testing"
)

// TestMatchPoliciesRESTRejectsUnknownSelector is the #5316 RED-on-revert guard.
//
// The match-policies handler consults only a fixed selector allowlist
// (matchPoliciesSelectorKeys). Before #5316 it enumerated DUPLICATES among
// that list (#3709) but never rejected an UNKNOWN/misspelled key. A typo such
// as `protcol` for `protocol` was therefore never examined: q.Get("protocol")
// returned "" and the shared simulator evaluated ALL protocols, so the endpoint
// could certify a broad PERMIT for a packet class the caller never intended to
// test — a fail-OPEN on a security-verification surface. The handler now 400s
// any key not in the allowlist, naming the offender.
//
// FAIL-ON-REVERT: removing the unknown-key enumeration makes the mistyped
// `protcol` key silently ignored, so the query returns 200 with a widened
// verdict, flipping the want-400 / name-the-key assertions red.
func TestMatchPoliciesRESTRejectsUnknownSelector(t *testing.T) {
	s := &Server{store: hostInboundAPIStore(t)}

	// The #5316 scenario: `protocol` misspelled as `protcol`. The two zones are
	// valid and single-valued, so the ONLY defect is the unknown key.
	code, body := matchStatus(t, s, "from_zone=trust&to_zone=untrust&protcol=tcp")
	if code != 400 {
		t.Fatalf("typo selector status = %d, want 400 (unknown selector); body: %s", code, body)
	}
	if !strings.Contains(body, "unknown selector parameter") || !strings.Contains(body, "protcol") {
		t.Fatalf("body = %s, want an unknown-selector error naming \"protcol\"", body)
	}

	// A few more misspellings / stray keys, each rejected by name.
	for _, tc := range []struct {
		raw, key string
	}{
		{"from_zone=trust&to_zone=untrust&src=10.0.0.1", "src"},
		{"from_zone=trust&to_zone=untrust&dstport=443", "dstport"},
		{"from_zone=trust&to_zone=untrust&application=junos-http", "application"},
		{"from_zone=trust&to_zone=untrust&format=json", "format"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			code, body := matchStatus(t, s, tc.raw)
			if code != 400 {
				t.Fatalf("unknown key %q status = %d, want 400; body: %s", tc.key, code, body)
			}
			if !strings.Contains(body, "unknown selector parameter") || !strings.Contains(body, tc.key) {
				t.Fatalf("unknown key %q body = %s, want an error naming it", tc.key, body)
			}
		})
	}
}

// TestMatchPoliciesRESTAcceptsAllKnownSelectors verifies the #5316 allowlist
// does not falsely reject a request that uses EVERY recognized selector key.
// This is the companion to the RED-on-revert test: it proves the fix rejects
// only UNKNOWN keys, not the legitimate selector set.
func TestMatchPoliciesRESTAcceptsAllKnownSelectors(t *testing.T) {
	s := &Server{store: hostInboundAPIStore(t)}

	// Exercise all nine selectors at once with well-formed values.
	raw := strings.Join([]string{
		"from_zone=trust",
		"to_zone=untrust",
		"src_ip=10.0.1.5",
		"dst_ip=10.0.2.5",
		"src_port=1024",
		"dst_port=443",
		"protocol=tcp",
		"icmp_type=8",
		"icmp_code=0",
	}, "&")
	code, body := matchStatus(t, s, raw)
	if code != 200 {
		t.Fatalf("all-known-selectors status = %d, want 200 (no false rejection); body: %s", code, body)
	}
}

// TestMatchPoliciesRESTNoSelectorStillMatches confirms an all-absent selector
// request (only the required zones, every other dimension the intentional
// match-any wildcard) stays 200 — the #5316 fix rejects unknown KEYS, never
// absent ones.
func TestMatchPoliciesRESTNoSelectorStillMatches(t *testing.T) {
	s := &Server{store: hostInboundAPIStore(t)}
	code, body := matchStatus(t, s, "from_zone=trust&to_zone=untrust")
	if code != 200 {
		t.Fatalf("zones-only query status = %d, want 200 (absent selectors are match-any); body: %s", code, body)
	}
}
