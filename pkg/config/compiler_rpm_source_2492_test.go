package config

import (
	"strings"
	"testing"
)

// TestRPMSourceAddressMalformedStrictRejects pins the #2492 commit-time
// gate: a non-empty but unparseable source-address is hard-rejected on
// the strict path (commit / commit-check). This FAILS against master,
// which accepts the malformed source and silently degrades the
// tcp-ping/http-get probe to a wildcard source bind.
func TestRPMSourceAddressMalformedStrictRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"out-of-range octet", "10.0.0.999"},
		{"not an ip", "not-an-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set services rpm probe P test t probe-type tcp-ping",
				"set services rpm probe P test t target 1.1.1.1",
				"set services rpm probe P test t source-address " + tc.src,
			}
			tree := buildTree(t, lines)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted malformed source-address %q; want strict reject", tc.src)
			}
			if !strings.Contains(err.Error(), "source-address: invalid IP address") {
				t.Fatalf("err = %v, want substring %q", err, "source-address: invalid IP address")
			}
		})
	}
}

// TestRPMSourceAddressMalformedLenientWarns pins the no-brick contract
// (#1960 doctrine): the same malformed source-address that the strict
// path rejects is TOLERATED on the lenient load / peer-sync path —
// downgraded to a warning so an already-persisted or peer-synced config
// still boots.
func TestRPMSourceAddressMalformedLenientWarns(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type tcp-ping",
		"set services rpm probe P test t target 1.1.1.1",
		"set services rpm probe P test t source-address 10.0.0.999",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on malformed source (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "rpm source-address") {
		t.Fatalf("expected a downgraded rpm source-address warning, warnings=%v", cfg.Warnings)
	}
}

// TestRPMSourceAddressFamilyMismatch covers layer 2: a v6 source with a
// v4 IP-literal target (and vice-versa) is unpinnable and rejected
// strict; a hostname target's family is unknown at commit time so the
// family check is skipped (accepted).
func TestRPMSourceAddressFamilyMismatch(t *testing.T) {
	t.Run("v6 source v4 literal target rejected", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t probe-type tcp-ping",
			"set services rpm probe P test t target 1.1.1.1",
			"set services rpm probe P test t source-address 2001:db8::1",
		}
		tree := buildTree(t, lines)
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "address family does not match") {
			t.Fatalf("err = %v, want family-mismatch rejection", err)
		}
	})

	t.Run("v4 source v6 literal target rejected", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t probe-type tcp-ping",
			"set services rpm probe P test t target 2001:db8::2",
			"set services rpm probe P test t source-address 10.0.0.1",
		}
		tree := buildTree(t, lines)
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "address family does not match") {
			t.Fatalf("err = %v, want family-mismatch rejection", err)
		}
	})

	t.Run("hostname target accepted (family unknown)", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t probe-type tcp-ping",
			"set services rpm probe P test t target example.com",
			"set services rpm probe P test t source-address 2001:db8::1",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("hostname target with v6 source must be accepted (family unknown): %v", err)
		}
	})
}

// TestRPMSourceAddressValidAndEmptyAccepted confirms the legitimate
// cases: an empty source-address (default bind) and a parseable
// same-family source both compile cleanly on the strict path.
func TestRPMSourceAddressValidAndEmptyAccepted(t *testing.T) {
	t.Run("empty source-address (default bind) accepted", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t probe-type tcp-ping",
			"set services rpm probe P test t target 1.1.1.1",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("empty source-address must be accepted (means default source): %v", err)
		}
	})

	t.Run("valid same-family source accepted", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t probe-type tcp-ping",
			"set services rpm probe P test t target 1.1.1.1",
			"set services rpm probe P test t source-address 10.0.0.5",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("valid v4 source + v4 target must be accepted: %v", err)
		}
	})
}

func hasWarningSubstr(warnings []string, sub string) bool {
	for _, w := range warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
