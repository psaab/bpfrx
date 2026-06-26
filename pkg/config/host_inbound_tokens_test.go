package config

import (
	"strings"
	"testing"
)

// TestHostInboundUnknownTokenFailsCommit asserts that an unknown / typo'd
// `host-inbound-traffic system-services` / `protocols` token is HARD-REJECTED at
// commit (#3200).
//
// This is the fail-on-revert guard for the split-brain bug: before the fix the
// schema modeled system-services / protocols as untyped containers and the
// compiler copied every child token verbatim with NO validation, so a typo such
// as `system-services sssh` committed cleanly. At runtime the two enforcement
// layers then DISAGREED — the nftables kernel mirror emitted no match (and, for
// an all-unknown stanza, fell OPEN) while the Rust AF_XDP classifier ignored the
// token and denied everything else (fail CLOSED). Remove
// validateHostInboundTokensStrict (or its dispatch in compiler.go) and the
// reject subtests go green on the BAD config, which is exactly the regression
// this test exists to catch.
func TestHostInboundUnknownTokenFailsCommit(t *testing.T) {
	cases := []struct {
		name    string
		cmds    []string
		wantSub string
	}{
		{
			name: "unknown system-service",
			cmds: []string{
				"set security zones security-zone untrust host-inbound-traffic system-services sssh",
			},
			wantSub: `system-services "sssh"`,
		},
		{
			name: "unknown protocol",
			cmds: []string{
				"set security zones security-zone trust host-inbound-traffic protocols ospff",
			},
			wantSub: `protocols "ospff"`,
		},
		{
			name: "wrong-case system-service (nft is case-sensitive)",
			cmds: []string{
				"set security zones security-zone trust host-inbound-traffic system-services SSH",
			},
			wantSub: `system-services "SSH"`,
		},
		{
			name: "good token mixed with a typo still rejects",
			cmds: []string{
				"set security zones security-zone trust host-inbound-traffic system-services ssh",
				"set security zones security-zone trust host-inbound-traffic system-services htp",
			},
			wantSub: `system-services "htp"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject an unknown host-inbound token, got nil error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not name the bad token (want substring %q)", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestHostInboundKnownTokensCommit asserts the strict validator does NOT reject
// legitimate host-inbound tokens — including the full-admit tokens, the
// routing-scoped `protocols all` (#3199), aliases, and a representative spread
// of services/protocols (#3200 anti-over-reject). A regression here would break
// valid operator configs.
func TestHostInboundKnownTokensCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services ping",
		"set security zones security-zone trust host-inbound-traffic system-services https",
		"set security zones security-zone trust host-inbound-traffic system-services dhcpv6",
		"set security zones security-zone trust host-inbound-traffic system-services netconf-ssh",
		"set security zones security-zone trust host-inbound-traffic protocols ospf",
		"set security zones security-zone trust host-inbound-traffic protocols bgp",
		"set security zones security-zone untrust host-inbound-traffic system-services all",
		"set security zones security-zone wan host-inbound-traffic protocols all",
		"set security zones security-zone dmz host-inbound-traffic system-services any-service",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected legitimate host-inbound tokens: %v", err)
	}
}

// TestHostInboundUnknownTokenLenientDowngradesToWarning asserts the tolerant
// load / peer-sync path downgrades the unknown-token reject to a warning instead
// of failing the compile, so an already-persisted or peer-synced config carrying
// a stale token still boots (#3200 / #1960 no-brick). Both enforcement layers
// ignore the unknown token (Rust ignores it; nft now fails CLOSED on a
// zero-match zone), so the leniently-loaded config is inert and consistent.
func TestHostInboundUnknownTokenLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust host-inbound-traffic system-services sssh",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on an unknown host-inbound token: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "host-inbound-traffic token (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded host-inbound-token warning, got warnings: %v", cfg.Warnings)
	}
}
