package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMixedCaseNamedPortNoCommitApplySplit is the dataplane half of #3372.
//
// A custom application with a MIXED-CASE named port (`destination-port HTTPS`)
// referenced by a security policy must lower through the userspace policy
// snapshot to the numeric port term (443) WITHOUT tripping the #2124 capability
// gate — i.e. no `__unsupported__` sentinel and no refuse-to-arm. The commit
// gate accepts the config (Junos service names are case-insensitive); this test
// pins that apply agrees, closing the commit/apply split the audit reported.
//
// The config is built from flat-set commands and run through CompileConfig so
// the test exercises the real AST -> typed-struct path (compileApplications ->
// resolveAppPort), NOT a hand-built struct. A hand-built config.Config would set
// app.DestinationPort = "HTTPS" verbatim and bypass the canonicalization under
// test, making the assertion tautological (and the existing
// userspacePortSpecRepresentable case-sensitivity tests already cover the raw
// gate).
//
// RED-on-revert: delete the strings.ToLower in pkg/config resolveAppPort and the
// compiled app.DestinationPort becomes "HTTPS" verbatim; the case-sensitive
// capability gate (userspacePortSpecRepresentable / Rust parse_port_spec) then
// rejects it, expandUserspacePolicyApplications returns ok=false, and
// buildOneRuleSnapshot emits the __unsupported__ sentinel instead of the 443
// term — this test flips RED.
func TestMixedCaseNamedPortNoCommitApplySplit(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec string
		port string
	}{
		{"upper-https", "HTTPS", "443"},
		{"mixed-http", "Http", "80"},
		{"upper-dns", "DNS", "53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			for _, cmd := range [][]string{
				{"applications", "application", "web", "protocol", "tcp"},
				{"applications", "application", "web", "destination-port", tc.spec},
				{"security", "zones", "security-zone", "trust"},
				{"security", "zones", "security-zone", "untrust"},
				{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "source-address", "any"},
				{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "destination-address", "any"},
				{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "application", "web"},
				{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "then", "permit"},
			} {
				if err := tree.SetPath(cmd); err != nil {
					t.Fatalf("SetPath(%v): %v", cmd, err)
				}
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}

			snaps, err := buildPolicySnapshots(cfg)
			if err != nil {
				t.Fatalf("buildPolicySnapshots: %v", err)
			}
			if len(snaps) != 1 {
				t.Fatalf("expected 1 policy rule snapshot, got %d", len(snaps))
			}
			terms := snaps[0].ApplicationTerms
			if len(terms) != 1 {
				t.Fatalf("expected exactly 1 application term, got %d: %+v", len(terms), terms)
			}
			term := terms[0]
			if term.Protocol == unsupportedApplicationSentinel {
				t.Fatalf("mixed-case named port %q emitted the __unsupported__ sentinel — commit/apply split (refuse-to-arm)", tc.spec)
			}
			if term.Protocol != "tcp" || term.DestinationPort != tc.port {
				t.Fatalf("term = {proto:%q dport:%q}, want {tcp %s} for %q", term.Protocol, term.DestinationPort, tc.port, tc.spec)
			}
		})
	}
}

// TestMixedCaseNamedPortSnapshotNotContentRejected pins the system-level
// property: the BUILT snapshot for a config whose only notable feature is a
// referenced mixed-case named-port application must carry NO policy-content
// rejection. A class-(i) rejection (the __unsupported__ sentinel that
// collectPolicyContentRejections records on snap.Capabilities) makes the
// helper's integrity preflight reject the WHOLE snapshot at apply (#3261) — the
// silent apply-time degradation the audit reported. With the case-fold reverted
// the raw "HTTPS" reaches the #2124 port gate, the term collapses to the
// sentinel, and PolicyContentRejected becomes non-empty — this flips RED.
func TestMixedCaseNamedPortSnapshotNotContentRejected(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range [][]string{
		{"applications", "application", "web", "protocol", "tcp"},
		{"applications", "application", "web", "destination-port", "HTTPS"},
		{"security", "zones", "security-zone", "trust"},
		{"security", "zones", "security-zone", "untrust"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "source-address", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "destination-address", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "application", "web"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "then", "permit"},
	} {
		if err := tree.SetPath(cmd); err != nil {
			t.Fatalf("SetPath(%v): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("snapshot rejected policy content for a referenced mixed-case named-port app — apply-time degradation (whole-snapshot preflight reject): %v", snap.Capabilities.PolicyContentRejected)
	}
}
