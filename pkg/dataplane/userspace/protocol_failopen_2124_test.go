package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2124 — a policy application term whose named protocol the Rust matcher could
// not parse (sctp/esp/ah/vrrp/igmp/pim/egp) silently failed OPEN to match-any.
// These tests pin the Go-side defenses: the capability gate fails closed on an
// unrepresentable protocol/port, canonicalizes the supported named protocols to
// their numeric wire form, and emits the __unsupported__ fail-closed sentinel
// (never nil) on a failed expansion so the published snapshot cannot fail open.

func twoZonePolicyCfg(app *config.Application, appName string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.Applications = map[string]*config.Application{app.Name: app}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "p",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{appName},
			},
			Action: config.PolicyPermit,
		}},
	}}
	return cfg
}

func TestUserspaceGateAcceptsAndCanonicalizesNamedProtocol(t *testing.T) {
	// esp must be supported (so a legit esp-only policy works) AND canonicalized
	// to its numeric wire form so an older helper that lacks the named-protocol
	// arms still parses it.
	cfg := twoZonePolicyCfg(&config.Application{Name: "esp-only", Protocol: "esp"}, "esp-only")
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"esp-only"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications = ok=false, want true for esp")
	}
	if len(terms) != 1 {
		t.Fatalf("len(terms) = %d, want 1", len(terms))
	}
	if terms[0].Protocol != "50" {
		t.Fatalf("esp canonicalized Protocol = %q, want \"50\"", terms[0].Protocol)
	}
	if !userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = false, want true for esp policy")
	}
}

func TestUserspaceGateFailsClosedOnUnknownProtocol(t *testing.T) {
	// A user-defined application with a protocol neither the Rust matcher nor
	// the centralized appid table can represent must fail the capability gate so
	// the dataplane refuses to arm (ForwardingSupported=false). Pre-fix this
	// returned ok=true (the fail-open).
	cfg := twoZonePolicyCfg(&config.Application{Name: "weird", Protocol: "definitely-not-a-proto"}, "weird")
	if _, ok := expandUserspacePolicyApplications(cfg, []string{"weird"}); ok {
		t.Fatal("expandUserspacePolicyApplications = ok=true, want false for unknown protocol")
	}
	if userspaceSupportsSecurityPolicies(cfg) {
		t.Fatal("userspaceSupportsSecurityPolicies = true, want false (refuse to arm) for unknown protocol")
	}
}

func TestUserspaceGateFailsClosedOnMalformedPort(t *testing.T) {
	for _, port := range []string{"99999", "5-1", "0", "abc"} {
		cfg := twoZonePolicyCfg(
			&config.Application{Name: "badport", Protocol: "tcp", DestinationPort: port},
			"badport",
		)
		if _, ok := expandUserspacePolicyApplications(cfg, []string{"badport"}); ok {
			t.Fatalf("expandUserspacePolicyApplications = ok=true for malformed port %q, want false", port)
		}
	}
}

func TestUserspaceGateAcceptsValidPortsAndAliases(t *testing.T) {
	for _, port := range []string{"", "443", "8080-8090", "https", "dns"} {
		cfg := twoZonePolicyCfg(
			&config.Application{Name: "okport", Protocol: "tcp", DestinationPort: port},
			"okport",
		)
		if _, ok := expandUserspacePolicyApplications(cfg, []string{"okport"}); !ok {
			t.Fatalf("expandUserspacePolicyApplications = ok=false for valid port %q, want true", port)
		}
	}
}

func TestBuildOneRuleSnapshotEmitsUnsupportedSentinel(t *testing.T) {
	// When expansion fails, the published rule must carry the __unsupported__
	// sentinel term (so Rust fails the whole snapshot closed), NEVER nil (which
	// Rust would read as genuine match-any — the publish-window fail-open).
	cfg := twoZonePolicyCfg(&config.Application{Name: "weird", Protocol: "definitely-not-a-proto"}, "weird")
	snap := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	terms := snap.Policies[0].ApplicationTerms
	if len(terms) != 1 {
		t.Fatalf("ApplicationTerms = %+v, want exactly the sentinel term", terms)
	}
	if terms[0].Protocol != unsupportedApplicationSentinel {
		t.Fatalf("sentinel Protocol = %q, want %q", terms[0].Protocol, unsupportedApplicationSentinel)
	}
}

func TestBuildOneRuleSnapshotNoSentinelForSupportedApp(t *testing.T) {
	// A supported named protocol must NOT trigger the sentinel; the rule carries
	// a normal canonicalized term.
	cfg := twoZonePolicyCfg(&config.Application{Name: "esp-only", Protocol: "esp"}, "esp-only")
	snap := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	terms := snap.Policies[0].ApplicationTerms
	if len(terms) != 1 || terms[0].Protocol != "50" {
		t.Fatalf("ApplicationTerms = %+v, want one esp term canonicalized to \"50\"", terms)
	}
}

func TestUserspacePortSpecRepresentableMirrorsRust(t *testing.T) {
	ok := []string{"", "1", "443", "65535", "80-90", "https", "ftp-data", "syslog"}
	for _, s := range ok {
		if !userspacePortSpecRepresentable(s) {
			t.Errorf("userspacePortSpecRepresentable(%q) = false, want true", s)
		}
	}
	bad := []string{"0", "65536", "99999", "5-1", "0-10", "abc", "80-", "-80", "80-abc"}
	for _, s := range bad {
		if userspacePortSpecRepresentable(s) {
			t.Errorf("userspacePortSpecRepresentable(%q) = true, want false", s)
		}
	}
}
