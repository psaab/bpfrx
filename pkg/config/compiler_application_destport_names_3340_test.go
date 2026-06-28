package config

import (
	"strings"
	"testing"
)

// #3340: a custom application's destination-port / source-port only recognized a
// hard-coded 15-name subset (http https ssh telnet ftp ftp-data smtp dns pop3
// imap snmp ntp bgp ldap syslog). Any other valid Junos service name — notably
// `domain`, the canonical alias of the already-accepted `dns` — was rejected at
// commit as "not a number or known service", even though the dataplane can
// represent the numeric port exactly. The fix resolves application named ports
// through the shared junosServicePorts catalog (the SAME SSOT the firewall-filter
// path uses) at compile time, so the dataplane only ever sees numerics. An
// unknown name still hard-rejects at the strict commit gate and downgrades to a
// warning on the lenient (tolerant load / HA sync) path.
//
// These trees are built from flat `set` commands via flatTreeFromSets — the only
// correct way to exercise the flat-set AST shape (see compiler_application_specs_test.go).

func referencedAppDestPort(destPort string) []string {
	return []string{
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port " + destPort,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	}
}

// The issue's headline case: `domain` (alias of `dns`, port 53) was rejected;
// it must now resolve and commit. Fail-on-revert: without resolveAppPort,
// "domain" reaches validatePortSpec's 15-name map (which has `dns` but not
// `domain`) and CompileConfig errors — this test goes RED.
func TestApplicationDestPort_DomainAlias_ResolvesAndCommits(t *testing.T) {
	tree := flatTreeFromSets(t, referencedAppDestPort("domain")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept application BAD with destination-port domain: %v", err)
	}
	if got := cfg.Applications.Applications["BAD"].DestinationPort; got != "53" {
		t.Fatalf("destination-port domain must resolve to numeric 53, got %q", got)
	}
}

// A spread of Junos service names beyond the old 15-name subset — including
// hyphenated names (ftp-data, kerberos-sec, tacacs-ds) that a naive range-split
// would mangle — must resolve to their numeric port and commit.
func TestApplicationDestPort_CatalogNames_ResolveAndCommit(t *testing.T) {
	cases := map[string]string{
		"domain":       "53",
		"www":          "80",
		"kerberos-sec": "88",
		"ftp-data":     "20",
		"tacacs-ds":    "65",
		"snmptrap":     "162",
		"radius":       "1812",
		"nfsd":         "2049",
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			tree := flatTreeFromSets(t, referencedAppDestPort(name)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept destination-port %q: %v", name, err)
			}
			if got := cfg.Applications.Applications["BAD"].DestinationPort; got != want {
				t.Fatalf("destination-port %q must resolve to %q, got %q", name, want, got)
			}
		})
	}
}

// Mixed-case service name must resolve (the catalog lookup is case-insensitive)
// rather than passing through unresolved. This is the application-path corner of
// the #3372 mixed-case concern — exercised here only to prove this change does
// not regress it; #3372 itself is out of scope.
func TestApplicationDestPort_MixedCaseName_Resolves(t *testing.T) {
	tree := flatTreeFromSets(t, referencedAppDestPort("Domain")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept mixed-case destination-port Domain: %v", err)
	}
	if got := cfg.Applications.Applications["BAD"].DestinationPort; got != "53" {
		t.Fatalf("mixed-case Domain must resolve to 53, got %q", got)
	}
}

// source-port named-port resolution rides the same path.
func TestApplicationSourcePort_CatalogName_Resolves(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol tcp",
		"set applications application BAD source-port domain",
		"set applications application BAD destination-port 80",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept source-port domain: %v", err)
	}
	if got := cfg.Applications.Applications["BAD"].SourcePort; got != "53" {
		t.Fatalf("source-port domain must resolve to 53, got %q", got)
	}
}

// Numeric ports and numeric ranges must keep working unchanged (positive
// control proving the resolver does not perturb the already-numeric path).
func TestApplicationDestPort_NumericAndRange_StillCommit(t *testing.T) {
	for _, spec := range []string{"443", "8080-8090"} {
		tree := flatTreeFromSets(t, referencedAppDestPort(spec)...)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("expected commit to accept destination-port %q: %v", spec, err)
		}
		if got := cfg.Applications.Applications["BAD"].DestinationPort; got != spec {
			t.Fatalf("numeric spec %q must pass through unchanged, got %q", spec, got)
		}
	}
}

// A named range (service-name endpoints) resolves to a numeric range.
func TestApplicationDestPort_NamedRange_Resolves(t *testing.T) {
	tree := flatTreeFromSets(t, referencedAppDestPort("http-https")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept destination-port http-https: %v", err)
	}
	if got := cfg.Applications.Applications["BAD"].DestinationPort; got != "80-443" {
		t.Fatalf("named range http-https must resolve to 80-443, got %q", got)
	}
}

// An inline term's destination-port named port resolves on the term path too.
func TestApplicationDestPort_InlineTerm_Resolves(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application MT term t1 protocol tcp destination-port domain",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("inline-term destination-port domain must compile: %v", err)
	}
	app := cfg.Applications.Applications["MT-t1"]
	if app == nil {
		t.Fatalf("expected inline-term application MT-t1, got %v", cfg.Applications.Applications)
	}
	if app.DestinationPort != "53" {
		t.Fatalf("inline-term destination-port domain must resolve to 53, got %q", app.DestinationPort)
	}
}

// An unknown service name must still hard-reject at the strict commit gate.
// Fail-on-revert: this is the unchanged strict-reject half of the contract — a
// genuinely unresolvable name (not in the catalog, not numeric) must never
// commit, so widening the catalog does not turn into accept-anything.
func TestApplicationDestPort_UnknownName_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedAppDestPort("not-a-service")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject application BAD with unknown destination-port not-a-service")
	}
	if !strings.Contains(err.Error(), "BAD") || !strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name application BAD and destination-port", err.Error())
	}
}

// No-brick (#1960/#3261): a config persisted/synced with a policy-referenced
// unknown-named-port application must still LOAD on the tolerant path
// (CompileConfigLenient) — downgraded to a warning, NOT a hard fail — so an
// upgraded/peer-syncing node does not fail closed on boot. The runtime #2124
// capability gate keeps that one unrepresentable app inert.
func TestApplicationDestPort_UnknownName_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, referencedAppDestPort("not-a-service")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a referenced unknown-named-port app must not fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application spec") && strings.Contains(w, "BAD") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient path to record an application-spec downgrade warning, got %v", cfg.Warnings)
	}
}
