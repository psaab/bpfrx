package config

import (
	"strings"
	"testing"
)

// #2142: an `set applications application <name>` with a malformed
// destination-port / source-port or an unknown protocol was only WARNED at
// commit (ValidateConfig), never rejected. Commit succeeded, the dataplane
// app-id compiler recorded the AppID name then skipped the unparsable port (a
// never-match AppID), and a policy referencing the application failed CLOSED on
// a permit rule or fell through OPEN on a deny rule. These tests drive the real
// strict commit path (CompileConfig) and the tolerant load path
// (CompileConfigLenient) through validateApplicationSpecsStrict.
//
// All trees are built from flat `set` commands via flatTreeFromSets (defined in
// compiler_interfaces_unsupported_test.go) — the only correct way to exercise
// the flat-set AST shape.

// referencedBadApp wires the issue's exact trigger: a policy `deny` rule that
// matches a malformed application. baseValid is the same structure with a VALID
// destination-port, proving the reject is caused by the bad spec, not the
// surrounding policy.
func referencedBadApp(destPort string) []string {
	return []string{
		// One leaf per `set` line: a single flat-set line nests each token as a
		// child of the previous, so `protocol tcp destination-port X` would bury
		// destination-port under protocol and the compiler would never see it
		// (see TestMultiTermApplication for the multi-token-chain pitfall).
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port " + destPort,
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	}
}

func TestApplicationSpec_ReferencedBadDestPort_RejectsAtCommit(t *testing.T) {
	// The issue's verbatim trigger: destination-port nope.
	tree := flatTreeFromSets(t, referencedBadApp("nope")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject application BAD with destination-port nope")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name application BAD and destination-port", err.Error())
	}
}

func TestApplicationSpec_ReferencedOutOfRangeDestPort_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedBadApp("99999")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject application BAD with destination-port 99999")
	}
}

func TestApplicationSpec_ReferencedInvertedRange_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedBadApp("200-100")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject application BAD with inverted range 200-100")
	}
}

func TestApplicationSpec_ReferencedUnknownProtocol_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol bogus",
		"set applications application BAD destination-port 80",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject application BAD with protocol bogus")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error %q must name application BAD and the bad protocol", err.Error())
	}
}

func TestApplicationSpec_ReferencedBadSourcePort_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol tcp",
		"set applications application BAD source-port nope",
		"set applications application BAD destination-port 80",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject application BAD with source-port nope")
	}
	if !strings.Contains(err.Error(), "source-port") {
		t.Fatalf("error %q must mention source-port", err.Error())
	}
}

// Non-tautological companion: the SAME policy structure with a VALID
// destination-port must commit cleanly, proving the reject above is caused by
// the malformed spec and not the surrounding policy.
func TestApplicationSpec_ReferencedValid_AcceptsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedBadApp("8080-8090")...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("expected commit to accept application BAD with valid range: %v", err)
	}
}

// A malformed application that is referenced via an application-SET (the policy
// names the set, not the app directly) must also reject at commit.
func TestApplicationSpec_ReferencedViaSet_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port nope",
		"set applications application-set SET application BAD",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application SET",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject application BAD referenced via application-set SET")
	}
}

// app-id (services application-identification) enabled: EVERY user application
// compiles into the catalog, so a malformed app must reject at commit even when
// no policy references it.
func TestApplicationSpec_AppIDEnabledUnreferencedBad_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port nope",
		"set services application-identification",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject unreferenced application BAD when app-id is enabled")
	}
}

// An UNREFERENCED application with app-id DISABLED is not matchable by anything,
// so its malformed spec stays a warning (the explicit referenced-vs-unreferenced
// distinction in #2142). This keeps an operator iterating on a not-yet-wired
// application library unblocked, and preserves existing configs that carry an
// unreferenced app with a port form the policy matcher cannot represent.
func TestApplicationSpec_UnreferencedBad_WarnsNotRejected(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol bogus",
		"set applications application BAD destination-port nope",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("unreferenced bad app must not reject at commit: %v", err)
	}
	// ValidateConfig still surfaces it as a warning (the show paths use this).
	var warned bool
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "BAD") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("expected ValidateConfig to warn about unreferenced bad application BAD")
	}
}

// No-brick (#1960 / #2008 doctrine): a config persisted/synced with a
// policy-referenced malformed application must still LOAD on the tolerant path
// (CompileConfigLenient) — downgraded to a warning — so an upgraded node does
// not fail closed on boot. The runtime #2124 capability gate fails the snapshot
// closed for the referenced app it cannot represent, so the leniently-loaded
// bad app is inert rather than silently mis-matching.
func TestApplicationSpec_ReferencedBad_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, referencedBadApp("nope")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a referenced bad app must not fail: %v", err)
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
