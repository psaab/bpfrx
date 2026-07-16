package config

import (
	"strings"
	"testing"
)

// #5821: the AppID display/filter surface (ResolveSessionName / SessionMatches,
// pkg/appid/runtime.go) uses the literal "UNKNOWN" as the "no known
// application" sentinel and carries a user-defined application/application-set
// name verbatim into the SAME flattened string. A catalog application literally
// named UNKNOWN is therefore indistinguishable from the sentinel — a
// `show`/`clear ... application UNKNOWN` selector cannot separate unclassified
// sessions from the configured app, and a filtered clear could delete both.
//
// These tests pin the strict reject at commit (CompileConfig) for the
// application, application-set, and multi-term (implicit-set) spellings and for
// every casing variant (SessionMatches folds case, so the reservation is
// case-insensitive), plus the lenient downgrade-to-warning on the tolerant load
// / peer-sync path (CompileConfigLenient) so an already-persisted config still
// boots (#1960).
//
// buildTreeFromSet (ipsec_proposal_ref_test.go) builds the candidate tree the
// way the configstore does (ParseSetCommand + SetPath), NOT NewParser — the
// parser merges newline-separated set lines into one node (per CLAUDE.md).

// FAIL-ON-REVERT: neutralizing validateReservedApplicationNamesStrict (making it
// `return nil`) makes CompileConfig ACCEPT `application UNKNOWN`, so this test
// goes RED (expects a rejection, gets nil).
func TestReservedApplicationNameRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application UNKNOWN protocol tcp",
		"set applications application UNKNOWN destination-port 80",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of application named UNKNOWN, got nil")
	}
	if !strings.Contains(err.Error(), "reserved") || !strings.Contains(err.Error(), "#5821") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Casing variants must collide too: SessionMatches folds case, so "unknown" and
// "Unknown" alias the sentinel just as "UNKNOWN" does.
func TestReservedApplicationNameCaseVariantsRejected(t *testing.T) {
	for _, variant := range []string{"unknown", "Unknown", "uNkNoWn"} {
		tree := buildTreeFromSet(t, []string{
			"set applications application " + variant + " protocol tcp",
			"set applications application " + variant + " destination-port 80",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig: expected rejection of application named %q (case variant of the sentinel), got nil", variant)
		}
		if !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("variant %q: unexpected error text: %v", variant, err)
		}
	}
}

// An application-set named UNKNOWN is rejected the same way (applications and
// application-sets share one flat Junos namespace). A valid predefined member
// keeps the set-member gate happy so the reservation gate is what fires.
func TestReservedApplicationSetNameRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application-set UNKNOWN application junos-http",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of application-set named UNKNOWN, got nil")
	}
	if !strings.Contains(err.Error(), "reserved") ||
		!strings.Contains(err.Error(), "application-set") ||
		!strings.Contains(err.Error(), "#5821") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// A MULTI-TERM `application UNKNOWN` mints an implicit application-set under its
// own name (cfg.Applications.ApplicationSets["UNKNOWN"]); the reservation gate
// walks that map too, so the authored parent name is still caught even though
// the compiler stores only the generated per-term application (UNKNOWN-t1).
func TestReservedMultiTermApplicationNameRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application UNKNOWN term t1 protocol tcp destination-port 80",
		"set applications application UNKNOWN term t2 protocol udp destination-port 53",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of multi-term application named UNKNOWN, got nil")
	}
	if !strings.Contains(err.Error(), "reserved") || !strings.Contains(err.Error(), "#5821") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// A normal application name is accepted; the reservation is scoped strictly to
// the sentinel and must not reject ordinary catalog names.
func TestNonReservedApplicationNameAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application my-app protocol tcp",
		"set applications application my-app destination-port 80",
		"set applications application-set my-set application my-app",
	})

	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: expected a normal application name to be accepted, got: %v", err)
	}
}

// A generated per-term application name (`<parent>-<term>`) never equals the
// reserved sentinel, so a normally-named multi-term application compiles clean.
func TestReservedGateDoesNotRejectGeneratedTermNames(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application unknown-svc term t1 protocol tcp destination-port 80",
	})

	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: expected multi-term application unknown-svc (not the sentinel) to be accepted, got: %v", err)
	}
}

// Tolerant load / peer-sync (#1960): an already-persisted config carrying the
// now-reserved name must still BOOT — the reject is downgraded to a warning so a
// running node does not brick on upgrade.
func TestReservedApplicationNameLenientDowngrade(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application UNKNOWN protocol tcp",
		"set applications application UNKNOWN destination-port 80",
	})

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: expected the reserved name to downgrade to a warning and boot, got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("CompileConfigLenient: expected a non-nil config on the tolerant path")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "reserved application name") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient: expected a 'reserved application name' warning, got: %v", cfg.Warnings)
	}
}

// The reserved literal must remain exactly "UNKNOWN" — the same value the AppID
// sentinel uses (appid.Unknown). If this constant changes, the reservation
// stops protecting the sentinel it is meant to reserve. (The cross-package
// canary in pkg/appid asserts equality with appid.Unknown directly.)
func TestReservedApplicationNameConstant(t *testing.T) {
	if ReservedApplicationName != "UNKNOWN" {
		t.Fatalf("ReservedApplicationName = %q, want \"UNKNOWN\"", ReservedApplicationName)
	}
}
