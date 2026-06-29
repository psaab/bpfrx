package config

import (
	"strings"
	"testing"
)

// #3352: an unknown leaf inside an inline `applications application <a> term
// <t> ...` was SILENTLY ignored — parseApplicationTerms switched on the known
// term leaves with no default arm, so a typo like `destination-poort 22` (and
// its value) were dropped and the term kept only its other constraints. A
// narrow `protocol tcp destination-port 22` term thus widened to all-TCP with
// NO destination-port, and the commit SUCCEEDED. The compiler now records the
// unknown keyword on Application.UnknownTermLeaves and
// validateApplicationSpecsStrict rejects it at the strict commit gate
// (lenient-warn on the tolerant load / peer-sync path).
//
// #3353: a per-application `alg` name was stored verbatim with no validation, so
// a typo like `alg ftpp` committed cleanly (a silent no-op — the operator
// believes an ALG is pinned when none is). The strict gate now rejects any name
// outside the four ALGs xpf implements (dns/ftp/sip/tftp), again lenient-warn on
// the tolerant path. NOTE: even a recognized per-application alg is validate-only
// today — per-application ALG enforcement is the deferred half of #3353.
//
// All trees are built from flat `set` commands via flatTreeFromSets — the only
// correct way to exercise set syntax (see CLAUDE.md). refApp / appNames are
// defined in compiler_application_junos_ping_3348_test.go.

// --- #3352: unknown inline-term leaf -----------------------------------------

// FAIL-ON-REVERT: removing the `default:` arm in parseApplicationTerms (or the
// `len(app.UnknownTermLeaves) > 0` block in validateApplicationSpecsStrict)
// makes this commit clean again, so CompileConfig returns nil and the
// `err == nil` assertion fires RED.
func TestApplicationTermUnknownLeaf_RejectsAtCommit(t *testing.T) {
	// The exact worked example from the issue: a misspelled destination-port that
	// silently widened a narrow TCP/22 term to all-TCP.
	tree := flatTreeFromSets(t, refApp("widen", "term t1 protocol tcp destination-poort 22")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to REJECT an unknown leaf (destination-poort) inside an inline term")
	}
	if !strings.Contains(err.Error(), "destination-poort") {
		t.Fatalf("error %q must name the unknown leaf destination-poort", err.Error())
	}
}

// A second typo shape (an entirely unknown keyword) also rejects, proving the
// gate is the default arm and not a destination-port-specific check.
func TestApplicationTermBogusLeaf_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("bogus", "term t1 protocol tcp frobnicate 9")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to REJECT an unknown leaf (frobnicate) inside an inline term")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("error %q must name the unknown leaf frobnicate", err.Error())
	}
}

// Non-tautological companion: the SAME term with the CORRECT spelling commits
// cleanly AND the destination-port constraint actually lands on the generated
// term application (a regression that accepted but dropped the port would be
// caught by the want check).
func TestApplicationTermValidLeaves_AcceptsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("ok", "term t1 protocol tcp destination-port 22 source-port 1024-65535")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected a well-formed inline term to commit cleanly: %v", err)
	}
	app := cfg.Applications.Applications["ok-t1"]
	if app == nil {
		t.Fatalf("inline-term application ok-t1 missing; have %v", appNames(cfg))
	}
	if app.DestinationPort != "22" {
		t.Fatalf("term destination-port must land as 22, got %q (silent widening regression)", app.DestinationPort)
	}
	if len(app.UnknownTermLeaves) != 0 {
		t.Fatalf("well-formed term must record no unknown leaves, got %v", app.UnknownTermLeaves)
	}
}

// No-brick (#1960): a config persisted/synced with an unknown inline-term leaf
// must still LOAD on the tolerant path, downgraded to a warning.
func TestApplicationTermUnknownLeaf_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("widen", "term t1 protocol tcp destination-poort 22")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of an unknown-term-leaf config must not fail: %v", err)
	}
	if !hasAppSpecWarning(cfg.Warnings, "destination-poort") {
		t.Fatalf("expected a downgraded application-spec warning naming destination-poort, got %v", cfg.Warnings)
	}
}

// --- #3353: per-application alg validation -----------------------------------

// FAIL-ON-REVERT: removing the alg block in validateApplicationSpecsStrict makes
// these commit clean again, turning the assertions RED.
func TestApplicationUnknownALG_RejectsAtCommit(t *testing.T) {
	// Top-level alg leaf.
	t.Run("top-level", func(t *testing.T) {
		tree := flatTreeFromSets(t, refApp("a", "protocol tcp", "alg ftpp")...)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected commit to REJECT a typo alg ftpp")
		}
		if !strings.Contains(err.Error(), "ftpp") || !strings.Contains(err.Error(), "alg") {
			t.Fatalf("error %q must name the bad alg and the alg keyword", err.Error())
		}
	})
	// Inline-term alg leaf (opaque to the schema walk — only the strict gate
	// covers it).
	t.Run("inline-term", func(t *testing.T) {
		tree := flatTreeFromSets(t, refApp("b", "term t1 protocol tcp alg sipp")...)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected commit to REJECT a typo alg sipp inside an inline term")
		}
		if !strings.Contains(err.Error(), "sipp") {
			t.Fatalf("error %q must name the bad alg sipp", err.Error())
		}
	})
}

// Every supported ALG (the four xpf implements) commits cleanly and the value
// lands on the compiled application.
func TestApplicationValidALG_AcceptsAtCommit(t *testing.T) {
	for _, alg := range []string{"dns", "ftp", "sip", "tftp"} {
		t.Run(alg, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("c", "protocol tcp", "alg "+alg)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept alg %s: %v", alg, err)
			}
			if app := cfg.Applications.Applications["c"]; app == nil || app.ALG != alg {
				t.Fatalf("alg %s must land on the compiled application, got %+v", alg, app)
			}
		})
	}
}

// No-brick (#1960): a config persisted/synced with an unsupported alg must still
// LOAD on the tolerant path, downgraded to a warning.
func TestApplicationUnknownALG_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("a", "protocol tcp", "alg ftpp")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of an unknown-alg config must not fail: %v", err)
	}
	if !hasAppSpecWarning(cfg.Warnings, "ftpp") {
		t.Fatalf("expected a downgraded application-spec warning naming ftpp, got %v", cfg.Warnings)
	}
}

func hasAppSpecWarning(warnings []string, needle string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "application spec") && strings.Contains(w, needle) {
			return true
		}
	}
	return false
}
