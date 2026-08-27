package config

import (
	"strings"
	"testing"
)

// #3366: a user-defined `applications application <name>` carries EITHER a
// direct match body (protocol / destination-port / source-port / timeout /
// icmp-type / icmp-code / alg) OR one or more `term` sub-blocks — Junos rejects
// the mix. Before this fix compileApplications stored ONLY the synthesized term
// applications for a term-bearing app (the `if len(terms) > 0` branch), silently
// DROPPING the direct match — for a deny application that erases the deny and
// lets traffic fall through (a fail-open under-match). A second gap: a
// single-valued leaf repeated inside one term was last-writer-wins, silently
// overriding the earlier value by token order.
//
// Trees are built from flat `set` commands via flatTreeFromSets + refApp /
// unrefAppOnly (shared helpers) — the only correct way to exercise the flat-set
// AST shape (NewParser merges newline-separated set lines).

// Core fail-on-revert: a REFERENCED application that mixes a direct match body
// with a `term` must be rejected at commit. Revert the structure gate and the
// direct `protocol tcp / destination-port 22` is silently dropped, only the term
// survives, CompileConfig succeeds, and this assertion goes RED.
func TestApplicationMixedDirectTerm_Referenced_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("mixed",
		"protocol tcp",
		"destination-port 22",
		"term t1 protocol udp destination-port 53")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to REJECT an app mixing a direct body with a term")
	}
	if !strings.Contains(err.Error(), "EITHER a direct match") {
		t.Fatalf("error should explain the EITHER/OR rule, got: %v", err)
	}
}

// Scope fail-on-revert: an UNREFERENCED app (outside applicationsToValidateStrict)
// mixing a direct body with a term must ALSO reject — the structure gate is a
// grammar error rejected at definition, like #3352/#3353, not reference-scoped.
func TestApplicationMixedDirectTerm_Unreferenced_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("lonely",
		"protocol tcp",
		"destination-port 22",
		"term t1 protocol udp destination-port 53")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT a mixed UNREFERENCED app")
	} else if !strings.Contains(err.Error(), "EITHER a direct match") {
		t.Fatalf("error should explain the EITHER/OR rule, got: %v", err)
	}
}

// Each direct match field independently triggers the gate when combined with a
// term (the silent drop is the same for any of them).
func TestApplicationMixedDirectTerm_EachDirectLeaf_Rejected(t *testing.T) {
	cases := []string{
		"protocol tcp",
		"destination-port 22",
		"source-port 1024-65535",
		"inactivity-timeout 300",
		"alg ftp",
		"icmp-type 8",
	}
	for _, direct := range cases {
		t.Run(direct, func(t *testing.T) {
			tree := flatTreeFromSets(t, unrefAppOnly("m",
				direct,
				"term t1 protocol tcp destination-port 80")...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("expected commit to REJECT direct %q + term", direct)
			} else if !strings.Contains(err.Error(), "EITHER a direct match") {
				t.Fatalf("error should explain the EITHER/OR rule, got: %v", err)
			}
		})
	}
}

// Hierarchical shape: a mixed direct+term app authored as a brace block must
// reject too (the compiler handles both AST shapes).
func TestApplicationMixedDirectTerm_Hierarchical_Rejected(t *testing.T) {
	tree := hierTree(t, `
applications {
    application mixed {
        protocol tcp;
        destination-port 22;
        term t1 {
            protocol udp;
            destination-port 53;
        }
    }
}
`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT a hierarchical mixed app")
	} else if !strings.Contains(err.Error(), "EITHER a direct match") {
		t.Fatalf("error should explain the EITHER/OR rule, got: %v", err)
	}
}

// Guard against over-rejection: a `description` is metadata, NOT a match
// constraint — an app with a description AND terms must still commit cleanly.
func TestApplicationMixedDirectTerm_DescriptionPlusTerm_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("descapp",
		"description \"two-term app\"",
		"term t1 protocol tcp destination-port 80")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("description + term must commit (description is not a match body): %v", err)
	}
	// The term application survives and the description is propagated onto it.
	app := cfg.Applications.Applications["descapp-t1"]
	if app == nil {
		t.Fatalf("term application descapp-t1 missing; have %v", appNames(cfg))
	}
	if app.DestinationPort != "80" {
		t.Fatalf("term must keep its destination-port 80, got %q", app.DestinationPort)
	}
}

// Guard: a direct-only app and a term-only app each commit cleanly (the gate
// fires only on the MIX, not on either shape alone).
func TestApplicationDirectOnly_And_TermOnly_Accepted(t *testing.T) {
	sets := append(
		unrefAppOnly("directapp", "protocol tcp", "destination-port 22"),
		unrefAppOnly("termapp", "term t1 protocol udp destination-port 53")...)
	tree := flatTreeFromSets(t, sets...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("direct-only and term-only apps must commit cleanly: %v", err)
	}
}

// #3366 duplicate scalar term leaf, core fail-on-revert: a destination-port
// repeated inside one inline term must be rejected. Before the fix the second
// value silently overrode the first (last-writer-wins). Revert the duplicate
// tracking and `destination-port 22 destination-port 80` commits as 80, so this
// assertion goes RED.
func TestApplicationTerm_DuplicateScalarLeaf_Rejected(t *testing.T) {
	cases := []struct {
		term string
		leaf string
	}{
		{"term t1 protocol tcp destination-port 22 destination-port 80", "destination-port"},
		{"term t1 protocol tcp source-port 1024 source-port 2048", "source-port"},
		{"term t1 protocol tcp inactivity-timeout 300 inactivity-timeout 600", "inactivity-timeout"},
		{"term t1 protocol tcp alg ftp alg dns", "alg"},
	}
	for _, c := range cases {
		t.Run(c.leaf, func(t *testing.T) {
			tree := flatTreeFromSets(t, unrefAppOnly("dup", c.term)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to REJECT duplicate %q inside a term", c.leaf)
			}
			if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), `"`+c.leaf+`"`) {
				t.Fatalf("error should name the duplicate leaf %q, got: %v", c.leaf, err)
			}
		})
	}
}

// Guard against over-rejection of the value-aware idempotent path: a scalar term
// leaf repeated with the SAME value is harmless (no value is silently lost) and
// must COMMIT — only a CONFLICTING (different-value) repeat is rejected. Pins (a)
// `destination-port 22` repeated as `destination-port 22`, and (b) the
// `inactivity-timeout 1800` + `timeout 1800` alias-same-value case (the two
// keywords set the same field). Flip the duplicate detection to value-blind
// (reject any repeat regardless of value) and this assertion goes RED.
func TestApplicationTerm_DuplicateScalarLeaf_Idempotent_Accepted(t *testing.T) {
	cases := []struct {
		name string
		term string
	}{
		{"same-destination-port", "term t1 protocol tcp destination-port 22 destination-port 22"},
		{"same-source-port", "term t1 protocol tcp source-port 1024 source-port 1024"},
		{"same-alg", "term t1 protocol tcp alg ftp alg ftp"},
		// timeout and inactivity-timeout are aliases for the same field; both set
		// to 1800 is idempotent, not a conflicting override.
		{"timeout-alias-same-value", "term t1 protocol tcp inactivity-timeout 1800 timeout 1800"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, unrefAppOnly("idem", c.term)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("an idempotent same-value repeat must COMMIT (only a "+
					"conflicting different-value repeat is rejected), got: %v", err)
			}
			// The single value survives on the generated term application.
			app := cfg.Applications.Applications["idem-t1"]
			if app == nil {
				t.Fatalf("term application idem-t1 missing; have %v", appNames(cfg))
			}
		})
	}
}

// Guard: a repeated `protocol` inside a term is the documented multi-protocol
// syntax (one application per unique protocol), NOT a duplicate — it must still
// commit and generate one app per protocol.
func TestApplicationTerm_RepeatedProtocol_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("multi",
		"term t1 protocol tcp protocol udp destination-port 53")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a multi-protocol term must commit (repeated protocol is not a duplicate): %v", err)
	}
	// Two protocols -> two synthesized apps, both keeping the port.
	for _, suffix := range []string{"multi-t1-tcp", "multi-t1-udp"} {
		if cfg.Applications.Applications[suffix] == nil {
			t.Fatalf("expected synthesized app %q; have %v", suffix, appNames(cfg))
		}
	}
}

// The tolerant load / peer-sync path (CompileConfigLenient) must NOT brick on a
// mixed app an older binary persisted — it downgrades the reject to a warning so
// the daemon still boots (#1960 no-brick). Revert the lenient downgrade and this
// goes RED.
func TestApplicationMixedDirectTerm_Lenient_DowngradesToWarning(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("mixed",
		"protocol tcp",
		"destination-port 22",
		"term t1 protocol udp destination-port 53")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must NOT fail on a mixed app (no-brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application structure") && strings.Contains(w, "EITHER a direct match") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path must record a downgrade warning; warnings: %v", cfg.Warnings)
	}
}
