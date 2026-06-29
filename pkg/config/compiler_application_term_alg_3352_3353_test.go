package config

import (
	"strings"
	"testing"
)

// #3352 / #3353: an inline `applications application <a> term <t> { ... }` is an
// opaque `args:1` schema leaf (children:nil), so the SchemaValidate walk cannot
// reach inside it. Before these fixes:
//   - #3352: an unknown leaf inside a term (a typo like `destination-poort 22`)
//     was silently dropped along with its value — parseApplicationTerms had no
//     default arm — so a narrow permit/deny term widened to all-protocol.
//   - #3353: a per-application `alg` name was a raw string with no validator, so
//     a typo (`alg ftpp`) committed cleanly and the operator believed an ALG was
//     pinned when none was.
//
// Trees are built from flat `set` commands via flatTreeFromSets + refApp (shared
// with compiler_application_junos_ping_3348_test.go) — the only correct way to
// exercise the flat-set AST shape.

// #3352 core fail-on-revert: an unknown leaf inside an inline term must be
// rejected at commit. Revert the parseApplicationTerms default arm (or the
// strict gate) and the typo'd leaf is silently dropped, the term compiles to
// all-TCP, CompileConfig succeeds, and this assertion goes RED.
func TestApplicationTerm_UnknownLeaf_Rejected(t *testing.T) {
	cases := []string{
		"term t1 protocol tcp destination-poort 22",
		"term t1 protocol tcp source-prt 1024",
		"term t1 protocol tcp bogus-leaf foo",
	}
	for _, term := range cases {
		t.Run(term, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("badterm", term)...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("expected commit to REJECT unknown term leaf %q", term)
			} else if !strings.Contains(err.Error(), "unknown statement") {
				t.Fatalf("error should mention the unknown statement, got: %v", err)
			}
		})
	}
}

// A WELL-FORMED inline term (only recognized leaves) still compiles and keeps
// its port constraint — guards the #3352 gate against over-rejection and proves
// the widening is gone (the term carries the destination-port, not all-TCP).
func TestApplicationTerm_ValidLeaves_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("okterm",
		"term t1 protocol tcp destination-port 22 source-port 1024-65535 inactivity-timeout 300")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept a well-formed inline term: %v", err)
	}
	app := cfg.Applications.Applications["okterm-t1"]
	if app == nil {
		t.Fatalf("inline-term application okterm-t1 missing; have %v", appNames(cfg))
	}
	if app.DestinationPort != "22" {
		t.Fatalf("term must keep its destination-port 22 (not widen to all-TCP), got %q", app.DestinationPort)
	}
	if app.SourcePort != "1024-65535" {
		t.Fatalf("term must keep its source-port, got %q", app.SourcePort)
	}
	if app.InactivityTimeout != 300 {
		t.Fatalf("term must keep its inactivity-timeout 300, got %d", app.InactivityTimeout)
	}
}

// #3353 core fail-on-revert: an unknown per-application `alg` name (top-level)
// must be rejected at commit. Revert the strict-gate ALG check and `alg ftpp`
// commits cleanly, so this assertion goes RED.
func TestApplicationALG_UnknownName_TopLevel_Rejected(t *testing.T) {
	for _, bad := range []string{"ftpp", "ssh", "h323", "bogus"} {
		t.Run(bad, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("bad", "protocol tcp", "alg "+bad)...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("expected commit to REJECT unknown alg %q", bad)
			} else if !strings.Contains(err.Error(), "unknown alg") {
				t.Fatalf("error should mention the unknown alg, got: %v", err)
			}
		})
	}
}

// #3353: an unknown `alg` inside an inline term must also be rejected — the term
// app carries the ALG and the strict gate validates it the same way.
func TestApplicationALG_UnknownName_InlineTerm_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("badterm", "term t protocol tcp alg ftpp")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT unknown inline-term alg")
	} else if !strings.Contains(err.Error(), "unknown alg") {
		t.Fatalf("error should mention the unknown alg, got: %v", err)
	}
}

// A supported `alg` name (the DNS/FTP/SIP/TFTP set the global `security alg`
// control exposes) must still commit and be recorded — guards against
// over-rejection and proves the SSOT set is honored on both paths.
func TestApplicationALG_SupportedNames_Accepted(t *testing.T) {
	for _, ok := range []string{"dns", "ftp", "sip", "tftp", "FTP"} {
		t.Run(ok, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("okalg", "protocol tcp", "alg "+ok)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept supported alg %q: %v", ok, err)
			}
			app := cfg.Applications.Applications["okalg"]
			if app == nil || app.ALG != ok {
				t.Fatalf("supported alg %q must be recorded on the application, got %+v", ok, app)
			}
		})
	}
}

// A supported inline-term `alg` still commits and is carried onto the generated
// term application.
func TestApplicationALG_SupportedName_InlineTerm_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("okterm", "term t protocol tcp alg ftp")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept inline-term alg ftp: %v", err)
	}
	app := cfg.Applications.Applications["okterm-t"]
	if app == nil || app.ALG != "ftp" {
		t.Fatalf("inline-term alg ftp must be recorded, got %+v", app)
	}
}
