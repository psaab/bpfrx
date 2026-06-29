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

// unrefAppOnly builds a config carrying ONLY `set applications application
// <name> <prop>...` lines — the application is NOT named by any policy,
// application-set, or NAT rule, so it is OUTSIDE applicationsToValidateStrict's
// referenced / app-id-enabled subset. The #3352/#3353 syntactic gate
// (validateApplicationSyntaxStrict) must still reject a typo'd term leaf or a
// bad alg here, at the moment the app is defined.
func unrefAppOnly(name string, props ...string) []string {
	var sets []string
	for _, p := range props {
		sets = append(sets, "set applications application "+name+" "+p)
	}
	return sets
}

// #3352 scope fail-on-revert (the Codex MERGE-NEEDS-MAJOR gap): an UNREFERENCED
// user application with a typo'd inline-term leaf must be rejected at commit.
// Before widening the gate to all user apps this committed silently (the app is
// not in applicationsToValidateStrict). Revert validateApplicationSyntaxStrict's
// all-user-apps loop and this goes RED.
func TestApplicationTerm_UnknownLeaf_Unreferenced_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("lonely", "term t1 protocol tcp destination-poort 22")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT unknown term leaf on an UNREFERENCED app")
	} else if !strings.Contains(err.Error(), "unknown statement") {
		t.Fatalf("error should mention the unknown statement, got: %v", err)
	}
}

// #3353 scope fail-on-revert: an UNREFERENCED user application with an
// unsupported `alg` must be rejected at commit (top-level and inline-term).
func TestApplicationALG_UnknownName_Unreferenced_Rejected(t *testing.T) {
	cases := [][]string{
		{"protocol tcp", "alg ftpp"},
		{"term t protocol tcp alg h323"},
	}
	for i, props := range cases {
		t.Run(strings.Join(props, "_"), func(t *testing.T) {
			tree := flatTreeFromSets(t, unrefAppOnly("lonely", props...)...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("case %d: expected commit to REJECT unknown alg on an UNREFERENCED app", i)
			} else if !strings.Contains(err.Error(), "unknown alg") {
				t.Fatalf("case %d: error should mention the unknown alg, got: %v", i, err)
			}
		})
	}
}

// Guard against over-rejection: an UNREFERENCED user app with only valid leaves
// and a supported alg still commits cleanly.
func TestApplicationTermALG_Unreferenced_Valid_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("lonely",
		"protocol tcp", "destination-port 22", "alg ftp",
		"term t protocol udp destination-port 53 alg dns")...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("expected commit to accept a well-formed UNREFERENCED app: %v", err)
	}
}

// Predefined junos-* applications (junos-rtsp / junos-ftp / ...) are owned by
// the PredefinedApplications table, NOT cfg.Applications.Applications, so the
// all-user-apps syntax gate never reaches them. A policy referencing a
// predefined app — including ones that legitimately carry ALGs — must still
// commit cleanly (the widening must not false-reject predefined apps).
func TestApplicationALG_PredefinedApp_NotRejected(t *testing.T) {
	for _, pre := range []string{"junos-rtsp", "junos-ftp"} {
		t.Run(pre, func(t *testing.T) {
			sets := []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application " + pre,
				"set security policies from-zone trust to-zone untrust policy p then permit",
			}
			tree := flatTreeFromSets(t, sets...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("expected commit to accept predefined app %q reference: %v", pre, err)
			}
			if _, isUser := PredefinedApplications[pre]; !isUser {
				t.Fatalf("test precondition: %q must be a predefined app", pre)
			}
		})
	}
}
