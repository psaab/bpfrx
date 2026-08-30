package config

import (
	"strings"
	"testing"
)

// log_profile_unimplemented_declaration_7502_test.go — #7502.
//
// `security log profile <*> category session field-extra-name` commits clean on
// the strict path and is never applied. `compileLog`'s `case "category":` arm is
// an explicit no-op — *"field-extra-name emission is out of scope for this
// increment"* — and `LogProfile` carries no field for the value.
//
// Of the 22 leaves the #7484/#7492 spelling-gate analysis found unread by the
// compiler, 21 declare it in their own `desc`, which is what an operator sees in
// `?` help. This was the exception, and it read exactly like a working feature.
//
// Session log records are an audit surface: an operator adding an extra field is
// usually satisfying a logging or compliance requirement, and a silent
// under-record is the worst way for that to fail — no commit warning, no runtime
// error, just a field that never appears.

// The unread leaf must SAY it is unread.
func TestFieldExtraNameDeclaresItselfUnimplemented7502(t *testing.T) {
	leaf := schemaForPath("security", "log", "profile", "category", "session", "field-extra-name")
	if leaf == nil {
		t.Fatal("the field-extra-name leaf is no longer at this schema path; this test " +
			"cannot check a description it cannot find, and a clean result would certify " +
			"nothing")
	}
	if !strings.Contains(leaf.desc, "parsed, not implemented") {
		t.Errorf("`field-extra-name` does not declare itself unimplemented. Its `desc` is "+
			"what `?` help shows, and the leaf commits clean while never reaching the "+
			"compiled configuration — so the CLI advertises a working feature that "+
			"silently under-records an audit surface (#7502). desc = %q", leaf.desc)
	}
}

// THE SIBLINGS ARE READ, and that must stay true.
//
// This is the half that stops the declaration being applied to the wrong leaf.
// `stream-name` and `default-profile` under the same parent ARE consumed by
// compileLog; if a future change made one of them a no-op, the honest response
// is to declare THAT leaf too — and this test is what forces the question
// instead of letting it join the silent set.
func TestLogProfileSiblingsAreStillRead7502(t *testing.T) {
	src := `security { log { mode stream;
    stream s1 { host { 192.0.2.1; } }
    profile P1 { stream-name s1; default-profile; }
} }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	prof := cfg.Security.Log.Profiles["P1"]
	if prof == nil {
		t.Fatal("profile P1 did not compile at all; the sibling assertions below would " +
			"then be reading a nil profile rather than an unread leaf")
	}
	if prof.StreamName != "s1" {
		t.Errorf("`stream-name` is no longer read (got %q). If that is deliberate it must "+
			"declare itself unimplemented like field-extra-name does (#7502)", prof.StreamName)
	}
	if !prof.DefaultProfile {
		t.Error("`default-profile` is no longer read. If that is deliberate it must " +
			"declare itself unimplemented like field-extra-name does (#7502)")
	}
}

// The measured fact the declaration rests on: the leaf's value does not reach
// the compiled configuration.
//
// Without this, the declaration is an unverified claim — and a leaf that later
// STARTS being implemented would keep a "(parsed, not implemented)" note that is
// now a lie in the opposite direction.
func TestFieldExtraNameValueIsNotApplied7502(t *testing.T) {
	src := `security { log { mode stream;
    stream s1 { host { 192.0.2.1; } }
    profile P1 { stream-name s1; category { session { field-extra-name zzq1; } } }
} }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected the stanza; #7502 measured it committing "+
			"CLEAN, so this test's premise has changed: %v", err)
	}
	prof := cfg.Security.Log.Profiles["P1"]
	if prof == nil {
		t.Fatal("profile P1 did not compile")
	}
	// LogProfile carries no field for the extra name at all. If one is added and
	// populated, this test should be replaced by one asserting the value lands —
	// and the schema note removed in the same change.
	if strings.Contains(strings.ToLower(prof.Name), "zzq1") || prof.StreamName == "zzq1" {
		t.Error("the extra-field value reached the compiled profile; field-extra-name is " +
			"implemented now, so its `(parsed, not implemented)` note is stale and must " +
			"be removed (#7502)")
	}
}
