package config

import (
	"strings"
	"testing"
)

// #3890: an application-set member is either `application <name>` or
// `application-set <name>`. The schema declares `application-set` as an opaque
// args:1 leaf (children:nil), so the SchemaValidate walk never reaches its
// members. Before this fix compileApplications' member switch had NO default
// arm, so a TYPO'd member keyword (e.g. `applicaton foo` for `application foo`,
// or a mistyped `application-set`) was SILENTLY DROPPED — the set was
// under-populated, and if referenced by a DENY policy the deny matched FEWER
// applications than intended (a fail-open under-match: traffic the operator
// meant to block is permitted). validateApplicationSyntaxStrict now hard-rejects
// a set carrying an unknown member keyword at commit; the tolerant load /
// peer-sync path downgrades it to a warning (#1960 no-brick).
//
// Flat-set trees are built via flatTreeFromSets (ParseSetCommand + SetPath) —
// the only correct way to exercise the flat-set AST shape.

// Core fail-on-revert: a typo'd member keyword is rejected at commit. Revert the
// default arm and the `applicaton junos-http` member is silently dropped, the
// set compiles as empty, CompileConfig succeeds, and this assertion goes RED.
func TestApplicationSetMember_TypoKeyword_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application-set web application junos-https",
		"set applications application-set web applicaton junos-http",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to REJECT an application-set with a typo'd member keyword")
	}
	if !strings.Contains(err.Error(), "unknown member statement") ||
		!strings.Contains(err.Error(), "applicaton") {
		t.Fatalf("error should name the bad member keyword and the set, got: %v", err)
	}
}

// A mistyped `application-set` (nested-set) keyword is caught the same way.
func TestApplicationSetMember_TypoNestedSetKeyword_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application-set child application junos-http",
		"set applications application-set parent application-sett child",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to REJECT a mistyped nested application-set keyword")
	}
	if !strings.Contains(err.Error(), "unknown member statement") ||
		!strings.Contains(err.Error(), "application-sett") {
		t.Fatalf("error should name the bad member keyword %q, got: %v", "application-sett", err)
	}
}

// The under-population is the security hole even when the set is UNREFERENCED —
// like #3352/#3353 this is a grammar error rejected at definition, not
// reference-scoped. A set defined but wired into no policy must still reject.
func TestApplicationSetMember_Typo_Unreferenced_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application-set lonely application junos-https",
		"set applications application-set lonely bogus junos-http",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT an UNREFERENCED set with a bad member")
	} else if !strings.Contains(err.Error(), "unknown member statement") {
		t.Fatalf("error should explain the member rule, got: %v", err)
	}
}

// The security-relevant end-to-end shape: a DENY policy references the set, and
// a typo'd member under-populates it. The commit MUST fail — otherwise the deny
// silently matches fewer apps (fail-open). Revert the gate and the config
// commits with the set missing junos-http, so this assertion goes RED.
func TestApplicationSetMember_Typo_DenyPolicy_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set applications application-set blocked application junos-https",
		"set applications application-set blocked applicaton junos-http",
		"set security policies from-zone trust to-zone untrust policy deny-bad match source-address any",
		"set security policies from-zone trust to-zone untrust policy deny-bad match destination-address any",
		"set security policies from-zone trust to-zone untrust policy deny-bad match application blocked",
		"set security policies from-zone trust to-zone untrust policy deny-bad then deny",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT a deny policy whose set has a typo'd (dropped) member")
	} else if !strings.Contains(err.Error(), "unknown member statement") {
		t.Fatalf("error should name the unknown member, got: %v", err)
	}
}

// Hierarchical (brace-block) shape: the compiler handles both AST shapes, so a
// typo'd member authored as a brace block must reject too.
func TestApplicationSetMember_Typo_Hierarchical_Rejected(t *testing.T) {
	tree := hierTree(t, `
applications {
    application-set web {
        application junos-https;
        applicaton junos-http;
    }
}
`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT a hierarchical set with a typo'd member")
	} else if !strings.Contains(err.Error(), "unknown member statement") {
		t.Fatalf("error should explain the member rule, got: %v", err)
	}
}

// Guard against over-rejection: a valid set with both member kinds
// (`application` and nested `application-set`) must commit cleanly AND be fully
// populated. This pins that the default arm does not swallow a legitimate
// member.
func TestApplicationSetMember_ValidMembers_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application app1 protocol tcp destination-port 80",
		"set applications application-set child application app1",
		"set applications application-set parent application junos-https",
		"set applications application-set parent application-set child",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a valid set (application + nested application-set) must commit: %v", err)
	}
	parent := cfg.Applications.ApplicationSets["parent"]
	if parent == nil {
		t.Fatalf("application-set parent missing from compiled config")
	}
	// The set is FULLY populated: both the direct app and the nested-set ref.
	if !contains(parent.Applications, "junos-https") {
		t.Fatalf("parent must keep direct member junos-https; have %v", parent.Applications)
	}
	if !contains(parent.Applications, "child") {
		t.Fatalf("parent must keep nested-set member child; have %v", parent.Applications)
	}
	if len(parent.UnknownMembers) != 0 {
		t.Fatalf("a valid set must record no unknown members; got %v", parent.UnknownMembers)
	}
	// The nested child is expandable end-to-end.
	expanded, err := ExpandApplicationSet("parent", &cfg.Applications)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(parent): %v", err)
	}
	if !contains(expanded, "app1") {
		t.Fatalf("expand(parent) = %v, missing app1 (reached via nested child)", expanded)
	}
}

// Guard: `description` is a legitimate Junos application-set statement
// (metadata), NOT an unknown member — an unreferenced set carrying only a
// description must still commit cleanly and record no unknown members. This is
// the documented way to author an otherwise-empty set (the #3144/#3434 empty-set
// gate rejects it only when it is REFERENCED). Flip the compiler to treat
// `description` as unknown and this goes RED.
func TestApplicationSetMember_DescriptionOnly_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application-set metaonly description \"documented set\"",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a description-only application-set must commit (description is metadata): %v", err)
	}
	set := cfg.Applications.ApplicationSets["metaonly"]
	if set == nil {
		t.Fatalf("application-set metaonly missing from compiled config")
	}
	if len(set.UnknownMembers) != 0 {
		t.Fatalf("`description` must not be flagged as an unknown member; got %v", set.UnknownMembers)
	}
	if len(set.Applications) != 0 {
		t.Fatalf("`description` must not add a member; got %v", set.Applications)
	}
}

// The tolerant load / peer-sync path (CompileConfigLenient) must NOT brick on a
// set an older binary persisted with a bad member — it downgrades the reject to
// a warning so the daemon still boots (#1960 no-brick). Revert the lenient
// downgrade and this goes RED.
func TestApplicationSetMember_Typo_Lenient_DowngradesToWarning(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application-set web application junos-https",
		"set applications application-set web applicaton junos-http",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must NOT fail on a bad member (no-brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application syntax") && strings.Contains(w, "unknown member statement") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path must record a downgrade warning; warnings: %v", cfg.Warnings)
	}
}
