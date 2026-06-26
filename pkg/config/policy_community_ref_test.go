package config

import (
	"strings"
	"testing"
)

// #2881: a policy-statement term's `from community <name>` (rendered FRR
// `match community <name>`) and `then community delete <name>` (rendered
// `set comm-list <name> delete`, added in #2848) reference an FRR
// `bgp community-list <name>` that xpf emits ONLY from a defined
// `policy-options community <name>`. A reference to an UNDEFINED community
// otherwise passes commit and breaks frr-reload at apply time (a dangling
// match/set line fails the WHOLE reload). These gates hard-reject at commit
// (CompileConfig) and warn-and-boot on the tolerant load path
// (CompileConfigLenient). Reverting validatePolicyCommunityReferencesStrict
// turns the reject tests RED.
//
// Tests drive the real CompileConfig (strict) / CompileConfigLenient
// (tolerant) paths via buildTreeFromSet (the shared flat-set helper).

func TestPolicyFromCommunityUndefinedRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement IMPORT term t1 from community NOTDEFINED",
		"set policy-options policy-statement IMPORT term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted `from community NOTDEFINED` with no community defined; expected rejection")
	}
	for _, want := range []string{"IMPORT", "t1", "NOTDEFINED", "community"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestPolicyFromCommunityDefinedAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options community DEFINED members 65000:100",
		"set policy-options policy-statement IMPORT term t1 from community DEFINED",
		"set policy-options policy-statement IMPORT term t1 then accept",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected `from community DEFINED` with the community defined: %v", err)
	}
}

func TestPolicyThenCommunityDeleteUndefinedRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement EXPORT term t1 then community delete NOLIST",
		"set policy-options policy-statement EXPORT term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted `then community delete NOLIST` with no community defined; expected rejection")
	}
	for _, want := range []string{"EXPORT", "t1", "NOLIST", "community"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestPolicyThenCommunityDeleteDefinedAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options community STRIP-ME members 65000:200",
		"set policy-options policy-statement EXPORT term t1 then community delete STRIP-ME",
		"set policy-options policy-statement EXPORT term t1 then accept",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected `then community delete STRIP-ME` with the community defined: %v", err)
	}
}

// A multi-list `then community delete [ A B ]` must validate EVERY referenced
// name — defining only the first must still reject on the second (the #2902
// multi-value slice is fully walked).
func TestPolicyThenCommunityDeleteMultiListUndefinedRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options community LISTA members 65000:1",
		"set policy-options policy-statement EXPORT term t1 then community delete [ LISTA LISTB ]",
		"set policy-options policy-statement EXPORT term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a multi-list `then community delete` with one undefined name; expected rejection")
	}
	if !strings.Contains(err.Error(), "LISTB") {
		t.Errorf("error %q missing the undefined community LISTB", err.Error())
	}
}

// `then community (set|add) <value>` carries a community VALUE, not a
// community-list reference, so it must NOT be rejected even with no
// `policy-options community` defined.
func TestPolicyThenCommunitySetAddValueNotRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement EXPORT term t1 then community set 65000:300",
		"set policy-options policy-statement EXPORT term t2 then community add 65000:400",
		"set policy-options policy-statement EXPORT term t1 then accept",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a `then community set|add <value>` clause (a value, not a list ref): %v", err)
	}
}

// Tolerant path: an already-persisted / peer-synced config referencing an
// undefined community must still BOOT (warn, not error) per the #1960
// fail-closed-on-load doctrine.
func TestPolicyCommunityUndefinedLenientWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement IMPORT term t1 from community NOTDEFINED",
		"set policy-options policy-statement IMPORT term t1 then accept",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on an undefined community reference: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy community reference") && strings.Contains(w, "NOTDEFINED") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a downgraded policy-community warning naming NOTDEFINED, got warnings: %v", cfg.Warnings)
	}
}
