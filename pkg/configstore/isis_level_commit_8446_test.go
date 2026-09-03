package configstore

import (
	"strings"
	"testing"
)

const isisBase8446 = `
system { host-name p; }
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }
`

func isisCommit8446(t *testing.T, stanza string) (level string, err error) {
	t.Helper()
	cfg, err := CheckText(isisBase8446+
		"protocols { isis { net 49.0001.1921.6800.1001.00; "+stanza+" } }\n", 0)
	if err != nil {
		return "", err
	}
	if cfg.Protocols.ISIS == nil {
		t.Fatalf("stanza %q committed but produced no ISIS config", stanza)
	}
	return cfg.Protocols.ISIS.Level, nil
}

// #8446: every one of these committed CLEAN before the fix, and each rendered
// no is-type line at all — silently widening the router to level-1-2. This
// binds the COMMIT GATE (configstore.CheckText, the real operator path), not
// CompileConfig, because the typed-leaf validator runs in SchemaValidate.
func TestISISLevelNonCanonicalRejectedAtCommit_8446(t *testing.T) {
	for _, stanza := range []string{
		"is-type level-3;", "is-type garbage;", "is-type 2;",
		"level level-3;", "level garbage;", "level 2;", "level LEVEL-2;",
	} {
		if _, err := isisCommit8446(t, stanza); err == nil {
			t.Errorf("%q committed clean — it renders no is-type line and widens the router", stanza)
		}
	}
}

func TestISISLevelCanonicalAcceptedAtCommit_8446(t *testing.T) {
	cases := map[string]string{
		"is-type level-1;":      "level-1",
		"is-type level-2;":      "level-2",
		"is-type level-1-2;":    "level-1-2",
		"is-type level-2-only;": "level-2", // the renderer's own spelling
		"level level-1;":        "level-1",
		"level level-2-only;":   "level-2",
	}
	for stanza, want := range cases {
		got, err := isisCommit8446(t, stanza)
		if err != nil {
			t.Errorf("%q REJECTED: %v", stanza, strings.SplitN(err.Error(), "\n", 2)[0])
			continue
		}
		if got != want {
			t.Errorf("%q stored Level=%q, want the canonical %q", stanza, got, want)
		}
	}
}

// The error must name the accepted spellings — an operator who typed `2` needs
// to be told what to type instead, not merely that `2` is wrong.
func TestISISLevelRejectionNamesTheSpellings_8446(t *testing.T) {
	_, err := isisCommit8446(t, "is-type 2;")
	if err == nil {
		t.Fatal("`is-type 2` committed clean")
	}
	for _, want := range []string{"level-1", "level-1-2", "level-2-only"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rejection message does not name the accepted spelling %q: %v", want, err)
		}
	}
}

// setSchema carries TWO copies of the isis subtree — schemaProtocols (the
// top-level `protocols` stanza) and schemaRoutingInstances (`routing-instances
// <name> protocols isis`). Every cell above exercises only the first. Without
// this one, stripping the validator from the routing-instance copy alone is a
// SURVIVING mutation and the second copy is unguarded — which is how a leaf
// ends up accepted in one context and rejected in the other.
func TestISISLevelTypedInRoutingInstanceCopyToo_8446(t *testing.T) {
	ri := func(stanza string) error {
		_, err := CheckText(isisBase8446+
			"routing-instances { vrf-a { instance-type virtual-router; protocols { isis { "+
			"net 49.0001.1921.6800.1001.00; "+stanza+" } } } }\n", 0)
		return err
	}
	// POSITIVE CONTROL: a canonical value must COMMIT here, so a rejection
	// below is the validator firing and not the stanza being unreachable.
	if err := ri("is-type level-1;"); err != nil {
		t.Fatalf("control: a canonical `is-type level-1` was rejected in a routing-instance: %v", err)
	}
	for _, stanza := range []string{"is-type garbage;", "is-type 2;", "level level-3;"} {
		if err := ri(stanza); err == nil {
			t.Errorf("routing-instances copy: %q committed clean — the second schema copy is unguarded", stanza)
		}
	}
}
