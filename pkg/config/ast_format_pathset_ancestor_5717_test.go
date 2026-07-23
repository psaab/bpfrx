package config

import (
	"strings"
	"testing"
)

// #5717 / codex-182 A3-b00-C001 (display half): a path-scoped
// `show configuration <path> | display set` (FormatPathSet) reconstructed the
// parent prefix by searching the display path for the FIRST token equal to the
// matched node's first key and stopping there. When an ANCESTOR argument equals
// that key — e.g. a security zone NAMED "interfaces" that holds an `interfaces`
// stanza, or a policy/term whose name equals a child keyword — the prefix was
// truncated at the ancestor and the emitted set line dropped the ancestor token,
// producing a malformed, NON-round-trippable line that pointed at a different
// object if replayed.
//
// The copy half of the same cohort (CopyPath first-keyword insertNode) was
// already repaired by #5822; this guards the display half.
//
// RED-on-revert: restore the left-to-right "stop at first token == firstKey"
// prefix derivation in FormatPathSet and these round-trip assertions fail — the
// ancestor "interfaces"/"trust" token disappears from the emitted set line.

func mustParse5717(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	return tree
}

func TestFormatPathSetAncestorEqualsKey_5717(t *testing.T) {
	// A security zone whose NAME equals the child keyword `interfaces`.
	src := `security {
    zones {
        security-zone interfaces {
            interfaces {
                ge-0/0/9.0;
            }
        }
    }
}`
	tree := mustParse5717(t, src)
	path := []string{"security", "zones", "security-zone", "interfaces", "interfaces"}
	got := strings.TrimSpace(tree.FormatPathSet(path))

	// The correct, round-trippable line retains BOTH the zone-name token and the
	// `interfaces` stanza keyword.
	want := "set security zones security-zone interfaces interfaces ge-0/0/9.0"
	if got != want {
		t.Fatalf("FormatPathSet dropped the ancestor token:\n got: %q\nwant: %q", got, want)
	}

	// The emitted set line must round-trip: re-parsing it (flat-set path, via
	// ParseSetCommand + SetPath per the project's flat-set testing rule) and
	// re-rendering reproduces the same statement (proves it is not malformed).
	rtTree := buildTreeFromSet(t, []string{got})
	if back := strings.TrimSpace(rtTree.FormatPathSet(path)); back != want {
		t.Fatalf("round-trip diverged:\n got: %q\nwant: %q", back, want)
	}
}

// A second shape: an ancestor policy NAMED after a descendant keyword. Here the
// term is named "match" (a legal Junos name) and the matched leaf keyword is
// also reachable such that a naive first-key search truncates the prefix.
func TestFormatPathSetPolicyNameEqualsKey_5717(t *testing.T) {
	// Policy NAMED "then" holding a `then permit` action: the matched node's
	// first key `then` also appears earlier as the policy name.
	src := `security {
    policies {
        from-zone trust to-zone untrust {
            policy then {
                then {
                    permit;
                }
            }
        }
    }
}`
	tree := mustParse5717(t, src)
	path := []string{
		"security", "policies", "from-zone", "trust", "to-zone", "untrust",
		"policy", "then", "then",
	}
	got := strings.TrimSpace(tree.FormatPathSet(path))
	want := "set security policies from-zone trust to-zone untrust policy then then permit"
	if got != want {
		t.Fatalf("FormatPathSet dropped the policy-name token:\n got: %q\nwant: %q", got, want)
	}
}
