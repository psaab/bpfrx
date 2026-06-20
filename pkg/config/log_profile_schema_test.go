package config_test

// Schema-validation tests for #2008 H7: the `security log profile <name>`
// stanza must be accepted by the #1319 typed-leaf gate (SchemaValidate)
// without a false reject, and the declared children (`stream-name`,
// `default-profile`, `category session field-extra-name`) must validate
// so the config-mode `?` completion can offer them. Uses the flat-set
// path (ParseSetCommand + SetPath via flatSchemaCheck).
//
// Note on the gate's contract: SchemaValidate is opt-in per leaf — an
// UNKNOWN keyword under a known parent is intentionally NOT rejected
// (schema_walk.go resolveSchemaChild == nil returns nil; reporting is
// left to the compiler). So the H7 schema win is recognition + completion
// of the declared subtree, not rejection of arbitrary children; these
// tests assert the declared forms validate cleanly.

import (
	"testing"
)

// TestSchema2008H7_LogProfile_FlatAccepts verifies the profile stanza and
// its declared children pass schema validation from flat-set syntax.
func TestSchema2008H7_LogProfile_FlatAccepts(t *testing.T) {
	err := flatSchemaCheck(t,
		"set security log stream s1 host 192.0.2.1",
		"set security log profile p1 stream-name s1",
		"set security log profile p1 default-profile",
		"set security log profile p1 category session field-extra-name hostname",
	)
	if err != nil {
		t.Fatalf("expected log profile stanza to pass schema validation, got: %v", err)
	}
}

// TestSchema2008H7_LogProfile_HierarchicalAccepts verifies the
// vsrx-ha.conf-shaped hierarchical profile block validates cleanly.
func TestSchema2008H7_LogProfile_HierarchicalAccepts(t *testing.T) {
	err := schemaCheck(t, `security {
    log {
        stream syslog-container {
            host 192.0.2.1;
            category all;
        }
        profile default-syslog {
            stream-name syslog-container;
            category {
                session {
                    field-extra-name hostname;
                }
            }
            default-profile;
        }
    }
}`)
	if err != nil {
		t.Fatalf("expected hierarchical log profile block to pass schema validation, got: %v", err)
	}
}
