package config

import (
	"strings"
	"testing"
)

// Tests for #3562: six strict-reject AST-walk validators inspected only the
// FIRST top-level `security` node (and first-only FindChild at deeper levels),
// so an offending stanza placed in a SECOND duplicate `security {}` block
// bypassed the strict reject. parseStatements (parser.go) APPENDS a repeated
// top-level block instead of merging it, and compileExpanded /
// compileSecurity / compilePolicies process EVERY `security` root, so the
// offending stanza was still COMPILED (and its fail-open diagnostic lost)
// while a first-`security`-only walk waved it through. This is reachable via
// the hierarchical LoadOverride path (configstore/store_command.go parses
// hierarchical input through NewParser), so these tests use NewParser — the
// CORRECT builder for the duplicate-block / LoadOverride path (flat-set
// SetPath would merge the two blocks).
//
// Each test puts a BENIGN first `security {}` block (zones only — no ipsec,
// no policies) and the offending stanza in the SECOND block. Reverting that
// validator's iterate-all-security walk back to first-`security`-only makes
// strict CompileConfig compile the config CLEAN → the assertion goes RED.

// countTopLevelSecurity returns the number of top-level `security` nodes in a
// parsed tree — the duplicate-block bypass premise. If a future parser merges
// duplicate top-level blocks this drops below 2 and these guards document why.
func countTopLevelSecurity(tree *ConfigTree) int {
	var n int
	for _, c := range tree.Children {
		if c.Name() == "security" {
			n++
		}
	}
	return n
}

// parseDupSecurity parses a hierarchical config string and asserts it produced
// at least two top-level `security` nodes (the bypass premise).
func parseDupSecurity(t *testing.T, cfgText string) *ConfigTree {
	t.Helper()
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	if got := countTopLevelSecurity(tree); got < 2 {
		t.Fatalf("expected >=2 top-level security blocks (the #3562 bypass premise), got %d", got)
	}
	return tree
}

// TestSecureTunnelBindIfaceCollisionRejectedAcrossDuplicateSecurityBlocks
// proves validateSecureTunnelBindInterfaceAST (#2933) inspects EVERY top-level
// `security` node. The first block carries no `ipsec`, so a first-`security`-
// only walk hit FindChild("ipsec")==nil and returned clean — the colliding
// st0 / st0.0 bind-interface aliases in the SECOND block were never checked.
func TestSecureTunnelBindIfaceCollisionRejectedAcrossDuplicateSecurityBlocks(t *testing.T) {
	tree := parseDupSecurity(t, `
security {
    zones {
        security-zone trust;
    }
}
security {
    ipsec {
        vpn V1 {
            bind-interface st0;
        }
        vpn V2 {
            bind-interface st0.0;
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a colliding bind-interface pair in the SECOND of two security blocks; want a strict reject (#2933 bypass)")
	}
	if !strings.Contains(err.Error(), "#2933") || !strings.Contains(err.Error(), "if_id 1") {
		t.Fatalf("reject error %q does not name #2933 and the shared if_id", err.Error())
	}
}

// TestPolicyMatchUnsupportedLeafRejectedAcrossDuplicateSecurityBlocks proves
// validatePolicyMatchLeavesStrict (#3113) inspects EVERY top-level `security`
// node. The first block carries no `policies`, so a first-`security`-only walk
// returned clean and the unsupported `dynamic-application` match leaf in the
// SECOND block silently widened the policy.
func TestPolicyMatchUnsupportedLeafRejectedAcrossDuplicateSecurityBlocks(t *testing.T) {
	tree := parseDupSecurity(t, `
security {
    zones {
        security-zone trust;
    }
}
security {
    policies {
        global {
            policy gp {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                    dynamic-application junos:FTP;
                }
                then {
                    permit;
                }
            }
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted an unsupported match leaf in the SECOND of two security blocks; want a strict reject (#3113 bypass)")
	}
	if !strings.Contains(err.Error(), "#3113") || !strings.Contains(err.Error(), "dynamic-application") {
		t.Fatalf("reject error %q does not name #3113 and the unsupported leaf", err.Error())
	}
}

// TestPolicyRequiredMatchRejectedAcrossDuplicateSecurityBlocks proves
// validatePolicyRequiredMatchStrict (#3044) inspects EVERY top-level
// `security` node. The first block carries no `policies`, so a first-
// `security`-only walk returned clean and the partial-match policy in the
// SECOND block (missing destination-address and application) silently widened
// to match-ANY.
func TestPolicyRequiredMatchRejectedAcrossDuplicateSecurityBlocks(t *testing.T) {
	tree := parseDupSecurity(t, `
security {
    zones {
        security-zone trust;
    }
}
security {
    policies {
        global {
            policy gp {
                match {
                    source-address any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a partial-match policy in the SECOND of two security blocks; want a strict reject (#3044 bypass)")
	}
	if !strings.Contains(err.Error(), "#3044") || !strings.Contains(err.Error(), "destination-address") {
		t.Fatalf("reject error %q does not name #3044 and a missing dimension", err.Error())
	}
}

// TestPolicyThenPermitRejectedAcrossDuplicateSecurityBlocks proves
// validatePolicyThenPermitStrict (#3114) inspects EVERY top-level `security`
// node. The unsupported `then permit application-services` modifier in the
// SECOND block would otherwise be silently dropped — turning a permit-with-
// inspection rule into an unconditional permit (a fail-open).
func TestPolicyThenPermitRejectedAcrossDuplicateSecurityBlocks(t *testing.T) {
	tree := parseDupSecurity(t, `
security {
    zones {
        security-zone trust;
    }
}
security {
    policies {
        global {
            policy gp {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit {
                        application-services {
                            utm-policy strict-web;
                        }
                    }
                }
            }
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted an unsupported then-permit modifier in the SECOND of two security blocks; want a strict reject (#3114 bypass)")
	}
	if !strings.Contains(err.Error(), "#3114") || !strings.Contains(err.Error(), "application-services") {
		t.Fatalf("reject error %q does not name #3114 and the unsupported then-permit child", err.Error())
	}
}

// TestPolicyThenRejectRejectedAcrossDuplicateSecurityBlocks proves
// validatePolicyThenRejectStrict (#3115) inspects EVERY top-level `security`
// node. The unsupported `then reject profile` modifier in the SECOND block
// would otherwise be silently dropped, leaving the configured custom reject
// response inert.
func TestPolicyThenRejectRejectedAcrossDuplicateSecurityBlocks(t *testing.T) {
	tree := parseDupSecurity(t, `
security {
    zones {
        security-zone trust;
    }
}
security {
    policies {
        global {
            policy gp {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    reject profile blocked-web;
                }
            }
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted an unsupported then-reject modifier in the SECOND of two security blocks; want a strict reject (#3115 bypass)")
	}
	if !strings.Contains(err.Error(), "#3115") || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("reject error %q does not name #3115 and the unsupported then-reject child", err.Error())
	}
}

// TestPolicyThenDenyRejectedAcrossDuplicateSecurityBlocks proves
// validatePolicyThenDenyStrict (#3141) inspects EVERY top-level `security`
// node. The unsupported `then deny profile` modifier in the SECOND block
// would otherwise be silently dropped.
func TestPolicyThenDenyRejectedAcrossDuplicateSecurityBlocks(t *testing.T) {
	tree := parseDupSecurity(t, `
security {
    zones {
        security-zone trust;
    }
}
security {
    policies {
        global {
            policy gp {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny profile blocked-web;
                }
            }
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted an unsupported then-deny modifier in the SECOND of two security blocks; want a strict reject (#3141 bypass)")
	}
	if !strings.Contains(err.Error(), "#3141") || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("reject error %q does not name #3141 and the unsupported then-deny modifier", err.Error())
	}
}
