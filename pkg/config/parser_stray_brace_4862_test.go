package config

import (
	"strings"
	"testing"
)

// #4862: Parser.Parse() never asserted the lexer reached EOF, and
// parseStatements() breaks on a top-level TokenRBrace identically to EOF. A
// single stray unmatched '}' at the top level therefore made the parser STOP
// with zero ParseErrors and silently drop every statement after the brace.
// Because LoadOverride / CheckText only gate on len(errs)==0, the truncated
// (weaker) config committed with no operator-visible warning — a fail-open
// config-acceptance path that could drop a trailing security/default-policy
// tail from an imported Junos config.
//
// The fix asserts EOF after the top-level parseStatements(): a stray '}' (or
// any leftover token) is a ParseError, and the parser resumes past it so the
// trailing config is recovered (never silently dropped) while the error still
// fails the commit.
//
// Fail-on-revert: run these against origin/master (or drop the EOF assertion
// loop from Parse) and the "Rejects" cases stop erroring and the trailing
// `security` node vanishes from the tree.

func hasTopLevelKey(tree *ConfigTree, key string) bool {
	for _, n := range tree.Children {
		if len(n.Keys) > 0 && n.Keys[0] == key {
			return true
		}
	}
	return false
}

// The exact TEST from the issue: a trailing stray brace must be a parse error,
// not a silent stop.
func TestParse4862_TrailingStrayBrace_IsError(t *testing.T) {
	p := NewParser(`system { host-name fw; } }`)
	tree, errs := p.Parse()
	if len(errs) == 0 {
		t.Fatal("expected a ParseError for a trailing stray '}', got none (fail-open silent truncation)")
	}
	// The well-formed prefix is still parsed.
	if !hasTopLevelKey(tree, "system") {
		t.Error("system stanza before the stray brace was dropped")
	}
}

// The dangerous scenario: security-relevant config AFTER a stray brace must not
// be silently discarded, and the parse must error.
func TestParse4862_StrayBraceDoesNotDropTrailingConfig(t *testing.T) {
	p := NewParser(`system {
    host-name fw;
} }
security {
    policies {
        default-policy {
            deny-all;
        }
    }
}`)
	tree, errs := p.Parse()
	if len(errs) == 0 {
		t.Fatal("expected a ParseError for the stray '}', got none")
	}
	if !hasTopLevelKey(tree, "system") {
		t.Error("system stanza (before the stray brace) missing")
	}
	if !hasTopLevelKey(tree, "security") {
		t.Error("security stanza AFTER the stray brace was silently dropped — fail-open")
	}
}

// A stray '}' as the very first token still errors and still recovers the
// trailing config.
func TestParse4862_LeadingStrayBrace_IsError(t *testing.T) {
	p := NewParser(`} system { host-name fw; }`)
	tree, errs := p.Parse()
	if len(errs) == 0 {
		t.Fatal("expected a ParseError for a leading stray '}', got none")
	}
	if !hasTopLevelKey(tree, "system") {
		t.Error("system stanza after the leading stray brace was dropped")
	}
}

// A well-formed, correctly-nested config must still parse clean — the EOF
// assertion must not false-positive on properly balanced braces.
func TestParse4862_WellFormedParsesClean(t *testing.T) {
	p := NewParser(`system {
    host-name fw;
}
security {
    policies {
        default-policy {
            deny-all;
        }
    }
}`)
	tree, errs := p.Parse()
	if len(errs) != 0 {
		t.Fatalf("well-formed config produced parse errors: %v", errs)
	}
	if !hasTopLevelKey(tree, "system") || !hasTopLevelKey(tree, "security") {
		t.Errorf("well-formed config lost a top-level stanza: %+v", tree.Children)
	}
}

// Deeply but correctly nested blocks must not trip the top-level EOF check
// (each inner block's own closing '}' is consumed by parseStatement).
func TestParse4862_DeepNestingParsesClean(t *testing.T) {
	p := NewParser(`interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}`)
	_, errs := p.Parse()
	if len(errs) != 0 {
		t.Fatalf("correctly-nested config produced parse errors: %v", errs)
	}
}

// The recorded error should name the offending line/column so an operator can
// find the stray brace.
func TestParse4862_ErrorNamesPosition(t *testing.T) {
	p := NewParser("system { host-name fw; }\n}\n")
	_, errs := p.Parse()
	if len(errs) == 0 {
		t.Fatal("expected an error")
	}
	// The stray brace is on line 2.
	if errs[0].Line != 2 {
		t.Errorf("error line = %d, want 2 (the stray brace line): %v", errs[0].Line, errs[0])
	}
	if !strings.Contains(errs[0].Message, "}") && !strings.Contains(errs[0].Message, "RBRACE") &&
		!strings.Contains(strings.ToLower(errs[0].Message), "brace") {
		t.Errorf("error message should reference the stray brace: %q", errs[0].Message)
	}
}
