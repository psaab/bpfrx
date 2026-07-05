package config

import (
	"strings"
	"testing"
)

// fable-review-164 H-2: the lexer stripped bracket-list delimiters with
// `l.advance(); return l.Next()` (one goroutine-stack frame per '[') and the
// recursive-descent parser had no nesting-depth guard. A sub-4 MiB payload of
// consecutive '[' — or a deeply nested `a{a{…}` brace payload — grew the stack
// past Go's 1 GiB maxstacksize and aborted xpfd with an unrecoverable
// `fatal error: stack overflow` (a runtime throw, not a recoverable panic).
//
// These tests exercise inputs an order of magnitude past the pre-fix crash
// threshold. With the fixes (iterative bracket skip in the lexer + the
// maxParseDepth cap in parseStatements) they complete without crashing and
// return clean errors/tokens. On revert of either fix the test binary crashes
// with a stack overflow (RED-on-revert).

// TestLexerBracketFloodNoStackOverflow feeds millions of consecutive '['
// characters through the lexer. Brackets are structural sugar (#2419) and are
// stripped, so the only token is EOF. Pre-fix this recursed one frame per
// bracket and overflowed the stack; the iterative skip makes it O(1) stack.
func TestLexerBracketFloodNoStackOverflow(t *testing.T) {
	const n = 6_000_000 // well past the reviewer's confirmed ~4M crash point
	input := strings.Repeat("[", n)

	l := NewLexer(input)
	tok := l.Next()
	if tok.Type != TokenEOF {
		t.Fatalf("bracket flood: first token = %v, want EOF (brackets are stripped)", tok.Type)
	}

	// The same input must survive the full parser path too (empty tree, no
	// crash). A bracketed run with no real tokens yields an empty config.
	tree, errs := NewParser(input).Parse()
	if tree == nil {
		t.Fatal("bracket flood: Parse returned nil tree")
	}
	if len(tree.Children) != 0 {
		t.Fatalf("bracket flood: expected empty tree, got %d children", len(tree.Children))
	}
	_ = errs // brackets-only input produces no statements; errors, if any, are fine
}

// TestLexerBracketListStillCollapses guards the #2419 behavior the iterative
// rewrite must preserve: `[ a b c ]` still yields the enclosed words as
// ordinary tokens with the brackets removed.
func TestLexerBracketListStillCollapses(t *testing.T) {
	l := NewLexer("from protocol [ tcp udp icmp ] ;")
	var got []string
	for {
		tok := l.Next()
		if tok.Type == TokenEOF {
			break
		}
		if tok.Type == TokenIdentifier {
			got = append(got, tok.Value)
		}
	}
	want := []string{"from", "protocol", "tcp", "udp", "icmp"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("bracket list tokens = %v, want %v (brackets must be stripped, #2419)", got, want)
	}

	// Full flat-set path still collapses the list onto one leaf (#2419 pin
	// preserved by the iterative lexer).
	tree := flatSetTree(t, []string{
		"set firewall family inet filter F term T from protocol [ tcp udp icmp ]",
	})
	keys := fromCriterionKeys(t, tree, "protocol")
	if strings.Join(keys, ",") != "protocol,tcp,udp,icmp" {
		t.Fatalf("flat-set bracket list Keys=%v, want [protocol tcp udp icmp]", keys)
	}
}

// TestParserModerateNestReturnsDepthError proves the depth cap FIRES: a nesting
// well above maxParseDepth (but far below any stack-overflow threshold) returns
// a ParseError, not a silently-accepted tree. On revert of the depth cap this
// nesting parses cleanly with zero errors, so the assertion fails (RED).
func TestParserModerateNestReturnsDepthError(t *testing.T) {
	const n = maxParseDepth + 100 // 356 — above the cap, nowhere near a crash
	src := strings.Repeat("a{", n) + strings.Repeat("}", n)

	_, errs := NewParser(src).Parse()
	if len(errs) == 0 {
		t.Fatal("deep nesting parsed with no error — depth cap did not fire")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nesting exceeds maximum depth") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a nesting-depth ParseError, got %v", errs)
	}
}

// TestParserDeepNestNoStackOverflow drives a nesting depth an order of
// magnitude past the pre-fix crash threshold. The maxParseDepth cap plus the
// iterative skipToBlockClose drain make it terminate with a bounded number of
// errors and no crash. On revert of the cap the mutual recursion overflows the
// stack and the test binary dies (RED-on-revert).
func TestParserDeepNestNoStackOverflow(t *testing.T) {
	const n = 2_000_000
	src := strings.Repeat("a{", n) + strings.Repeat("}", n)

	tree, errs := NewParser(src).Parse()
	if tree == nil {
		t.Fatal("deep nest: Parse returned nil tree")
	}
	if len(errs) == 0 {
		t.Fatal("deep nest: expected a depth-limit error")
	}
	// The drain keeps the error count bounded (~one), not O(n).
	if len(errs) > maxParseDepth+2 {
		t.Fatalf("deep nest: error count %d not bounded by the depth cap", len(errs))
	}
}

// TestParserNormalConfigUnaffected confirms the depth cap does not perturb an
// ordinary configuration's parse (a realistic hierarchy is only a handful of
// levels deep).
func TestParserNormalConfigUnaffected(t *testing.T) {
	src := `security {
    zones {
        security-zone trust {
            interfaces {
                ge-0-0-0 {
                    host-inbound-traffic {
                        system-services {
                            ping;
                        }
                    }
                }
            }
        }
    }
}`
	tree, errs := NewParser(src).Parse()
	if len(errs) != 0 {
		t.Fatalf("normal config parse errors: %v", errs)
	}
	if tree.FindChild("security") == nil {
		t.Fatal("normal config: security stanza missing")
	}
}
