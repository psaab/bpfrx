package config

import (
	"strings"
	"testing"
)

// TestParseSetVerbSemicolonTruncation_5194 is the #5194 A3-b3-F7 fail-on-revert
// guard. ParseSetVerb broke its token loop on TokenSemicolon OR TokenEOF and
// returned without checking for remaining input, so a line like
// `set system host-name fw; delete security policies` applied ONLY the hostname
// and silently discarded everything after `;` while the caller (LoadSet) reported
// the line applied. The fix permits at most one terminating semicolon then
// requires EOF, rejecting any subsequent token with position.
//
// Fail-on-revert: restore `if tok.Type == TokenEOF || tok.Type == TokenSemicolon
// { break }` and the multi-statement leg goes RED (it parses with no error and
// drops the trailing `delete`).
func TestParseSetVerbSemicolonTruncation_5194(t *testing.T) {
	// A second statement crammed after ';' must be rejected, not truncated.
	if _, _, err := ParseSetVerb("set system host-name fw; delete security policies"); err == nil {
		t.Fatal("ParseSetVerb must reject a second statement after ';' instead of silently discarding it")
	} else if !strings.Contains(err.Error(), ";") {
		t.Fatalf("error must mention the ';' terminator, got: %v", err)
	}

	// A single trailing semicolon is a valid terminator.
	verb, path, err := ParseSetVerb("set system host-name fw;")
	if err != nil {
		t.Fatalf("a single trailing ';' must be accepted: %v", err)
	}
	if verb != "set" || strings.Join(path, " ") != "system host-name fw" {
		t.Fatalf("verb=%q path=%v, want set [system host-name fw]", verb, path)
	}

	// No semicolon at all still parses.
	if _, path, err := ParseSetVerb("set system host-name fw"); err != nil || strings.Join(path, " ") != "system host-name fw" {
		t.Fatalf("no-semicolon line must parse: err=%v path=%v", err, path)
	}

	// At most ONE terminating semicolon: `;;` is rejected.
	if _, _, err := ParseSetVerb("set system host-name fw ;;"); err == nil {
		t.Fatal("ParseSetVerb must reject a doubled ';;' terminator")
	}
}
