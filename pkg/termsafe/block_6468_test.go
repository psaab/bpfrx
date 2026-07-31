package termsafe

import (
	"strings"
	"testing"
)

// #6468 residual surfaces. Two device/remote-supplied strings still reached an
// operator terminal unescaped after the lease-field fix:
//
//   - the DDNS LastError column, which can carry a PROVIDER response body —
//     safe for dyndns2/duckdns/generic (they wrap it in %q) but not for
//     Cloudflare / Route 53, which embed the provider message with %s;
//   - raw `vtysh` stdout, which carries remote-advertised text: the BGP peer's
//     hostname capability, IS-IS dynamic hostname TLVs, OSPF router IDs.
//
// The first takes SanitizeForDisplay (a single-line field, where an embedded
// newline is itself a forgery vector — it can fake a table row). The second
// needs SanitizeBlockForDisplay, because SanitizeForDisplay escapes \n and \t
// too and would collapse a whole BGP table into one \x0a-laden line.

// A CSI erase-line escape embedded in a remote-advertised BGP hostname.
const evilPeerHostname = "rtr1\x1b[2Kfake-peer"

func TestSanitizeBlockPreservesLayoutControls(t *testing.T) {
	in := "line one\n\tindented\nline three\n"
	if got := SanitizeBlockForDisplay(in); got != in {
		t.Fatalf("a clean multi-line block must pass through byte-identical\n got: %q\nwant: %q", got, in)
	}
	// The fast path must actually engage — otherwise every vtysh print
	// allocates a builder for nothing.
	if !blockDisplaySafe(in) {
		t.Fatalf("blockDisplaySafe must accept LF/TAB so the clean path stays allocation-free")
	}
}

func TestSanitizeBlockEscapesTerminalControlsInsideALine(t *testing.T) {
	// A realistic vtysh-shaped table with the escape buried in one cell.
	in := "BGP neighbor is 10.0.0.1, remote AS 65001\n" +
		"  Hostname: " + evilPeerHostname + "\n" +
		"  BGP state = Established\n"

	got := SanitizeBlockForDisplay(in)

	if strings.Contains(got, "\x1b") {
		t.Fatalf("the ESC introducer must be neutralized; got %q", got)
	}
	if !strings.Contains(got, `\x1b`) {
		t.Fatalf("the ESC must be rendered as a visible escape so the operator sees what the peer sent; got %q", got)
	}
	// Layout survives: same number of lines, and the tabless structure intact.
	if want, have := strings.Count(in, "\n"), strings.Count(got, "\n"); want != have {
		t.Fatalf("line structure must survive sanitization: want %d newlines, got %d\n%q", want, have, got)
	}
	if !strings.HasPrefix(got, "BGP neighbor is 10.0.0.1") {
		t.Fatalf("unrelated content must be untouched; got %q", got)
	}
}

func TestSanitizeBlockEscapesCarriageReturn(t *testing.T) {
	// CR is deliberately NOT a preserved layout control: it re-homes the cursor
	// and lets later text overwrite a line the operator already read.
	in := "real line\rforged line\n"
	got := SanitizeBlockForDisplay(in)
	if strings.Contains(got, "\r") {
		t.Fatalf("a bare CR must be escaped (line-overwrite forgery); got %q", got)
	}
	if !strings.Contains(got, `\x0d`) {
		t.Fatalf("CR must render as a visible escape; got %q", got)
	}
}

func TestSanitizeBlockEscapesC1AndInvalidUTF8(t *testing.T) {
	// U+009B is the single-byte CSI introducer; 0xC0 is an invalid UTF-8 lead.
	in := "ab\n" + string([]byte{'c', 0xC0, 'd'}) + "\n"
	got := SanitizeBlockForDisplay(in)
	if strings.ContainsRune(got, '') {
		t.Fatalf("the C1 CSI introducer must be escaped; got %q", got)
	}
	if !strings.Contains(got, `\x9b`) || !strings.Contains(got, `\xc0`) {
		t.Fatalf("C1 and invalid-UTF-8 bytes must both render as visible escapes; got %q", got)
	}
	if strings.Count(got, "\n") != 2 {
		t.Fatalf("newlines must survive; got %q", got)
	}
}

// TestSanitizeBlockDiffersFromSingleLineOnLayout is the reason the block
// variant exists at all: applying the single-line sanitizer to a table would
// destroy it. If these two ever agree on a multi-line input, the block variant
// has lost its purpose and the vtysh surfaces are being mangled.
func TestSanitizeBlockDiffersFromSingleLineOnLayout(t *testing.T) {
	in := "row one\nrow two\n"
	block := SanitizeBlockForDisplay(in)
	single := SanitizeForDisplay(in)

	if block != in {
		t.Fatalf("block sanitizer must leave a clean table alone; got %q", block)
	}
	if single == in {
		t.Fatalf("precondition: the single-line sanitizer is expected to escape newlines — " +
			"if it no longer does, SanitizeBlockForDisplay may be redundant and should be re-justified")
	}
	if !strings.Contains(single, `\x0a`) {
		t.Fatalf("precondition: single-line sanitizer should render LF as \\x0a; got %q", single)
	}
}
