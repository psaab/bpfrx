package termsafe

import (
	"bytes"
	"strings"
	"testing"
)

// #7389: SanitizingWriter is the shape change that lets the streaming CLI
// sites (tcpdump, ping, traceroute) be guarded at all. Each test below binds a
// property the naive implementation gets wrong.

func TestSanitizingWriterEscapesControlBytes_7389(t *testing.T) {
	var out bytes.Buffer
	w := NewSanitizingWriter(&out)
	// An OSC sequence is the canonical terminal-injection payload: it can
	// drive a clipboard write. tcpdump renders packet bytes as ASCII, so a
	// remote party chooses these.
	if _, err := w.Write([]byte("hop1 \x1b]0;pwned\x07 name\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "\x1b") || strings.Contains(got, "\x07") {
		t.Errorf("raw control bytes reached the terminal: %q", got)
	}
	if !strings.Contains(got, "hop1") || !strings.Contains(got, "name") {
		t.Errorf("sanitizing destroyed the legitimate text: %q", got)
	}
}

// The subtle one. A read boundary can fall mid-rune, and a chunk-at-a-time
// sanitizer would escape the split halves as invalid UTF-8 — making the
// SANITIZER the thing that corrupts legitimate output. Holding the partial
// line until its newline keeps runes intact.
func TestSanitizingWriterDoesNotCorruptARuneSplitAcrossWrites_7389(t *testing.T) {
	const s = "héllo wörld\n" // multi-byte runes
	for split := 1; split < len(s)-1; split++ {
		var out bytes.Buffer
		w := NewSanitizingWriter(&out)
		if _, err := w.Write([]byte(s[:split])); err != nil {
			t.Fatalf("Write(first): %v", err)
		}
		if _, err := w.Write([]byte(s[split:])); err != nil {
			t.Fatalf("Write(second): %v", err)
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if out.String() != s {
			t.Fatalf("split at %d corrupted a rune: got %q want %q", split, out.String(), s)
		}
	}
}

// The security-relevant one. Buffering until a newline is an
// ATTACKER-CONTROLLED ALLOCATION: whoever sends the packets decides whether a
// newline ever arrives. The writer must emit anyway past its bound.
func TestSanitizingWriterBoundsAnUnterminatedLine_7389(t *testing.T) {
	var out bytes.Buffer
	w := NewSanitizingWriter(&out)
	// No newline anywhere, more than the bound.
	chunk := bytes.Repeat([]byte("A"), 8*1024)
	for written := 0; written < maxBufferedLine+len(chunk); written += len(chunk) {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if out.Len() == 0 {
		t.Fatalf("nothing emitted after %d bytes with no newline — the writer "+
			"is holding an unbounded, attacker-chosen amount of data", maxBufferedLine+len(chunk))
	}
}

// A final line with no trailing newline must not be silently dropped: for a
// diagnostic that is the line most likely to say why it stopped.
func TestSanitizingWriterFlushEmitsPartialLine_7389(t *testing.T) {
	var out bytes.Buffer
	w := NewSanitizingWriter(&out)
	if _, err := w.Write([]byte("traceroute: no reply")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("emitted a partial line before Flush: %q", out.String())
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !strings.Contains(out.String(), "no reply") {
		t.Errorf("Flush dropped the final unterminated line: %q", out.String())
	}
}

// io.Writer's contract: report all of p consumed. The sanitized form is a
// different length (escaping grows it), so returning the underlying writer's
// count would make callers see a short write and retry — duplicating output.
func TestSanitizingWriterReportsInputLengthConsumed_7389(t *testing.T) {
	var out bytes.Buffer
	w := NewSanitizingWriter(&out)
	in := []byte("a\x1bb\n")
	n, err := w.Write(in)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(in) {
		t.Errorf("Write reported %d of %d consumed; a short write makes callers "+
			"retry and duplicate output", n, len(in))
	}
	if out.Len() <= len(in) {
		t.Logf("note: escaped output %q is not longer than input — check the fixture", out.String())
	}
}
