package feeds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file is the #4922 fail-on-revert suite. The dynamic-address feed
// invalid-line sample was bounded by COUNT (maxInvalidSample = 5) but NOT by
// BYTES: the scanner admits malformed lines up to maxLineBytes (1 MiB), parseFeed
// retained the first 5 VERBATIM, installSnapshot/AllFeeds kept+deep-copied them,
// and a changed degraded feed logged the full slice. One feed could therefore
// pin ~5 MiB of verbatim garbage and emit multi-MB slog records — all within the
// advertised feed limits. The fix caps each retained entry to a small escaped
// prefix (maxInvalidSampleBytes) plus the original byte length, applied at the
// retention point so every downstream copy/log inherits the bounded form.

// isPrintableASCII reports whether s contains only printable ASCII (0x20-0x7e).
// strconv.Quote output is always printable ASCII, so a correctly-escaped sample
// entry passes even when the source line held NULs / control bytes / invalid
// UTF-8.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// bigMalformedLine builds a malformed (non-CIDR, non-IP) line of n bytes that is
// safely under the scanner token cap (so it is admitted and reaches the sample
// retention path rather than tripping bufio.ErrTooLong).
func bigMalformedLine(n int) string {
	if n >= maxLineBytes {
		panic("bigMalformedLine would trip the scanner cap")
	}
	return strings.Repeat("x", n)
}

// TestInvalidSampleBigLineByteBounded is the core #4922 fail-on-revert test: a
// near-1-MiB malformed line must be retained as a short escaped prefix, NOT the
// verbatim ~1 MiB line. Reverting to `append(invalidSample, line)` makes the
// entry ~1 MiB and turns the len assertion RED.
func TestInvalidSampleBigLineByteBounded(t *testing.T) {
	const bigLen = maxLineBytes - 1024 // ~1 MiB, safely under the scanner cap
	body := "192.0.2.0/24\n" + bigMalformedLine(bigLen) + "\n"

	res, err := parseFeed(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseFeed error: %v", err)
	}
	if res.invalidLines != 1 {
		t.Fatalf("invalidLines = %d, want 1", res.invalidLines)
	}
	if len(res.invalidSample) != 1 {
		t.Fatalf("invalidSample len = %d, want 1", len(res.invalidSample))
	}
	entry := res.invalidSample[0]
	if len(entry) > maxInvalidSampleEntryBytes {
		t.Fatalf("retained sample entry is %d bytes, want <= %d (verbatim ~%d-byte line was NOT byte-bounded)",
			len(entry), maxInvalidSampleEntryBytes, bigLen)
	}
	// Sanity: the entry is dramatically smaller than the original line.
	if len(entry) >= bigLen/10 {
		t.Fatalf("retained entry %d bytes is not a small prefix of the %d-byte line", len(entry), bigLen)
	}
}

// TestInvalidSampleOriginalLengthRecorded confirms the retained record carries
// the TRUE original byte length even though only a short prefix is kept, so an
// operator can triage "line was N bytes, starts with <prefix>".
func TestInvalidSampleOriginalLengthRecorded(t *testing.T) {
	const bigLen = maxLineBytes - 1024
	body := "192.0.2.0/24\n" + bigMalformedLine(bigLen) + "\n"

	res, err := parseFeed(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseFeed error: %v", err)
	}
	entry := res.invalidSample[0]
	wantMeta := fmt.Sprintf("%d bytes total", bigLen)
	if !strings.Contains(entry, wantMeta) {
		t.Fatalf("retained entry %q does not record the original byte length %q", entry, wantMeta)
	}
}

// TestInvalidSampleAggregateBounded confirms the count cap (<= 5 entries) AND the
// aggregate byte budget both hold when a body serves many near-1-MiB malformed
// lines, and that every individual entry is per-entry bounded.
func TestInvalidSampleAggregateBounded(t *testing.T) {
	const bigLen = maxLineBytes - 1024
	var b strings.Builder
	b.WriteString("192.0.2.0/24\n") // one valid prefix so parse succeeds
	const garbage = 12              // more than maxInvalidSample
	for i := 0; i < garbage; i++ {
		b.WriteString(bigMalformedLine(bigLen))
		b.WriteByte('\n')
	}

	res, err := parseFeed(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parseFeed error: %v", err)
	}
	if res.invalidLines != garbage {
		t.Errorf("invalidLines = %d, want %d", res.invalidLines, garbage)
	}
	if len(res.invalidSample) > maxInvalidSample {
		t.Fatalf("invalidSample retained %d entries, want <= %d (count cap)", len(res.invalidSample), maxInvalidSample)
	}
	total := 0
	for i, s := range res.invalidSample {
		if len(s) > maxInvalidSampleEntryBytes {
			t.Errorf("entry %d is %d bytes, want <= %d", i, len(s), maxInvalidSampleEntryBytes)
		}
		total += len(s)
	}
	if total > maxInvalidSampleTotalBytes {
		t.Fatalf("aggregate retained sample = %d bytes, want <= %d", total, maxInvalidSampleTotalBytes)
	}
}

// TestInvalidSampleEscapesControlBytes confirms a malformed line carrying NULs,
// control bytes, and invalid UTF-8 is escaped to a printable-ASCII form — no raw
// control bytes ever reach a slog record or CLI show.
func TestInvalidSampleEscapesControlBytes(t *testing.T) {
	nasty := "bad\x00\x01\x02\x7f\xff\xfeline" // NUL, control, invalid UTF-8
	body := "192.0.2.0/24\n" + nasty + "\n"

	res, err := parseFeed(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseFeed error: %v", err)
	}
	if len(res.invalidSample) != 1 {
		t.Fatalf("invalidSample len = %d, want 1", len(res.invalidSample))
	}
	entry := res.invalidSample[0]
	if strings.ContainsRune(entry, 0) {
		t.Errorf("retained entry contains a raw NUL byte: %q", entry)
	}
	if !isPrintableASCII(entry) {
		t.Errorf("retained entry contains non-printable bytes: %q", entry)
	}
	// The escaped form should still be a valid quoted string we can round-trip.
	if _, uerr := strconv.Unquote(entry); uerr != nil {
		t.Errorf("retained entry is not a valid quoted string: %q (%v)", entry, uerr)
	}
}

// TestInvalidSampleShortLinePreserved is the no-over-truncation guard: a short
// malformed line (< the byte cap) is retained quoted-but-otherwise-intact, so the
// diagnostic value for the common stray-text case is preserved.
func TestInvalidSampleShortLinePreserved(t *testing.T) {
	body := "192.0.2.0/24\nnot-an-ip-just-text\n"

	res, err := parseFeed(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseFeed error: %v", err)
	}
	if len(res.invalidSample) != 1 {
		t.Fatalf("invalidSample len = %d, want 1", len(res.invalidSample))
	}
	entry := res.invalidSample[0]
	if want := strconv.Quote("not-an-ip-just-text"); entry != want {
		t.Fatalf("short line retained as %q, want %q (no over-truncation)", entry, want)
	}
	// A short line carries no byte-length annotation (its size is self-evident).
	if strings.Contains(entry, "bytes total") {
		t.Errorf("short line unexpectedly annotated with a byte length: %q", entry)
	}
}

// TestInvalidSampleBoundedThroughAllFeeds proves the bound is applied at the
// retention point, so installSnapshot's store AND AllFeeds' deep copy (the paths
// that feed the degraded slog.Warn and the `show security dynamic-address`
// display) only ever see the small escaped form — the memory-retention half of
// the #4922 bug, not just the log site.
func TestInvalidSampleBoundedThroughAllFeeds(t *testing.T) {
	const bigLen = maxLineBytes - 1024
	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n"+bigMalformedLine(bigLen)+"\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	m := New(func() error { return nil })
	fs := m.newFeed("huge", ts.URL, time.Hour)
	m.fetchFeed(context.Background(), fs)

	info := m.AllFeeds()["huge"]
	if !info.Degraded || info.InvalidLines != 1 {
		t.Fatalf("feed not degraded as expected: %+v", info)
	}
	if len(info.InvalidSample) != 1 {
		t.Fatalf("InvalidSample len = %d, want 1", len(info.InvalidSample))
	}
	if got := len(info.InvalidSample[0]); got > maxInvalidSampleEntryBytes {
		t.Fatalf("AllFeeds surfaced a %d-byte sample entry, want <= %d (retention-point bound not inherited)",
			got, maxInvalidSampleEntryBytes)
	}
}
