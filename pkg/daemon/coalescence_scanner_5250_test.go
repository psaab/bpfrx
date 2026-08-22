package daemon

import (
	"bytes"
	"strings"
	"testing"
)

// #5250 (A7-b1 F1). parseEthtoolCoalesce scanned with a default bufio.Scanner
// (64 KiB line cap) and checked neither scanner.Err() nor how far it got. A
// single over-long line therefore stopped the scan silently and the function
// still returned parsed=true over the PREFIX it had managed to read.
//
// That falsely-complete answer is not merely logged: applyCoalescenceOne feeds
// it to capture.captureMlx5Coalesce as the operator's pre-xpfd baseline (which
// restore-on-disable later writes back to the NIC) and to the MIN1 drift
// comparison. So the harm is a corrupted restore baseline built from values the
// parser never finished reading.
func TestParseEthtoolCoalesceOverLongLineIsNotReportedAsParsed(t *testing.T) {
	// A real prefix, then a line longer than the 1 MiB ceiling (and so also
	// longer than bufio's 64 KiB default), then the field the parser would
	// otherwise have picked up.
	var b bytes.Buffer
	b.WriteString("Coalesce parameters for ge-0-0-1:\n")
	b.WriteString("Adaptive RX: off  TX: off\n")
	b.WriteString("rx-usecs: 8\n")
	b.WriteString("pkt-rate-low: " + strings.Repeat("9", (1<<20)+4096) + "\n")
	b.WriteString("tx-usecs: 16\n")

	rx, tx, adaptRX, adaptTX, parsed := parseEthtoolCoalesce(b.Bytes())
	if parsed {
		t.Fatalf("an over-long line must not report parsed=true; got rx=%d tx=%d "+
			"adaptRX=%v adaptTX=%v — the scanner is unbuffered/unchecked again and "+
			"a PREFIX of the settings is being taken for the whole", rx, tx, adaptRX, adaptTX)
	}
	if rx != 0 || tx != 0 || adaptRX || adaptTX {
		t.Errorf("a not-parsed result must carry zero values, got rx=%d tx=%d adaptRX=%v adaptTX=%v",
			rx, tx, adaptRX, adaptTX)
	}
}

// The raised cap is what lets a long-but-plausible line still parse, so the
// fix is a bound and not a new failure mode: the same output under the old
// 64 KiB cap truncated, and now it is read to the end.
func TestParseEthtoolCoalesceReadsPastTheOldDefaultCap(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("Coalesce parameters for ge-0-0-1:\n")
	b.WriteString("Adaptive RX: on  TX: on\n")
	// 70 KiB of padding on a COMMENT-shaped line: over the old 64 KiB default,
	// under the new 1 MiB ceiling.
	b.WriteString("# " + strings.Repeat("x", 70*1024) + "\n")
	b.WriteString("rx-usecs: 8\n")
	b.WriteString("tx-usecs: 16\n")

	rx, tx, adaptRX, adaptTX, parsed := parseEthtoolCoalesce(b.Bytes())
	if !parsed {
		t.Fatal("a 70 KiB line is under the raised cap and must parse")
	}
	if rx != 8 || tx != 16 || !adaptRX || !adaptTX {
		t.Fatalf("rx=%d tx=%d adaptRX=%v adaptTX=%v, want 8/16/true/true", rx, tx, adaptRX, adaptTX)
	}
}

// Ordinary output is unaffected — the fix must not change the common path.
func TestParseEthtoolCoalesceNormalOutputUnchanged(t *testing.T) {
	out := []byte("Coalesce parameters for ge-0-0-1:\n" +
		"Adaptive RX: off  TX: off\n" +
		"rx-usecs: 8\n" +
		"tx-usecs: 16\n")
	rx, tx, adaptRX, adaptTX, parsed := parseEthtoolCoalesce(out)
	if !parsed || rx != 8 || tx != 16 || adaptRX || adaptTX {
		t.Fatalf("parsed=%v rx=%d tx=%d adaptRX=%v adaptTX=%v, want true/8/16/false/false",
			parsed, rx, tx, adaptRX, adaptTX)
	}
}
