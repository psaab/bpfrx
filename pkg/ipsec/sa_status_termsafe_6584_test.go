// #6584 site B: swanctl SA output reaching an operator terminal unescaped.
//
// A CORRECTION TO THE ISSUE'S FRAMING, which changes where the fix belongs.
// The issue calls this "raw swanctl SA output" — the same raw-block class as
// the journalctl surface. It is not. `stdout.String()` never reaches a
// terminal: it goes only to parseSAOutput. What reaches the terminal are the
// PARSED FIELDS, printed a line at a time by
// `show security ipsec security-associations [detail]`, as a width-formatted
// row by the statistics view, and again by both of their gRPC mirrors.
//
// So this is #6579's PARSED-ROW class, and the guard goes at INGEST rather
// than at ~24 render sites across two renderers. #6579's own review recorded
// what a sweep that wide does: "reverting all 14 call-site edits left the
// suite green, because the only test file exercised the primitive" — and the
// miss it shipped was an entire renderer. The tree already accepts
// sanitize-at-ingest for LLDP.
//
// Guarding the WHOLE record rather than the fields believed to be
// peer-controlled is the #6579 rule, and it is load-bearing here: the parser
// is strings.Split/Fields-based, so which swanctl column lands in which struct
// field is a property of the current strongSwan output format, not an
// invariant this repo controls.
//
// FAIL-ON-REVERT: drop the sanitizeSAStatus loop from GetSAStatus and the
// escape survives into every field below.
package ipsec

import (
	"strings"
	"testing"
)

// hostileSwanctlOutput is shaped like real `swanctl --list-sas` output with an
// OSC 52 clipboard write, a CSI erase, a CR and a bare LF folded into the
// peer-influenced traffic-selector fields.
const hostileSwanctlOutput = "vpn-a: #1, ESTABLISHED, IKEv2, 1111111111111111_i* 2222222222222222_r\n" +
	"  local  'CN=fw' @ 192.0.2.1[500]\n" +
	"  remote 'CN=peer' @ 198.51.100.9[500]\n" +
	"  vpn-a: #2, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256\n" +
	"    installed 42s ago, rekeying in 3358s, expires in 3918s\n" +
	"    in  c0ffee01,  1234 bytes,    10 packets\n" +
	"    out deadbeef,  5678 bytes,    20 packets\n" +
	"    local  10.0.0.0/24\x1b]52;c;cGF5bG9hZA==\x07\n" +
	"    remote 10.1.0.0/24\x1b[2J\rSPOOFED\n"

// rawTermControl reports control bytes that survived into a rendered value.
func rawTermControl(s string) []byte {
	var got []byte
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x20 || b == 0x7f {
			got = append(got, b)
		}
	}
	return got
}

// TestSAStatusFieldsAreSanitizedAtIngest6584 drives the real parser and the
// real ingest guard, then checks EVERY field of every record — not just the
// two the payload happened to land in. A per-field spot check would pass a
// guard that covered one column.
func TestSAStatusFieldsAreSanitizedAtIngest6584(t *testing.T) {
	sas := parseSAOutput(hostileSwanctlOutput)
	if len(sas) == 0 {
		t.Fatal("fixture parsed to zero SAs — the payload never reaches a field, so " +
			"this test would pass against unguarded code")
	}
	for i := range sas {
		sanitizeSAStatus(&sas[i])
	}

	sawPayload := false
	for i, sa := range sas {
		for name, v := range map[string]string{
			"Name": sa.Name, "ConnectionName": sa.ConnectionName,
			"LocalAddr": sa.LocalAddr, "RemoteAddr": sa.RemoteAddr,
			"State": sa.State, "LocalTS": sa.LocalTS, "RemoteTS": sa.RemoteTS,
			"InBytes": sa.InBytes, "OutBytes": sa.OutBytes,
			"InPackets": sa.InPackets, "OutPackets": sa.OutPackets,
			"SPIIn": sa.SPIIn, "SPIOut": sa.SPIOut, "Rekey": sa.Rekey,
		} {
			if got := rawTermControl(v); len(got) != 0 {
				t.Errorf("SA[%d].%s carries raw control bytes %q: %q — an OSC 52 here "+
					"writes the operator's clipboard the moment the SA table is "+
					"displayed (#6584)", i, name, got, v)
			}
			if strings.Contains(v, `\x1b`) {
				sawPayload = true
			}
		}
	}
	if !sawPayload {
		t.Fatal("no field contains the ESCAPED payload, so the hostile bytes never " +
			"reached a struct field at all — the fixture does not exercise the guard. " +
			"Check parseSAOutput still maps the traffic-selector lines.")
	}
}

// TestSAStatusSanitizeDoesNotAlterOrdinaryOutput6584 is the over-reach guard.
// The SA table is read by operators; mangling ordinary values is its own bug.
func TestSAStatusSanitizeDoesNotAlterOrdinaryOutput6584(t *testing.T) {
	const clean = "vpn-branch: #7, ESTABLISHED, IKEv2, aaaa_i* bbbb_r\n" +
		"  local  'CN=fw.example.com' @ 192.0.2.1[500]\n" +
		"  remote 'CN=branch.example.com' @ 198.51.100.9[4500]\n" +
		"  vpn-branch: #9, reqid 2, INSTALLED, TUNNEL, ESP:AES_GCM_16-256\n" +
		"    installed 42s ago, rekeying in 3358s, expires in 3918s\n" +
		"    in  c0ffee01,  1234 bytes,    10 packets\n" +
		"    out deadbeef,  5678 bytes,    20 packets\n" +
		"    local  10.0.0.0/24\n" +
		"    remote 10.1.0.0/24\n"

	before := parseSAOutput(clean)
	after := parseSAOutput(clean)
	for i := range after {
		sanitizeSAStatus(&after[i])
	}
	if len(before) != len(after) || len(before) == 0 {
		t.Fatalf("fixture parsed to %d/%d SAs", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("sanitizing altered an ordinary SA record:\n before: %+v\n after:  %+v\n"+
				"Well-formed swanctl output must pass through byte-identical (#6584)",
				before[i], after[i])
		}
	}
}
