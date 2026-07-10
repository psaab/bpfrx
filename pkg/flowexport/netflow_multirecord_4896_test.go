package flowexport

import (
	"net"
	"testing"
	"time"

	"encoding/binary"
)

// TestNetflowV9MultiRecordContiguous_4896 is the regression guard for #4896:
// the v9 encoder padded EACH data record to a 4-byte boundary and packed the
// padded records into one Data FlowSet, but the template advertises the
// UNPADDED sum of field lengths. A standards-compliant collector walks records
// at the template width, so every record after the first was misdecoded (its
// tuple/counters shifted by the 2-3 pad bytes the encoder inserted between
// records).
//
// The fix makes records contiguous at the template width and rounds only the
// enclosing FlowSet once (RFC 3954 terminal padding). This test decodes EVERY
// record at the template-advertised stride and asserts each record's src IP and
// src port land exactly where a collector expects them. It drives 2-record and
// 7-record FlowSets, v4 and v6, with flowDirection both on and off — the
// single-record TestV9DataRecordSizeConsistency cannot catch the shift.
//
// FAIL-ON-REVERT: reintroducing the per-record padding in recordSize makes the
// encoder stride by the padded width while this decoder walks the template
// width, so record 1+ read the wrong bytes → RED.
//
// The stride/length here are derived from templateFieldLenSum4896 — the sum of
// the template's advertised field lengths, exactly what a standards-compliant
// collector reads from the template FlowSet — NOT from recordSize(). Using
// recordSize() would move the decoder's stride together with the bug and mask
// it (that is precisely why the collector misdecodes: it trusts the template,
// not the encoder's internal record size).
func templateFieldLenSum4896(fields []templateField) int {
	n := 0
	for _, f := range fields {
		n += int(f.fieldLen)
	}
	return n
}

func TestNetflowV9MultiRecordContiguous_4896(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	now := boot.Add(time.Second)

	for _, includeDir := range []bool{false, true} {
		for _, v6 := range []bool{false, true} {
			for _, n := range []int{2, 7} {
				opts := V9TemplateOptions{IncludeFlowDir: includeDir}
				fields := buildTemplateFieldsV4(opts)
				if v6 {
					fields = buildTemplateFieldsV6(opts)
				}
				// The width a collector walks records at: the sum of the
				// template's advertised field lengths, derived independently of
				// recordSize() so the assertions catch a stride/template
				// divergence (the #4896 bug).
				recLen := templateFieldLenSum4896(fields)

				// src port sits right after src+dst addresses in the record body.
				srcPortOff := 4 + 4
				if v6 {
					srcPortOff = 16 + 16
				}

				recs := make([]FlowRecord, n)
				for i := range recs {
					r := FlowRecord{
						SrcPort:   uint16(1000 + i),
						DstPort:   80,
						Protocol:  6,
						StartTime: now,
						EndTime:   now,
						IsIPv6:    v6,
					}
					if v6 {
						r.SrcIP = net.ParseIP("2001:db8::")
						r.SrcIP[15] = byte(i + 1) // unique per record
						r.DstIP = net.ParseIP("2001:db8::200")
						r.NATSrcIP = r.SrcIP
						r.NATDstIP = r.DstIP
					} else {
						r.SrcIP = net.IPv4(10, 0, 0, byte(i+1)) // unique per record
						r.DstIP = net.IPv4(172, 16, 80, 200)
						r.NATSrcIP = r.SrcIP
						r.NATDstIP = r.DstIP
					}
					recs[i] = r
				}

				fs := encodeDataFlowSet(recs, boot, opts)

				// FlowSet Length field == header + N contiguous records, rounded
				// up once (terminal padding).
				wantLen := dataFlowSetLen(n, recLen)
				if got := int(binary.BigEndian.Uint16(fs[2:4])); got != wantLen {
					t.Fatalf("v6=%v dir=%v n=%d: FlowSet Length = %d, want %d",
						v6, includeDir, n, got, wantLen)
				}
				if len(fs) != wantLen {
					t.Fatalf("v6=%v dir=%v n=%d: encoded len = %d, want %d",
						v6, includeDir, n, len(fs), wantLen)
				}

				// Walk records at the template width; each must decode its own
				// src IP and src port. If padding is reintroduced the stride
				// diverges from recLen and record 1+ mismatch.
				for i := 0; i < n; i++ {
					base := 4 + i*recLen
					var gotIP net.IP
					if v6 {
						gotIP = net.IP(fs[base : base+16])
					} else {
						gotIP = net.IP(fs[base : base+4])
					}
					if !gotIP.Equal(recs[i].SrcIP) {
						t.Fatalf("v6=%v dir=%v n=%d: record %d src IP = %s, want %s (record misaligned — padding vs template mismatch)",
							v6, includeDir, n, i, gotIP, recs[i].SrcIP)
					}
					gotPort := binary.BigEndian.Uint16(fs[base+srcPortOff : base+srcPortOff+2])
					if gotPort != recs[i].SrcPort {
						t.Fatalf("v6=%v dir=%v n=%d: record %d src port = %d, want %d",
							v6, includeDir, n, i, gotPort, recs[i].SrcPort)
					}
				}
			}
		}
	}
}
