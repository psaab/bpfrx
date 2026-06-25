package flowexport

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// #2526: golden byte-level tests for the RFC 5103 / RFC 8158 post-NAT
// (translated) tuple now exported by the NetFlow v9 and IPFIX encoders.
//
// These tests pin BOTH the wire offset/value of the post-NAT fields AND the
// template/encoder length agreement. fail-on-revert: removing the post-NAT
// serialization from the encoders shrinks the record (the constant/template
// length assertions go red) and the offset value checks read the wrong bytes.

// Post-NAT element/field type IDs, asserted independently of the package
// constants so a typo'd constant cannot make the test agree with itself.
const (
	wantElemPostNatSrcIPv4 = 225
	wantElemPostNatDstIPv4 = 226
	wantElemPostNapatSrc   = 227
	wantElemPostNapatDst   = 228
	wantElemPostNatSrcIPv6 = 281
	wantElemPostNatDstIPv6 = 282
)

// --- IPFIX -----------------------------------------------------------------

func TestIPFIXTemplateV4_PostNATFields(t *testing.T) {
	// The four post-NAT fields are the LAST four template entries.
	n := len(ipfixTemplateV4)
	got := ipfixTemplateV4[n-4:]
	want := []ipfixField{
		{wantElemPostNatSrcIPv4, 4},
		{wantElemPostNatDstIPv4, 4},
		{wantElemPostNapatSrc, 2},
		{wantElemPostNapatDst, 2},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("v4 template post-NAT field %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// Template/encoder length agreement: sum(template) == recordSize const.
	sum := 0
	for _, f := range ipfixTemplateV4 {
		sum += int(f.length)
	}
	if sum != ipfixRecordSizeV4 {
		t.Fatalf("ipfixRecordSizeV4 = %d, want sum(template) = %d", ipfixRecordSizeV4, sum)
	}
	if ipfixRecordSizeV4 != 63 {
		t.Fatalf("ipfixRecordSizeV4 = %d, want 63 (pre-NAT 45 + 2 src/dst mask (#2866) + 4 ingressInterface (#2749) + 12 post-NAT)", ipfixRecordSizeV4)
	}
}

func TestIPFIXTemplateV6_PostNATFields(t *testing.T) {
	n := len(ipfixTemplateV6)
	got := ipfixTemplateV6[n-4:]
	want := []ipfixField{
		{wantElemPostNatSrcIPv6, 16},
		{wantElemPostNatDstIPv6, 16},
		{wantElemPostNapatSrc, 2},
		{wantElemPostNapatDst, 2},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("v6 template post-NAT field %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	sum := 0
	for _, f := range ipfixTemplateV6 {
		sum += int(f.length)
	}
	if sum != ipfixRecordSizeV6 {
		t.Fatalf("ipfixRecordSizeV6 = %d, want sum(template) = %d", ipfixRecordSizeV6, sum)
	}
	if ipfixRecordSizeV6 != 111 {
		t.Fatalf("ipfixRecordSizeV6 = %d, want 111 (pre-NAT 69 + 2 src/dst mask (#2866) + 4 ingressInterface (#2749) + 36 post-NAT)", ipfixRecordSizeV6)
	}
}

// TestIPFIXEncodeV4_PostNATGolden encodes a NAT'd v4 flow and asserts the
// post-NAT tuple appears at the right offset with the translated values, and
// that the data set is exactly the new record size.
func TestIPFIXEncodeV4_PostNATGolden(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rec := FlowRecord{
		SrcIP:      net.IPv4(10, 0, 1, 100),
		DstIP:      net.IPv4(172, 16, 80, 200),
		SrcPort:    40000,
		DstPort:    80,
		Protocol:   6,
		StartTime:  now,
		EndTime:    now,
		NATSrcIP:   net.IPv4(203, 0, 113, 5),
		NATDstIP:   net.IPv4(172, 16, 80, 200),
		NATSrcPort: 50001,
		NATDstPort: 80,
	}
	ds := encodeIPFIXDataSet([]FlowRecord{rec})
	if got := binary.BigEndian.Uint16(ds[2:4]); int(got) != 4+ipfixRecordSizeV4 {
		t.Fatalf("data set length = %d, want %d", got, 4+ipfixRecordSizeV4)
	}
	if len(ds) != 4+ipfixRecordSizeV4 {
		t.Fatalf("encoded len = %d, want %d", len(ds), 4+ipfixRecordSizeV4)
	}
	// Post-NAT tuple is the last 12 bytes of the record.
	postOff := 4 + ipfixRecordSizeV4 - 12
	if ip := net.IP(ds[postOff : postOff+4]); !ip.Equal(net.IPv4(203, 0, 113, 5).To4()) {
		t.Errorf("postNatSrcIPv4 = %s, want 203.0.113.5", ip)
	}
	if ip := net.IP(ds[postOff+4 : postOff+8]); !ip.Equal(net.IPv4(172, 16, 80, 200).To4()) {
		t.Errorf("postNatDstIPv4 = %s, want 172.16.80.200", ip)
	}
	if p := binary.BigEndian.Uint16(ds[postOff+8 : postOff+10]); p != 50001 {
		t.Errorf("postNapatSrcPort = %d, want 50001", p)
	}
	if p := binary.BigEndian.Uint16(ds[postOff+10 : postOff+12]); p != 80 {
		t.Errorf("postNapatDstPort = %d, want 80", p)
	}
}

// TestIPFIXEncodeV6_PostNATGolden mirrors the v4 golden for IPv6 (NPTv6-style
// source translation).
func TestIPFIXEncodeV6_PostNATGolden(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	natSrc := net.ParseIP("2001:db8:dead::1")
	rec := FlowRecord{
		SrcIP:      net.ParseIP("fd00::1"),
		DstIP:      net.ParseIP("2001:db8::200"),
		SrcPort:    40000,
		DstPort:    443,
		Protocol:   6,
		StartTime:  now,
		EndTime:    now,
		IsIPv6:     true,
		NATSrcIP:   natSrc,
		NATDstIP:   net.ParseIP("2001:db8::200"),
		NATSrcPort: 40000,
		NATDstPort: 443,
	}
	ds := encodeIPFIXDataSet([]FlowRecord{rec})
	if got := binary.BigEndian.Uint16(ds[2:4]); int(got) != 4+ipfixRecordSizeV6 {
		t.Fatalf("data set length = %d, want %d", got, 4+ipfixRecordSizeV6)
	}
	postOff := 4 + ipfixRecordSizeV6 - 36
	if ip := net.IP(ds[postOff : postOff+16]); !ip.Equal(natSrc) {
		t.Errorf("postNatSrcIPv6 = %s, want %s", ip, natSrc)
	}
	if ip := net.IP(ds[postOff+16 : postOff+32]); !ip.Equal(net.ParseIP("2001:db8::200")) {
		t.Errorf("postNatDstIPv6 = %s, want 2001:db8::200", ip)
	}
	if p := binary.BigEndian.Uint16(ds[postOff+32 : postOff+34]); p != 40000 {
		t.Errorf("postNapatSrcPort = %d, want 40000", p)
	}
}

// --- NetFlow v9 ------------------------------------------------------------

func TestNetflowTemplateV4_PostNATFields(t *testing.T) {
	n := len(netflowTemplateFieldsV4)
	got := netflowTemplateFieldsV4[n-4:]
	want := []templateField{
		{wantElemPostNatSrcIPv4, 4},
		{wantElemPostNatDstIPv4, 4},
		{wantElemPostNapatSrc, 2},
		{wantElemPostNapatDst, 2},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("v9 v4 template post-NAT field %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// Record size derives from the template. #2613 dropped 11 unpopulated body
	// bytes; the pre-NAT v4 body is 39 bytes; #2749 re-added ingressInterface
	// (IE 10, 4B) with a real value; +12 post-NAT = 39+4+12 = 55, padded to 56.
	if rs := recordSize(netflowTemplateFieldsV4); rs != 56 {
		t.Fatalf("v9 v4 recordSize = %d, want 56 (39 pre-NAT body + 4 ingressInterface (#2749) + 12 post-NAT, padded)", rs)
	}
}

// netflowUnpaddedLen returns the summed (unpadded) field length; the v9
// encoder writes fields sequentially then pads the record at the END, so the
// post-NAT tuple sits at the last 12/36 unpadded bytes, NOT at
// recordSize-12.
func netflowUnpaddedLen(fields []templateField) int {
	n := 0
	for _, f := range fields {
		n += int(f.fieldLen)
	}
	return n
}

func TestNetflowTemplateV6_PostNATFields(t *testing.T) {
	n := len(netflowTemplateFieldsV6)
	got := netflowTemplateFieldsV6[n-4:]
	want := []templateField{
		{wantElemPostNatSrcIPv6, 16},
		{wantElemPostNatDstIPv6, 16},
		{wantElemPostNapatSrc, 2},
		{wantElemPostNapatDst, 2},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("v9 v6 template post-NAT field %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// #2613 dropped the same 11 unpopulated body bytes: the pre-NAT v6 body is
	// 63 bytes; #2749 re-added ingressInterface (IE 10, 4B) with a real value;
	// +36 post-NAT = 63+4+36 = 103, padded to 104.
	if rs := recordSize(netflowTemplateFieldsV6); rs != 104 {
		t.Fatalf("v9 v6 recordSize = %d, want 104 (63 pre-NAT body + 4 ingressInterface (#2749) + 36 post-NAT, padded)", rs)
	}
}

func TestNetflowEncodeV4_PostNATGolden(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	now := boot.Add(time.Second)
	opts := DefaultV9TemplateOptions()
	rec := FlowRecord{
		SrcIP:      net.IPv4(10, 0, 1, 100),
		DstIP:      net.IPv4(172, 16, 80, 200),
		SrcPort:    40000,
		DstPort:    80,
		Protocol:   6,
		StartTime:  now,
		EndTime:    now,
		NATSrcIP:   net.IPv4(203, 0, 113, 5),
		NATDstIP:   net.IPv4(172, 16, 80, 200),
		NATSrcPort: 50001,
		NATDstPort: 80,
	}
	fs := encodeDataFlowSet([]FlowRecord{rec}, boot, opts)
	recSize := recordSize(netflowTemplateFieldsV4)
	// FlowSet = 4 (header) + recSize.
	if len(fs) != 4+recSize {
		t.Fatalf("v9 v4 flowset len = %d, want %d", len(fs), 4+recSize)
	}
	// Post-NAT tuple is the last 12 UNPADDED bytes (v9 pads at the end).
	postOff := 4 + netflowUnpaddedLen(netflowTemplateFieldsV4) - 12
	if ip := net.IP(fs[postOff : postOff+4]); !ip.Equal(net.IPv4(203, 0, 113, 5).To4()) {
		t.Errorf("v9 postNatSrcIPv4 = %s, want 203.0.113.5", ip)
	}
	if ip := net.IP(fs[postOff+4 : postOff+8]); !ip.Equal(net.IPv4(172, 16, 80, 200).To4()) {
		t.Errorf("v9 postNatDstIPv4 = %s, want 172.16.80.200", ip)
	}
	if p := binary.BigEndian.Uint16(fs[postOff+8 : postOff+10]); p != 50001 {
		t.Errorf("v9 postNapatSrcPort = %d, want 50001", p)
	}
	if p := binary.BigEndian.Uint16(fs[postOff+10 : postOff+12]); p != 80 {
		t.Errorf("v9 postNapatDstPort = %d, want 80", p)
	}
}

func TestNetflowEncodeV6_PostNATGolden(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	now := boot.Add(time.Second)
	opts := DefaultV9TemplateOptions()
	natSrc := net.ParseIP("2001:db8:dead::1")
	rec := FlowRecord{
		SrcIP:      net.ParseIP("fd00::1"),
		DstIP:      net.ParseIP("2001:db8::200"),
		SrcPort:    40000,
		DstPort:    443,
		Protocol:   6,
		StartTime:  now,
		EndTime:    now,
		IsIPv6:     true,
		NATSrcIP:   natSrc,
		NATDstIP:   net.ParseIP("2001:db8::200"),
		NATSrcPort: 40000,
		NATDstPort: 443,
	}
	fs := encodeDataFlowSet([]FlowRecord{rec}, boot, opts)
	recSize := recordSize(netflowTemplateFieldsV6)
	if len(fs) != 4+recSize {
		t.Fatalf("v9 v6 flowset len = %d, want %d", len(fs), 4+recSize)
	}
	postOff := 4 + netflowUnpaddedLen(netflowTemplateFieldsV6) - 36
	if ip := net.IP(fs[postOff : postOff+16]); !ip.Equal(natSrc) {
		t.Errorf("v9 postNatSrcIPv6 = %s, want %s", ip, natSrc)
	}
	if ip := net.IP(fs[postOff+16 : postOff+32]); !ip.Equal(net.ParseIP("2001:db8::200")) {
		t.Errorf("v9 postNatDstIPv6 = %s, want 2001:db8::200", ip)
	}
}

// --- zero-NAT decision: post == pre ---------------------------------------

// TestExportSessionClose_NoNAT_PostEqualsPre proves the documented zero-NAT
// decision: when the SESSION_CLOSE carried no translation (nil / unspecified
// NAT IP, zero NAT port), ExportSessionClose emits post-NAT == pre-NAT so
// every record carries the mandatory template fields (Junos/vSRX behaviour).
func TestExportSessionClose_NoNAT_PostEqualsPre(t *testing.T) {
	cases := []struct {
		name string
		evt  SessionCloseData
	}{
		{
			name: "nil NAT IPs and zero ports",
			evt: SessionCloseData{
				SrcIP:   net.IPv4(10, 0, 1, 100),
				DstIP:   net.IPv4(172, 16, 80, 200),
				SrcPort: 40000,
				DstPort: 80,
			},
		},
		{
			name: "unspecified NAT IPs (dataplane reported 0.0.0.0)",
			evt: SessionCloseData{
				SrcIP:    net.IPv4(10, 0, 1, 100),
				DstIP:    net.IPv4(172, 16, 80, 200),
				SrcPort:  40000,
				DstPort:  80,
				NATSrcIP: net.IPv4(0, 0, 0, 0),
				NATDstIP: net.IPv4(0, 0, 0, 0),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rsrc, rdst, rsp, rdp := resolvePostNAT(
				tc.evt.SrcIP, tc.evt.DstIP, tc.evt.SrcPort, tc.evt.DstPort,
				tc.evt.NATSrcIP, tc.evt.NATDstIP, tc.evt.NATSrcPort, tc.evt.NATDstPort)
			if !rsrc.Equal(tc.evt.SrcIP) {
				t.Errorf("post src IP = %s, want pre %s", rsrc, tc.evt.SrcIP)
			}
			if !rdst.Equal(tc.evt.DstIP) {
				t.Errorf("post dst IP = %s, want pre %s", rdst, tc.evt.DstIP)
			}
			if rsp != tc.evt.SrcPort || rdp != tc.evt.DstPort {
				t.Errorf("post ports = %d/%d, want pre %d/%d", rsp, rdp, tc.evt.SrcPort, tc.evt.DstPort)
			}
		})
	}
}

// TestResolvePostNAT_IndependentHalves proves address-only and port-only
// translation each fall back independently.
func TestResolvePostNAT_IndependentHalves(t *testing.T) {
	// Source address+port translated; destination untouched.
	rsrc, rdst, rsp, rdp := resolvePostNAT(
		net.IPv4(10, 0, 1, 100), net.IPv4(172, 16, 80, 200), 40000, 80,
		net.IPv4(203, 0, 113, 5), nil, 50001, 0)
	if !rsrc.Equal(net.IPv4(203, 0, 113, 5)) {
		t.Errorf("src IP not translated: %s", rsrc)
	}
	if !rdst.Equal(net.IPv4(172, 16, 80, 200)) {
		t.Errorf("dst IP should fall back to pre: %s", rdst)
	}
	if rsp != 50001 {
		t.Errorf("src port not translated: %d", rsp)
	}
	if rdp != 80 {
		t.Errorf("dst port should fall back to pre: %d", rdp)
	}
}

// TestNoNAT_EncodedPostEqualsPre encodes a non-NAT flow end-to-end through
// the v9 v4 encoder (after resolvePostNAT) and asserts the post-NAT tuple in
// the wire bytes equals the pre-NAT tuple.
func TestNoNAT_EncodedPostEqualsPre(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	now := boot.Add(time.Second)
	src := net.IPv4(10, 0, 1, 100)
	dst := net.IPv4(172, 16, 80, 200)
	rsrc, rdst, rsp, rdp := resolvePostNAT(src, dst, 40000, 80, nil, nil, 0, 0)
	rec := FlowRecord{
		SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: 80, Protocol: 6,
		StartTime: now, EndTime: now,
		NATSrcIP: rsrc, NATDstIP: rdst, NATSrcPort: rsp, NATDstPort: rdp,
	}
	fs := encodeDataFlowSet([]FlowRecord{rec}, boot, DefaultV9TemplateOptions())
	postOff := 4 + netflowUnpaddedLen(netflowTemplateFieldsV4) - 12
	// pre-NAT src/dst at the start of the record (offset 4).
	if !bytes.Equal(fs[postOff:postOff+4], fs[4:8]) {
		t.Errorf("post src IP != pre src IP: %x vs %x", fs[postOff:postOff+4], fs[4:8])
	}
	if !bytes.Equal(fs[postOff+4:postOff+8], fs[8:12]) {
		t.Errorf("post dst IP != pre dst IP: %x vs %x", fs[postOff+4:postOff+8], fs[8:12])
	}
}
