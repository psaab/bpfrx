package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// #3748/#5312 fail-on-revert pins for the IPFIX sampler Options Template (Set ID
// 3, template ID 258) + Options Data Record that advertises the group's 1-in-N
// sampling configuration.
//
// Before #3748 ipfixSetIDOptionsTemplate (Set ID 3) was a bare constant: no
// options template and no sampler record were ever built or sent, so a
// collector could not learn the sampling rate and could not scale the sampled
// record count by N.
//
// #5312: xpf samples at SESSION-RECORD (Flow) granularity, so the record MUST
// carry the RFC 7014 FLOW-selection IEs (flowSelectorAlgorithm 390 /
// samplingFlowInterval 396 / samplingFlowSpacing 397), NOT the PSAMP
// PACKET-selection IEs (selectorAlgorithm 304 / samplingPacketInterval 305 /
// samplingPacketSpace 306). The packet-selection IEs would tell a standards
// collector to renormalize each record's octet/packet counters by N, inflating
// the already-complete per-session volume.
//
// The IE numbers/set IDs are asserted as literals independent of the package
// constants so a typo'd constant cannot make a test agree with itself.
const (
	wantOptionsSetID          uint16 = 3
	wantOptionsTemplateID     uint16 = 258
	wantObservationDomainIDIE uint16 = 149
	// #5312: RFC 7014 flow-selection IEs (record granularity).
	wantFlowSelectorAlgorithmIE uint16 = 390
	wantSamplingFlowIntervalIE  uint16 = 396
	wantSamplingFlowSpacingIE   uint16 = 397
	wantSystematicCountAlgo     uint16 = 1
	// #5312: the PSAMP packet-selection IEs that MUST NOT appear — advertising
	// them mis-describes record sampling as packet sampling.
	psampSelectorAlgorithmIE    uint16 = 304
	psampSamplingPacketInterval uint16 = 305
	psampSamplingPacketSpace    uint16 = 306
)

// decodeOptionsTemplateRecord walks an Options Template Set (Set ID 3, RFC 7011
// §3.4.2.2) and returns the template ID, scope field count, and the ordered
// field specifiers (scope fields first). The Options Template Record header is
// 6 bytes (Template ID, Field Count, Scope Field Count). It fails the test on
// any length drift, which is the integrity check for the 6-byte header sizing.
func decodeOptionsTemplateRecord(t *testing.T, ts []byte) (tmplID, scopeCount uint16, specs []ipfixSpec) {
	t.Helper()
	if len(ts) < 10 {
		t.Fatalf("options template set too short: %d bytes", len(ts))
	}
	setID := binary.BigEndian.Uint16(ts[0:2])
	if setID != wantOptionsSetID {
		t.Fatalf("set ID = %d, want %d (options template set)", setID, wantOptionsSetID)
	}
	setLen := int(binary.BigEndian.Uint16(ts[2:4]))
	if setLen != len(ts) {
		t.Fatalf("options template set header length = %d, want %d (encoded length)", setLen, len(ts))
	}
	tmplID = binary.BigEndian.Uint16(ts[4:6])
	fieldCount := int(binary.BigEndian.Uint16(ts[6:8]))
	scopeCount = binary.BigEndian.Uint16(ts[8:10])
	off := 10
	for i := 0; i < fieldCount; i++ {
		if off+4 > len(ts) {
			t.Fatalf("options template: ran off the end at field %d/%d", i, fieldCount)
		}
		raw := binary.BigEndian.Uint16(ts[off : off+2])
		length := binary.BigEndian.Uint16(ts[off+2 : off+4])
		off += 4
		var pen uint32
		if raw&0x8000 != 0 {
			if off+4 > len(ts) {
				t.Fatalf("options template: enterprise field missing PEN")
			}
			pen = binary.BigEndian.Uint32(ts[off : off+4])
			off += 4
		}
		specs = append(specs, ipfixSpec{elementID: raw & 0x7fff, length: length, enterprise: pen})
	}
	if off != len(ts) {
		t.Fatalf("options template walk consumed %d bytes, set is %d — header sizing drift", off, len(ts))
	}
	return tmplID, scopeCount, specs
}

// TestIPFIXOptionsTemplateSetDecode decodes the encoder output directly (no
// wire) and pins the sampler Options Template shape: Set ID 3, template ID 258,
// exactly one scope field (observationDomainId, IE 149) followed by the three
// RFC 7014 FLOW-selection option fields (flowSelectorAlgorithm 390,
// samplingFlowInterval 396, samplingFlowSpacing 397) with the correct lengths,
// and asserts the PSAMP PACKET-selection IEs are ABSENT (#5312).
func TestIPFIXOptionsTemplateSetDecode(t *testing.T) {
	ts := encodeIPFIXOptionsTemplateSet()
	tmplID, scopeCount, specs := decodeOptionsTemplateRecord(t, ts)
	if tmplID != wantOptionsTemplateID {
		t.Errorf("options template ID = %d, want %d", tmplID, wantOptionsTemplateID)
	}
	if scopeCount != 1 {
		t.Errorf("scope field count = %d, want 1", scopeCount)
	}
	// The distinct template ID must not collide with the data templates.
	if wantOptionsTemplateID == ipfixTemplateIDv4 || wantOptionsTemplateID == ipfixTemplateIDv6 {
		t.Fatalf("options template ID %d collides with a data template ID", wantOptionsTemplateID)
	}
	want := []ipfixSpec{
		{elementID: wantObservationDomainIDIE, length: 4},
		{elementID: wantFlowSelectorAlgorithmIE, length: 2},
		{elementID: wantSamplingFlowIntervalIE, length: 8},
		{elementID: wantSamplingFlowSpacingIE, length: 8},
	}
	if len(specs) != len(want) {
		t.Fatalf("field count = %d, want %d (%v)", len(specs), len(want), specs)
	}
	for i, w := range want {
		if specs[i].elementID != w.elementID || specs[i].length != w.length || specs[i].enterprise != 0 {
			t.Errorf("field[%d] = %+v, want elementID=%d length=%d enterprise=0", i, specs[i], w.elementID, w.length)
		}
	}
	// #5312: the misleading PSAMP packet-selection IEs must NOT be advertised —
	// they would tell a collector to renormalize per-record octet/packet counts
	// by N, mis-describing record-granularity sampling as packet sampling.
	for _, bad := range []uint16{psampSelectorAlgorithmIE, psampSamplingPacketInterval, psampSamplingPacketSpace} {
		if _, ok := findSpec(specs, bad, 0); ok {
			t.Errorf("options template advertises packet-selection IE %d — record-granularity sampling must use RFC 7014 flow-selection IEs (390/396/397)", bad)
		}
	}
}

// TestIPFIXOptionsSamplerDataSetDecode pins the Options Data Record encoding
// across the sampled and degenerate (unsampled) rates: interval is always 1 and
// space is N-1 for 1-in-N (0 for the degenerate rate<=1 case).
func TestIPFIXOptionsSamplerDataSetDecode(t *testing.T) {
	const odid uint32 = 0xDEADBEEF
	cases := []struct {
		rate      int
		wantSpace uint64
	}{
		{rate: 100, wantSpace: 99},
		{rate: 2, wantSpace: 1},
		{rate: 1, wantSpace: 0}, // degenerate: 1-in-1 (no sampling)
		{rate: 0, wantSpace: 0}, // degenerate: export-all
	}
	for _, c := range cases {
		ds := encodeIPFIXOptionsSamplerDataSet(odid, c.rate)
		if len(ds) != 4+ipfixOptionsSamplerRecordSize {
			t.Fatalf("rate %d: data set len = %d, want %d", c.rate, len(ds), 4+ipfixOptionsSamplerRecordSize)
		}
		if setID := binary.BigEndian.Uint16(ds[0:2]); setID != wantOptionsTemplateID {
			t.Errorf("rate %d: data set ID = %d, want %d (== options template ID)", c.rate, setID, wantOptionsTemplateID)
		}
		if setLen := int(binary.BigEndian.Uint16(ds[2:4])); setLen != len(ds) {
			t.Errorf("rate %d: data set header length = %d, want %d", c.rate, setLen, len(ds))
		}
		rec := ds[4:]
		if got := binary.BigEndian.Uint32(rec[0:4]); got != odid {
			t.Errorf("rate %d: observationDomainId scope = %#x, want %#x", c.rate, got, odid)
		}
		if got := binary.BigEndian.Uint16(rec[4:6]); got != wantSystematicCountAlgo {
			t.Errorf("rate %d: flowSelectorAlgorithm = %d, want %d (systematic count-based)", c.rate, got, wantSystematicCountAlgo)
		}
		if got := binary.BigEndian.Uint64(rec[6:14]); got != 1 {
			t.Errorf("rate %d: samplingFlowInterval = %d, want 1", c.rate, got)
		}
		if got := binary.BigEndian.Uint64(rec[14:22]); got != c.wantSpace {
			t.Errorf("rate %d: samplingFlowSpacing = %d, want %d (N-1)", c.rate, got, c.wantSpace)
		}
	}
}

// TestIPFIXSamplerOptionsWireLoopback exercises the real exporter wire path
// (NewIPFIXExporter -> sendTemplates) over a loopback UDP collector for a
// SAMPLED group, mirroring the #2609 harness, and asserts:
//   - sendTemplates emits the data template set (message 1) THEN a second
//     message carrying the sampler Options Template (Set ID 3) + Options Data
//     Record (Set ID 258);
//   - the options record scope (observationDomainId) equals the group's ODID
//     (== the message header ObservationID);
//   - the advertised rate is systematic count-based FLOW selection (RFC 7014),
//     samplingFlowInterval=1, samplingFlowSpacing=N-1;
//   - the Options Data Record advances the header Sequence Number by exactly one
//     (it is a Data Record; #2609 convention).
//
// RED-on-revert: dropping the sampler emission from sendTemplates makes the
// message-2 read time out (no options message) -> t.Fatalf, and the decode
// asserts on Set ID 3 / template 258 / the sampler IEs never run.
func TestIPFIXSamplerOptionsWireLoopback(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	const rate = 100
	ec := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: pc.LocalAddr().String()}},
		InstanceName: "samp-inst", // non-default -> real hashed ODID (#3740)
		TemplateName: "t1",
		SamplingRate: rate,
	}
	e, err := NewIPFIXExporter(ec)
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	defer e.Close()

	readPkt := func() []byte {
		buf := make([]byte, 4096)
		if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("collector read (expected the #3748 sampler options message): %v", err)
		}
		return buf[:n]
	}

	e.sendTemplates()

	// Message 1: the data template set (Set ID 2).
	p1 := readPkt()
	if len(p1) < 18 {
		t.Fatalf("short template packet: %d bytes", len(p1))
	}
	if setID := binary.BigEndian.Uint16(p1[16:18]); setID != ipfixSetIDTemplate {
		t.Fatalf("message 1 first set ID = %d, want %d (data template set)", setID, ipfixSetIDTemplate)
	}

	// Message 2: sampler Options Template Set + Options Data Set.
	p2 := readPkt()
	if len(p2) < 16+10 {
		t.Fatalf("short options packet: %d bytes", len(p2))
	}
	if ver := binary.BigEndian.Uint16(p2[0:2]); ver != 10 {
		t.Fatalf("options message version = %d, want 10", ver)
	}
	if msgLen := int(binary.BigEndian.Uint16(p2[2:4])); msgLen != len(p2) {
		t.Fatalf("options message header length = %d, want %d", msgLen, len(p2))
	}
	msgSeq := binary.BigEndian.Uint32(p2[8:12])
	msgODID := binary.BigEndian.Uint32(p2[12:16])
	if msgODID != e.sourceID {
		t.Fatalf("options message ObservationID = %#x, want %#x (group ODID)", msgODID, e.sourceID)
	}
	if msgSeq != 0 {
		t.Fatalf("options message sequence = %d, want 0 (no prior data records)", msgSeq)
	}

	body := p2[16:]
	optsTmplLen := int(binary.BigEndian.Uint16(body[2:4]))
	if optsTmplLen <= 0 || optsTmplLen > len(body) {
		t.Fatalf("options template set length = %d, body = %d", optsTmplLen, len(body))
	}
	optsTmpl := body[:optsTmplLen]
	optsData := body[optsTmplLen:]

	// --- Options Template (Set ID 3) ---
	tmplID, scopeCount, specs := decodeOptionsTemplateRecord(t, optsTmpl)
	if tmplID != wantOptionsTemplateID {
		t.Errorf("wire options template ID = %d, want %d", tmplID, wantOptionsTemplateID)
	}
	if scopeCount != 1 {
		t.Errorf("wire scope field count = %d, want 1", scopeCount)
	}
	if len(specs) < 1 || specs[0].elementID != wantObservationDomainIDIE {
		t.Errorf("wire scope field = %+v, want observationDomainId (IE %d)", specs, wantObservationDomainIDIE)
	}
	for _, ie := range []uint16{wantFlowSelectorAlgorithmIE, wantSamplingFlowIntervalIE, wantSamplingFlowSpacingIE} {
		if _, ok := findSpec(specs, ie, 0); !ok {
			t.Errorf("wire options template missing flow-selection sampler IE %d", ie)
		}
	}
	// #5312: the packet-selection IEs must not ride the wire template.
	for _, bad := range []uint16{psampSelectorAlgorithmIE, psampSamplingPacketInterval, psampSamplingPacketSpace} {
		if _, ok := findSpec(specs, bad, 0); ok {
			t.Errorf("wire options template advertises packet-selection IE %d — must be RFC 7014 flow-selection", bad)
		}
	}

	// --- Options Data Record (Set ID 258) ---
	if len(optsData) != 4+ipfixOptionsSamplerRecordSize {
		t.Fatalf("wire options data set len = %d, want %d", len(optsData), 4+ipfixOptionsSamplerRecordSize)
	}
	if setID := binary.BigEndian.Uint16(optsData[0:2]); setID != wantOptionsTemplateID {
		t.Errorf("wire options data set ID = %d, want %d", setID, wantOptionsTemplateID)
	}
	rec := optsData[4:]
	if got := binary.BigEndian.Uint32(rec[0:4]); got != e.sourceID {
		t.Errorf("wire options record scope ODID = %#x, want %#x", got, e.sourceID)
	}
	if got := binary.BigEndian.Uint16(rec[4:6]); got != wantSystematicCountAlgo {
		t.Errorf("wire flowSelectorAlgorithm = %d, want %d", got, wantSystematicCountAlgo)
	}
	if got := binary.BigEndian.Uint64(rec[6:14]); got != 1 {
		t.Errorf("wire samplingFlowInterval = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint64(rec[14:22]); got != uint64(rate-1) {
		t.Errorf("wire samplingFlowSpacing = %d, want %d (N-1)", got, rate-1)
	}

	// The Options Data Record is a Data Record: it advanced the counter by one.
	e.mu.Lock()
	seq := e.seq
	e.mu.Unlock()
	if seq != 1 {
		t.Fatalf("cumulative sequence after sampler options = %d, want 1 "+
			"(the Options Data Record counts toward the sequence; #2609 convention)", seq)
	}
}

// TestIPFIXSamplerOptionsAbsentWhenUnsampled pins the degenerate handling: an
// export-all group (SamplingRate 0/1) must NOT emit any sampler options — a
// collector then correctly assumes 1-in-1. sendTemplates emits only the data
// template message; a second read times out.
func TestIPFIXSamplerOptionsAbsentWhenUnsampled(t *testing.T) {
	for _, rate := range []int{0, 1} {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		ec := &ExportConfig{
			Collectors:   []CollectorConfig{{Address: pc.LocalAddr().String()}},
			SamplingRate: rate,
		}
		e, err := NewIPFIXExporter(ec)
		if err != nil {
			pc.Close()
			t.Fatalf("NewIPFIXExporter: %v", err)
		}
		if e.emitSampler {
			t.Errorf("rate %d: emitSampler = true, want false (unsampled)", rate)
		}
		if e.optionsTemplateSet != nil || e.optionsDataSet != nil {
			t.Errorf("rate %d: precomputed sampler options must be nil when unsampled", rate)
		}

		e.sendTemplates()

		// Message 1: the data template set.
		buf := make([]byte, 4096)
		if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		if _, _, err := pc.ReadFrom(buf); err != nil {
			t.Fatalf("rate %d: collector got no data template: %v", rate, err)
		}
		// No message 2: a short read must time out.
		if err := pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		if n, _, err := pc.ReadFrom(buf); err == nil {
			t.Errorf("rate %d: unexpected second packet (%d bytes) — unsampled group must not emit sampler options", rate, n)
		}
		e.Close()
		pc.Close()
	}
}
