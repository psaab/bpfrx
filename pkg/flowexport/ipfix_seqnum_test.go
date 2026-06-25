package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestIPFIXTemplateRefreshPreservesSequenceNumber is the #2609 fail-on-revert
// guard. RFC 7011 §3.1 / §10.3.2: the IPFIX header Sequence Number is the
// cumulative count of Data Records sent in all prior Messages for this
// Observation Domain (i.e. the sequence of the NEXT Data Record). A Message
// carrying only Template Sets contains no Data Records, so it MUST NOT advance
// the counter — but it MUST carry the CURRENT cumulative value, not 0.
//
// The pre-fix code hardcoded SequenceNumber: 0 in sendTemplates(). After data
// records had been exported, a periodic template refresh rewound the header
// sequence to 0, which loss/sequence-tracking collectors read as packet loss
// or an exporter restart.
//
// This test exercises the real wire path: it stands up a loopback UDP
// collector, sends a data batch (advancing the counter), triggers a template
// refresh, then sends more data, and parses the captured header sequence
// numbers off the wire. It asserts:
//   - template-refresh header carries the current cumulative data-record count
//     (NOT 0) once records have been sent
//   - the template refresh does NOT advance the counter (no data records)
//   - the subsequent data send resumes exactly where the prior data left off
//
// Revert the fix (SequenceNumber: 0 in sendTemplates) and the refresh-after-
// data assertion goes red: the captured template header reads 0 instead of the
// cumulative count.
func TestIPFIXTemplateRefreshPreservesSequenceNumber(t *testing.T) {
	// Loopback UDP collector to capture the exact bytes hitting the wire.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	collectorAddr := pc.LocalAddr().String()

	ec := &ExportConfig{
		Collectors: []CollectorConfig{{Address: collectorAddr}},
	}
	e, err := NewIPFIXExporter(ec)
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	defer e.Close()

	// seqOf parses the IPFIX header (RFC 7011 §3.1) off a captured packet and
	// returns (version, sequenceNumber). The header is 16 bytes; the sequence
	// number is at offset 8..12, big-endian.
	readPkt := func() []byte {
		buf := make([]byte, 2048)
		if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom (collector got no packet): %v", err)
		}
		if n < 16 {
			t.Fatalf("short IPFIX packet: %d bytes", n)
		}
		return buf[:n]
	}
	seqOf := func(pkt []byte) (version, setID uint16, seq uint32) {
		version = binary.BigEndian.Uint16(pkt[0:2])
		seq = binary.BigEndian.Uint32(pkt[8:12])
		// First set ID after the 16-byte header (2 = template set, >=256 data).
		setID = binary.BigEndian.Uint16(pkt[16:18])
		return version, setID, seq
	}

	mkRecords := func(n int) []FlowRecord {
		recs := make([]FlowRecord, n)
		for i := range recs {
			recs[i] = FlowRecord{
				SrcIP:     net.IPv4(10, 0, 0, 1),
				DstIP:     net.IPv4(10, 0, 0, 2),
				SrcPort:   1000 + uint16(i),
				DstPort:   80,
				Protocol:  6,
				StartTime: time.Now(),
				EndTime:   time.Now(),
			}
		}
		return recs
	}

	// 1) Send a first data batch of 3 records. First data packet's header
	//    sequence is 0 (no prior data records); the counter then advances to 3.
	e.sendRecords(mkRecords(3))
	_, setID, seq := seqOf(readPkt())
	if setID < 256 {
		t.Fatalf("expected a data set (set ID >= 256), got set ID %d", setID)
	}
	if seq != 0 {
		t.Fatalf("first data packet sequence = %d, want 0 (no prior data records)", seq)
	}

	// 2) Trigger a template refresh. RFC 7011: the template-only Message
	//    carries the CURRENT cumulative data-record count (3), and does NOT
	//    advance the counter (it has no data records).
	e.sendTemplates()
	ver, setID, seq := seqOf(readPkt())
	if ver != 10 {
		t.Fatalf("template packet version = %d, want 10 (IPFIX)", ver)
	}
	if setID != ipfixSetIDTemplate {
		t.Fatalf("expected a template set (set ID %d), got set ID %d", ipfixSetIDTemplate, setID)
	}
	if seq != 3 {
		t.Fatalf("template-refresh header sequence = %d, want 3 "+
			"(RFC 7011 §3.1: cumulative data-record count, NOT reset to 0) (#2609)", seq)
	}

	// 3) Send 2 more data records. The data sequence MUST resume at 3 (the
	//    template refresh did not consume or reset the counter); the counter
	//    then advances to 5.
	e.sendRecords(mkRecords(2))
	_, setID, seq = seqOf(readPkt())
	if setID < 256 {
		t.Fatalf("expected a data set (set ID >= 256), got set ID %d", setID)
	}
	if seq != 3 {
		t.Fatalf("post-refresh data packet sequence = %d, want 3 "+
			"(template refresh must not advance or reset the data-record counter) (#2609)", seq)
	}

	// The exporter's running counter is now 5 (3 + 2), proving the template
	// refresh contributed 0 to the cumulative data-record count.
	e.mu.Lock()
	finalSeq := e.seq
	e.mu.Unlock()
	if finalSeq != 5 {
		t.Fatalf("final cumulative seq = %d, want 5 (3 + 2 data records; "+
			"template refresh must count 0)", finalSeq)
	}
}
