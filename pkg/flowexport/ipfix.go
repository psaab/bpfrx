package flowexport

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// IPFIX field Information Element IDs (IANA-assigned, RFC 5102).
const (
	ipfixOctetDeltaCount          = 1
	ipfixPacketDeltaCount         = 2
	ipfixProtocolIdentifier       = 4
	ipfixIpClassOfService         = 5
	ipfixTcpControlBits           = 6
	ipfixSourceTransportPort      = 7
	ipfixSourceIPv4Address        = 8
	ipfixDestinationTransportPort = 11
	ipfixDestinationIPv4Address   = 12
	ipfixIngressInterface         = 10
	ipfixEgressInterface          = 14
	ipfixSourceIPv6Address        = 27
	ipfixDestinationIPv6Address   = 28
	ipfixFlowDirection            = 61
	ipfixApplicationId            = 95
	ipfixFlowStartMilliseconds    = 152
	ipfixFlowEndMilliseconds      = 153
	// RFC 5103 post-NAT (translated) tuple elements. IPv4 addresses 225/226
	// (ipv4Address, 4B); transport ports 227/228 (unsigned16, 2B), which are
	// family-agnostic and reused for IPv6. IPv6 addresses 281/282
	// (ipv6Address, 16B) per RFC 8158. Confirmed against the IANA "IP Flow
	// Information Export (IPFIX) Entities" registry (#2526).
	ipfixPostNatSourceIPv4Address      = 225
	ipfixPostNatDestinationIPv4Address = 226
	ipfixPostNapatSourceTransportPort  = 227
	ipfixPostNapatDestTransportPort    = 228
	ipfixPostNatSourceIPv6Address      = 281
	ipfixPostNatDestinationIPv6Address = 282
)

// IPFIX Set IDs (RFC 7011 Section 3.3.2).
const (
	ipfixSetIDTemplate        = 2
	ipfixSetIDOptionsTemplate = 3
	// Data set IDs >= 256
)

// IPFIX template IDs.
const (
	ipfixTemplateIDv4 = 256
	ipfixTemplateIDv6 = 257
)

// ipfixField defines a template field with IANA element ID and length.
type ipfixField struct {
	elementID uint16
	length    uint16
}

// ipfixTemplateV4 defines the IPv4 IPFIX template fields.
var ipfixTemplateV4 = []ipfixField{
	{ipfixSourceIPv4Address, 4},
	{ipfixDestinationIPv4Address, 4},
	{ipfixSourceTransportPort, 2},
	{ipfixDestinationTransportPort, 2},
	{ipfixProtocolIdentifier, 1},
	{ipfixIpClassOfService, 1},
	{ipfixTcpControlBits, 2}, // IPFIX uses 2 bytes for TCP flags (RFC 7011)
	{ipfixFlowDirection, 1},
	{ipfixIngressInterface, 4},
	{ipfixEgressInterface, 4},
	{ipfixPacketDeltaCount, 8},
	{ipfixOctetDeltaCount, 8},
	{ipfixFlowStartMilliseconds, 8},
	{ipfixFlowEndMilliseconds, 8},
	// #2526: post-NAT (translated) tuple, appended last.
	{ipfixPostNatSourceIPv4Address, 4},
	{ipfixPostNatDestinationIPv4Address, 4},
	{ipfixPostNapatSourceTransportPort, 2},
	{ipfixPostNapatDestTransportPort, 2},
}

// ipfixTemplateV6 defines the IPv6 IPFIX template fields.
var ipfixTemplateV6 = []ipfixField{
	{ipfixSourceIPv6Address, 16},
	{ipfixDestinationIPv6Address, 16},
	{ipfixSourceTransportPort, 2},
	{ipfixDestinationTransportPort, 2},
	{ipfixProtocolIdentifier, 1},
	{ipfixIpClassOfService, 1},
	{ipfixTcpControlBits, 2},
	{ipfixFlowDirection, 1},
	{ipfixIngressInterface, 4},
	{ipfixEgressInterface, 4},
	{ipfixPacketDeltaCount, 8},
	{ipfixOctetDeltaCount, 8},
	{ipfixFlowStartMilliseconds, 8},
	{ipfixFlowEndMilliseconds, 8},
	// #2526: post-NAT (translated) tuple, appended last. v6 addresses use the
	// 16-byte RFC 8158 elements; ports reuse the family-agnostic 227/228.
	{ipfixPostNatSourceIPv6Address, 16},
	{ipfixPostNatDestinationIPv6Address, 16},
	{ipfixPostNapatSourceTransportPort, 2},
	{ipfixPostNapatDestTransportPort, 2},
}

// ipfixRecordSizeV4 is the byte size of a single IPv4 IPFIX data record.
// pre-NAT 5-tuple + meta + counters + timestamps = 57; #2526 post-NAT tuple
// (4+4+2+2) = 12 → 69.
// 4+4+2+2+1+1+2+1+4+4+8+8+8+8 + 4+4+2+2 = 69
const ipfixRecordSizeV4 = 69

// ipfixRecordSizeV6 is the byte size of a single IPv6 IPFIX data record.
// pre-NAT body = 81; #2526 post-NAT tuple (16+16+2+2) = 36 → 117.
// 16+16+2+2+1+1+2+1+4+4+8+8+8+8 + 16+16+2+2 = 117
const ipfixRecordSizeV6 = 117

// ipfixRecordSizeV4 / V6 must equal the sum of their template field lengths.
// A drift between the template (what the collector parses) and the encoder
// (record size) corrupts every record — pin it at build time (#2526).
var _ = func() struct{} {
	sum := func(fs []ipfixField) int {
		n := 0
		for _, f := range fs {
			n += int(f.length)
		}
		return n
	}
	if sum(ipfixTemplateV4) != ipfixRecordSizeV4 {
		panic("ipfixRecordSizeV4 != sum(ipfixTemplateV4)")
	}
	if sum(ipfixTemplateV6) != ipfixRecordSizeV6 {
		panic("ipfixRecordSizeV6 != sum(ipfixTemplateV6)")
	}
	return struct{}{}
}()

// ipfixHeader is the 16-byte IPFIX message header (RFC 7011 Section 3.1).
type ipfixHeader struct {
	Version        uint16 // always 10
	Length         uint16 // total message length including header
	ExportTime     uint32 // epoch seconds
	SequenceNumber uint32 // cumulative number of data records
	ObservationID  uint32 // observation domain ID
}

func encodeIPFIXHeader(h ipfixHeader) []byte {
	b := make([]byte, 16)
	encodeIPFIXHeaderInto(b, h)
	return b
}

func encodeIPFIXHeaderInto(b []byte, h ipfixHeader) {
	binary.BigEndian.PutUint16(b[0:2], h.Version)
	binary.BigEndian.PutUint16(b[2:4], h.Length)
	binary.BigEndian.PutUint32(b[4:8], h.ExportTime)
	binary.BigEndian.PutUint32(b[8:12], h.SequenceNumber)
	binary.BigEndian.PutUint32(b[12:16], h.ObservationID)
}

// encodeIPFIXTemplateSet builds an IPFIX template set containing v4 and v6 templates.
func encodeIPFIXTemplateSet() []byte {
	v4fields := len(ipfixTemplateV4)
	v6fields := len(ipfixTemplateV6)
	// Set header (4 bytes) + 2 template record headers (4 each) + field specifiers (4 each)
	totalLen := 4 + (4 + v4fields*4) + (4 + v6fields*4)

	b := make([]byte, totalLen)
	off := 0

	// Set header: Set ID = 2 (Template Set), Length
	binary.BigEndian.PutUint16(b[off:off+2], ipfixSetIDTemplate)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(totalLen))
	off += 4

	// IPv4 template record header
	binary.BigEndian.PutUint16(b[off:off+2], ipfixTemplateIDv4)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(v4fields))
	off += 4
	for _, f := range ipfixTemplateV4 {
		binary.BigEndian.PutUint16(b[off:off+2], f.elementID) // no enterprise bit
		binary.BigEndian.PutUint16(b[off+2:off+4], f.length)
		off += 4
	}

	// IPv6 template record header
	binary.BigEndian.PutUint16(b[off:off+2], ipfixTemplateIDv6)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(v6fields))
	off += 4
	for _, f := range ipfixTemplateV6 {
		binary.BigEndian.PutUint16(b[off:off+2], f.elementID)
		binary.BigEndian.PutUint16(b[off+2:off+4], f.length)
		off += 4
	}

	return b
}

// encodeIPFIXDataSet builds an IPFIX data set from a batch of records.
func encodeIPFIXDataSet(records []FlowRecord) []byte {
	if len(records) == 0 {
		return nil
	}
	isV6 := records[0].IsIPv6
	var tmplID uint16
	var recSize int
	if isV6 {
		tmplID = ipfixTemplateIDv6
		recSize = ipfixRecordSizeV6
	} else {
		tmplID = ipfixTemplateIDv4
		recSize = ipfixRecordSizeV4
	}

	totalLen := ipfixDataSetLen(len(records), recSize)
	b := make([]byte, totalLen)
	encodeIPFIXDataSetInto(b, records, tmplID, recSize)
	return b
}

func ipfixDataSetLen(recordCount, recSize int) int {
	return 4 + recordCount*recSize
}

func encodeIPFIXDataSetInto(b []byte, records []FlowRecord, tmplID uint16, recSize int) {
	if len(records) == 0 {
		return
	}
	totalLen := ipfixDataSetLen(len(records), recSize)
	binary.BigEndian.PutUint16(b[0:2], tmplID)
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	off := 4
	isV6 := records[0].IsIPv6
	for _, r := range records {
		if isV6 {
			off = encodeIPFIXRecordV6(b, off, r)
		} else {
			off = encodeIPFIXRecordV4(b, off, r)
		}
	}
	clear(b[off:totalLen])
}

func encodeIPFIXRecordV4(b []byte, off int, r FlowRecord) int {
	src4 := r.SrcIP.To4()
	dst4 := r.DstIP.To4()
	if src4 == nil {
		src4 = net.IPv4zero.To4()
	}
	if dst4 == nil {
		dst4 = net.IPv4zero.To4()
	}
	copy(b[off:off+4], src4)
	off += 4
	copy(b[off:off+4], dst4)
	off += 4
	binary.BigEndian.PutUint16(b[off:off+2], r.SrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.DstPort)
	off += 2
	b[off] = r.Protocol
	off++
	b[off] = r.TOS
	off++
	binary.BigEndian.PutUint16(b[off:off+2], uint16(r.TCPFlags))
	off += 2
	b[off] = r.Direction
	off++
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	binary.BigEndian.PutUint64(b[off:off+8], r.Packets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.Bytes)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], uint64(r.StartTime.UnixMilli()))
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], uint64(r.EndTime.UnixMilli()))
	off += 8
	// #2526: post-NAT (translated) tuple — 225/226/227/228.
	natSrc4 := r.NATSrcIP.To4()
	natDst4 := r.NATDstIP.To4()
	if natSrc4 == nil {
		natSrc4 = net.IPv4zero.To4()
	}
	if natDst4 == nil {
		natDst4 = net.IPv4zero.To4()
	}
	copy(b[off:off+4], natSrc4)
	off += 4
	copy(b[off:off+4], natDst4)
	off += 4
	binary.BigEndian.PutUint16(b[off:off+2], r.NATSrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.NATDstPort)
	off += 2
	return off
}

func encodeIPFIXRecordV6(b []byte, off int, r FlowRecord) int {
	src16 := r.SrcIP.To16()
	dst16 := r.DstIP.To16()
	if src16 == nil {
		src16 = net.IPv6zero
	}
	if dst16 == nil {
		dst16 = net.IPv6zero
	}
	copy(b[off:off+16], src16)
	off += 16
	copy(b[off:off+16], dst16)
	off += 16
	binary.BigEndian.PutUint16(b[off:off+2], r.SrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.DstPort)
	off += 2
	b[off] = r.Protocol
	off++
	b[off] = r.TOS
	off++
	binary.BigEndian.PutUint16(b[off:off+2], uint16(r.TCPFlags))
	off += 2
	b[off] = r.Direction
	off++
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	binary.BigEndian.PutUint64(b[off:off+8], r.Packets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.Bytes)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], uint64(r.StartTime.UnixMilli()))
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], uint64(r.EndTime.UnixMilli()))
	off += 8
	// #2526: post-NAT (translated) tuple — 281/282 (16B) + 227/228 (2B).
	natSrc16 := r.NATSrcIP.To16()
	natDst16 := r.NATDstIP.To16()
	if natSrc16 == nil {
		natSrc16 = net.IPv6zero
	}
	if natDst16 == nil {
		natDst16 = net.IPv6zero
	}
	copy(b[off:off+16], natSrc16)
	off += 16
	copy(b[off:off+16], natDst16)
	off += 16
	binary.BigEndian.PutUint16(b[off:off+2], r.NATSrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.NATDstPort)
	off += 2
	return off
}

// IPFIXExporter sends IPFIX (NetFlow v10) messages to configured collectors.
type IPFIXExporter struct {
	cfg         *ExportConfig
	sourceID    uint32
	templateSet []byte

	mu    sync.Mutex
	seq   uint32 // cumulative data record count
	conns *collectorConns

	batch flowBatch

	exportedFlows atomic.Uint64
	exportedPkts  atomic.Uint64
	// #2465: see Exporter.estimatedDurations — count of close flows whose
	// StartTime fell back to the packet-count heuristic (no real creation ts).
	estimatedDurations atomic.Uint64
}

// NewIPFIXExporter creates a new IPFIX exporter. cfg is held by pointer
// (never copied) for the same reason as NewExporter: ExportConfig
// embeds the live 1-in-N sampleCounter (atomic.Uint64) and copying it
// would fork the counter, re-seeding the sampling cadence (#2224).
func NewIPFIXExporter(cfg *ExportConfig) (*IPFIXExporter, error) {
	e := &IPFIXExporter{
		cfg:         cfg,
		sourceID:    1,
		templateSet: encodeIPFIXTemplateSet(),
	}

	conns, err := dialCollectors(cfg.Collectors)
	if err != nil {
		return nil, err
	}
	e.conns = conns

	return e, nil
}

// Run starts the IPFIX exporter. Blocks until ctx is cancelled.
func (e *IPFIXExporter) Run(ctx context.Context) {
	e.sendTemplates()

	templateTicker := time.NewTicker(e.cfg.TemplateRefreshRate)
	defer templateTicker.Stop()

	batchTicker := time.NewTicker(100 * time.Millisecond)
	defer batchTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.flushBatches()
			return
		case <-templateTicker.C:
			e.sendTemplates()
		case <-batchTicker.C:
			e.flushBatches()
		}
	}
}

// ExportSessionClose queues a flow record for IPFIX export.
func (e *IPFIXExporter) ExportSessionClose(rec logging.EventRecord, evt SessionCloseData) {
	// #2465: prefer the real session-creation timestamp for StartTime; fall
	// back to the packet-count heuristic (and count it) only when absent.
	startTime, usedEstimate := flowStartTime(rec, evt.Protocol)
	if usedEstimate {
		e.estimatedDurations.Add(1)
	}
	// #2526: resolve the post-NAT tuple with pre-NAT fallback so every
	// exported record carries the RFC 5103 / RFC 8158 post-NAT fields
	// (post == pre when the flow was not translated).
	natSrcIP, natDstIP, natSrcPort, natDstPort := resolvePostNAT(
		evt.SrcIP, evt.DstIP, evt.SrcPort, evt.DstPort,
		evt.NATSrcIP, evt.NATDstIP, evt.NATSrcPort, evt.NATDstPort)
	fr := FlowRecord{
		SrcIP:      evt.SrcIP,
		DstIP:      evt.DstIP,
		SrcPort:    evt.SrcPort,
		DstPort:    evt.DstPort,
		Protocol:   evt.Protocol,
		Packets:    rec.SessionPkts,
		Bytes:      rec.SessionBytes,
		StartTime:  startTime,
		EndTime:    rec.Time,
		IsIPv6:     evt.IsIPv6,
		NATSrcIP:   natSrcIP,
		NATDstIP:   natDstIP,
		NATSrcPort: natSrcPort,
		NATDstPort: natDstPort,
	}

	e.batch.add(fr)
}

// Stats returns export statistics.
func (e *IPFIXExporter) Stats() (flows, packets uint64) {
	return e.exportedFlows.Load(), e.exportedPkts.Load()
}

// EstimatedDurations returns the count of exported session-close flows whose
// StartTime was derived from the packet-count heuristic (#2465) rather than a
// real session-creation timestamp.
func (e *IPFIXExporter) EstimatedDurations() uint64 {
	return e.estimatedDurations.Load()
}

// CollectorHealth returns a per-collector write-health snapshot (#2464).
func (e *IPFIXExporter) CollectorHealth() []CollectorHealth {
	return e.conns.health()
}

// Close shuts down all collector connections.
func (e *IPFIXExporter) Close() {
	e.conns.close()
}

func (e *IPFIXExporter) sendTemplates() {
	// RFC 7011 §3.1 / §10.3.2: the IPFIX Sequence Number is the cumulative
	// count of Data Records sent in all prior Messages for this Observation
	// Domain (the value of the NEXT Data Record's sequence). A Message that
	// carries only (Options) Template Sets contains no Data Records, so it
	// MUST NOT advance the counter — but it MUST carry the current cumulative
	// value, not 0. Emitting 0 on every periodic template refresh rewinds the
	// header sequence, which loss/sequence-tracking collectors (pmacct,
	// Elastiflow) read as packet loss or an exporter restart (#2609). Read
	// e.seq under e.mu WITHOUT incrementing it (no data records are sent).
	e.mu.Lock()
	seq := e.seq
	e.mu.Unlock()

	now := time.Now()
	hdr := ipfixHeader{
		Version:        10,
		Length:         uint16(16 + len(e.templateSet)),
		ExportTime:     uint32(now.Unix()),
		SequenceNumber: seq,
		ObservationID:  e.sourceID,
	}

	pkt := make([]byte, 16+len(e.templateSet))
	encodeIPFIXHeaderInto(pkt[:16], hdr)
	copy(pkt[16:], e.templateSet)
	e.conns.writeAll(pkt, "ipfix template send failed")
}

func (e *IPFIXExporter) flushBatches() {
	v4, v6 := e.batch.drain()

	if len(v4) > 0 {
		e.sendRecords(v4)
	}
	if len(v6) > 0 {
		e.sendRecords(v6)
	}
}

func (e *IPFIXExporter) sendRecords(records []FlowRecord) {
	if len(records) == 0 {
		return
	}

	isV6 := records[0].IsIPv6
	var (
		recSize int
		tmplID  uint16
	)
	if isV6 {
		recSize = ipfixRecordSizeV6
		tmplID = ipfixTemplateIDv6
	} else {
		recSize = ipfixRecordSizeV4
		tmplID = ipfixTemplateIDv4
	}

	// Reserve 16 bytes for IPFIX header + 4 bytes for set header
	maxRecords := (maxPayload - 16 - 4) / recSize
	if maxRecords < 1 {
		maxRecords = 1
	}

	for i := 0; i < len(records); i += maxRecords {
		end := i + maxRecords
		if end > len(records) {
			end = len(records)
		}
		batch := records[i:end]
		dataLen := ipfixDataSetLen(len(batch), recSize)

		e.mu.Lock()
		seq := e.seq
		e.seq += uint32(len(batch))
		e.mu.Unlock()

		now := time.Now()
		hdr := ipfixHeader{
			Version:        10,
			Length:         uint16(16 + dataLen),
			ExportTime:     uint32(now.Unix()),
			SequenceNumber: seq,
			ObservationID:  e.sourceID,
		}

		pkt := make([]byte, 16+dataLen)
		encodeIPFIXHeaderInto(pkt[:16], hdr)
		encodeIPFIXDataSetInto(pkt[16:], batch, tmplID, recSize)
		e.conns.writeAll(pkt, "ipfix data send failed")

		e.exportedFlows.Add(uint64(len(batch)))
		e.exportedPkts.Add(1)
	}
}
