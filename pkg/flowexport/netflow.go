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

// NetFlow v9 field type IDs (RFC 3954).
const (
	fieldInBytes       = 1
	fieldInPkts        = 2
	fieldProtocol      = 4
	fieldSrcTos        = 5
	fieldTCPFlags      = 6
	fieldL4SrcPort     = 7
	fieldIPv4SrcAddr   = 8
	fieldSrcMask       = 9
	fieldInputSNMP     = 10
	fieldL4DstPort     = 11
	fieldIPv4DstAddr   = 12
	fieldDstMask       = 13
	fieldOutputSNMP    = 14
	fieldLastSwitched  = 21
	fieldFirstSwitched = 22
	fieldIPv6SrcAddr   = 27
	fieldIPv6DstAddr   = 28
	fieldIPv6SrcMask   = 29
	fieldIPv6DstMask   = 30
	fieldDirection     = 61
	fieldIPv4Ident     = 54
	// RFC 5103 / RFC 8158 post-NAT (translated) tuple. NetFlow v9 templates
	// carry the same IANA element type IDs as IPFIX (#2526). IPv4 addresses
	// 225/226 (4B), transport ports 227/228 (2B, family-agnostic), IPv6
	// addresses 281/282 (16B).
	fieldPostNatSrcIPv4   = 225
	fieldPostNatDstIPv4   = 226
	fieldPostNapatSrcPort = 227
	fieldPostNapatDstPort = 228
	fieldPostNatSrcIPv6   = 281
	fieldPostNatDstIPv6   = 282
)

// Template IDs for IPv4 and IPv6.
const (
	templateIDv4 = 256
	templateIDv6 = 257
)

// flowsetIDTemplate is the FlowSet ID for template records.
const flowsetIDTemplate = 0

// Maximum UDP payload size for NetFlow packets.
const maxPayload = 1400

// templateField describes a single field in a v9 template.
type templateField struct {
	fieldType uint16
	fieldLen  uint16
}

// V9TemplateOptions controls which optional fields are included in v9 templates.
type V9TemplateOptions struct {
	IncludeFlowDir bool // include fieldDirection (export-extension flow-dir)
}

var (
	netflowTemplateFieldsV4 = []templateField{
		{fieldIPv4SrcAddr, 4},
		{fieldIPv4DstAddr, 4},
		{fieldL4SrcPort, 2},
		{fieldL4DstPort, 2},
		{fieldProtocol, 1},
		{fieldSrcTos, 1},
		{fieldTCPFlags, 1},
		{fieldDirection, 1},
		{fieldInputSNMP, 4},
		{fieldOutputSNMP, 4},
		{fieldInPkts, 8},
		{fieldInBytes, 8},
		{fieldFirstSwitched, 4},
		{fieldLastSwitched, 4},
		{fieldSrcMask, 1},
		{fieldDstMask, 1},
		// #2526: post-NAT (translated) tuple, appended last.
		{fieldPostNatSrcIPv4, 4},
		{fieldPostNatDstIPv4, 4},
		{fieldPostNapatSrcPort, 2},
		{fieldPostNapatDstPort, 2},
	}
	netflowTemplateFieldsV4NoDir = []templateField{
		{fieldIPv4SrcAddr, 4},
		{fieldIPv4DstAddr, 4},
		{fieldL4SrcPort, 2},
		{fieldL4DstPort, 2},
		{fieldProtocol, 1},
		{fieldSrcTos, 1},
		{fieldTCPFlags, 1},
		{fieldInputSNMP, 4},
		{fieldOutputSNMP, 4},
		{fieldInPkts, 8},
		{fieldInBytes, 8},
		{fieldFirstSwitched, 4},
		{fieldLastSwitched, 4},
		{fieldSrcMask, 1},
		{fieldDstMask, 1},
		// #2526: post-NAT (translated) tuple, appended last.
		{fieldPostNatSrcIPv4, 4},
		{fieldPostNatDstIPv4, 4},
		{fieldPostNapatSrcPort, 2},
		{fieldPostNapatDstPort, 2},
	}
	netflowTemplateFieldsV6 = []templateField{
		{fieldIPv6SrcAddr, 16},
		{fieldIPv6DstAddr, 16},
		{fieldL4SrcPort, 2},
		{fieldL4DstPort, 2},
		{fieldProtocol, 1},
		{fieldSrcTos, 1},
		{fieldTCPFlags, 1},
		{fieldDirection, 1},
		{fieldInputSNMP, 4},
		{fieldOutputSNMP, 4},
		{fieldInPkts, 8},
		{fieldInBytes, 8},
		{fieldFirstSwitched, 4},
		{fieldLastSwitched, 4},
		{fieldIPv6SrcMask, 1},
		{fieldIPv6DstMask, 1},
		// #2526: post-NAT (translated) tuple, appended last (v6 addrs 16B).
		{fieldPostNatSrcIPv6, 16},
		{fieldPostNatDstIPv6, 16},
		{fieldPostNapatSrcPort, 2},
		{fieldPostNapatDstPort, 2},
	}
	netflowTemplateFieldsV6NoDir = []templateField{
		{fieldIPv6SrcAddr, 16},
		{fieldIPv6DstAddr, 16},
		{fieldL4SrcPort, 2},
		{fieldL4DstPort, 2},
		{fieldProtocol, 1},
		{fieldSrcTos, 1},
		{fieldTCPFlags, 1},
		{fieldInputSNMP, 4},
		{fieldOutputSNMP, 4},
		{fieldInPkts, 8},
		{fieldInBytes, 8},
		{fieldFirstSwitched, 4},
		{fieldLastSwitched, 4},
		{fieldIPv6SrcMask, 1},
		{fieldIPv6DstMask, 1},
		// #2526: post-NAT (translated) tuple, appended last (v6 addrs 16B).
		{fieldPostNatSrcIPv6, 16},
		{fieldPostNatDstIPv6, 16},
		{fieldPostNapatSrcPort, 2},
		{fieldPostNapatDstPort, 2},
	}
)

// DefaultV9TemplateOptions returns options with all extensions enabled (backward compat).
func DefaultV9TemplateOptions() V9TemplateOptions {
	return V9TemplateOptions{IncludeFlowDir: true}
}

// buildTemplateFieldsV4 returns the IPv4 template fields based on options.
func buildTemplateFieldsV4(opts V9TemplateOptions) []templateField {
	if opts.IncludeFlowDir {
		return netflowTemplateFieldsV4
	}
	return netflowTemplateFieldsV4NoDir
}

// buildTemplateFieldsV6 returns the IPv6 template fields based on options.
func buildTemplateFieldsV6(opts V9TemplateOptions) []templateField {
	if opts.IncludeFlowDir {
		return netflowTemplateFieldsV6
	}
	return netflowTemplateFieldsV6NoDir
}

// recordSize computes the data record size from template fields, padded to 4 bytes.
func recordSize(fields []templateField) int {
	size := 0
	for _, f := range fields {
		size += int(f.fieldLen)
	}
	// Pad to 4-byte boundary
	pad := (4 - size%4) % 4
	return size + pad
}

// nfHeader is the 20-byte NetFlow v9 packet header.
type nfHeader struct {
	Version   uint16
	Count     uint16
	SysUptime uint32 // milliseconds since boot
	UnixSecs  uint32
	SeqNumber uint32
	SourceID  uint32
}

func encodeHeaderInto(b []byte, h nfHeader) {
	binary.BigEndian.PutUint16(b[0:2], h.Version)
	binary.BigEndian.PutUint16(b[2:4], h.Count)
	binary.BigEndian.PutUint32(b[4:8], h.SysUptime)
	binary.BigEndian.PutUint32(b[8:12], h.UnixSecs)
	binary.BigEndian.PutUint32(b[12:16], h.SeqNumber)
	binary.BigEndian.PutUint32(b[16:20], h.SourceID)
}

func encodeHeader(h nfHeader) []byte {
	b := make([]byte, 20)
	encodeHeaderInto(b, h)
	return b
}

// encodeTemplateFlowSet builds a template FlowSet containing both v4 and v6 templates.
func encodeTemplateFlowSet(opts V9TemplateOptions) []byte {
	v4fields := buildTemplateFieldsV4(opts)
	v6fields := buildTemplateFieldsV6(opts)

	// FlowSet header (4 bytes) + 2 template headers (4 each) + field entries
	totalLen := 4 + (4 + len(v4fields)*4) + (4 + len(v6fields)*4)

	b := make([]byte, totalLen)
	off := 0

	// FlowSet header: ID=0 (template), Length
	binary.BigEndian.PutUint16(b[off:off+2], flowsetIDTemplate)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(totalLen))
	off += 4

	// IPv4 template
	binary.BigEndian.PutUint16(b[off:off+2], templateIDv4)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(len(v4fields)))
	off += 4
	for _, f := range v4fields {
		binary.BigEndian.PutUint16(b[off:off+2], f.fieldType)
		binary.BigEndian.PutUint16(b[off+2:off+4], f.fieldLen)
		off += 4
	}

	// IPv6 template
	binary.BigEndian.PutUint16(b[off:off+2], templateIDv6)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(len(v6fields)))
	off += 4
	for _, f := range v6fields {
		binary.BigEndian.PutUint16(b[off:off+2], f.fieldType)
		binary.BigEndian.PutUint16(b[off+2:off+4], f.fieldLen)
		off += 4
	}

	return b
}

// encodeDataFlowSet builds a data FlowSet from a batch of records.
// All records in a batch must be the same AF (v4 or v6).
func encodeDataFlowSet(records []FlowRecord, bootTime time.Time, opts V9TemplateOptions) []byte {
	if len(records) == 0 {
		return nil
	}
	tmplID, fields, recSize := netflowTemplateConfig(records[0].IsIPv6, opts)
	totalLen := dataFlowSetLen(len(records), recSize)
	b := make([]byte, totalLen)
	encodeDataFlowSetInto(b, records, bootTime, tmplID, fields, recSize)
	return b
}

func netflowTemplateConfig(isV6 bool, opts V9TemplateOptions) (uint16, []templateField, int) {
	if isV6 {
		fields := buildTemplateFieldsV6(opts)
		return templateIDv6, fields, recordSize(fields)
	}
	fields := buildTemplateFieldsV4(opts)
	return templateIDv4, fields, recordSize(fields)
}

func dataFlowSetLen(recordCount, recSize int) int {
	totalLen := 4 + recordCount*recSize
	pad := (4 - totalLen%4) % 4
	return totalLen + pad
}

func encodeDataFlowSetInto(b []byte, records []FlowRecord, bootTime time.Time,
	tmplID uint16, fields []templateField, recSize int,
) {
	if len(records) == 0 {
		return
	}
	totalLen := dataFlowSetLen(len(records), recSize)
	binary.BigEndian.PutUint16(b[0:2], tmplID)
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	off := 4
	isV6 := records[0].IsIPv6
	includeFlowDir := fieldSetIncludesFlowDir(fields)
	for _, r := range records {
		if isV6 {
			off = encodeRecordV6(b, off, r, bootTime,
				includeFlowDir, recSize)
		} else {
			off = encodeRecordV4(b, off, r, bootTime,
				includeFlowDir, recSize)
		}
	}
	clear(b[off:totalLen])
}

func fieldSetIncludesFlowDir(fields []templateField) bool {
	for _, f := range fields {
		if f.fieldType == fieldDirection {
			return true
		}
	}
	return false
}

func encodeRecordV4(b []byte, off int, r FlowRecord, bootTime time.Time,
	includeFlowDir bool, recSize int,
) int {
	startOff := off
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
	b[off] = r.TCPFlags
	off++
	if includeFlowDir {
		b[off] = r.Direction
		off++
	}
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	binary.BigEndian.PutUint64(b[off:off+8], r.Packets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.Bytes)
	off += 8
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.StartTime))
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.EndTime))
	off += 4
	b[off] = r.SrcMask
	off++
	b[off] = r.DstMask
	off++
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
	return startOff + recSize
}

func encodeRecordV6(b []byte, off int, r FlowRecord, bootTime time.Time,
	includeFlowDir bool, recSize int,
) int {
	startOff := off
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
	b[off] = r.TCPFlags
	off++
	if includeFlowDir {
		b[off] = r.Direction
		off++
	}
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	binary.BigEndian.PutUint64(b[off:off+8], r.Packets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.Bytes)
	off += 8
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.StartTime))
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.EndTime))
	off += 4
	b[off] = r.SrcMask
	off++
	b[off] = r.DstMask
	off++
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
	return startOff + recSize
}

func uptimeMs(boot, t time.Time) uint32 {
	d := t.Sub(boot)
	if d < 0 {
		return 0
	}
	return uint32(d.Milliseconds())
}

// Exporter sends NetFlow v9 packets to configured collectors.
type Exporter struct {
	cfg             *ExportConfig
	bootTime        time.Time
	sourceID        uint32
	fieldsV4        []templateField
	fieldsV6        []templateField
	recSizeV4       int
	recSizeV6       int
	templateFlowSet []byte

	mu    sync.Mutex
	seq   uint32
	conns *collectorConns

	// Batching: accumulate records, flush periodically
	batch flowBatch

	// Stats
	exportedFlows atomic.Uint64
	exportedPkts  atomic.Uint64
	// #2465: count of session-close flows whose StartTime fell back to the
	// packet-count heuristic because the close event carried no real
	// session-creation timestamp (rec.Created == 0). A high value relative to
	// exportedFlows means most flows are still being timed by the old guess —
	// operator-visible signal that the dataplane is not stamping creation
	// times (e.g. all closes arriving via the explicit-delete / HA-purge path).
	estimatedDurations atomic.Uint64
}

// NewExporter creates a new NetFlow v9 exporter. cfg is held by pointer
// (never copied) because ExportConfig embeds the live 1-in-N
// sampleCounter (atomic.Uint64); copying it would fork the counter and
// silently re-seed the sampling cadence (#2224). The caller (the daemon
// reconcile path) shares the same *ExportConfig with the session-close
// callback so there is exactly one counter per exporter.
func NewExporter(cfg *ExportConfig) (*Exporter, error) {
	e := &Exporter{
		cfg:      cfg,
		bootTime: time.Now(),
		sourceID: 1,
		fieldsV4: buildTemplateFieldsV4(cfg.V9TemplateOpts),
		fieldsV6: buildTemplateFieldsV6(cfg.V9TemplateOpts),
	}
	e.recSizeV4 = recordSize(e.fieldsV4)
	e.recSizeV6 = recordSize(e.fieldsV6)
	e.templateFlowSet = encodeTemplateFlowSet(cfg.V9TemplateOpts)

	conns, err := dialCollectors(cfg.Collectors)
	if err != nil {
		return nil, err
	}
	e.conns = conns

	return e, nil
}

// Run starts the exporter's background goroutines. Blocks until ctx is cancelled.
func (e *Exporter) Run(ctx context.Context) {
	// Send initial template
	e.sendTemplates()

	templateTicker := time.NewTicker(e.cfg.TemplateRefreshRate)
	defer templateTicker.Stop()

	batchTicker := time.NewTicker(100 * time.Millisecond)
	defer batchTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining batches
			e.flushBatches()
			return
		case <-templateTicker.C:
			e.sendTemplates()
		case <-batchTicker.C:
			e.flushBatches()
		}
	}
}

// ExportSessionClose converts a session-close event into a flow record and queues it.
func (e *Exporter) ExportSessionClose(rec logging.EventRecord, evt SessionCloseData) {
	// #2465: use the real session-creation timestamp for StartTime when the
	// close event carries one; fall back to the packet-count heuristic only
	// when it is absent (and count that for operator visibility).
	startTime, usedEstimate := flowStartTime(rec, evt.Protocol)
	if usedEstimate {
		e.estimatedDurations.Add(1)
	}
	// #2526: resolve the post-NAT tuple with pre-NAT fallback so every
	// exported record carries the RFC 5103 post-NAT fields (post == pre when
	// the flow was not translated).
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

// EstimatedDurations returns the count of exported session-close flows whose
// StartTime was derived from the packet-count heuristic (#2465) rather than a
// real session-creation timestamp.
func (e *Exporter) EstimatedDurations() uint64 {
	return e.estimatedDurations.Load()
}

// Stats returns export statistics.
func (e *Exporter) Stats() (flows, packets uint64) {
	return e.exportedFlows.Load(), e.exportedPkts.Load()
}

// CollectorHealth returns a per-collector write-health snapshot (#2464):
// write attempts/failures, last error and the last success/failure
// timestamps for every collector this exporter writes to.
func (e *Exporter) CollectorHealth() []CollectorHealth {
	return e.conns.health()
}

// Close shuts down all collector connections.
func (e *Exporter) Close() {
	e.conns.close()
}

func (e *Exporter) sendTemplates() {
	e.mu.Lock()
	seq := e.seq
	e.seq++
	e.mu.Unlock()

	now := time.Now()
	hdr := nfHeader{
		Version:   9,
		Count:     2, // 2 templates
		SysUptime: uptimeMs(e.bootTime, now),
		UnixSecs:  uint32(now.Unix()),
		SeqNumber: seq,
		SourceID:  e.sourceID,
	}

	pkt := make([]byte, 20+len(e.templateFlowSet))
	encodeHeaderInto(pkt[:20], hdr)
	copy(pkt[20:], e.templateFlowSet)
	e.conns.writeAll(pkt, "netflow template send failed")
}

func (e *Exporter) flushBatches() {
	v4, v6 := e.batch.drain()

	if len(v4) > 0 {
		e.sendRecords(v4)
	}
	if len(v6) > 0 {
		e.sendRecords(v6)
	}
}

func (e *Exporter) sendRecords(records []FlowRecord) {
	if len(records) == 0 {
		return
	}

	isV6 := records[0].IsIPv6
	var (
		fields  []templateField
		recSize int
		tmplID  uint16
	)
	if isV6 {
		fields = e.fieldsV6
		recSize = e.recSizeV6
		tmplID = templateIDv6
	} else {
		fields = e.fieldsV4
		recSize = e.recSizeV4
		tmplID = templateIDv4
	}

	// Split into chunks that fit in maxPayload
	// Reserve 20 bytes for header + 4 bytes for flowset header
	maxRecords := (maxPayload - 20 - 4) / recSize
	if maxRecords < 1 {
		maxRecords = 1
	}

	for i := 0; i < len(records); i += maxRecords {
		end := i + maxRecords
		if end > len(records) {
			end = len(records)
		}
		batch := records[i:end]
		dataLen := dataFlowSetLen(len(batch), recSize)

		e.mu.Lock()
		seq := e.seq
		e.seq++
		e.mu.Unlock()

		now := time.Now()
		hdr := nfHeader{
			Version:   9,
			Count:     uint16(len(batch)),
			SysUptime: uptimeMs(e.bootTime, now),
			UnixSecs:  uint32(now.Unix()),
			SeqNumber: seq,
			SourceID:  e.sourceID,
		}

		pkt := make([]byte, 20+dataLen)
		encodeHeaderInto(pkt[:20], hdr)
		encodeDataFlowSetInto(pkt[20:], batch, e.bootTime,
			tmplID, fields, recSize)
		e.conns.writeAll(pkt, "netflow data send failed")

		e.exportedFlows.Add(uint64(len(batch)))
		e.exportedPkts.Add(1)
	}
}
