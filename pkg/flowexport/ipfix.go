// Package flowexport implements IPFIX (RFC 7011 / NetFlow v10) flow data export.
package flowexport

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/logging"
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
}

// ipfixRecordSizeV4 is the byte size of a single IPv4 IPFIX data record.
// 4+4+2+2+1+1+2+1+4+4+8+8+8+8 = 57
const ipfixRecordSizeV4 = 57

// ipfixRecordSizeV6 is the byte size of a single IPv6 IPFIX data record.
// 16+16+2+2+1+1+2+1+4+4+8+8+8+8 = 81
const ipfixRecordSizeV6 = 81

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
	return off
}

// IPFIXExporter sends IPFIX (NetFlow v10) messages to configured collectors.
type IPFIXExporter struct {
	cfg         ExportConfig
	sourceID    uint32
	templateSet []byte

	mu    sync.Mutex
	seq   uint32 // cumulative data record count
	conns []net.Conn

	batchMu sync.Mutex
	batchV4 []FlowRecord
	batchV6 []FlowRecord

	exportedFlows atomic.Uint64
	exportedPkts  atomic.Uint64
}

// NewIPFIXExporter creates a new IPFIX exporter.
func NewIPFIXExporter(cfg ExportConfig) (*IPFIXExporter, error) {
	e := &IPFIXExporter{
		cfg:         cfg,
		sourceID:    1,
		templateSet: encodeIPFIXTemplateSet(),
	}

	for _, cc := range cfg.Collectors {
		var conn net.Conn
		var err error
		if cc.SourceAddress != "" {
			laddr, _ := net.ResolveUDPAddr("udp", cc.SourceAddress+":0")
			raddr, err2 := net.ResolveUDPAddr("udp", cc.Address)
			if err2 != nil {
				return nil, fmt.Errorf("resolve collector %s: %w", cc.Address, err2)
			}
			conn, err = net.DialUDP("udp", laddr, raddr)
		} else {
			conn, err = net.Dial("udp", cc.Address)
		}
		if err != nil {
			for _, c := range e.conns {
				c.Close()
			}
			return nil, fmt.Errorf("dial collector %s: %w", cc.Address, err)
		}
		e.conns = append(e.conns, conn)
	}

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
	fr := FlowRecord{
		SrcIP:     evt.SrcIP,
		DstIP:     evt.DstIP,
		SrcPort:   evt.SrcPort,
		DstPort:   evt.DstPort,
		Protocol:  evt.Protocol,
		Packets:   rec.SessionPkts,
		Bytes:     rec.SessionBytes,
		StartTime: rec.Time.Add(-estimateSessionDuration(rec.SessionPkts, evt.Protocol)),
		EndTime:   rec.Time,
		IsIPv6:    evt.IsIPv6,
	}

	e.batchMu.Lock()
	if fr.IsIPv6 {
		e.batchV6 = append(e.batchV6, fr)
	} else {
		e.batchV4 = append(e.batchV4, fr)
	}
	e.batchMu.Unlock()
}

// Stats returns export statistics.
func (e *IPFIXExporter) Stats() (flows, packets uint64) {
	return e.exportedFlows.Load(), e.exportedPkts.Load()
}

// Close shuts down all collector connections.
func (e *IPFIXExporter) Close() {
	for _, c := range e.conns {
		c.Close()
	}
}

func (e *IPFIXExporter) sendTemplates() {
	now := time.Now()
	hdr := ipfixHeader{
		Version:        10,
		Length:         uint16(16 + len(e.templateSet)),
		ExportTime:     uint32(now.Unix()),
		SequenceNumber: 0, // template-only messages use seq=0 per convention
		ObservationID:  e.sourceID,
	}

	pkt := make([]byte, 16+len(e.templateSet))
	encodeIPFIXHeaderInto(pkt[:16], hdr)
	copy(pkt[16:], e.templateSet)
	for _, c := range e.conns {
		if _, err := c.Write(pkt); err != nil {
			slog.Debug("ipfix template send failed", "err", err)
		}
	}
}

func (e *IPFIXExporter) flushBatches() {
	e.batchMu.Lock()
	v4 := e.batchV4
	v6 := e.batchV6
	e.batchV4 = nil
	e.batchV6 = nil
	e.batchMu.Unlock()

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
		for _, c := range e.conns {
			if _, err := c.Write(pkt); err != nil {
				slog.Debug("ipfix data send failed", "err", err)
			}
		}

		e.exportedFlows.Add(uint64(len(batch)))
		e.exportedPkts.Add(1)
	}
}

// BuildIPFIXExportConfig resolves IPFIX config into an ExportConfig.
// Falls back to v9 collectors/sampling if no IPFIX-specific overrides.
func BuildIPFIXExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig {
	if fo == nil || fo.Sampling == nil || len(fo.Sampling.Instances) == 0 {
		return nil
	}
	if svc == nil || svc.FlowMonitoring == nil || svc.FlowMonitoring.VersionIPFIX == nil {
		return nil
	}

	activeTimeout := 60 * time.Second
	inactiveTimeout := 15 * time.Second
	refreshRate := 60 * time.Second

	for _, tmpl := range svc.FlowMonitoring.VersionIPFIX.Templates {
		if tmpl.FlowActiveTimeout > 0 {
			activeTimeout = time.Duration(tmpl.FlowActiveTimeout) * time.Second
		}
		if tmpl.FlowInactiveTimeout > 0 {
			inactiveTimeout = time.Duration(tmpl.FlowInactiveTimeout) * time.Second
		}
		if tmpl.TemplateRefreshRate > 0 {
			refreshRate = time.Duration(tmpl.TemplateRefreshRate) * time.Second
		}
		break // use first template
	}

	ec := &ExportConfig{
		FlowActiveTimeout:   activeTimeout,
		FlowInactiveTimeout: inactiveTimeout,
		TemplateRefreshRate: refreshRate,
	}

	// Reuse same sampling rate + collectors as v9 (shared forwarding-options)
	for _, inst := range fo.Sampling.Instances {
		if inst.InputRate > 0 {
			ec.SamplingRate = inst.InputRate
			break
		}
	}

	for _, inst := range fo.Sampling.Instances {
		families := []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6}
		for _, fam := range families {
			if fam == nil {
				continue
			}
			for _, fs := range fam.FlowServers {
				addr := fs.Address
				if fs.Port > 0 {
					addr = fmt.Sprintf("%s:%d", fs.Address, fs.Port)
				}
				srcAddr := fam.SourceAddress
				if srcAddr == "" {
					srcAddr = fam.InlineJflowSourceAddress
				}
				ec.Collectors = append(ec.Collectors, CollectorConfig{
					Address:       addr,
					SourceAddress: srcAddr,
				})
			}
		}
	}

	if len(ec.Collectors) == 0 {
		return nil
	}

	// Deduplicate collectors
	seen := make(map[string]bool)
	deduped := ec.Collectors[:0]
	for _, c := range ec.Collectors {
		key := collectorKey(c)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, c)
		}
	}
	ec.Collectors = deduped

	return ec
}
