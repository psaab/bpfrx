// Package flowexport implements NetFlow v9 flow data export.
package flowexport

import (
	"encoding/binary"
	"net"
	"time"
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

// FlowRecord holds the data for a single NetFlow record.
type FlowRecord struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	TOS       uint8
	TCPFlags  uint8
	Direction uint8
	InIf      uint32
	OutIf     uint32
	Packets   uint64
	Bytes     uint64
	StartTime time.Time
	EndTime   time.Time
	SrcMask   uint8
	DstMask   uint8
	IsIPv6    bool
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
	return startOff + recSize
}

func uptimeMs(boot, t time.Time) uint32 {
	d := t.Sub(boot)
	if d < 0 {
		return 0
	}
	return uint32(d.Milliseconds())
}
