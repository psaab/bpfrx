package cluster

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"golang.org/x/sys/unix"
)

// monotonicSeconds returns the monotonic clock in seconds.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

// MonotonicNanos returns the monotonic clock (CLOCK_MONOTONIC) in
// nanoseconds. Liveness timestamps must be stored and compared in this
// domain instead of time.Now().UnixNano(): round-tripping wall-clock
// nanos through time.Unix(0, n) strips Go's monotonic reading, so every
// age computed from the stored value moves with wall-clock steps (NTP
// makestep, manual date -s, VM pause/resume) — a forward step larger
// than the heartbeat timeout falsely declares the peer lost (#1792).
// Exported because pkg/daemon's heartbeat suppression guard lives in
// the same liveness domain.
func MonotonicNanos() int64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano()
}

// rebaseTimestamp adjusts a peer timestamp to the local monotonic clock domain.
func rebaseTimestamp(peerTS uint64, offset int64) uint64 {
	v := int64(peerTS) + offset
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// writeFull loops until all bytes are written or an error occurs, handling
// short writes from TCP backpressure.
func writeFull(conn net.Conn, buf []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(syncWriteDeadline)); err != nil {
		return err
	}
	defer conn.SetWriteDeadline(time.Time{})
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}
func writeMsg(conn net.Conn, msgType uint8, payload []byte) error {
	buf := make([]byte, syncHeaderSize+len(payload))
	copy(buf[:4], syncMagic[:])
	buf[4] = msgType
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(payload)))
	copy(buf[syncHeaderSize:], payload)
	return writeFull(conn, buf)
}
func encodeSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) []byte {
	payload := encodeSessionV4Payload(key, val)
	return encodeRawMessage(syncMsgSessionV4, payload)
}
func encodeRawMessage(msgType uint8, payload []byte) []byte {
	hdr := make([]byte, syncHeaderSize)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = msgType
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	return append(hdr, payload...)
}
func encodeSessionV4Payload(key dataplane.SessionKey, val dataplane.SessionValue) []byte {
	keySize := 16
	valSize := 160
	// +8 for the #2170 install Generation, +8 for the #3301 trailing
	// AppTimeout(u32)+PolicyCounterIdx(u32). All length-gated: an old decoder
	// stops after the field it knows and ignores the rest.
	buf := make([]byte, keySize+valSize+8+8)
	off := 0
	copy(buf[off:], key.SrcIP[:])
	off += 4
	copy(buf[off:], key.DstIP[:])
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], key.DstPort)
	off += 2
	buf[off] = key.Protocol
	off += 4
	buf[off] = val.State
	off++
	buf[off] = val.Flags
	off++
	buf[off] = val.TCPState
	off++
	buf[off] = val.IsReverse
	off += 5
	binary.LittleEndian.PutUint64(buf[off:], val.SessionID)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.Created)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.LastSeen)
	off += 8
	binary.LittleEndian.PutUint32(buf[off:], val.Timeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyID)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.IngressZone)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.EgressZone)
	off += 2
	binary.LittleEndian.PutUint32(buf[off:], val.NATSrcIP)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.NATDstIP)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.NATSrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.NATDstPort)
	off += 2
	binary.LittleEndian.PutUint64(buf[off:], val.FwdPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.FwdBytes)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevBytes)
	off += 8
	copy(buf[off:], val.ReverseKey.SrcIP[:])
	off += 4
	copy(buf[off:], val.ReverseKey.DstIP[:])
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.DstPort)
	off += 2
	buf[off] = val.ReverseKey.Protocol
	off += 4
	buf[off] = val.ALGType
	off++
	buf[off] = val.LogFlags
	off += 3
	binary.LittleEndian.PutUint32(buf[off:], val.FibIfindex)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.FibVlanID)
	off += 2
	copy(buf[off:], val.FibDmac[:])
	off += 6
	copy(buf[off:], val.FibSmac[:])
	off += 6
	binary.LittleEndian.PutUint16(buf[off:], val.FibGen)
	off += 2
	// #2170: install generation (length-gated trailing field).
	binary.LittleEndian.PutUint64(buf[off:], val.Generation)
	off += 8
	// #3301: per-application idle timeout (seconds) + per-rule hit-counter
	// handle (length-gated trailing fields). Old decoders stop after the
	// generation and ignore these; absent => 0 (global timeout / no counter).
	binary.LittleEndian.PutUint32(buf[off:], val.AppTimeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyCounterIdx)
	off += 4
	return buf[:off]
}
func encodeSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) []byte {
	payload := encodeSessionV6Payload(key, val)
	hdr := make([]byte, syncHeaderSize)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgSessionV6
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	return append(hdr, payload...)
}
func encodeSessionV6Payload(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) []byte {
	buf := make([]byte, 512)
	off := 0
	copy(buf[off:], key.SrcIP[:])
	off += 16
	copy(buf[off:], key.DstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(buf[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], key.DstPort)
	off += 2
	buf[off] = key.Protocol
	off += 4
	buf[off] = val.State
	off++
	buf[off] = val.Flags
	off++
	buf[off] = val.TCPState
	off++
	buf[off] = val.IsReverse
	off += 5
	binary.LittleEndian.PutUint64(buf[off:], val.SessionID)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.Created)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.LastSeen)
	off += 8
	binary.LittleEndian.PutUint32(buf[off:], val.Timeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyID)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.IngressZone)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.EgressZone)
	off += 2
	copy(buf[off:], val.NATSrcIP[:])
	off += 16
	copy(buf[off:], val.NATDstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(buf[off:], val.NATSrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.NATDstPort)
	off += 2
	binary.LittleEndian.PutUint64(buf[off:], val.FwdPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.FwdBytes)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevBytes)
	off += 8
	copy(buf[off:], val.ReverseKey.SrcIP[:])
	off += 16
	copy(buf[off:], val.ReverseKey.DstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.DstPort)
	off += 2
	buf[off] = val.ReverseKey.Protocol
	off += 4
	buf[off] = val.ALGType
	off++
	buf[off] = val.LogFlags
	off += 3
	binary.LittleEndian.PutUint32(buf[off:], val.FibIfindex)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.FibVlanID)
	off += 2
	copy(buf[off:], val.FibDmac[:])
	off += 6
	copy(buf[off:], val.FibSmac[:])
	off += 6
	binary.LittleEndian.PutUint16(buf[off:], val.FibGen)
	off += 2
	// #2170: install generation (length-gated trailing field).
	binary.LittleEndian.PutUint64(buf[off:], val.Generation)
	off += 8
	// #3301: per-application idle timeout + per-rule hit-counter handle
	// (length-gated trailing fields; see encodeSessionV4Payload).
	binary.LittleEndian.PutUint32(buf[off:], val.AppTimeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyCounterIdx)
	off += 4
	return buf[:off]
}

// encodeDeleteV4 emits a delete message for a v4 session key. The 16-byte
// 5-tuple payload grows to 24 bytes with a length-gated trailing #2170
// install Generation: an old decoder reads only the first 16 bytes (its
// `len(payload) >= 16` check tolerates the longer payload) and ignores the
// generation; a new decoder reads the trailing uint64 when present. A
// generation of 0 means "unknown / legacy" and the receiver falls back to
// today's unconditional delete.
func encodeDeleteV4(key dataplane.SessionKey, gen uint64) []byte {
	hdr := make([]byte, syncHeaderSize+24)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgDeleteV4
	binary.LittleEndian.PutUint32(hdr[8:12], 24)
	off := syncHeaderSize
	copy(hdr[off:], key.SrcIP[:])
	off += 4
	copy(hdr[off:], key.DstIP[:])
	off += 4
	binary.LittleEndian.PutUint16(hdr[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(hdr[off:], key.DstPort)
	off += 2
	hdr[off] = key.Protocol
	off += 4 // 5-tuple block is 16 bytes total (1 proto byte + 3 pad)
	binary.LittleEndian.PutUint64(hdr[off:], gen)
	return hdr
}
func encodeDeleteV6(key dataplane.SessionKeyV6, gen uint64) []byte {
	hdr := make([]byte, syncHeaderSize+48)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgDeleteV6
	binary.LittleEndian.PutUint32(hdr[8:12], 48)
	off := syncHeaderSize
	copy(hdr[off:], key.SrcIP[:])
	off += 16
	copy(hdr[off:], key.DstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(hdr[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(hdr[off:], key.DstPort)
	off += 2
	hdr[off] = key.Protocol
	off += 4 // 5-tuple block is 40 bytes total (1 proto byte + 3 pad)
	binary.LittleEndian.PutUint64(hdr[off:], gen)
	return hdr
}

// decodeSessionV4Payload decodes a v4 session from wire format. It returns the
// decoded key, value, and an ok flag. The layout must match encodeSessionV4Payload.
func decodeSessionV4Payload(payload []byte) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	var key dataplane.SessionKey
	var val dataplane.SessionValue
	if len(payload) < 16 {
		return key, val, false
	}
	off := 0
	copy(key.SrcIP[:], payload[off:off+4])
	off += 4
	copy(key.DstIP[:], payload[off:off+4])
	off += 4
	key.SrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.DstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.Protocol = payload[off]
	off += 4
	if off+8 > len(payload) {
		return key, val, false
	}
	val.State = payload[off]
	off++
	val.Flags = payload[off]
	off++
	val.TCPState = payload[off]
	off++
	val.IsReverse = payload[off]
	off += 5
	if off+48 > len(payload) {
		return key, val, true
	}
	val.SessionID = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Created = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.LastSeen = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Timeout = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.PolicyID = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.IngressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.EgressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.NATSrcIP = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.NATDstIP = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.NATSrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.NATDstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	if off+32 > len(payload) {
		return key, val, true
	}
	val.FwdPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.FwdBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	if off+16 <= len(payload) {
		copy(val.ReverseKey.SrcIP[:], payload[off:off+4])
		off += 4
		copy(val.ReverseKey.DstIP[:], payload[off:off+4])
		off += 4
		val.ReverseKey.SrcPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.DstPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.Protocol = payload[off]
		off += 4
	}
	if off+2 <= len(payload) {
		val.ALGType = payload[off]
		off++
		val.LogFlags = payload[off]
		off += 3
	}
	if off+20 <= len(payload) {
		val.FibIfindex = binary.LittleEndian.Uint32(payload[off:])
		off += 4
		val.FibVlanID = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		copy(val.FibDmac[:], payload[off:off+6])
		off += 6
		copy(val.FibSmac[:], payload[off:off+6])
		off += 6
		val.FibGen = binary.LittleEndian.Uint16(payload[off:])
		off += 2
	}
	// #2170: install generation (length-gated; absent → 0 = legacy peer).
	if off+8 <= len(payload) {
		val.Generation = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #3301: per-application idle timeout + per-rule hit-counter handle
	// (length-gated; absent → 0 = legacy peer / global timeout / no counter).
	if off+4 <= len(payload) {
		val.AppTimeout = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	if off+4 <= len(payload) {
		val.PolicyCounterIdx = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	return key, val, true
}

// decodeSessionV6Payload decodes a v6 session from wire format. It returns the
// decoded key, value, and an ok flag. The layout must match encodeSessionV6Payload.
func decodeSessionV6Payload(payload []byte) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	var key dataplane.SessionKeyV6
	var val dataplane.SessionValueV6
	if len(payload) < 40 {
		return key, val, false
	}
	off := 0
	copy(key.SrcIP[:], payload[off:off+16])
	off += 16
	copy(key.DstIP[:], payload[off:off+16])
	off += 16
	key.SrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.DstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.Protocol = payload[off]
	off += 4
	if off+8 > len(payload) {
		return key, val, false
	}
	val.State = payload[off]
	off++
	val.Flags = payload[off]
	off++
	val.TCPState = payload[off]
	off++
	val.IsReverse = payload[off]
	off += 5
	if off+48 > len(payload) {
		return key, val, true
	}
	val.SessionID = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Created = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.LastSeen = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Timeout = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.PolicyID = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.IngressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.EgressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	if off+36 > len(payload) {
		return key, val, true
	}
	copy(val.NATSrcIP[:], payload[off:off+16])
	off += 16
	copy(val.NATDstIP[:], payload[off:off+16])
	off += 16
	val.NATSrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.NATDstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	if off+32 > len(payload) {
		return key, val, true
	}
	val.FwdPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.FwdBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	if off+40 <= len(payload) {
		copy(val.ReverseKey.SrcIP[:], payload[off:off+16])
		off += 16
		copy(val.ReverseKey.DstIP[:], payload[off:off+16])
		off += 16
		val.ReverseKey.SrcPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.DstPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.Protocol = payload[off]
		off += 4
	}
	if off+2 <= len(payload) {
		val.ALGType = payload[off]
		off++
		val.LogFlags = payload[off]
		off += 3
	}
	if off+20 <= len(payload) {
		val.FibIfindex = binary.LittleEndian.Uint32(payload[off:])
		off += 4
		val.FibVlanID = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		copy(val.FibDmac[:], payload[off:off+6])
		off += 6
		copy(val.FibSmac[:], payload[off:off+6])
		off += 6
		val.FibGen = binary.LittleEndian.Uint16(payload[off:])
		off += 2
	}
	// #2170: install generation (length-gated; absent → 0 = legacy peer).
	if off+8 <= len(payload) {
		val.Generation = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #3301: per-application idle timeout + per-rule hit-counter handle
	// (length-gated; absent → 0 = legacy peer / global timeout / no counter).
	if off+4 <= len(payload) {
		val.AppTimeout = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	if off+4 <= len(payload) {
		val.PolicyCounterIdx = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	return key, val, true
}

// encodeIPsecSAPayload encodes a list of IPsec connection names as
// newline-separated bytes.
func encodeIPsecSAPayload(names []string) []byte {
	if len(names) == 0 {
		return nil
	}
	joined := ""
	for i, name := range names {
		if i > 0 {
			joined += "\n"
		}
		joined += name
	}
	return []byte(joined)
}

// decodeIPsecSAPayload decodes a newline-separated list of IPsec connection names.
func decodeIPsecSAPayload(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}
	parts := strings.Split(string(payload), "\n")
	var names []string
	for _, p := range parts {
		if p != "" {
			names = append(names, p)
		}
	}
	return names
}

// --- #2239 HA DHCP-server lease sync wire codec ---------------------------
//
// A DHCP-lease payload is a full-set push of the active leases this node serves
// for one family. The framing is a 4-byte lease COUNT followed by COUNT
// length-prefixed lease records. Each record is itself length-gated so the
// schema can grow: a decoder reads only the fields the inner length covers,
// tolerating a longer record from a newer peer (trailing fields ignored) and a
// shorter record from an older peer (absent fields default to zero) — the same
// length-gated-trailing-field discipline as #2170 sessions. The lease wire
// carries REMAINING LIFETIME (not absolute expiry) so the receiver re-anchors
// to its local clock at seed (the #2239 clock invariant).

// putLeaseString appends a uint16-length-prefixed string.
func putLeaseString(b []byte, s string) []byte {
	b = binary.LittleEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

// getLeaseString reads a uint16-length-prefixed string at off, returning the
// value, the new offset, and ok. ok is false if the buffer is too short
// (truncated record — caller stops decoding that record's remaining fields).
func getLeaseString(buf []byte, off int) (string, int, bool) {
	if off+2 > len(buf) {
		return "", off, false
	}
	n := int(binary.LittleEndian.Uint16(buf[off:]))
	off += 2
	if off+n > len(buf) {
		return "", off, false
	}
	return string(buf[off : off+n]), off + n, true
}

// encodeOneLease serializes one SyncLease into a self-describing record body
// (without the outer record-length prefix). Field order is fixed and append-
// only; decoders read what the record length covers.
func encodeOneLease(l dhcpserver.SyncLease) []byte {
	b := make([]byte, 0, 96)
	b = append(b, byte(l.Family))
	b = putLeaseString(b, l.Address)
	b = binary.LittleEndian.AppendUint32(b, uint32(l.SubnetID))
	b = binary.LittleEndian.AppendUint32(b, uint32(l.ValidLife))
	b = binary.LittleEndian.AppendUint32(b, uint32(l.Remaining))
	b = append(b, byte(l.State))
	// identity + naming (variable). v4: hwaddr, clientid. v6: duid, iaid,
	// leasetype, prefixlen. Both families carry all slots; the unused ones
	// are empty/zero so the record layout is family-uniform and append-only.
	b = putLeaseString(b, l.HWAddress)
	b = putLeaseString(b, l.ClientID)
	b = putLeaseString(b, l.DUID)
	b = binary.LittleEndian.AppendUint32(b, l.IAID)
	b = putLeaseString(b, l.LeaseType)
	b = binary.LittleEndian.AppendUint32(b, uint32(l.PrefixLen))
	b = putLeaseString(b, l.Hostname)
	var flags byte
	if l.FQDNFwd {
		flags |= 0x01
	}
	if l.FQDNRev {
		flags |= 0x02
	}
	b = append(b, flags)
	return b
}

// decodeOneLease parses a record body produced by encodeOneLease. It is
// length-gated: each field read checks bounds and stops at the first short
// read, so a legacy (shorter) record yields zero values for absent trailing
// fields and a future (longer) record's extra fields are ignored.
func decodeOneLease(buf []byte) dhcpserver.SyncLease {
	var l dhcpserver.SyncLease
	off := 0
	if off >= len(buf) {
		return l
	}
	l.Family = int(buf[off])
	off++
	var ok bool
	if l.Address, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if off+4 > len(buf) {
		return l
	}
	l.SubnetID = int(binary.LittleEndian.Uint32(buf[off:]))
	off += 4
	if off+4 > len(buf) {
		return l
	}
	l.ValidLife = int(binary.LittleEndian.Uint32(buf[off:]))
	off += 4
	if off+4 > len(buf) {
		return l
	}
	l.Remaining = int(binary.LittleEndian.Uint32(buf[off:]))
	off += 4
	if off >= len(buf) {
		return l
	}
	l.State = int(buf[off])
	off++
	if l.HWAddress, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if l.ClientID, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if l.DUID, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if off+4 > len(buf) {
		return l
	}
	l.IAID = binary.LittleEndian.Uint32(buf[off:])
	off += 4
	if l.LeaseType, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if off+4 > len(buf) {
		return l
	}
	l.PrefixLen = int(binary.LittleEndian.Uint32(buf[off:]))
	off += 4
	if l.Hostname, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if off < len(buf) {
		flags := buf[off]
		l.FQDNFwd = flags&0x01 != 0
		l.FQDNRev = flags&0x02 != 0
	}
	return l
}

// encodeDHCPLeasePayload serializes a full-set lease push: a 4-byte count
// followed by length-prefixed lease records. An empty set encodes as a 4-byte
// zero count (a legitimate "I serve no leases" message, distinct from a legacy
// peer that never sends this type at all).
func encodeDHCPLeasePayload(leases []dhcpserver.SyncLease) []byte {
	b := make([]byte, 0, 8+len(leases)*64)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(leases)))
	for _, l := range leases {
		rec := encodeOneLease(l)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(rec)))
		b = append(b, rec...)
	}
	return b
}

// decodeDHCPLeasePayload parses a full-set lease push. A truncated payload
// stops decoding at the last complete record (fail-safe: a partial message
// yields the leases that fully arrived rather than erroring the whole push).
func decodeDHCPLeasePayload(payload []byte) []dhcpserver.SyncLease {
	if len(payload) < 4 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(payload[:4]))
	off := 4
	// Clamp the preallocation to what the payload can physically hold: count
	// is untrusted on-wire data, and each record consumes at least its 4-byte
	// length prefix, so there can be at most len(payload)/4 records. Without
	// this, a corrupt/malicious frame claiming count=0xFFFFFFFF would attempt
	// a ~hundreds-of-GB make() (SyncLease is ~160 bytes) and panic before the
	// loop's truncation guard fires. Valid payloads are unaffected (a real
	// count is always <= len(payload)/4). Clamping count also bounds the loop.
	if maxRecords := len(payload) / 4; count > maxRecords {
		count = maxRecords
	}
	out := make([]dhcpserver.SyncLease, 0, count)
	for i := 0; i < count; i++ {
		if off+4 > len(payload) {
			break
		}
		recLen := int(binary.LittleEndian.Uint32(payload[off:]))
		off += 4
		if recLen < 0 || off+recLen > len(payload) {
			break
		}
		out = append(out, decodeOneLease(payload[off:off+recLen]))
		off += recLen
	}
	return out
}
