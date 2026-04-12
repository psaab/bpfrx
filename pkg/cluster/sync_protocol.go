package cluster

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/psaab/bpfrx/pkg/dataplane"
	"golang.org/x/sys/unix"
)

// monotonicSeconds returns the monotonic clock in seconds.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
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
	buf := make([]byte, keySize+valSize)
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
	return buf[:off]
}
func encodeDeleteV4(key dataplane.SessionKey) []byte {
	hdr := make([]byte, syncHeaderSize+16)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgDeleteV4
	binary.LittleEndian.PutUint32(hdr[8:12], 16)
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
	return hdr
}
func encodeDeleteV6(key dataplane.SessionKeyV6) []byte {
	hdr := make([]byte, syncHeaderSize+40)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgDeleteV6
	binary.LittleEndian.PutUint32(hdr[8:12], 40)
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
