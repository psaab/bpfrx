package cluster

import (
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #8121: the idle persistent-NAT lease channel.
//
// #7360 rebuilds a persistent lease on the standby from the synced sessions
// that hold it, which reaches every lease with live flows — every lease session
// sync can observe, since a lease is learned FROM a session. An IDLE lease has
// none, yet on the active node it is still live and still reusable, so a client
// whose flows all closed within the persistence timeout keeps its translated
// port there and loses it across a failover. This carries that population.
//
// WHY THIS IS ADDITIVE — NO SessionSyncWireVersion / CurrentHAProtocolVersion
// BUMP. The same three reasons #7147 records for syncMsgFenceAck, re-verified
// against this tree:
//
//  1. handleMessage's `switch msgType` (sync_conn_read.go) has NO default arm
//     and framing is length-prefixed, so a peer that predates this type skips
//     the frame without desyncing the stream. #2239 (syncMsgDHCPLease*) and
//     #6650 (syncMsgPeerCapabilities) both relied on this and both declined to
//     bump.
//  2. Nothing existing changes shape. This is a new type carrying a new record;
//     no field on any current message is redefined.
//  3. Bumping would be actively harmful. MinCompatHAProtocolVersion ==
//     CurrentHAProtocolVersion, so the accepted window is a single point and a
//     bump makes it [N+1, N+1], refusing a peer at N — the bump itself would
//     break the rolling upgrade this feature has to survive.
//
// A mixed-version pair degrades exactly to pre-#8121 behaviour: the old node
// ignores the frame, the new node receives nothing, and idle leases are simply
// not rebuilt — which is the state before this landed, not a broken one.
const (
	// syncMsgPersistentNatLease carries a full set of the sender's IDLE
	// persistent-NAT leases (#8121).
	//
	// 38 is the first id above every one ever allocated. It is deliberately NOT
	// 34: sync.go records that 34 was syncMsgAuthUpgradeAck and is "left unused
	// rather than recycled: a frame numbered 34 meant something else in every
	// build before this one". Filling a retired number is the one way an
	// additive frame stops being additive, because an old peer still reads the
	// old meaning.
	syncMsgPersistentNatLease = 38
)

// encodePersistentNatLeasePayload serializes a full set of idle leases.
//
// Records are encoded FIRST so an unencodable one drops individually while the
// count prefix stays consistent with what was actually emitted — the #4892
// shape, and the reason the string helper returns an error rather than
// narrowing a uint16 length. Dropping one lease costs that client its port on
// takeover; misframing the peer's decode corrupts every record after it.
func encodePersistentNatLeasePayload(leases []userspace.IdleLeaseWire) []byte {
	recs := make([][]byte, 0, len(leases))
	for _, l := range leases {
		rec, err := encodeOnePersistentNatLease(l)
		if err != nil {
			slog.Warn("cluster sync: dropping unencodable persistent-NAT lease from sync push",
				"pool", l.Pool, "src", l.SrcIP, "err", err)
			continue
		}
		recs = append(recs, rec)
	}
	b := make([]byte, 0, 8+len(recs)*96)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(recs)))
	for _, rec := range recs {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(rec)))
		b = append(b, rec...)
	}
	return b
}

func encodeOnePersistentNatLease(l userspace.IdleLeaseWire) ([]byte, error) {
	b := make([]byte, 0, 96)
	var err error
	if b, err = putLeaseString(b, l.Pool); err != nil {
		return nil, fmt.Errorf("encode idle lease Pool: %w", err)
	}
	b = append(b, l.Protocol)
	if b, err = putLeaseString(b, l.SrcIP); err != nil {
		return nil, fmt.Errorf("encode idle lease SrcIP: %w", err)
	}
	b = binary.LittleEndian.AppendUint16(b, l.SrcPort)
	if b, err = putLeaseString(b, l.RemoteIP); err != nil {
		return nil, fmt.Errorf("encode idle lease RemoteIP: %w", err)
	}
	b = binary.LittleEndian.AppendUint16(b, l.RemotePort)
	if b, err = putLeaseString(b, l.TranslatedIP); err != nil {
		return nil, fmt.Errorf("encode idle lease TranslatedIP: %w", err)
	}
	b = binary.LittleEndian.AppendUint16(b, l.TranslatedPort)
	var addressOnly byte
	if l.AddressOnly {
		addressOnly = 1
	}
	b = append(b, addressOnly)
	b = binary.LittleEndian.AppendUint64(b, l.RemainingNs)
	b = binary.LittleEndian.AppendUint64(b, l.TimeoutNs)
	return b, nil
}

// decodePersistentNatLeasePayload parses a full-set push. The bool reports
// whether the payload decoded COMPLETELY: a full-set push REPLACES the peer set,
// so a truncated prefix must not be installed as if it were the whole thing —
// the #7175 discipline. The caller retains its previous set when this is false.
func decodePersistentNatLeasePayload(buf []byte) ([]userspace.IdleLeaseWire, bool) {
	if len(buf) < 4 {
		return nil, false
	}
	count := int(binary.LittleEndian.Uint32(buf))
	off := 4
	out := make([]userspace.IdleLeaseWire, 0, count)
	for i := 0; i < count; i++ {
		if off+4 > len(buf) {
			return out, false
		}
		n := int(binary.LittleEndian.Uint32(buf[off:]))
		off += 4
		if off+n > len(buf) {
			return out, false
		}
		rec, ok := decodeOnePersistentNatLease(buf[off : off+n])
		if !ok {
			return out, false
		}
		out = append(out, rec)
		off += n
	}
	return out, true
}

func decodeOnePersistentNatLease(buf []byte) (userspace.IdleLeaseWire, bool) {
	var l userspace.IdleLeaseWire
	off := 0
	var ok bool
	if l.Pool, off, ok = getLeaseString(buf, off); !ok {
		return l, false
	}
	if off >= len(buf) {
		return l, false
	}
	l.Protocol = buf[off]
	off++
	if l.SrcIP, off, ok = getLeaseString(buf, off); !ok {
		return l, false
	}
	if off+2 > len(buf) {
		return l, false
	}
	l.SrcPort = binary.LittleEndian.Uint16(buf[off:])
	off += 2
	if l.RemoteIP, off, ok = getLeaseString(buf, off); !ok {
		return l, false
	}
	if off+2 > len(buf) {
		return l, false
	}
	l.RemotePort = binary.LittleEndian.Uint16(buf[off:])
	off += 2
	if l.TranslatedIP, off, ok = getLeaseString(buf, off); !ok {
		return l, false
	}
	if off+2 > len(buf) {
		return l, false
	}
	l.TranslatedPort = binary.LittleEndian.Uint16(buf[off:])
	off += 2
	if off >= len(buf) {
		return l, false
	}
	l.AddressOnly = buf[off] == 1
	off++
	if off+16 > len(buf) {
		return l, false
	}
	l.RemainingNs = binary.LittleEndian.Uint64(buf[off:])
	l.TimeoutNs = binary.LittleEndian.Uint64(buf[off+8:])
	return l, true
}

// QueuePersistentNatLeases pushes this node's full idle-lease set to the peer.
// Fail-open, mirroring QueueDHCPLeases: a write error is logged and disconnects
// the conn (the next reconnect re-pushes) and NEVER blocks NAT allocation.
func (s *SessionSync) QueuePersistentNatLeases(leases []userspace.IdleLeaseWire) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	seq := s.persistentNatLeaseSeqCounter.Add(1)
	payload := appendFullSetSeq(encodePersistentNatLeasePayload(leases), s.syncEpoch, seq)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgPersistentNatLease, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: persistent-NAT lease send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	slog.Debug("cluster sync: persistent-NAT idle lease set sent", "count", len(leases))
}
