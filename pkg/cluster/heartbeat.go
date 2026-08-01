package cluster

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// HeartbeatPort is the UDP port used for cluster heartbeat.
	HeartbeatPort = 4784

	// heartbeatMagic identifies xpf cluster heartbeat packets.
	heartbeatMagic = "BPFX"

	// heartbeatVersion is the current protocol version.
	heartbeatVersion = 1

	// LegacyHAProtocolVersion is the compatibility version implicitly used by
	// older heartbeats that predate explicit HA protocol advertisement.
	LegacyHAProtocolVersion uint16 = 1

	// CurrentHAProtocolVersion is the HA/session-transfer compatibility version
	// used to decide whether mixed software builds can still hand off RGs. Bump
	// this only when heartbeat/session-sync/failover wire semantics change in a
	// way that breaks mixed-version interoperability.
	CurrentHAProtocolVersion = LegacyHAProtocolVersion

	// MinCompatHAProtocolVersion is the OLDEST HA protocol version
	// CurrentHAProtocolVersion can still interoperate with — the back-compat
	// floor the #1930 INC-3 mixed-base image-replace gate advertises. It is NOT
	// LegacyHAProtocolVersion: legacy is a fixed historical constant (1), whereas
	// this is the deliberate "how far back are we compatible" decision that an
	// author MUST re-evaluate on every CurrentHAProtocolVersion bump. They are
	// equal today (this build speaks 1 and is compatible back to 1); a future
	// incompatible bump raises Current AND sets this floor to the oldest peer the
	// new build can still sync with (which may equal Current if no back-compat).
	MinCompatHAProtocolVersion = CurrentHAProtocolVersion

	// maxHeartbeatSize is the max packet size we'll read/write.
	// 1472 = 1500 MTU - 20 IP header - 8 UDP header.
	maxHeartbeatSize = 1472

	// DefaultHeartbeatInterval is the default heartbeat send interval.
	DefaultHeartbeatInterval = 100 * time.Millisecond

	// DefaultHeartbeatThreshold is the default missed heartbeat count before peer is lost.
	DefaultHeartbeatThreshold = 5

	// heartbeatStartupGrace is the cold-boot config-apply grace window. For
	// this long after a receiver starts, the local config apply phase (VRF
	// binding, FRR reload, fabric creation, RETH MAC down/up) can disrupt the
	// control-link UDP receive path for 10-15+ seconds. BOTH peer-liveness
	// decisions hold behind this floor so a simultaneous cold boot cannot
	// split-brain:
	//   - seen-then-lost: suppress peer-lost entirely — a recovering node must
	//     not declare a live peer dead on the first dropped heartbeat.
	//   - never-seen-at-boot: suppress single-node promotion (#4386). Deciding
	//     a peer NEVER EXISTED is different from a peer that WAS seen then went
	//     silent: on a simultaneous boot the first heartbeats from a live peer
	//     are dropped and lastSeen stays 0 on BOTH nodes, so promoting at
	//     threshold*interval (~500ms) makes BOTH claim the RETH virtual MAC.
	//     The floor lets a slow-to-appear peer be heard first while a
	//     genuinely-absent peer (single-node deployment) still promotes once it
	//     elapses.
	heartbeatStartupGrace = 30 * time.Second

	// heartbeatAuthMagic marks the optional #4107 PSK/HMAC auth trailer.
	// Distinct from heartbeatMagic ("BPFX") so a reader can unambiguously
	// detect a trailer at the tail of a frame. The trailer is appended AFTER
	// the optional version trailer; UnmarshalHeartbeat ignores any bytes past
	// the version section, so a signed frame is wire-compatible with a legacy
	// or not-yet-keyed peer (dual-accept during a rolling upgrade).
	heartbeatAuthMagic = "XPFA"

	// heartbeatAuthMACSize is the HMAC-SHA256 digest length.
	heartbeatAuthMACSize = 32

	// heartbeatAuthTrailerSize = magic(4) + session(8) + counter(8) + HMAC(32).
	// session+counter are the anti-replay nonce: a random per-sender-process
	// session id plus a monotonic per-session counter.
	heartbeatAuthTrailerSize = 4 + 8 + 8 + heartbeatAuthMACSize
)

// HeartbeatPacket is the wire format for cluster heartbeats.
// Layout:
//
//	[0:4]   Magic "BPFX"
//	[4]     Version (1)
//	[5]     NodeID
//	[6:8]   ClusterID (little-endian uint16)
//	[8]     NumGroups
//	[9..]   Per-group entries (5 bytes each):
//	          [0] GroupID
//	          [1:3] Priority (little-endian uint16)
//	          [3] Weight
//	          [4] State
//	After groups:
//	  NumMonitors (1 byte)
//	  Per-monitor:
//	    [0] RGID
//	    [1] Flags (bit0=up)
//	    [2] Weight
//	    [3] NameLen
//	    [4..4+NameLen] Interface name
//	After monitors:
//	  Optional VersionTrailer:
//	    [0] VersionLen
//	    [1..1+VersionLen] SoftwareVersion bytes
//	    [..] uint16 little-endian HAProtocolVersion
//
// The trailing version trailer is optional; packets may end after the monitor
// section. When present, the trailer always starts with a length byte, even if
// the software version string is empty, so newer readers can unambiguously find
// the HA protocol version. Older readers ignore any bytes after the optional
// software-version field, and newer readers treat a missing trailer as the
// legacy protocol version.
type HeartbeatPacket struct {
	NodeID            uint8
	ClusterID         uint16
	Groups            []HeartbeatGroup
	Monitors          []HeartbeatMonitor
	SoftwareVersion   string
	HAProtocolVersion uint16
}

// HeartbeatGroup is a per-RG entry in the heartbeat.
type HeartbeatGroup struct {
	GroupID  uint8
	Priority uint16
	Weight   uint8
	State    uint8
}

// HeartbeatMonitor is a per-interface monitor entry in the heartbeat.
type HeartbeatMonitor struct {
	RGID      uint8
	Weight    uint8
	Up        bool
	Interface string
}

// heartbeatHeaderSize is Magic(4) + Version(1) + NodeID(1) + ClusterID(2) + NumGroups(1).
const heartbeatHeaderSize = 9

// heartbeatGroupSize is GroupID(1) + Priority(2) + Weight(1) + State(1).
const heartbeatGroupSize = 5

// maxHeartbeatGroups is the largest number of redundancy-group entries the
// heartbeat wire format can carry. The group-count field (buf[8]) and every
// per-group id byte are uint8, so a 256th group would overflow the count to 0
// and desync it from the records still written; and the frame is a fixed
// maxHeartbeatSize buffer written as 9 + N*5 bytes, so ~293 groups index past
// it and panic. 255 is the binding uint8 count limit and also fits the buffer
// (9 + 255*5 = 1284 <= maxHeartbeatSize). The commit-time gate
// config.validateChassisClusterStrict rejects any config above this; the
// marshaler caps here as a defensive backstop so it stays panic-safe and the
// count byte always matches the body even on a leniently-loaded / peer-synced
// config (#4434).
const maxHeartbeatGroups = 255

const maxHeartbeatSoftwareVersionSize = 255

// oversizeHeartbeatGroupsWarn logs the defensive group-count truncation in
// marshalHeartbeatBody at most once per process. Once
// config.validateChassisClusterStrict gates commits this path should never
// fire, but the heartbeat sender runs every heartbeat-interval, so an
// unguarded per-send log would flood journald (#4434).
var oversizeHeartbeatGroupsWarn sync.Once

func normalizeHAProtocolVersion(version uint16) uint16 {
	if version == 0 {
		return LegacyHAProtocolVersion
	}
	return version
}

// MarshalHeartbeat encodes a heartbeat packet to wire format.
// The output is capped at maxHeartbeatSize. RG group entries are always
// included (they are critical for election). When SoftwareVersion is present,
// space for it is reserved first so monitor truncation never drops version
// metadata. If monitors would cause the packet to exceed the limit, the monitor
// section is truncated and the version field is preserved.
func MarshalHeartbeat(pkt *HeartbeatPacket) []byte {
	return marshalHeartbeatBody(pkt, 0)
}

// marshalHeartbeatBody encodes the heartbeat wire body, keeping tailReserve
// bytes free at the tail of the frame for a trailer the caller appends (the
// #4107 auth trailer). tailReserve==0 is the plain legacy encoding, byte-for-
// byte what MarshalHeartbeat always produced. The election-critical header +
// RG groups are always written and the SOFTWARE version is reserved next; only
// the best-effort monitor section is truncated to fit within
// maxHeartbeatSize-tailReserve. Because the reserve is honored WHILE building
// the body, a keyed frame ALWAYS has room for its HMAC — a heartbeat is never
// silently downgraded to unsigned (the #4107 invariant; see
// MarshalHeartbeatAuth).
func marshalHeartbeatBody(pkt *HeartbeatPacket, tailReserve int) []byte {
	buf := make([]byte, maxHeartbeatSize)
	copy(buf[0:4], heartbeatMagic)
	buf[4] = heartbeatVersion
	buf[5] = pkt.NodeID
	binary.LittleEndian.PutUint16(buf[6:8], pkt.ClusterID)
	// #4434: bound the group section to the heartbeat wire limit. The count
	// byte and each per-group id byte are uint8 and the frame is a fixed
	// buffer, so an over-size redundancy-group set would overflow the count
	// (256 -> 0, desyncing it from the records actually written) or index
	// past the buffer and panic. The commit gate rejects such a config; this
	// defensive cap keeps a leniently-loaded / peer-synced config panic-safe
	// and the count byte consistent with the body.
	groups := pkt.Groups
	if len(groups) > maxHeartbeatGroups {
		oversizeHeartbeatGroupsWarn.Do(func() {
			slog.Warn("cluster: redundancy-group count exceeds heartbeat wire "+
				"limit; advertising only the first groups",
				"groups", len(pkt.Groups), "wire_limit", maxHeartbeatGroups)
		})
		groups = groups[:maxHeartbeatGroups]
	}
	buf[8] = uint8(len(groups))

	off := heartbeatHeaderSize
	for _, g := range groups {
		buf[off] = g.GroupID
		binary.LittleEndian.PutUint16(buf[off+1:off+3], g.Priority)
		buf[off+3] = g.Weight
		buf[off+4] = g.State
		off += heartbeatGroupSize
	}

	var version []byte
	const heartbeatVersionTrailerSize = 1 + 2 // version length byte + HA protocol version
	versionReserve := heartbeatVersionTrailerSize
	if pkt.SoftwareVersion != "" {
		version = []byte(pkt.SoftwareVersion)
		if len(version) > maxHeartbeatSoftwareVersionSize {
			version = version[:maxHeartbeatSoftwareVersionSize]
		}
		if off+heartbeatVersionTrailerSize+len(version) <= maxHeartbeatSize-tailReserve {
			versionReserve = heartbeatVersionTrailerSize + len(version)
		} else {
			version = nil
		}
	}

	// Append monitor section, fitting as many monitors as possible.
	monCountOff := off // remember offset of NumMonitors byte
	buf[off] = 0       // NumMonitors — updated below
	off++
	numMon := 0
	for _, mon := range pkt.Monitors {
		nameBytes := []byte(mon.Interface)
		entrySize := 4 + len(nameBytes) // RGID + Flags + Weight + NameLen + name
		if off+entrySize > maxHeartbeatSize-versionReserve-tailReserve {
			break
		}
		buf[off] = mon.RGID
		flags := uint8(0)
		if mon.Up {
			flags |= 1
		}
		buf[off+1] = flags
		buf[off+2] = mon.Weight
		buf[off+3] = uint8(len(nameBytes))
		off += 4
		copy(buf[off:off+len(nameBytes)], nameBytes)
		off += len(nameBytes)
		numMon++
	}
	buf[monCountOff] = uint8(numMon)
	if off+versionReserve+tailReserve <= maxHeartbeatSize {
		buf[off] = uint8(len(version))
		off++
		if len(version) > 0 {
			copy(buf[off:off+len(version)], version)
			off += len(version)
		}
		binary.LittleEndian.PutUint16(buf[off:off+2], normalizeHAProtocolVersion(pkt.HAProtocolVersion))
		off += 2
	}
	return buf[:off]
}

// UnmarshalHeartbeat decodes a heartbeat packet from wire format.
func UnmarshalHeartbeat(data []byte) (*HeartbeatPacket, error) {
	if len(data) < heartbeatHeaderSize {
		return nil, fmt.Errorf("heartbeat too short: %d bytes", len(data))
	}
	if string(data[0:4]) != heartbeatMagic {
		return nil, fmt.Errorf("invalid heartbeat magic: %q", string(data[0:4]))
	}
	if data[4] != heartbeatVersion {
		return nil, fmt.Errorf("unsupported heartbeat version: %d", data[4])
	}

	pkt := &HeartbeatPacket{
		NodeID:            data[5],
		ClusterID:         binary.LittleEndian.Uint16(data[6:8]),
		HAProtocolVersion: LegacyHAProtocolVersion,
	}

	numGroups := int(data[8])
	need := heartbeatHeaderSize + numGroups*heartbeatGroupSize
	if len(data) < need {
		return nil, fmt.Errorf("heartbeat truncated: have %d, need %d", len(data), need)
	}

	pkt.Groups = make([]HeartbeatGroup, numGroups)
	off := heartbeatHeaderSize
	for i := 0; i < numGroups; i++ {
		pkt.Groups[i] = HeartbeatGroup{
			GroupID:  data[off],
			Priority: binary.LittleEndian.Uint16(data[off+1 : off+3]),
			Weight:   data[off+3],
			State:    data[off+4],
		}
		off += heartbeatGroupSize
	}

	// Parse monitor section if present (backwards compatible — old packets
	// without monitors just have no remaining data). If the monitor section
	// is truncated (sender capped at maxHeartbeatSize), return whatever
	// monitors were successfully parsed rather than erroring — RG state
	// (already parsed above) is the critical data.
	monitorSectionComplete := true
	if off < len(data) {
		numMonitors := int(data[off])
		off++
		for i := 0; i < numMonitors; i++ {
			if off+4 > len(data) {
				monitorSectionComplete = false
				break // truncated — return what we have
			}
			rgID := data[off]
			up := data[off+1]&1 != 0
			weight := data[off+2]
			nameLen := int(data[off+3])
			off += 4
			if off+nameLen > len(data) {
				monitorSectionComplete = false
				break // truncated name — return what we have
			}
			name := string(data[off : off+nameLen])
			off += nameLen
			pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
				RGID:      rgID,
				Weight:    weight,
				Up:        up,
				Interface: name,
			})
		}
	}
	versionSectionComplete := false
	if monitorSectionComplete && off < len(data) {
		versionLen := int(data[off])
		off++
		if off+versionLen <= len(data) {
			pkt.SoftwareVersion = string(data[off : off+versionLen])
			off += versionLen
			versionSectionComplete = true
		} else {
			return pkt, nil
		}
	}
	if monitorSectionComplete && versionSectionComplete && off+2 <= len(data) {
		pkt.HAProtocolVersion = normalizeHAProtocolVersion(binary.LittleEndian.Uint16(data[off : off+2]))
	}

	return pkt, nil
}

// --- #4107 control-channel authentication (heartbeat/election) -------------
//
// The cluster heartbeat drives election: handlePeerHeartbeat rebuilds peer RG
// state directly from the packet and runs runElection(), so a forged cleartext
// heartbeat can force the local node PRIMARY or demote the peer. When a shared
// PSK (chassis cluster authentication-key) is configured, the sender appends an
// HMAC-SHA256 trailer over the whole frame plus an anti-replay nonce, and the
// receiver rejects a heartbeat that fails (or, once both nodes are keyed, lacks)
// authentication BEFORE it can refresh peer liveness or drive election.
//
// Dual-accept (rolling upgrade): a node without a key emits and accepts legacy
// frames; a keyed node accepts an unauthenticated frame until it has observed
// the peer authenticate (proving both nodes hold the key), after which an
// unauthenticated frame is a downgrade attack and is rejected. This mirrors the
// #4126 VRRP-checksum dual-accept migration: accept both wire forms during the
// upgrade window, enforce once both sides speak the new form.

// MarshalHeartbeatAuth encodes a heartbeat and, when authKey is non-empty,
// appends the PSK/HMAC auth trailer so the receiver can reject a forged or
// tampered heartbeat. session is a per-sender-process random value and counter
// is a per-session monotonic send counter; together they are the anti-replay
// nonce (a new session re-anchors the receiver after a restart/reboot; a
// strictly increasing counter rejects intra-session replays). When authKey is
// empty the output is byte-identical to MarshalHeartbeat — a node without a key
// emits legacy frames (dual-accept). The key is never logged.
//
// INVARIANT: once a key is configured, the returned frame is ALWAYS signed. The
// trailer space is reserved WHILE building the body (marshalHeartbeatBody drops
// best-effort monitor entries to make room), so a heartbeat is never silently
// downgraded to unsigned — a silent downgrade would make an ENFORCING peer
// reject every frame and split the cluster (dual-primary). At realistic RG +
// monitor counts the reserve never even bites; the belt-and-suspenders guard
// below is unreachable and fails LOUD rather than emitting cleartext.
func MarshalHeartbeatAuth(pkt *HeartbeatPacket, authKey []byte, session, counter uint64) []byte {
	return marshalHeartbeatAuthEpoch(pkt, authKey, session, counter, 0)
}

// marshalHeartbeatAuthEpoch is MarshalHeartbeatAuth plus the optional #6169
// boot-epoch section. A non-zero epoch inserts
//
//	[ marker(8) = HMAC(key, bootEpochLabel)[:8] ][ epoch(8, little-endian) ]
//
// BETWEEN the body and the auth trailer. epoch == 0 emits a byte-identical
// legacy frame (the peer has no epoch to advertise yet, or could not persist
// one).
//
// The section placement is what makes this a NON-BREAKING wire change, and it
// is not interchangeable with appending after the trailer (which is what failed
// review in #6370 — a v1 receiver looking for "XPFA" at len-52 found body bytes,
// read the frame as unsigned, and an enforcing v1 peer rejected every frame,
// splitting a keyed cluster mid-upgrade). With the section BEFORE the trailer:
//
//   - the 52-byte auth trailer stays at the fixed tail, so heartbeatAuthTrailer
//     still locates it at len-52 on a v1 receiver;
//   - the signed span is still everything but the trailing digest, so a v1
//     receiver's verifyHeartbeatMAC recomputes over exactly the bytes a v2
//     sender signed and the HMAC verifies — the epoch is INSIDE the signed
//     region and therefore unforgeable; and
//   - UnmarshalHeartbeat stops after the version section and ignores the rest,
//     so a v1 receiver simply never sees the epoch.
//
// Bidirectional compatibility with no HAProtocolVersion bump.
func marshalHeartbeatAuthEpoch(pkt *HeartbeatPacket, authKey []byte, session, counter, epoch uint64) []byte {
	if len(authKey) == 0 {
		return marshalHeartbeatBody(pkt, 0)
	}
	epochSection := 0
	if epoch != 0 {
		epochSection = heartbeatEpochSectionSize
	}
	// Reserve the epoch section AND the trailer up front so the signed frame is
	// guaranteed to fit. Reserving only the trailer would let a maximal frame
	// reach maxHeartbeatSize+16 bytes, which the receiver's maxHeartbeatSize
	// read buffer silently TRUNCATES — destroying the HMAC and making an
	// enforcing peer reject every frame.
	tailReserve := epochSection + heartbeatAuthTrailerSize
	body := marshalHeartbeatBody(pkt, tailReserve)
	if len(body)+tailReserve > maxHeartbeatSize {
		// Unreachable: the RG group count is uint8-bounded and monitors were
		// already truncated to leave the reserve. Guard so a future change can
		// never SILENTLY downgrade a keyed heartbeat to unsigned (which an
		// enforcing peer rejects → split-brain). Fail loud and still sign
		// rather than emit an unsigned frame.
		slog.Error("cluster: keyed heartbeat exceeds frame cap after monitor truncation; signing anyway to preserve the auth invariant",
			"body_bytes", len(body), "cap", maxHeartbeatSize)
	}
	trailer := make([]byte, heartbeatAuthTrailerSize)
	copy(trailer[0:4], heartbeatAuthMagic)
	binary.LittleEndian.PutUint64(trailer[4:12], session)
	binary.LittleEndian.PutUint64(trailer[12:20], counter)

	out := make([]byte, 0, len(body)+tailReserve)
	out = append(out, body...)
	if epochSection > 0 {
		out = append(out, heartbeatEpochMarker(authKey)...)
		out = binary.LittleEndian.AppendUint64(out, epoch)
	}
	// Sign the body PLUS the epoch section PLUS magic+session+counter
	// (everything but the digest), so the epoch, the nonce and the whole packet
	// are all bound by the MAC.
	mac := hmac.New(sha256.New, authKey)
	mac.Write(out)
	mac.Write(trailer[:20])
	copy(trailer[20:], mac.Sum(nil))

	return append(out, trailer...)
}

// heartbeatAuthTrailer locates the auth trailer at the tail of a raw heartbeat
// frame and returns its nonce. present is false when the frame carries no
// trailer (a legacy / not-yet-keyed peer).
func heartbeatAuthTrailer(data []byte) (session, counter uint64, present bool) {
	if len(data) < heartbeatAuthTrailerSize {
		return 0, 0, false
	}
	start := len(data) - heartbeatAuthTrailerSize
	if !bytes.Equal(data[start:start+4], []byte(heartbeatAuthMagic)) {
		return 0, 0, false
	}
	session = binary.LittleEndian.Uint64(data[start+4 : start+12])
	counter = binary.LittleEndian.Uint64(data[start+12 : start+20])
	return session, counter, true
}

// verifyHeartbeatMAC recomputes the HMAC over the signed span (everything but
// the trailing 32-byte digest) and compares it in constant time. It presumes a
// trailer is present (heartbeatAuthTrailer returned present) and authKey is
// non-empty; it returns false otherwise.
func verifyHeartbeatMAC(data, authKey []byte) bool {
	if len(authKey) == 0 || len(data) < heartbeatAuthTrailerSize {
		return false
	}
	signed := data[:len(data)-heartbeatAuthMACSize]
	got := data[len(data)-heartbeatAuthMACSize:]
	mac := hmac.New(sha256.New, authKey)
	mac.Write(signed)
	return hmac.Equal(got, mac.Sum(nil))
}

// heartbeatReplaySessions bounds how many distinct sender sessions the
// anti-replay tracker remembers a counter watermark for. Each genuine peer
// reboot picks a fresh random session (randomSessionID) and consumes one slot;
// the oldest watermark is evicted FIFO once the ring is full.
//
// #5477 security bound — and its honest limit. The retired-session watermarks
// must be bounded (a peer that reboots forever cannot grow the ring without
// limit). This map RAISES the on-link REPLAY attacker's cost — from the
// pre-#5477 single-watermark A->B->A loop (only 2 recorded incarnations) to
// heartbeatReplaySessions+1 distinct recorded incarnations — but it is NOT an
// absolute bar:
//
//   - HMAC-SHA256 over the nonce blocks fabricating a valid frame for any NEW
//     session id, and blocks fabricating a counter beyond the highest the
//     genuine peer ever signed for a session. So the attacker can only REPLAY
//     the session incarnations they captured off the wire.
//   - With FEWER than heartbeatReplaySessions+1 recorded incarnations, every
//     replay of a retired session is at/below its remembered watermark and is
//     rejected — the sustained A->B->A loop #5477 targets is fully closed.
//   - With heartbeatReplaySessions+1 OR MORE recorded incarnations the bound is
//     defeatable by REPLAY ALONE (no reboot, no minting): a replayed frame
//     whose session is not currently in the ring is "never-seen" from the
//     ring's view, so admit() re-records it and evicts the oldest FIFO entry.
//     FIFO always leaves exactly one just-evicted session to replay back in as
//     never-seen, so an attacker holding >= heartbeatReplaySessions+1
//     incarnations can churn the ring and SUSTAIN the replay indefinitely.
//     (Confirmed empirically: M == heartbeatReplaySessions recordings -> all
//     replays rejected; M == heartbeatReplaySessions+1 -> sustained admits.)
//
// This receiver-only map cannot close that residual completely: a full fix
// needs a boot-epoch / monotonic-across-reboot counter carried in the frame (a
// wire change), tracked as a follow-up. It does NOT cause a genuine-peer
// lockout (an evicted live-peer watermark just makes the peer's next frame
// never-seen -> admitted) and cannot grow memory (fixed 64-slot array).
//
// 64 slots (64*16 = 1 KiB) bounds memory while forcing an attacker to have
// captured 65+ distinct peer SESSIONS before any replay is sustainable.
//
// The unit is a session id, not a daemon boot, and the two are not the same:
// a session id is minted per heartbeatSender (see authSession below), so every
// peer heartbeat RESTART — a DHCP-triggered VRF rebind, an HA comms restart —
// mints a new one without the peer rebooting. Two consequences, both of which
// only became relevant once #5086 made this ring outlive a local restart:
// routine peer restarts now permanently consume slots, so the ring reaches
// eviction pressure from legitimate traffic alone; and the attacker's capture
// cost for the churn above is 65 sessions, which are cheaper to harvest than
// 65 daemon boots. Neither is a regression — before #5086 any local restart
// wiped the whole ring, so this worst case is a strict subset of that one.
const heartbeatReplaySessions = 64

// replaySessionMark is one remembered (session, high-water counter) pair.
type replaySessionMark struct {
	session uint64
	counter uint64
}

// heartbeatAuthReplay tracks per-peer anti-replay state for authenticated
// heartbeats. A sender advertises a random per-process session id and a
// monotonic per-session counter (MarshalHeartbeatAuth). The receiver keeps a
// bounded set of per-session high-water counters and:
//
//   - accepts a strictly increasing counter within a KNOWN session (the live
//     session advancing), and
//   - accepts a genuinely NEW, never-seen session with any counter — a sender
//     restart/reboot picks a fresh random session, so a real reboot (a routine
//     HA event) is never mistaken for a replay and failover is never wedged.
//
// #5477: it REJECTS a return to a session already at or below its remembered
// watermark. Before this, the tracker held exactly ONE (session, counter): any
// session switch reset the watermark, so an on-link attacker who recorded
// authenticated frames from two incarnations A and B could alternate
// A->B->A->B forever — each switch re-anchored and re-admitted the SAME
// recorded A frames, refreshing peer liveness and applying their STALE
// role/priority (a forged liveness/election drive). Session ids are RANDOM
// (unordered), so a strictly-newer test like fullSetSeqGuard cannot be used:
// remembering a bounded per-session watermark is what distinguishes a real
// reboot (new id) from a replay of a retired incarnation (known id, no counter
// advance).
//
// Touched only from the single readLoop goroutine, so it needs no locking.
type heartbeatAuthReplay struct {
	marks [heartbeatReplaySessions]replaySessionMark
	// count is the number of occupied slots, saturating at len(marks). next is
	// the FIFO write cursor for eviction once the ring is full. While filling,
	// next == count and the valid entries are marks[:count]; once full, count
	// stays at len(marks) and next cycles, so marks[:count] still spans every
	// live entry for the lookup scan.
	count int
	next  int
}

// admit reports whether (session, counter) is fresh (not a replay) and, when
// fresh, advances the per-session watermark (or records a new session). Callers
// must invoke admit only after the MAC has verified — an unauthenticated caller
// must never mutate replay state.
func (a *heartbeatAuthReplay) admit(session, counter uint64) bool {
	// Known session: admit only a strictly-advancing counter. A frame at or
	// below the watermark is a replay — including a return to a RETIRED session
	// whose watermark we still remember (#5477: the attacker cannot exceed the
	// highest counter the genuine peer ever signed for that session).
	for i := 0; i < a.count; i++ {
		if a.marks[i].session == session {
			if counter > a.marks[i].counter {
				a.marks[i].counter = counter
				return true
			}
			return false
		}
	}
	// Never-seen session: a genuine reboot draws a fresh random session, so
	// accept and record a new watermark. Bounded FIFO — evict the oldest once
	// the ring is full (see the heartbeatReplaySessions security bound above).
	a.marks[a.next] = replaySessionMark{session: session, counter: counter}
	a.next = (a.next + 1) % len(a.marks)
	if a.count < len(a.marks) {
		a.count++
	}
	return true
}

// heartbeatAuthState is the per-PEER control-channel authentication state:
// the anti-replay watermarks and the sticky "peer has authenticated" flag.
//
// #5086: this state lives on the Manager (process lifetime), NOT on the
// heartbeatReceiver (heartbeat lifetime). Every StartHeartbeat builds a brand
// new heartbeatReceiver, and StartHeartbeat runs on far more than a daemon
// boot — RestartHeartbeat on a DHCP-triggered VRF rebind
// (daemon_apply_dataplane.go), and the HA comms (re)start
// (daemon_ha_sync.go). While the tracker was a receiver field, each of those
// routine events discarded every retired-session watermark, so the #5477
// A->B->A rollback re-opened in full: an attacker holding captured
// authenticated frames from retired peer incarnations replays them into the
// empty tracker and each one is "never-seen" -> admitted, refreshing peer
// liveness and applying stale election state for the whole captured run. A
// heartbeat restart is exactly the moment the local node is least able to
// afford a peer it wrongly believes is alive.
//
// Anchoring the state to the Manager makes the retired-session memory span the
// process instead of the socket. The bound is unchanged and does not grow with
// restart count, uptime, or the number of peer incarnations observed: one
// fixed heartbeatAuthReplay ring (heartbeatReplaySessions * 16 B = 1 KiB) plus
// a mutex and an atomic, allocated once per Manager.
//
// The mutex is required now that the ring outlives a single readLoop: the
// StartHeartbeat stop-then-start sequence joins the previous readLoop before
// the next one runs, but the tracker is no longer confined to one goroutine's
// lifetime and must not depend on that ordering to stay race-free.
type heartbeatAuthState struct {
	mu     sync.Mutex
	replay heartbeatAuthReplay

	// highEpoch is the #6169 across-reboot floor: the highest boot epoch ever
	// accepted from the peer. It is O(1) state (one uint64) that gives the
	// receiver a TOTAL ORDER over peer incarnations, which the session ring
	// cannot provide — session ids are random and unordered, so the ring can
	// only remember a bounded set of them and is churnable by replay once the
	// attacker holds more captured sessions than it has slots.
	//
	// Anchored here (Manager lifetime, #5086/#6642) rather than on the
	// heartbeatReceiver on purpose: a receiver-scoped floor is zeroed by every
	// StartHeartbeat — including RestartHeartbeat on a routine DHCP-triggered
	// VRF rebind and the HA comms restart — and a zero floor re-admits and
	// re-latches a replayed retired epoch, defeating the gate entirely.
	//
	// 0 means "no epoch accepted yet" and is also the sender's "advertise no
	// epoch" sentinel, so it can never be a real floor.
	highEpoch uint64

	// epochSeen is the DOWNGRADE LATCH: the peer has proved it runs a build
	// that emits boot epochs, so an epochless frame from it is now refused.
	//
	// Without this the epoch closes almost nothing. An attacker's captured
	// incarnations are, by construction, mostly from BEFORE the upgrade and so
	// carry no epoch; if epochless frames are accepted forever the floor is
	// never even consulted. Measured on the first cut of this change: with the
	// floor latched at a live peer's epoch, 975/975 epochless replays were
	// still admitted.
	//
	// DURABILITY — deliberately PROCESS-SCOPED, not on disk.
	//
	// A durable latch would additionally cover "the survivor's daemon restarts
	// while the genuine peer is silent", but it was removed after review priced
	// it: it needs a peer-floor state file, which turns a deliberate rollback
	// into "delete the right file on the right node and restart" (a procedure
	// run under incident pressure), opens a crash window between accepting a
	// frame and committing the floor, needs cross-process locking on the
	// receive path, and makes an in-range-but-wrong epoch a lockout that
	// outlives reboots.
	//
	// What process scope costs is narrow, because this state already lives on
	// the Manager (#5086/#6642): a heartbeat restart, a DHCP-triggered VRF
	// rebind and an HA comms restart all PRESERVE it. Only a full daemon
	// restart clears it, and a live peer re-arms it with its next heartbeat —
	// one DefaultHeartbeatInterval, ~100ms. So the uncovered case needs a
	// daemon restart AND a genuinely absent peer AND an attacker holding
	// pre-upgrade captures; and rotating the control-link PSK, already a
	// REQUIRED post-upgrade step, retires those captures outright.
	//
	// It also makes rollback recovery "restart xpfd", an operation operators
	// already perform, instead of a documented rm.
	epochSeen bool

	// epochlessAdmitted counts authenticated heartbeats ADMITTED without a boot
	// epoch, and epochDowngradeRejected counts those refused because the peer
	// had already proved it emits them. Atomics, not mu-guarded, because
	// HeartbeatStats reads them from another goroutine.
	//
	// These exist so the #6169 residual is OBSERVABLE. Without a counter an
	// operator who has upgraded both nodes has no way to tell whether the
	// cluster is still accepting pre-upgrade-shaped frames — the exposure would
	// be invisible and the documentation would be the only defence. A non-zero
	// epochlessAdmitted after a completed rollout means either a node is still
	// on an old build or someone is replaying captures; a non-zero
	// epochDowngradeRejected means the latch is actively refusing something.
	epochlessAdmitted      atomic.Uint64
	epochDowngradeRejected atomic.Uint64

	// peerAuthSeen is sticky and READ cross-goroutine
	// (Manager.HeartbeatPeerAuthSeen, consumed by the gRPC fabric listener to
	// arm its downgrade-guard off the fast-arming heartbeat instead of the
	// lazily-arming on-demand fabric RPCs), so it is an atomic rather than
	// mu-guarded.
	peerAuthSeen atomic.Bool
}

// admitAuthed is the #6169 anti-replay decision for one MAC-VERIFIED frame:
// the boot-epoch floor and the bounded session ring applied as ONE transaction
// under the state lock. Callers must invoke it only after the MAC has verified.
//
// hasEpoch reports whether the frame carried a boot-epoch section
// (heartbeatFrameEpoch).
//
// ORDER IS LOAD-BEARING. The epoch floor is tested BEFORE the session ring is
// consulted, and a frame rejected by the floor never reaches ring.admit. Test
// it after, and the gate is bypassable: ring.admit RECORDS a never-seen session
// as a side effect, so a replayed retired frame would still evict a live
// watermark and churn the ring even while being rejected. That inverted
// ordering is what failed review on the earlier attempt (#6370).
//
// The three cases:
//
//   - epoch < highEpoch — a RETIRED incarnation. Reject. This is the #6169
//     close: no matter how many captured sessions the attacker churns the ring
//     with, every one of them belongs to an incarnation at or below the highest
//     epoch already seen, so they never reach the ring at all.
//   - epoch == highEpoch — the SAME incarnation. Fall through to the ring,
//     which is what handles within-incarnation replay (unchanged #6167
//     behaviour).
//   - epoch > highEpoch — a genuinely NEWER incarnation. Let the ring vet the
//     nonce, then raise the floor. The floor only ever rises to a value the
//     genuine peer actually signed, so replaying a captured high-epoch frame
//     cannot push the floor above the live peer and lock it out.
//
// MIGRATION + THE DOWNGRADE LATCH (dual-accept, the #4126 VRRP-checksum /
// heartbeatAuthDecision pattern).
//
// An epochless frame is accepted and passed to the ring exactly as before —
// UNTIL the peer has proved it emits epochs. From then on an epochless frame
// from that peer is refused. Both halves are required:
//
//   - Accepting epochless frames before the peer has proved otherwise is what
//     keeps a rolling upgrade from splitting the cluster, and it is why the
//     latch is armed by OBSERVATION rather than by local build version.
//   - Refusing them afterwards is what actually closes #6169. An attacker's
//     captures are by construction mostly PRE-upgrade and therefore epochless;
//     without the latch they bypass the floor entirely and the fix would only
//     defend against an attacker who started capturing after the upgrade.
//     Measured on the first cut of this change: floor latched at a live peer's
//     epoch, and still 975/975 epochless replays admitted.
//
// The latch is armed by an ACCEPTED frame that carried an epoch section, and it
// is restored at start from the DURABLE floor — an in-memory latch is cleared
// by exactly the receiver restart an attacker waits for.
//
// WHAT MAKES THE LATCH SAFE is the sender-side invariant in heartbeat_epoch.go:
// a keyed heartbeat carries no epoch IF AND ONLY IF the peer runs a pre-#6169
// build. A storage fault does NOT stop a healthy node emitting an epoch (it
// falls back to a wall-clock value and logs), so no runtime fault can make this
// node refuse a live peer. The one remaining trigger is a genuine ROLLBACK of
// the peer to a pre-#6169 build, which is a deliberate, operator-initiated act:
// that peer's frames are refused until an operator clears the persisted floor
// (see pkg/cluster/README.md). This is the same trade #4107's sticky
// peerAuthSeen already makes for the auth trailer, made durable.
//
// The three epoch cases, once the peer is known to emit them:
//
//   - epoch < highEpoch — a RETIRED incarnation. Reject. This is the #6169
//     close: no matter how many captured sessions the attacker churns the ring
//     with, every one belongs to an incarnation at or below the highest epoch
//     already seen, so they never reach the ring at all.
//   - epoch == highEpoch — the SAME incarnation. Fall through to the ring,
//     which is what handles within-incarnation replay (unchanged #6167
//     behaviour).
//   - epoch > highEpoch — a genuinely NEWER incarnation. Let the ring vet the
//     nonce, then raise the floor. The floor only ever rises to a value the
//     genuine peer actually signed, so replaying a captured high-epoch frame
//     cannot push the floor above the live peer and lock it out.
//
// An epoch the floor cannot ORDER (epochOrderable: outside the absolute
// plausibility band, or more than bootEpochMaxSkew ahead of our own clock) is
// REFUSED. It is tested before anything else in the hasEpoch path, so such a
// frame never reaches the floor comparison, never touches the ring, and never
// arms the latch — s.epochSeen stays false. A corrupt far-future value
// therefore cannot slam the one-way door.
//
// The second-order consequence is the safe direction and is deliberate: a peer
// whose clock runs more than a year ahead is refused outright, and because the
// latch never armed on it, its EPOCHLESS frames would still be accepted if it
// were later rolled back. Refusing an unorderable epoch never strands a peer
// that comes back into range.
func (s *heartbeatAuthState) admitAuthed(hasEpoch bool, epoch, session, counter uint64) bool {
	return s.admitAuthedLocked(hasEpoch, epoch, session, counter)
}

// admitAuthedLocked is the locked half of admitAuthed.
func (s *heartbeatAuthState) admitAuthedLocked(hasEpoch bool, epoch, session, counter uint64) (ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !hasEpoch {
		if s.epochSeen {
			// Downgrade: this peer has proved it emits epochs.
			s.epochDowngradeRejected.Add(1)
			return false
		}
		// The migration window — and the ONLY residual an operator can still be
		// exposed to on merge day, since a capture taken before the upgrade is
		// epochless and this node has not yet seen proof the peer emits epochs.
		// Counted so that exposure is visible rather than inferred: a peer still
		// sending epochless frames after both nodes are upgraded is either
		// mid-rollout or an attack, and both are things an operator must see.
		// Surfaced through HeartbeatStats.EpochlessAdmitted.
		ok := s.replay.admit(session, counter)
		if ok {
			s.epochlessAdmitted.Add(1)
		}
		return ok
	}
	// An epoch the floor cannot ORDER is refused, not admitted-and-ignored.
	// Admitting it would recreate the epochless bypass in miniature: a frame
	// outside the comparable range is governed by the bounded ring alone, so
	// captures from an incarnation that once emitted an out-of-range epoch would
	// replay indefinitely. See epochOrderable.
	if !epochOrderable(epoch, time.Now().UnixNano()) {
		return false
	}
	if epoch < s.highEpoch {
		return false
	}
	if !s.replay.admit(session, counter) {
		return false
	}
	s.epochSeen = true
	if epoch > s.highEpoch {
		s.highEpoch = epoch
	}
	return true
}

// peerEpochFloor reports the highest peer boot epoch accepted so far (0 when
// none). Diagnostics and tests only.
func (s *heartbeatAuthState) peerEpochFloor() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.highEpoch
}

// peerEpochLatched reports whether the peer has proved it emits boot epochs, so
// an epochless frame from it is now refused. Diagnostics and tests only.
func (s *heartbeatAuthState) peerEpochLatched() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epochSeen
}

// peerAuthenticated reports whether the peer has ever sent a valid
// HMAC-authenticated heartbeat (sticky for the life of the process).
func (s *heartbeatAuthState) peerAuthenticated() bool {
	return s.peerAuthSeen.Load()
}

// notePeerAuthenticated records that the peer proved it holds the PSK. From
// then on an unauthenticated frame from it is a downgrade attack.
func (s *heartbeatAuthState) notePeerAuthenticated() {
	s.peerAuthSeen.Store(true)
}

// heartbeatAuthState returns the Manager's process-lifetime control-channel
// auth state — the state a new heartbeatReceiver binds to so a restart does
// not reset anti-replay (#5086). A nil Manager (unit tests constructing a
// standalone receiver) gets a fresh private state rather than a nil deref, so
// a test receiver behaves exactly like a never-restarted production one.
func (m *Manager) heartbeatAuthState() *heartbeatAuthState {
	if m == nil {
		return &heartbeatAuthState{}
	}
	return &m.hbAuth
}

// heartbeatAuthDecision applies the #4107 dual-accept policy for one received
// heartbeat and returns whether to accept it (and, when rejected, a short
// reason for logging — never the key or packet bytes).
//
//	keyConfigured — the local ControlLinkAuthKey is set (we can verify).
//	present       — the frame carried an auth trailer.
//	macOK         — the trailer's HMAC verified (only meaningful when present).
//	nonceFresh    — the nonce passed anti-replay (only meaningful when macOK).
//	peerAuthSeen  — we have previously accepted an authenticated heartbeat from
//	                the peer (sticky: proves the peer holds the key, so both
//	                nodes are keyed and an unauthenticated frame is now forged).
//
// Policy:
//   - No local key: dual-accept everything — this node cannot verify and may be
//     the not-yet-upgraded / not-yet-keyed side of a rolling upgrade.
//   - Local key + auth trailer: enforce — reject a bad HMAC or a replayed nonce.
//   - Local key + no trailer + peer never authenticated: dual-accept — the peer
//     has not started signing yet (rolling upgrade / key not yet synced).
//   - Local key + no trailer + peer HAS authenticated: reject — a downgrade to
//     cleartext once both nodes are keyed is an attack.
func heartbeatAuthDecision(keyConfigured, present, macOK, nonceFresh, peerAuthSeen bool) (bool, string) {
	if !keyConfigured {
		return true, ""
	}
	if present {
		if !macOK {
			return false, "hmac verification failed"
		}
		if !nonceFresh {
			return false, "stale nonce (replay)"
		}
		return true, ""
	}
	if peerAuthSeen {
		return false, "missing auth trailer (enforced: peer previously authenticated)"
	}
	return true, ""
}

// heartbeatNonce returns the next control-channel anti-replay nonce for a
// heartbeat send: this daemon incarnation's session id (drawn once, lazily) and
// a strictly increasing per-incarnation counter.
//
// #6169: Manager-scoped, NOT per-heartbeatSender — see the hbNonceOnce field
// comment for why a per-sender session made the receiver's bounded ring
// churnable within a single peer boot epoch.
func (m *Manager) heartbeatNonce() (session, counter uint64) {
	m.hbNonceOnce.Do(func() { m.hbSession = randomSessionID() })
	return m.hbSession, m.hbCounter.Add(1)
}

// randomSessionID returns a random 64-bit anti-replay session id. On the
// (practically impossible) crypto/rand failure it falls back to the monotonic
// clock, which is still process-unique for the receiver's re-anchor logic.
func randomSessionID() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(MonotonicNanos())
	}
	return binary.LittleEndian.Uint64(b[:])
}

// PeerGroupState holds the last-known state of a peer's redundancy group.
type PeerGroupState struct {
	GroupID  int
	Priority int
	Weight   int
	State    NodeState
}

// heartbeatSender sends periodic heartbeat packets.
type heartbeatSender struct {
	mgr        *Manager
	conn       *net.UDPConn
	peerAddr   *net.UDPAddr
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
	sent       atomic.Uint64
	sendErrors atomic.Uint64
}

// heartbeatReceiver listens for peer heartbeat packets.
type heartbeatReceiver struct {
	mgr        *Manager
	conn       *net.UDPConn
	threshold  int
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
	lastSeen   atomic.Int64 // CLOCK_MONOTONIC nanos of last heartbeat (MonotonicNanos)
	received   atomic.Uint64
	recvErrors atomic.Uint64
	startedAt  time.Time // when receiver started (for initial peer-lost detection)

	// auth is the #4107 control-channel auth state (anti-replay watermarks +
	// the sticky peer-authenticated flag). It is a POINTER to state owned by
	// the Manager, not an embedded value: the tracker must outlive this
	// receiver so a heartbeat restart cannot discard the retired-session
	// memory and re-open the #5086 replay. newHeartbeatReceiver always sets
	// it; it is never nil.
	auth *heartbeatAuthState
}

// peerAuthenticated reports whether the peer has ever sent a valid
// HMAC-authenticated heartbeat (sticky). It proves the peer holds the
// control-link PSK and is signing — the arming signal the gRPC fabric
// listener reuses so its downgrade-guard engages within ~one heartbeat
// interval of the peer coming up, not on the next on-demand fabric RPC.
func (r *heartbeatReceiver) peerAuthenticated() bool {
	return r.auth.peerAuthenticated()
}

func newHeartbeatSender(mgr *Manager, conn *net.UDPConn, peerAddr *net.UDPAddr, interval time.Duration) *heartbeatSender {
	return &heartbeatSender{
		mgr:      mgr,
		conn:     conn,
		peerAddr: peerAddr,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (s *heartbeatSender) start() {
	s.wg.Add(1)
	go s.run()
}

func (s *heartbeatSender) run() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.send()
		}
	}
}

func (s *heartbeatSender) send() {
	pkt := s.mgr.buildHeartbeat()
	// #4107: sign the frame when a control-channel PSK is configured. The key
	// is fetched fresh each tick so a commit that sets/clears it takes effect
	// without a heartbeat restart. Never logged.
	var data []byte
	if key := s.mgr.controlLinkAuthKey(); len(key) > 0 {
		session, counter := s.mgr.heartbeatNonce()
		// #6169: carry the boot epoch when one has been durably persisted; 0
		// emits a byte-identical legacy frame.
		data = marshalHeartbeatAuthEpoch(pkt, key, session, counter, s.mgr.heartbeatBootEpoch())
	} else {
		data = MarshalHeartbeat(pkt)
	}
	if _, err := s.conn.WriteToUDP(data, s.peerAddr); err != nil {
		s.sendErrors.Add(1)
		slog.Debug("cluster: heartbeat send failed", "err", err)
	} else {
		s.sent.Add(1)
	}
}

func (s *heartbeatSender) stop() {
	close(s.stopCh)
	s.wg.Wait()
	// Close the send socket after the run loop has exited (wg.Wait above) so
	// there is no write-after-close race. Without this the sender FD leaks on
	// every heartbeat stop/restart (#4033); the receiver already closes its
	// conn in stop().
	s.conn.Close()
}

func newHeartbeatReceiver(mgr *Manager, conn *net.UDPConn, threshold int, interval time.Duration) *heartbeatReceiver {
	r := &heartbeatReceiver{
		mgr:       mgr,
		conn:      conn,
		threshold: threshold,
		interval:  interval,
		stopCh:    make(chan struct{}),
		// #5086: bind to the Manager's process-lifetime auth state so a
		// heartbeat restart (VRF rebind, comms restart) keeps every retired
		// peer-session watermark instead of starting from an empty tracker
		// that re-admits captured frames. mgr is nil only in unit tests that
		// exercise a standalone receiver; those get their own state, which is
		// exactly the pre-#5086 per-receiver scope and is safe because such a
		// receiver is never restarted.
		auth: mgr.heartbeatAuthState(),
	}
	return r
}

func (r *heartbeatReceiver) start() {
	r.startedAt = time.Now()
	r.wg.Add(2)
	go r.readLoop()
	go r.timeoutLoop()
}

func (r *heartbeatReceiver) readLoop() {
	defer r.wg.Done()
	buf := make([]byte, maxHeartbeatSize)

	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		r.conn.SetReadDeadline(time.Now().Add(r.interval))
		n, _, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-r.stopCh:
				return
			default:
				slog.Debug("cluster: heartbeat read error", "err", err)
				continue
			}
		}

		pkt, err := UnmarshalHeartbeat(buf[:n])
		if err != nil {
			r.recvErrors.Add(1)
			slog.Warn("cluster: invalid heartbeat", "err", err)
			continue
		}

		// Validate cluster ID.
		if int(pkt.ClusterID) != r.mgr.ClusterID() {
			r.recvErrors.Add(1)
			slog.Warn("cluster: heartbeat from wrong cluster",
				"got", pkt.ClusterID, "want", r.mgr.ClusterID())
			continue
		}

		// A same-cluster heartbeat carrying OUR node-id is not a loopback on a
		// unicast point-to-point control link (a node never receives its own
		// frame) — it is a peer misconfigured with a duplicate node-id, an
		// INVALID cluster (#4549 F11). Surface it (rate-limited) so the
		// operator fixes /etc/xpf/node-id, then discard it: it cannot be told
		// apart from a stray loopback and a duplicate-node-id cluster is
		// unresolvable at runtime, so it must never drive election.
		if int(pkt.NodeID) == r.mgr.NodeID() {
			r.mgr.NoteDuplicateNodeIDHeartbeat()
			continue
		}

		// #4107 control-channel authentication. When a PSK is configured the
		// heartbeat/election channel is HMAC-authenticated; a forged or
		// replayed heartbeat is rejected HERE, before it can refresh peer
		// liveness (lastSeen) or drive election (handlePeerHeartbeat).
		// Dual-accept keeps a mixed-version / not-yet-keyed cluster from
		// splitting — see heartbeatAuthDecision. The key is never logged.
		key := r.mgr.controlLinkAuthKey()
		session, counter, present := heartbeatAuthTrailer(buf[:n])
		macOK := present && len(key) > 0 && verifyHeartbeatMAC(buf[:n], key)
		// #6169: the boot epoch is read ONLY from a MAC-verified frame — only a
		// verified frame authorises treating len-52 as the end of the signed
		// body — and the epoch floor is applied BEFORE the session ring so a
		// replayed retired incarnation never churns it.
		var (
			epoch    uint64
			hasEpoch bool
		)
		if macOK {
			epoch, hasEpoch = heartbeatFrameEpoch(buf[:n], key)
		}
		nonceFresh := macOK && r.auth.admitAuthed(hasEpoch, epoch, session, counter)
		accept, reason := heartbeatAuthDecision(len(key) > 0, present, macOK, nonceFresh, r.peerAuthenticated())
		if !accept {
			r.recvErrors.Add(1)
			// #6169: an authenticated frame that lost its epoch after the peer
			// had proved it signs one is operator-actionable (a deliberate
			// rollback stays refused until the floor is cleared), so surface it
			// distinctly instead of burying it in the generic replay reason.
			if macOK && !hasEpoch && r.auth.peerEpochLatched() {
				r.mgr.NoteEpochDowngradeHeartbeat()
			}
			slog.Warn("cluster: heartbeat auth rejected",
				"reason", reason, "peer_node", pkt.NodeID)
			continue
		}
		if macOK {
			// The peer proved it holds the key — from now on an
			// unauthenticated frame from it is a downgrade attack. This also
			// arms the gRPC fabric listener's downgrade-guard (via
			// Manager.HeartbeatPeerAuthSeen).
			r.auth.notePeerAuthenticated()
		}

		r.received.Add(1)
		// Store CLOCK_MONOTONIC, not wall clock: the timeout comparison
		// must be immune to wall-clock steps (#1792).
		r.lastSeen.Store(MonotonicNanos())
		r.mgr.handlePeerHeartbeat(pkt)
	}
}

func (r *heartbeatReceiver) timeoutLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.checkTimeout()
		}
	}
}

// checkTimeout runs one peer-liveness evaluation tick. Split out of
// timeoutLoop so the cold-boot never-seen floor and the steady-state
// staleness decision are unit testable without driving the ticker goroutine.
func (r *heartbeatReceiver) checkTimeout() {
	timeout := time.Duration(r.threshold) * r.interval
	lastNano := r.lastSeen.Load()
	if lastNano == 0 {
		// No heartbeat ever received. Deciding a peer NEVER EXISTED at boot
		// is not the same as a peer that WAS seen then went silent: on a
		// simultaneous cold boot the local config apply phase disrupts the
		// control-link RX for 10-15+ seconds, so the first heartbeats from a
		// live peer are dropped and lastSeen stays 0 on BOTH nodes. Promoting
		// at threshold*interval (~500ms) would then make BOTH claim primary
		// and the RETH virtual MAC — split-brain (#4386). Hold the never-seen
		// promotion behind the SAME cold-boot grace the seen-then-lost path
		// uses below. A genuinely-absent peer (single-node deployment, or a
		// peer that will never come up) still promotes once the grace elapses,
		// so this delays the decision, it never blocks it.
		// (r.startedAt is a direct time.Time, so time.Since uses its embedded
		// monotonic reading — already step-safe.)
		if neverSeenConfirmed(time.Since(r.startedAt), heartbeatStartupGrace) {
			r.mgr.handlePeerNeverSeen()
		}
		return
	}
	// During the cold-boot grace, suppress peer-lost entirely. The config
	// apply phase (VRF binding, FRR reload, fabric creation, RETH MAC) can
	// disrupt the UDP receive path on the control link for 10-15+ seconds.
	// Without this grace, the recovering node sees one peer heartbeat then
	// declares peer lost — creating split-brain. (r.startedAt is a direct
	// time.Time, so time.Since uses its embedded monotonic reading — already
	// step-safe.)
	if time.Since(r.startedAt) < heartbeatStartupGrace {
		return
	}
	// Compare in the CLOCK_MONOTONIC domain. The previous
	// time.Unix(0, lastNano) round-trip produced a Time with no monotonic
	// reading, making time.Since pure wall-clock — a forward step > timeout
	// fired a false peer-lost on a healthy cluster (#1792).
	if heartbeatStale(lastNano, MonotonicNanos(), timeout) {
		r.mgr.handlePeerTimeout()
	}
}

// neverSeenConfirmed reports whether a receiver that has never seen a peer
// heartbeat (lastSeen == 0) has waited out the cold-boot config-apply grace
// and may now confirm the peer absent to drive single-node election. It is a
// startup FLOOR, not a steady-state timeout: threshold*interval (~500ms) is
// correct for a peer that WAS seen then went silent, but far too aggressive
// for deciding a peer never existed at boot, where the first heartbeats are
// commonly dropped by the local config apply disruption (#4386). Returning
// true once sinceStart >= grace guarantees a genuinely-absent peer still
// promotes — the floor delays the never-seen decision, it never blocks it.
func neverSeenConfirmed(sinceStart, grace time.Duration) bool {
	return sinceStart >= grace
}

// heartbeatStale reports whether the last peer heartbeat is older than
// timeout. Both timestamps are CLOCK_MONOTONIC nanoseconds (MonotonicNanos),
// so the decision is immune to wall-clock steps. A nowMono earlier than
// lastSeenMono (cannot happen on a correct monotonic clock, but cheap to
// tolerate) yields a negative age and reports not-stale.
func heartbeatStale(lastSeenMono, nowMono int64, timeout time.Duration) bool {
	return time.Duration(nowMono-lastSeenMono) > timeout
}

// peerHeartbeatFresh reports whether a peer heartbeat has been received and is
// currently within the timeout window — i.e. NOT stale. It re-reads lastSeen
// against the live monotonic clock, so a heartbeat that landed since the
// timeout was first declared is observed. A receiver that has never seen a
// heartbeat (lastSeen == 0) is not "fresh".
//
// This is the truth source for handlePeerTimeout's post-guard re-check: after a
// slow guard window, the only correct question is "is the heartbeat fresh
// again?", not "is peerAlive still set?" (peerAlive is essentially always true
// at that point — a fresh heartbeat only keeps it true).
func (r *heartbeatReceiver) peerHeartbeatFresh() bool {
	lastNano := r.lastSeen.Load()
	if lastNano == 0 {
		return false
	}
	timeout := time.Duration(r.threshold) * r.interval
	return !heartbeatStale(lastNano, MonotonicNanos(), timeout)
}

func (r *heartbeatReceiver) stop() {
	close(r.stopCh)
	r.conn.Close()
	r.wg.Wait()
}
