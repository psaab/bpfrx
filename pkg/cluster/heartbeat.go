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
	if len(authKey) == 0 {
		return marshalHeartbeatBody(pkt, 0)
	}
	// Reserve the trailer up front so the signed frame is guaranteed to fit.
	body := marshalHeartbeatBody(pkt, heartbeatAuthTrailerSize)
	if len(body)+heartbeatAuthTrailerSize > maxHeartbeatSize {
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
	// Sign the body PLUS magic+session+counter (everything but the digest), so
	// the nonce and the whole packet are bound by the MAC.
	mac := hmac.New(sha256.New, authKey)
	mac.Write(body)
	mac.Write(trailer[:20])
	copy(trailer[20:], mac.Sum(nil))

	out := make([]byte, 0, len(body)+heartbeatAuthTrailerSize)
	out = append(out, body...)
	out = append(out, trailer...)
	return out
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

// heartbeatAuthReplay tracks per-peer anti-replay state for authenticated
// heartbeats. A sender advertises a random per-process session id and a
// monotonic per-session counter (MarshalHeartbeatAuth). The receiver accepts a
// strictly increasing counter within a session and RE-ANCHORS on a new session
// id — a sender restart/reboot picks a fresh random session, so a genuine
// reboot (a routine HA event) is never mistaken for a replay and failover is
// never wedged. Touched only from the single readLoop goroutine.
type heartbeatAuthReplay struct {
	session uint64
	counter uint64
	seen    bool
}

// admit reports whether (session, counter) is fresh (not a replay) and, when
// fresh, advances the watermark. Callers must invoke admit only after the MAC
// has verified — an unauthenticated caller must never mutate replay state.
func (a *heartbeatAuthReplay) admit(session, counter uint64) bool {
	if !a.seen || session != a.session {
		a.session = session
		a.counter = counter
		a.seen = true
		return true
	}
	if counter > a.counter {
		a.counter = counter
		return true
	}
	return false
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

	// #4107 anti-replay: a random per-process session id plus a monotonic
	// per-session counter. A new sender (StartHeartbeat/RestartHeartbeat)
	// re-seeds authSession so the receiver re-anchors after a restart/reboot.
	authSession uint64
	authCounter atomic.Uint64
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

	// #4107 control-channel auth state. authReplay is touched only from
	// readLoop. peerAuthSeen is written from readLoop but READ cross-goroutine
	// (Manager.HeartbeatPeerAuthSeen, consumed by the gRPC fabric listener to
	// arm its downgrade-guard off the fast-arming heartbeat instead of the
	// lazily-arming on-demand fabric RPCs), so it is an atomic.
	authReplay   heartbeatAuthReplay // per-peer anti-replay watermark
	peerAuthSeen atomic.Bool         // sticky: peer has sent a valid authed HB
}

// peerAuthenticated reports whether the peer has ever sent a valid
// HMAC-authenticated heartbeat (sticky). It proves the peer holds the
// control-link PSK and is signing — the arming signal the gRPC fabric
// listener reuses so its downgrade-guard engages within ~one heartbeat
// interval of the peer coming up, not on the next on-demand fabric RPC.
func (r *heartbeatReceiver) peerAuthenticated() bool {
	return r.peerAuthSeen.Load()
}

func newHeartbeatSender(mgr *Manager, conn *net.UDPConn, peerAddr *net.UDPAddr, interval time.Duration) *heartbeatSender {
	return &heartbeatSender{
		mgr:         mgr,
		conn:        conn,
		peerAddr:    peerAddr,
		interval:    interval,
		stopCh:      make(chan struct{}),
		authSession: randomSessionID(),
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
		data = MarshalHeartbeatAuth(pkt, key, s.authSession, s.authCounter.Add(1))
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
		nonceFresh := macOK && r.authReplay.admit(session, counter)
		accept, reason := heartbeatAuthDecision(len(key) > 0, present, macOK, nonceFresh, r.peerAuthSeen.Load())
		if !accept {
			r.recvErrors.Add(1)
			slog.Warn("cluster: heartbeat auth rejected",
				"reason", reason, "peer_node", pkt.NodeID)
			continue
		}
		if macOK {
			// The peer proved it holds the key — from now on an
			// unauthenticated frame from it is a downgrade attack. This also
			// arms the gRPC fabric listener's downgrade-guard (via
			// Manager.HeartbeatPeerAuthSeen).
			r.peerAuthSeen.Store(true)
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
