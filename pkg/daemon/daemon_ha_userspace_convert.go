package daemon

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// buildZoneIDs replicates the dataplane compiler's STABLE zone ID assignment
// (#3075): config.StableZoneID(name), a pure FNV-1a fold of the zone NAME into
// [1, ZoneIDReservedMin-1]. It MUST stay byte-identical to
// pkg/dataplane.assignZoneIDs so an HA session delta resolves to the same local
// id the compiler installed (enforced by an HA-symmetry test). The id is a pure
// function of the name — never of the zone set or compile order — so both nodes
// agree by construction and an earlier-sorting zone add/remove never renumbers
// a surviving zone's in-flight session metadata (the sorted-positional defect
// this replaces).
func buildZoneIDs(cfg *config.Config) map[string]uint16 {
	ids := make(map[string]uint16, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		ids[name] = config.StableZoneID(name)
	}
	return ids
}

func daemonMonotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

// userspaceSyncedSessionIDNamespace reserves the high 16 bits of the node-local
// BPF-ABI SessionID minted for an HA-synced session (#6198).
//
// The Rust dataplane's own stable id (`SessionTable::alloc_session_id`, #4915 —
// carried across the cluster wire as the DISTINCT RTFlowSessionID, #5212) is
// `(worker_id & 0xFFFF) << 48 | counter48`, where `worker_id` is a worker/queue
// index (`set_worker_id`, userspace-dp/src/session/mod.rs). Reserving 0xFFFF for
// the Go-minted ids keeps the two id spaces disjoint inside the shared BPF
// conntrack mirror: the helper stamps its own id for sessions it owns, the
// control plane stamps one of these for a peer-synced session it installs, and
// neither can ever alias the other.
const userspaceSyncedSessionIDNamespace = uint64(0xFFFF) << 48

// userspaceSyncedSessionIDCounterMask is the low-48-bit counter space inside
// that namespace — the same width the dataplane allocator uses.
const userspaceSyncedSessionIDCounterMask = uint64(0x0000_FFFF_FFFF_FFFF)

// userspaceSyncedSessionIDSeedShift is how far the boot clock is shifted to seed
// the counter, i.e. how much counter space each SECOND of system uptime claims:
// 2^24 ≈ 16.7M ids.
const userspaceSyncedSessionIDSeedShift = 24

// userspaceSyncedSessionIDSeed returns the counter value a daemon incarnation
// starts from, given the system uptime in seconds at which it began.
//
// A bare counter starting at 0 would make ids REPEAT across an xpfd restart: the
// new incarnation re-mints 1, 2, 3… while entries the peer's conntrack mirror
// still holds from the previous incarnation (sessions this node closed while it
// was down, whose keys the post-restart bulk re-export never overwrites) carry
// exactly those values. The old now<<16|Slot composition did NOT have that flaw,
// because CLOCK_MONOTONIC is system uptime and keeps increasing across a daemon
// restart — so seeding is what keeps this change a strict improvement rather than
// a trade.
//
// Seeding from the same boot clock restores the property. Each second of uptime
// advances the seed by 2^24, so a restarting incarnation starts above its
// predecessor's high-water mark unless that predecessor averaged more than ~16.7M
// synced-session conversions PER SECOND — orders of magnitude above what the
// dataplane can produce (MAX_SESSIONS is 10M in total). The mask bounds the seed
// to the 48-bit counter space; it wraps after 2^24 seconds (~194 days) of uptime,
// and a wrap can only alias ids minted ~194 days earlier, long since aged out of
// any mirror.
func userspaceSyncedSessionIDSeed(monotonicSeconds uint64) uint64 {
	return (monotonicSeconds << userspaceSyncedSessionIDSeedShift) & userspaceSyncedSessionIDCounterMask
}

// userspaceSyncedSessionIDs is the node-local monotonic allocator behind
// nextUserspaceSyncedSessionID, seeded from the boot clock on first use.
var (
	userspaceSyncedSessionIDs    atomic.Uint64
	userspaceSyncedSessionIDOnce sync.Once
)

// nextUserspaceSyncedSessionID mints the node-local BPF-ABI SessionID stamped on
// a session converted from a userspace-helper delta (#6198).
//
// It replaces the previous `uint64(now)<<16 | uint64(delta.Slot&0xffff)`
// composition, which was NOT an identity at all: `delta.Slot` is the AF_XDP
// BINDING slot (`BindingIdentity.slot`, userspace-dp/src/afxdp/session_delta.rs
// — one per interface/queue, a handful per node), and the binary event stream
// that carries the primary delta path never decodes it at all
// (`decodeSessionEvent` in pkg/dataplane/userspace/eventstream.go leaves it 0).
// Every session converted within the same monotonic SECOND therefore collapsed
// onto ONE id, conflating unrelated flows in `show security flow session` and in
// the REST/gRPC session views. A monotonic counter gives every CONVERSION a
// distinct id — see the per-conversion note below.
//
// The counter is seeded from the boot clock on first use
// (userspaceSyncedSessionIDSeed) so ids do not repeat across an xpfd restart
// either. It is masked to 48 bits and never returns 0 (`0` is the established
// "no id / unknown" sentinel that makes `flowSessionDisplayID` fall back to the
// per-row ordinal), so even the unreachable wrap case stays well-formed rather
// than aliasing the namespace bits or emitting the sentinel.
//
// The id is per CONVERSION, not stable per session: a bulk resync re-converts
// live sessions and re-stamps them with fresh ids, and the `close` branch of
// queueUserspaceSessionDeltas converts purely to derive the key and discards the
// id it mints. Both are harmless in a 48-bit space, and the old composition
// churned the id the same way — what changed is that concurrent sessions no
// longer SHARE one.
//
// This id stays NODE-LOCAL by design: the cross-node correlatable id is the
// separate RTFlowSessionID (#5212), which rides its own wire field and is
// adopted verbatim by the peer helper. See docs/session-sync-architecture.md.
func nextUserspaceSyncedSessionID() uint64 {
	userspaceSyncedSessionIDOnce.Do(func() {
		userspaceSyncedSessionIDs.Store(userspaceSyncedSessionIDSeed(daemonMonotonicSeconds()))
	})
	counter := userspaceSyncedSessionIDs.Add(1) & userspaceSyncedSessionIDCounterMask
	if counter == 0 {
		counter = 1
	}
	return userspaceSyncedSessionIDNamespace | counter
}

func userspaceSessionTimeout(proto uint8) uint32 {
	switch proto {
	case 6:
		return 300
	case 17:
		return 60
	case 1, 58:
		return 15
	default:
		return 30
	}
}

func userspaceHostToNetwork16(v uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	return binary.NativeEndian.Uint16(raw[:])
}

func userspaceNetworkToHost16(v uint16) uint16 {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], v)
	return binary.BigEndian.Uint16(raw[:])
}

func userspaceReverseKeyV4(key dataplane.SessionKey, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKey {
	rev := dataplane.SessionKey{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		copy(rev.SrcIP[:], ip)
	}
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		copy(rev.DstIP[:], ip)
	}
	if delta.NATDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(delta.NATDstPort)
	}
	if delta.NATSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(delta.NATSrcPort)
	}
	return rev
}

func userspaceForwardWireKeyV4(key dataplane.SessionKey, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKey {
	wire := key
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		copy(wire.SrcIP[:], ip)
		wire.SrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		copy(wire.DstIP[:], ip)
		wire.DstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	return wire
}

func effectiveUserspaceNATSrcPort(delta dpuserspace.SessionDeltaInfo) uint16 {
	if delta.NATSrcPort != 0 {
		return delta.NATSrcPort
	}
	if delta.NATSrcIP != "" {
		return delta.SrcPort
	}
	return 0
}

func effectiveUserspaceNATDstPort(delta dpuserspace.SessionDeltaInfo) uint16 {
	if delta.NATDstPort != 0 {
		return delta.NATDstPort
	}
	if delta.NATDstIP != "" {
		return delta.DstPort
	}
	return 0
}

func userspaceReverseKeyV6(key dataplane.SessionKeyV6, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKeyV6 {
	rev := dataplane.SessionKeyV6{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		copy(rev.SrcIP[:], ip)
	}
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		copy(rev.DstIP[:], ip)
	}
	if delta.NATDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(delta.NATDstPort)
	}
	if delta.NATSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(delta.NATSrcPort)
	}
	return rev
}

func userspaceParseSyncMAC(raw string) [6]byte {
	var out [6]byte
	if raw == "" {
		return out
	}
	mac, err := net.ParseMAC(raw)
	if err != nil || len(mac) != len(out) {
		return out
	}
	copy(out[:], mac)
	return out
}

func userspaceSessionFromDeltaV4(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	src := net.ParseIP(delta.SrcIP).To4()
	dst := net.ParseIP(delta.DstIP).To4()
	if src == nil || dst == nil {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	var key dataplane.SessionKey
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	// #919/#922: prefer the u16 zone IDs from the binary event-stream
	// payload (decoded by eventstream.go; #3075 widened that wire field to
	// u16); fall back to legacy name-string lookup for older helpers that
	// emit JSON deltas only.
	ingressZone := delta.IngressZoneID
	if ingressZone == 0 {
		ingressZone = zoneIDs[delta.IngressZone]
	}
	egressZone := delta.EgressZoneID
	if egressZone == 0 {
		egressZone = zoneIDs[delta.EgressZone]
	}
	if ingressZone == 0 || egressZone == 0 {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValue{
		State: 4, // SESS_STATE_ESTABLISHED
		// SessionID is the BPF-ABI conntrack id: node-local, and unique per
		// converted session since #6198 (the previous now<<16|Slot composition
		// collapsed every session converted in the same second onto one id).
		SessionID: nextUserspaceSyncedSessionID(),
		// #5212: the ORIGINATING node's stable RT_FLOW session id (distinct from
		// SessionID above). Carried across the cluster sync wire so a peer-synced
		// session adopts it and its SESSION_CREATE/CLOSE records correlate across
		// nodes. 0 on a legacy helper => a fresh local id is allocated on import.
		RTFlowSessionID: delta.RTFlowSessionID,
		Created:         now,
		LastSeen:        now,
		Timeout:         userspaceSessionTimeout(delta.Protocol),
		IngressZone:     ingressZone,
		EgressZone:      egressZone,
		ReverseKey:      userspaceReverseKeyV4(key, delta),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = userspaceParseSyncMAC(delta.NeighborMAC)
	val.FibSmac = userspaceParseSyncMAC(delta.SrcMAC)
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		val.Flags |= dataplane.SessFlagSNAT
		val.NATSrcIP = binary.NativeEndian.Uint32(ip)
		val.NATSrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		val.Flags |= dataplane.SessFlagDNAT
		val.NATDstIP = binary.NativeEndian.Uint32(ip)
		val.NATDstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	// #2785: stamp the admitting policy's per-policy `then log` selection
	// onto the synced session so it emits the same RT_FLOW
	// SESSION_CREATE/CLOSE records after failover. These bits ride the
	// cluster wire on LogFlags and are re-applied to the peer helper's
	// SyncedSessionEntry via buildSessionSyncRequest.
	if delta.LogSessionInit {
		val.LogFlags |= dataplane.LogFlagSessionInit
	}
	if delta.LogSessionClose {
		val.LogFlags |= dataplane.LogFlagSessionClose
	}
	// #3301: carry the admitting policy's firewall metadata so a peer-promoted
	// session is correctly attributed (PolicyID), counted (PolicyCounterIdx),
	// and aged (AppTimeout = per-application idle timeout, seconds) after
	// failover instead of degrading to policy 0 / no counter / global timeout.
	val.PolicyID = delta.PolicyID
	val.PolicyCounterIdx = delta.PolicyCounterIdx
	val.AppTimeout = delta.AppTimeout
	return key, val, true
}

// userspaceForwardWireAliasV4 derives the fabric-redirect forward-wire alias
// entry from an ALREADY-CONVERTED base session.
//
// It takes the converted base rather than re-converting the delta because
// nextUserspaceSyncedSessionID mints a FRESH id per conversion (#6198): a second
// conversion of the same delta would split one logical session across two
// SessionIDs, where the alias and its base entry must share one. It also drops a
// redundant conversion from the delta path.
func userspaceForwardWireAliasV4(key dataplane.SessionKey, val dataplane.SessionValue, delta dpuserspace.SessionDeltaInfo) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	wireKey := userspaceForwardWireKeyV4(key, delta)
	if wireKey == key {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	return wireKey, val, true
}

func userspaceSessionFromDeltaV6(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	src := net.ParseIP(delta.SrcIP).To16()
	dst := net.ParseIP(delta.DstIP).To16()
	if src == nil || dst == nil {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	var key dataplane.SessionKeyV6
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	// #919/#922: prefer the u16 zone IDs from the binary event-stream
	// payload; fall back to legacy name-string lookup for JSON deltas.
	ingressZone := delta.IngressZoneID
	if ingressZone == 0 {
		ingressZone = zoneIDs[delta.IngressZone]
	}
	egressZone := delta.EgressZoneID
	if egressZone == 0 {
		egressZone = zoneIDs[delta.EgressZone]
	}
	if ingressZone == 0 || egressZone == 0 {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValueV6{
		State: 4, // SESS_STATE_ESTABLISHED
		// SessionID is the BPF-ABI conntrack id: node-local, and unique per
		// converted session since #6198 (see the V4 converter).
		SessionID: nextUserspaceSyncedSessionID(),
		// #5212: the ORIGINATING node's stable RT_FLOW session id (see V4) —
		// adopted by a peer-synced session so its RT_FLOW records correlate
		// across HA nodes; 0 on a legacy helper => fresh local id on import.
		RTFlowSessionID: delta.RTFlowSessionID,
		Created:         now,
		LastSeen:        now,
		Timeout:         userspaceSessionTimeout(delta.Protocol),
		IngressZone:     ingressZone,
		EgressZone:      egressZone,
		ReverseKey:      userspaceReverseKeyV6(key, delta),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = userspaceParseSyncMAC(delta.NeighborMAC)
	val.FibSmac = userspaceParseSyncMAC(delta.SrcMAC)
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		val.Flags |= dataplane.SessFlagSNAT
		copy(val.NATSrcIP[:], ip)
		val.NATSrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		val.Flags |= dataplane.SessFlagDNAT
		copy(val.NATDstIP[:], ip)
		val.NATDstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	// #2785: stamp the per-policy `then log` selection (see V4).
	if delta.LogSessionInit {
		val.LogFlags |= dataplane.LogFlagSessionInit
	}
	if delta.LogSessionClose {
		val.LogFlags |= dataplane.LogFlagSessionClose
	}
	// #3301: carry the admitting policy's firewall metadata (see V4).
	val.PolicyID = delta.PolicyID
	val.PolicyCounterIdx = delta.PolicyCounterIdx
	val.AppTimeout = delta.AppTimeout
	// #4565: stamp the NAT64 translated pool SOURCE so the cluster wire + peer
	// helper carry it, letting a peer-PROMOTED NAT64 session rebuild its reverse
	// (v4->v6) BIB after failover. Non-empty delta.Nat64SnatV4 (decoded from the
	// FLAG_NAT64 open frame) marks a NAT64 cross-family session.
	if ip := net.ParseIP(delta.Nat64SnatV4).To4(); ip != nil {
		copy(val.Nat64SnatV4[:], ip)
	}
	return key, val, true
}

func userspaceForwardWireKeyV6(key dataplane.SessionKeyV6, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKeyV6 {
	wire := key
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		copy(wire.SrcIP[:], ip)
		wire.SrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		copy(wire.DstIP[:], ip)
		wire.DstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	return wire
}

// userspaceForwardWireAliasV6 is the V6 twin of userspaceForwardWireAliasV4 —
// same reason for taking the already-converted base (#6198).
func userspaceForwardWireAliasV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, delta dpuserspace.SessionDeltaInfo) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	wireKey := userspaceForwardWireKeyV6(key, delta)
	if wireKey == key {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	return wireKey, val, true
}
