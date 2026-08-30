package userspace

import (
	"time"
)

type HAStateUpdateRequest struct {
	Groups []HAGroupStatus `json:"groups,omitempty"`
}

type HAGroupStatus struct {
	RGID              int    `json:"rg_id"`
	Active            bool   `json:"active"`
	WatchdogTimestamp uint64 `json:"watchdog_timestamp,omitempty"`
	// #1642: lease-telemetry fields the Rust helper serializes on
	// HAGroupStatus (protocol/binding.rs). Observability only — the HA
	// failover *decision* is taken from BPF maps via mergeHAStateFromMaps,
	// not from these. JSON tags MUST match the Rust serde rename(...) exactly.
	ForwardingActive bool   `json:"forwarding_active,omitempty"`
	LeaseState       string `json:"lease_state,omitempty"`
	LeaseUntil       uint64 `json:"lease_until,omitempty"`
}

type SessionDeltaDrainRequest struct {
	Max uint32 `json:"max,omitempty"`
}

type SessionExportRequest struct {
	OwnerRGs []int  `json:"owner_rgs,omitempty"`
	Max      uint32 `json:"max,omitempty"`
}

type SessionSyncRequest struct {
	Operation   string `json:"operation,omitempty"`
	AddrFamily  uint8  `json:"addr_family,omitempty"`
	Protocol    uint8  `json:"protocol,omitempty"`
	SrcIP       string `json:"src_ip,omitempty"`
	DstIP       string `json:"dst_ip,omitempty"`
	SrcPort     uint16 `json:"src_port,omitempty"`
	DstPort     uint16 `json:"dst_port,omitempty"`
	IngressZone string `json:"ingress_zone,omitempty"`
	EgressZone  string `json:"egress_zone,omitempty"`
	// #919/#922: u16 zone-id mirrors. Additive — the Rust daemon
	// prefers the IDs when nonzero and falls back to the legacy
	// name strings otherwise. Old peers without these fields
	// continue to work (Rust serde sets the IDs to 0).
	IngressZoneID uint16 `json:"ingress_zone_id,omitempty"`
	EgressZoneID  uint16 `json:"egress_zone_id,omitempty"`
	// #7095: the LOCAL ingress identity a peer-imported session should carry,
	// resolved on THIS node from the cluster-stable fold the sender put on the
	// wire. #6928 deliberately imported 0 because the sender's IFINDEX is
	// node-local and would name a different NIC here; these are this node's own
	// numbers for the interface the peer named, so they are safe to store.
	//
	// Additive and omitempty, like the zone-id mirrors above: an older helper
	// decodes them via serde(default) to 0 and keeps the pre-#7095 behaviour of
	// recording no ingress identity.
	IngressIfindex   int    `json:"ingress_ifindex,omitempty"`
	IngressVLANID    uint16 `json:"ingress_vlan_id,omitempty"`
	OwnerRGID        int    `json:"owner_rg_id,omitempty"`
	EgressIfindex    int    `json:"egress_ifindex,omitempty"`
	TXIfindex        int    `json:"tx_ifindex,omitempty"`
	TunnelEndpointID uint16 `json:"tunnel_endpoint_id,omitempty"`
	TXVLANID         uint16 `json:"tx_vlan_id,omitempty"`
	NextHop          string `json:"next_hop,omitempty"`
	NeighborMAC      string `json:"neighbor_mac,omitempty"`
	SrcMAC           string `json:"src_mac,omitempty"`
	NATSrcIP         string `json:"nat_src_ip,omitempty"`
	NATDstIP         string `json:"nat_dst_ip,omitempty"`
	NATSrcPort       uint16 `json:"nat_src_port,omitempty"`
	NATDstPort       uint16 `json:"nat_dst_port,omitempty"`
	FabricIngress    bool   `json:"fabric_ingress,omitempty"`
	IsReverse        bool   `json:"is_reverse,omitempty"`
	// #2785: the admitting policy's per-policy `then log` selection, carried
	// so a session synced to the peer logs the same RT_FLOW
	// SESSION_CREATE/CLOSE records after failover. omitempty is safe — an old
	// helper without these keys decodes them via serde(default) to false (no
	// per-policy log), bit-identical to pre-#2785 behavior.
	LogSessionInit  bool `json:"log_session_init,omitempty"`
	LogSessionClose bool `json:"log_session_close,omitempty"`
	// Generation carries the #2170 HA install generation to the helper so
	// its in-memory SyncedSessionEntry can mirror the cluster apply layer's
	// generation guard (belt-and-suspenders for helper-originated deletes
	// and the delayed-stale-install variant). Plain uint64 with NO
	// omitempty: a 0 value MUST serialize as 0 (legacy/unknown) so an old
	// helper without the field still decodes via serde(default), and a new
	// helper sees an explicit 0 rather than a missing key — the #1961
	// wire-type discipline (no omitempty ambiguity on a numeric field). The
	// Rust side declares `#[serde(default)] generation: u64`.
	Generation uint64 `json:"generation"`
	// #3301: the admitting policy's firewall metadata, carried so a
	// peer-PROMOTED session is correctly attributed, counted, and aged after
	// failover instead of degrading to policy 0 / no counter / the global
	// timeout. omitempty is safe — an old helper without these keys decodes
	// them via serde(default) to 0, which is the legitimate "unattributed /
	// no per-rule counter / use-global-timeout" value, bit-identical to the
	// pre-#3301 synced-session behavior (rolling-upgrade safe).
	//
	// PolicyID is the admitting policy ID (#3056 namespace). PolicyCounterIdx
	// is the 1-based per-rule hit-counter handle (#3073); HA requires
	// identical config on both nodes so the same idx resolves the same rule.
	// InactivityTimeout is the per-application idle timeout in SECONDS (#3227,
	// matching SessionValue.AppTimeout); the helper converts it to ns.
	PolicyID          uint32 `json:"policy_id,omitempty"`
	PolicyCounterIdx  uint32 `json:"policy_counter_idx,omitempty"`
	InactivityTimeout uint32 `json:"inactivity_timeout,omitempty"`
	// #4565: the NAT64 translated pool SOURCE (dotted-quad IPv4). A non-empty
	// value is the peer helper's signal that this is a NAT64 cross-family
	// session — it sets nat.nat64, rewrites the forward source to this v4 pool
	// address, and reconstructs the reverse (v4->v6) BIB (orig v6 src/dst from
	// the synced forward v6 key, dst_v4 from the /96-embedded low 32 of the key
	// dst). This is the one part of the reverse mapping not carried by the
	// synced forward key. omitempty is safe — an old helper without the key
	// decodes it via serde(default) to "" (not NAT64), bit-identical to
	// pre-#4565 (rolling-upgrade safe).
	Nat64SnatV4 string `json:"nat64_snat_v4,omitempty"`
	// #5212: the ORIGINATING node's stable RT_FLOW session id (the dataplane's
	// alloc_session_id value). Carried so a peer-PROMOTED session ADOPTS the
	// originating node's id rather than minting a fresh node-local one on import
	// — its RT_FLOW SESSION_CREATE (origin node) and SESSION_CLOSE (possibly the
	// peer, after failover) then share one correlatable id. The helper stamps it
	// onto the imported entry (build_synced_session_entry). omitempty is safe —
	// an old helper without the key decodes it via serde(default) to 0, the "no
	// id carried" sentinel that falls back to a fresh local id (rolling-upgrade
	// safe). The Rust side declares `#[serde(rename = "session_id", default)]`.
	RTFlowSessionID uint64 `json:"session_id,omitempty"`
}

// SessionDeltaInfo is the HA session-open/close delta as it reaches this
// daemon. ONE Go struct serves BOTH transports (#7194):
//
//   - the BINARY open frame (userspace-dp event_stream/codec/session_sync.rs),
//     decoded by decodeSessionEvent in eventstream.go. Positional little-endian
//     bytes behind a length prefix and NO version field; trailing fields are
//     tolerated by per-field length gates, so a decoder can only survive fields
//     appended at the TAIL.
//   - the JSON RPC-fallback delta (userspace-dp protocol/binding.rs
//     SessionDeltaInfo), drained every 100ms while the binary stream is down and
//     every 5s as reconciliation while it is up, plus every helper-requested
//     FullResync export.
//
// Both legs come from the SAME helper process, so they share its schema.
//
// The transports are kept equivalent by two artefacts, and it is worth being
// precise about which does what, because one is build-time and one is runtime:
//
//   - session_delta_transport_parity_7194_test.go (#8043) compares the Rust
//     JSON producer's wire names against this struct's json tags. It is a
//     BUILD-TIME check between two source trees. It cannot see what a RUNNING
//     helper actually carries.
//   - the DERIVED schema fingerprint (session_delta_schema.go, #7194) is the
//     RUNTIME half: the helper advertises a hash of its own wire-name set on
//     ProcessStatus, and a mismatch withholds the sync instead of installing a
//     record whose zeros mean "field not carried" rather than "no value".
//
// The second exists because a zero is ambiguous at the consumer: policy_id 0
// means BOTH "no policy attribution" and "this producer does not carry the
// field". #5865 shipped five such fields on the binary leg and not the JSON
// leg, and #5212 -> #6312 shipped rt_flow_session_id one issue apart, each
// without a version bump — because there was no version to bump.
type SessionDeltaInfo struct {
	Timestamp   time.Time `json:"timestamp"`
	Slot        uint32    `json:"slot"`
	QueueID     uint32    `json:"queue_id"`
	WorkerID    uint32    `json:"worker_id"`
	Interface   string    `json:"interface,omitempty"`
	Ifindex     int       `json:"ifindex,omitempty"`
	Event       string    `json:"event"`
	AddrFamily  uint8     `json:"addr_family,omitempty"`
	Protocol    uint8     `json:"protocol,omitempty"`
	SrcIP       string    `json:"src_ip,omitempty"`
	DstIP       string    `json:"dst_ip,omitempty"`
	SrcPort     uint16    `json:"src_port,omitempty"`
	DstPort     uint16    `json:"dst_port,omitempty"`
	IngressZone string    `json:"ingress_zone,omitempty"`
	EgressZone  string    `json:"egress_zone,omitempty"`
	// #919/#922: u16 zone-id mirrors decoded directly from the binary
	// event-stream payload (bytes [21],[22] u8 → u16 here for symmetry
	// with SessionSyncRequest). The HA delta path prefers these IDs;
	// the legacy strings stay populated when JSON callers fill them.
	IngressZoneID    uint16 `json:"ingress_zone_id,omitempty"`
	EgressZoneID     uint16 `json:"egress_zone_id,omitempty"`
	OwnerRGID        int    `json:"owner_rg_id,omitempty"`
	Disposition      string `json:"disposition,omitempty"`
	Origin           string `json:"origin,omitempty"`
	EgressIfindex    int    `json:"egress_ifindex,omitempty"`
	TXIfindex        int    `json:"tx_ifindex,omitempty"`
	TunnelEndpointID uint16 `json:"tunnel_endpoint_id,omitempty"`
	TXVLANID         uint16 `json:"tx_vlan_id,omitempty"`
	NextHop          string `json:"next_hop,omitempty"`
	NeighborMAC      string `json:"neighbor_mac,omitempty"`
	SrcMAC           string `json:"src_mac,omitempty"`
	NATSrcIP         string `json:"nat_src_ip,omitempty"`
	NATDstIP         string `json:"nat_dst_ip,omitempty"`
	NATSrcPort       uint16 `json:"nat_src_port,omitempty"`
	NATDstPort       uint16 `json:"nat_dst_port,omitempty"`
	FabricRedirect   bool   `json:"fabric_redirect,omitempty"`
	FabricIngress    bool   `json:"fabric_ingress,omitempty"`
	// #2785: the admitting policy's per-policy `then log` selection. Decoded
	// from the binary open-frame flags byte (bits 1<<3/1<<4) AND mirrored on
	// the JSON RPC-fallback delta; stamped onto the synced session's
	// LogFlags so it logs identically after failover.
	LogSessionInit  bool `json:"log_session_init,omitempty"`
	LogSessionClose bool `json:"log_session_close,omitempty"`
	// #3301: the admitting policy's firewall metadata, decoded from the
	// trailing fields of the binary open frame (after NextHop) AND — since
	// #6949 — mirrored on the JSON RPC-fallback delta. Stamped onto the synced
	// SessionValue (PolicyID/PolicyCounterIdx/AppTimeout) by
	// daemon_ha_userspace.go so the cluster sync wire and the peer helper carry
	// them, correcting a peer-promoted session's policy attribution /
	// hit-count / idle timeout after failover. PolicyID = #3056 policy ID;
	// PolicyCounterIdx = #3073 1-based per-rule counter handle; AppTimeout =
	// #3227 per-application idle timeout in SECONDS.
	//
	// The "AND mirrored on the JSON RPC-fallback delta" half of that sentence
	// was FALSE from #3301 until #6949: the Rust producer
	// (userspace-dp/src/protocol/binding.rs) had no such fields, so that leg —
	// drained every 100 ms while the event stream is down, every 5 s while it
	// is up, and re-serialized whole on every helper-requested FullResync —
	// delivered all three as 0 on every session it carried. Nothing surfaced
	// it: a rendered id of 0 displays as `unattributed` (#6851), the same as a
	// session no policy admitted. Auditing this leg from the consumer side, as
	// the natural reading of this comment invited, concluded it was already at
	// parity. Since #6949 both producers derive these from ONE helper
	// (`session::SessionSyncAttribution`) and destructure it exhaustively, so a
	// divergence no longer compiles, and
	// TestSessionDeltaPolicyAttributionWireKeysLockstepWithRust6949 pins these
	// struct tags to the keys that helper's JSON leg actually emits.
	PolicyID         uint32 `json:"policy_id,omitempty"`
	PolicyCounterIdx uint32 `json:"policy_counter_idx,omitempty"`
	AppTimeout       uint32 `json:"app_timeout,omitempty"`
	// #4565: NAT64 cross-family marker (open-frame flags bit 1<<5) + the
	// translated pool SOURCE (trailing 4 bytes). Stamped onto the synced
	// SessionValueV6 (SessFlagNAT64 + Nat64SnatV4) by daemon_ha_userspace.go so
	// the cluster sync wire and the peer helper carry them, letting a
	// peer-PROMOTED NAT64 session rebuild its reverse (v4->v6) BIB after
	// failover. Nat64SnatV4 is the one datum not reconstructable from the synced
	// forward v6 key (the orig v6 src/dst ARE the key; dst_v4 is the /96 low 32).
	// Also mirrored on the JSON RPC-fallback delta since #6949; before that a
	// NAT64 session promoted from that leg could not rebuild its reverse BIB at
	// all — a translation failure after failover, not a mis-attribution.
	Nat64       bool   `json:"nat64,omitempty"`
	Nat64SnatV4 string `json:"nat64_snat_v4,omitempty"`
	// #5212: the ORIGINATING node's stable RT_FLOW session id, decoded from the
	// trailing u64 of the binary open frame (after the #4565 snat_v4) AND —
	// since #6312 — from the JSON RPC-fallback delta, whose Rust producer
	// declares `#[serde(rename = "rt_flow_session_id")]` on
	// SessionDeltaInfo.rt_flow_session_id. The two spellings are held in
	// agreement by TestSessionDeltaRTFlowSessionIDWireKeyLockstepWithRust6312;
	// before #6312 the JSON leg carried no id at all, so a session recovered
	// through the drain_session_deltas polling fallback or the owner-RG resync
	// export lost its cross-node correlation. Stamped onto the synced
	// SessionValue{,V6}.RTFlowSessionID by daemon_ha_userspace.go so the cluster
	// sync wire and the peer helper carry it, letting a peer-synced session adopt
	// the originating node's id (SESSION_CREATE/CLOSE correlate across HA nodes).
	// Absent on an old helper => 0, the standby allocs a fresh local id
	// (pre-#5212 behavior, rolling-upgrade safe).
	RTFlowSessionID uint64 `json:"rt_flow_session_id,omitempty"`
}
