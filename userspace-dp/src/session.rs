use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
use crate::nat::NatDecision;
use crate::nat64::Nat64ReverseInfo;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

const SESSION_GC_INTERVAL_NS: u64 = 1_000_000_000;
const DEFAULT_MAX_SESSIONS: usize = 131072;
const DEFAULT_TCP_SESSION_TIMEOUT_NS: u64 = 300_000_000_000;
const TCP_CLOSING_TIMEOUT_NS: u64 = 30_000_000_000;
const DEFAULT_UDP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const DEFAULT_ICMP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const OTHER_SESSION_TIMEOUT_NS: u64 = 30_000_000_000;

/// Configurable session timeout values (in nanoseconds).
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionTimeouts {
    pub(crate) tcp_established_ns: u64,
    pub(crate) udp_ns: u64,
    pub(crate) icmp_ns: u64,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            tcp_established_ns: DEFAULT_TCP_SESSION_TIMEOUT_NS,
            udp_ns: DEFAULT_UDP_SESSION_TIMEOUT_NS,
            icmp_ns: DEFAULT_ICMP_SESSION_TIMEOUT_NS,
        }
    }
}

impl SessionTimeouts {
    /// Build from snapshot timeout values (in seconds). A value of 0 means use
    /// the default.
    pub(crate) fn from_seconds(tcp_secs: u64, udp_secs: u64, icmp_secs: u64) -> Self {
        Self {
            tcp_established_ns: if tcp_secs > 0 {
                tcp_secs * 1_000_000_000
            } else {
                DEFAULT_TCP_SESSION_TIMEOUT_NS
            },
            udp_ns: if udp_secs > 0 {
                udp_secs * 1_000_000_000
            } else {
                DEFAULT_UDP_SESSION_TIMEOUT_NS
            },
            icmp_ns: if icmp_secs > 0 {
                icmp_secs * 1_000_000_000
            } else {
                DEFAULT_ICMP_SESSION_TIMEOUT_NS
            },
        }
    }
}
const MAX_SESSION_DELTAS: usize = 4096;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

#[allow(unused_macros)]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct SessionKey {
    pub addr_family: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone, Debug)]
struct SessionEntry {
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    install_epoch: u64,
    last_seen_ns: u64,
    expires_after_ns: u64,
    closing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionDecision {
    pub(crate) resolution: ForwardingResolution,
    pub(crate) nat: NatDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: Arc<str>,
    pub(crate) egress_zone: Arc<str>,
    pub(crate) owner_rg_id: i32,
    pub(crate) fabric_ingress: bool,
    pub(crate) is_reverse: bool,
    /// For NAT64 sessions: stores original IPv6 addresses so reverse IPv4
    /// replies can be translated back.
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionLookup {
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForwardSessionMatch {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionOrigin {
    ForwardFlow,
    ReverseFlow,
    LocalMiss,
    MissingNeighborSeed,
    SyncImport,
    SharedMaterialize,
    SharedPromote,
    #[allow(dead_code)] // enum variant for completeness
    WorkerLocalImport,
}

impl SessionOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ForwardFlow => "forward_flow",
            Self::ReverseFlow => "reverse_flow",
            Self::LocalMiss => "local_miss",
            Self::MissingNeighborSeed => "missing_neighbor_seed",
            Self::SyncImport => "sync_import",
            Self::SharedMaterialize => "shared_materialize",
            Self::SharedPromote => "shared_promote",
            Self::WorkerLocalImport => "worker_local_import",
        }
    }

    /// Returns true for origins that represent peer-synced sessions.
    /// These are sessions that arrived from the HA peer rather than
    /// being created by local traffic.
    pub(crate) fn is_peer_synced(self) -> bool {
        matches!(
            self,
            Self::SyncImport | Self::SharedMaterialize | Self::WorkerLocalImport
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionDeltaKind {
    Open,
    Close,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionDelta {
    pub(crate) kind: SessionDeltaKind,
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) fabric_redirect_sync: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpiredSession {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
}

pub(crate) struct SessionTable {
    sessions: FxHashMap<SessionKey, SessionEntry>,
    nat_reverse_index: FxHashMap<SessionKey, SessionKey>,
    forward_wire_index: FxHashMap<SessionKey, SessionKey>,
    reverse_translated_index: FxHashMap<SessionKey, SessionKey>,
    owner_rg_sessions: FxHashMap<i32, FxHashSet<SessionKey>>,
    deltas: VecDeque<SessionDelta>,
    last_gc_ns: u64,
    max_sessions: usize,
    timeouts: SessionTimeouts,
    epoch_counter: u64,
    expired: u64,
    create_drops: u64,
    delta_drops: u64,
    delta_drained: u64,
}

impl SessionTable {
    pub fn new() -> Self {
        Self {
            sessions: FxHashMap::default(),
            nat_reverse_index: FxHashMap::default(),
            forward_wire_index: FxHashMap::default(),
            reverse_translated_index: FxHashMap::default(),
            owner_rg_sessions: FxHashMap::default(),
            deltas: VecDeque::with_capacity(MAX_SESSION_DELTAS.min(256)),
            last_gc_ns: 0,
            max_sessions: DEFAULT_MAX_SESSIONS,
            timeouts: SessionTimeouts::default(),
            epoch_counter: 0,
            expired: 0,
            create_drops: 0,
            delta_drops: 0,
            delta_drained: 0,
        }
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch_counter += 1;
        self.epoch_counter
    }

    /// Update the configurable session timeouts.
    pub fn set_timeouts(&mut self, timeouts: SessionTimeouts) {
        self.timeouts = timeouts;
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Update the last-seen timestamp for a session (prevents GC expiry).
    /// Used by the flow cache to amortize session keepalive.
    #[inline]
    pub fn touch(&mut self, key: &SessionKey, now_ns: u64) {
        if let Some(entry) = self.sessions.get_mut(key) {
            entry.last_seen_ns = now_ns;
        }
    }

    pub fn expire_stale_entries(&mut self, now_ns: u64) -> Vec<ExpiredSession> {
        if self.last_gc_ns != 0 && now_ns.saturating_sub(self.last_gc_ns) < SESSION_GC_INTERVAL_NS {
            return Vec::new();
        }
        self.last_gc_ns = now_ns;
        let stale = self
            .sessions
            .iter()
            .filter_map(|(key, entry)| {
                if now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut expired_entries = Vec::with_capacity(stale.len());
        for key in &stale {
            if let Some(entry) = self.remove_entry(key) {
                let decision = entry.decision;
                let metadata = entry.metadata;
                if key.protocol == PROTO_TCP {
                    debug_log!(
                        "SESS_EXPIRE: proto=TCP {}:{} -> {}:{} closing={} age_ns={} timeout_ns={} rev={} origin={} nat=({:?},{:?})",
                        key.src_ip,
                        key.src_port,
                        key.dst_ip,
                        key.dst_port,
                        entry.closing,
                        now_ns.saturating_sub(entry.last_seen_ns),
                        entry.expires_after_ns,
                        metadata.is_reverse,
                        entry.origin.as_str(),
                        decision.nat.rewrite_src,
                        decision.nat.rewrite_dst,
                    );
                }
                if !metadata.is_reverse && !entry.origin.is_peer_synced() {
                    self.push_delta(SessionDelta {
                        kind: SessionDeltaKind::Close,
                        key: key.clone(),
                        decision,
                        metadata: metadata.clone(),
                        origin: entry.origin,
                        fabric_redirect_sync: false,
                    });
                }
                expired_entries.push(ExpiredSession {
                    key: key.clone(),
                    decision,
                    metadata,
                    origin: entry.origin,
                });
            }
        }
        let expired = expired_entries.len() as u64;
        self.expired = self.expired.saturating_add(expired);
        expired_entries
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn expire_stale(&mut self, now_ns: u64) -> u64 {
        self.expire_stale_entries(now_ns).len() as u64
    }

    pub fn lookup(
        &mut self,
        key: &SessionKey,
        now_ns: u64,
        tcp_flags: u8,
    ) -> Option<SessionLookup> {
        let actual_key = if self.sessions.contains_key(key) {
            key.clone()
        } else if let Some(alias) = self.reverse_translated_index.get(key) {
            alias.clone()
        } else {
            return None;
        };
        self.sessions.get_mut(&actual_key).map(|entry| {
            if matches!(key.protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
                if !entry.closing {
                    debug_log!(
                        "SESS_CLOSING: {} proto=TCP {}:{} -> {}:{} rev={} tcp_flags=0x{:02x}",
                        if (tcp_flags & TCP_RST) != 0 {
                            "RST"
                        } else {
                            "FIN"
                        },
                        key.src_ip,
                        key.src_port,
                        key.dst_ip,
                        key.dst_port,
                        entry.metadata.is_reverse,
                        tcp_flags,
                    );
                }
                entry.closing = true;
            }
            entry.last_seen_ns = now_ns;
            entry.expires_after_ns = if matches!(key.protocol, PROTO_TCP) && entry.closing {
                TCP_CLOSING_TIMEOUT_NS
            } else {
                session_timeout_ns(key.protocol, tcp_flags, &self.timeouts)
            };
            SessionLookup {
                decision: entry.decision,
                metadata: entry.metadata.clone(),
            }
        })
    }

    pub fn find_forward_nat_match(&self, reply_key: &SessionKey) -> Option<ForwardSessionMatch> {
        let forward_key = self.nat_reverse_index.get(reply_key)?;
        let entry = self.sessions.get(forward_key)?;
        if entry.metadata.is_reverse
            || !reply_matches_forward_session(forward_key, entry.decision.nat, reply_key)
        {
            return None;
        }
        Some(ForwardSessionMatch {
            key: forward_key.clone(),
            decision: entry.decision,
            metadata: entry.metadata.clone(),
        })
    }

    pub fn find_forward_wire_match(&self, wire_key: &SessionKey) -> Option<ForwardSessionMatch> {
        let forward_key = self.forward_wire_index.get(wire_key)?;
        let entry = self.sessions.get(forward_key)?;
        if entry.metadata.is_reverse
            || forward_wire_key(forward_key, entry.decision.nat) != *wire_key
        {
            return None;
        }
        Some(ForwardSessionMatch {
            key: forward_key.clone(),
            decision: entry.decision,
            metadata: entry.metadata.clone(),
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn install_with_protocol(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        self.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            now_ns,
            protocol,
            tcp_flags,
        )
    }

    pub fn install_with_protocol_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        if self.sessions.len() >= self.max_sessions {
            self.create_drops = self.create_drops.saturating_add(1);
            return false;
        }
        self.remove_entry(&key);
        let epoch = self.next_epoch();
        self.sessions.insert(
            key.clone(),
            SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                expires_after_ns: session_timeout_ns(protocol, tcp_flags, &self.timeouts),
                closing: matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0,
            },
        );
        self.index_forward_nat_key(&key, decision, &metadata);
        if !metadata.is_reverse && !origin.is_peer_synced() {
            self.push_delta(SessionDelta {
                kind: SessionDeltaKind::Open,
                key,
                decision,
                metadata,
                origin,
                fabric_redirect_sync: false,
            });
        }
        true
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn upsert_synced(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        allow_replace_local: bool,
    ) -> bool {
        self.upsert_synced_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::SyncImport,
            now_ns,
            protocol,
            tcp_flags,
            allow_replace_local,
        )
    }

    pub fn upsert_synced_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        allow_replace_local: bool,
    ) -> bool {
        // Reject peer data that would clobber a locally-owned session
        // unless explicitly allowed (e.g. during HA activation).
        if matches!(self.sessions.get(&key), Some(existing) if !existing.origin.is_peer_synced())
            && !allow_replace_local
        {
            return false;
        }
        self.remove_entry(&key);
        let epoch = self.next_epoch();
        let index_key = key.clone();
        self.sessions.insert(
            key,
            SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                expires_after_ns: session_timeout_ns(protocol, tcp_flags, &self.timeouts),
                closing: matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0,
            },
        );
        self.index_forward_nat_key(&index_key, decision, &metadata);
        true
    }

    /// Unified session update function replacing promote_synced,
    /// refresh_local, and refresh_for_ha_activation.
    ///
    /// Collision rules:
    /// - `ha_activation=true`: always updates (highest priority, used by
    ///   RefreshOwnerRGs to re-resolve all sessions with local state)
    /// - Peer-synced entries (origin.is_peer_synced()): local traffic can
    ///   promote them (sets new origin + emits delta)
    /// - Local entries (!origin.is_peer_synced()): rejects older peer data
    pub fn update_session(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        ha_activation: bool,
    ) -> bool {
        let Some(mut entry) = self.remove_entry(key) else {
            return false;
        };
        if !ha_activation {
            if entry.origin.is_peer_synced() && !origin.is_peer_synced() {
                // Peer-synced entry being promoted by local traffic — allow
            } else if entry.origin.is_peer_synced() && origin.is_peer_synced() {
                // Both peer-synced: reject (refresh_local on synced entry)
                self.restore_entry(key.clone(), entry);
                return false;
            } else if !entry.origin.is_peer_synced() && origin.is_peer_synced() {
                // Local entry: reject peer data trying to overwrite
                self.restore_entry(key.clone(), entry);
                return false;
            }
            // Both local: allow (local refresh of local entry)
        }
        let was_peer_synced = entry.origin.is_peer_synced();
        entry.decision = decision;
        entry.metadata = metadata.clone();
        entry.origin = origin;
        entry.install_epoch = self.next_epoch();
        entry.last_seen_ns = now_ns;
        entry.expires_after_ns = session_timeout_ns(protocol, tcp_flags, &self.timeouts);
        entry.closing = matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0;
        self.restore_entry(key.clone(), entry);
        // Emit open delta when promoting a peer-synced entry to local
        if was_peer_synced && !origin.is_peer_synced() && !metadata.is_reverse {
            self.push_delta(SessionDelta {
                kind: SessionDeltaKind::Open,
                key: key.clone(),
                decision,
                metadata,
                origin,
                fabric_redirect_sync: false,
            });
        }
        true
    }

    /// Thin wrapper for local-only refresh (non-HA-activation path).
    /// Keeps the existing origin; skips peer-synced entries.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn refresh_local(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        tcp_flags: u8,
    ) -> bool {
        let origin = self
            .sessions
            .get(key)
            .map(|e| e.origin)
            .unwrap_or(SessionOrigin::ForwardFlow);
        self.update_session(
            key,
            decision,
            metadata,
            origin,
            now_ns,
            key.protocol,
            tcp_flags,
            false,
        )
    }

    /// Convenience: refresh for HA activation (always updates regardless
    /// of origin). Preserves existing origin.
    pub fn refresh_for_ha_activation(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        tcp_flags: u8,
    ) -> bool {
        let origin = self
            .sessions
            .get(key)
            .map(|e| e.origin)
            .unwrap_or(SessionOrigin::ForwardFlow);
        self.update_session(
            key,
            decision,
            metadata,
            origin,
            now_ns,
            key.protocol,
            tcp_flags,
            true,
        )
    }

    /// Promote a peer-synced session to local ownership.
    /// Convenience wrapper around update_session.
    pub fn promote_synced_with_origin(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        self.update_session(
            key,
            decision,
            metadata,
            origin,
            now_ns,
            protocol,
            tcp_flags,
            false,
        )
    }

    pub fn emit_open_delta_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        fabric_redirect_sync: bool,
    ) {
        if metadata.is_reverse {
            return;
        }
        self.push_delta(SessionDelta {
            kind: SessionDeltaKind::Open,
            key,
            decision,
            metadata,
            origin,
            fabric_redirect_sync,
        });
    }

    pub fn delete(&mut self, key: &SessionKey) {
        self.remove_entry(key);
    }

    pub fn entry_with_origin(
        &self,
        key: &SessionKey,
    ) -> Option<(SessionDecision, SessionMetadata, SessionOrigin)> {
        self.sessions
            .get(key)
            .map(|entry| (entry.decision, entry.metadata.clone(), entry.origin))
    }

    pub fn owner_rg_session_keys(&self, owner_rgs: &[i32]) -> Vec<SessionKey> {
        owner_rg_session_keys_from_index(&self.owner_rg_sessions, owner_rgs)
    }

    pub fn take_synced_local(&mut self, key: &SessionKey) -> Option<SessionLookup> {
        let Some(entry) = self.sessions.get(key) else {
            return None;
        };
        if !entry.origin.is_peer_synced()
            || entry.metadata.is_reverse
            || entry.decision.resolution.disposition != ForwardingDisposition::LocalDelivery
        {
            return None;
        }
        self.remove_entry(key).map(|entry| SessionLookup {
            decision: entry.decision,
            metadata: entry.metadata,
        })
    }

    pub fn demote_owner_rg(&mut self, owner_rg_id: i32) -> Vec<crate::session::SessionKey> {
        if owner_rg_id <= 0 {
            return Vec::new();
        }
        let mut demoted_keys = Vec::new();
        for key in self.owner_rg_session_keys(&[owner_rg_id]) {
            let Some(entry) = self.sessions.get_mut(&key) else {
                continue;
            };
            if entry.origin.is_peer_synced() {
                continue;
            }
            entry.origin = SessionOrigin::SyncImport;
            demoted_keys.push(key);
        }
        demoted_keys
    }

    pub fn drain_deltas(&mut self, max: usize) -> Vec<SessionDelta> {
        let drain = max.max(1).min(self.deltas.len());
        let mut out = Vec::with_capacity(drain);
        for _ in 0..drain {
            if let Some(delta) = self.deltas.pop_front() {
                out.push(delta);
            }
        }
        self.delta_drained = self.delta_drained.saturating_add(out.len() as u64);
        out
    }

    pub fn has_pending_deltas(&self) -> bool {
        !self.deltas.is_empty()
    }

    pub fn iter_with_origin(
        &self,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, SessionOrigin),
    ) {
        for (key, entry) in &self.sessions {
            f(key, entry.decision, &entry.metadata, entry.origin);
        }
    }

    /// Iterate over all session entries with idle time (in nanoseconds).
    pub fn iter_with_idle(
        &self,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, u64),
    ) {
        self.iter_with_idle_and_origin(now_ns, |key, decision, metadata, _origin, idle_ns| {
            f(key, decision, metadata, idle_ns)
        });
    }

    pub fn iter_with_idle_and_origin(
        &self,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, SessionOrigin, u64),
    ) {
        for (key, entry) in &self.sessions {
            let idle_ns = now_ns.saturating_sub(entry.last_seen_ns);
            f(key, entry.decision, &entry.metadata, entry.origin, idle_ns);
        }
    }

    fn push_delta(&mut self, delta: SessionDelta) {
        if self.deltas.len() >= MAX_SESSION_DELTAS {
            self.delta_drops = self.delta_drops.saturating_add(1);
            return;
        }
        self.deltas.push_back(delta);
    }

    fn remove_entry(&mut self, key: &SessionKey) -> Option<SessionEntry> {
        let entry = self.sessions.remove(key)?;
        self.remove_forward_nat_index(key, entry.decision, &entry.metadata);
        remove_owner_rg_index_entry(&mut self.owner_rg_sessions, entry.metadata.owner_rg_id, key);
        Some(entry)
    }

    fn restore_entry(&mut self, key: SessionKey, entry: SessionEntry) -> Option<SessionEntry> {
        self.index_forward_nat_key(&key, entry.decision, &entry.metadata);
        self.sessions.insert(key, entry)
    }

    fn index_forward_nat_key(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: &SessionMetadata,
    ) {
        if metadata.is_reverse {
            let translated = translated_session_key(key, decision.nat);
            if translated != *key {
                self.reverse_translated_index
                    .insert(translated, key.clone());
            }
        } else {
            self.nat_reverse_index
                .insert(reverse_wire_key(key, decision.nat), key.clone());
            let reverse_canonical = reverse_canonical_key(key, decision.nat);
            if reverse_canonical != *key {
                self.nat_reverse_index
                    .insert(reverse_canonical, key.clone());
            }
            let forward_wire = forward_wire_key(key, decision.nat);
            if forward_wire != *key {
                self.forward_wire_index.insert(forward_wire, key.clone());
            }
        }
        if metadata.owner_rg_id > 0 {
            self.owner_rg_sessions
                .entry(metadata.owner_rg_id)
                .or_default()
                .insert(key.clone());
        }
    }

    fn remove_forward_nat_index(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: &SessionMetadata,
    ) {
        if metadata.is_reverse {
            let translated = translated_session_key(key, decision.nat);
            if matches!(
                self.reverse_translated_index.get(&translated),
                Some(existing) if existing == key
            ) {
                self.reverse_translated_index.remove(&translated);
            }
            return;
        }
        let reverse_wire = reverse_wire_key(key, decision.nat);
        if matches!(self.nat_reverse_index.get(&reverse_wire), Some(existing) if existing == key) {
            self.nat_reverse_index.remove(&reverse_wire);
        }
        let reverse_canonical = reverse_canonical_key(key, decision.nat);
        if matches!(self.nat_reverse_index.get(&reverse_canonical), Some(existing) if existing == key)
        {
            self.nat_reverse_index.remove(&reverse_canonical);
        }
        let forward_wire = forward_wire_key(key, decision.nat);
        if matches!(self.forward_wire_index.get(&forward_wire), Some(existing) if existing == key) {
            self.forward_wire_index.remove(&forward_wire);
        }
    }
}

fn owner_rg_session_keys_from_index(
    index: &FxHashMap<i32, FxHashSet<SessionKey>>,
    owner_rgs: &[i32],
) -> Vec<SessionKey> {
    let mut keys = FxHashSet::default();
    for owner_rg_id in owner_rgs {
        if let Some(entries) = index.get(owner_rg_id) {
            keys.extend(entries.iter().cloned());
        }
    }
    keys.into_iter().collect()
}

fn remove_owner_rg_index_entry(
    index: &mut FxHashMap<i32, FxHashSet<SessionKey>>,
    owner_rg_id: i32,
    key: &SessionKey,
) {
    if owner_rg_id <= 0 {
        return;
    }
    if let Some(entries) = index.get_mut(&owner_rg_id) {
        entries.remove(key);
        if entries.is_empty() {
            index.remove(&owner_rg_id);
        }
    }
}

fn session_timeout_ns(protocol: u8, tcp_flags: u8, timeouts: &SessionTimeouts) -> u64 {
    match protocol {
        PROTO_TCP => {
            if (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
                TCP_CLOSING_TIMEOUT_NS
            } else {
                timeouts.tcp_established_ns
            }
        }
        PROTO_UDP => timeouts.udp_ns,
        PROTO_ICMP | PROTO_ICMPV6 => timeouts.icmp_ns,
        _ => OTHER_SESSION_TIMEOUT_NS,
    }
}

pub(crate) fn reply_matches_forward_session(
    forward_key: &SessionKey,
    nat: NatDecision,
    reply_key: &SessionKey,
) -> bool {
    reverse_wire_key(forward_key, nat) == *reply_key
        || reverse_canonical_key(forward_key, nat) == *reply_key
}

pub(crate) fn forward_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
        )
    };
    let wire_src = nat.rewrite_src.unwrap_or(forward_key.src_ip);
    let wire_dst = nat.rewrite_dst.unwrap_or(forward_key.dst_ip);
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        let proto = if af == libc::AF_INET as u8 && forward_key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && forward_key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            forward_key.protocol
        };
        (af, proto)
    } else {
        (forward_key.addr_family, forward_key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
    }
}

pub(crate) fn translated_session_key(key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (key.src_port, key.dst_port)
    } else {
        (
            nat.rewrite_src_port.unwrap_or(key.src_port),
            nat.rewrite_dst_port.unwrap_or(key.dst_port),
        )
    };
    SessionKey {
        addr_family: key.addr_family,
        protocol: key.protocol,
        src_ip: nat.rewrite_src.unwrap_or(key.src_ip),
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port,
        dst_port,
    }
}

fn reverse_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
        )
    };
    let wire_src = nat.rewrite_dst.unwrap_or(forward_key.dst_ip);
    let wire_dst = nat.rewrite_src.unwrap_or(forward_key.src_ip);
    // NAT64: the reverse (reply) packet is a different address family.
    // Determine the AF from the NAT-rewritten addresses.
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        // ICMPv6 ↔ ICMP protocol mapping.
        let proto = if af == libc::AF_INET as u8 && forward_key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && forward_key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            forward_key.protocol
        };
        (af, proto)
    } else {
        (forward_key.addr_family, forward_key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
    }
}

pub(crate) fn reverse_canonical_key(forward_key: &SessionKey, _nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (forward_key.dst_port, forward_key.src_port)
    };
    SessionKey {
        addr_family: forward_key.addr_family,
        protocol: forward_key.protocol,
        src_ip: forward_key.dst_ip,
        dst_ip: forward_key.src_ip,
        src_port,
        dst_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn key_v4() -> SessionKey {
        SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 12345,
            dst_port: 443,
        }
    }

    fn key_v6() -> SessionKey {
        SessionKey {
            addr_family: 10,
            protocol: PROTO_UDP,
            src_ip: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("v6 src")),
            dst_ip: IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().expect("v6 dst")),
            src_port: 5555,
            dst_port: 53,
        }
    }

    fn resolution() -> ForwardingResolution {
        ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
        }
    }

    fn decision() -> SessionDecision {
        SessionDecision {
            resolution: resolution(),
            nat: NatDecision::default(),
        }
    }

    fn metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: Arc::<str>::from("lan"),
            egress_zone: Arc::<str>::from("wan"),
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        }
    }

    #[test]
    fn session_lookup_hits_after_install() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10
        ));
        let hit = table.lookup(&key, now + 1_000_000, 0x10);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: metadata(),
            })
        );
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Open);
        assert_eq!(deltas[0].key, key);
    }

    #[test]
    fn session_expire_removes_stale_entries() {
        let mut table = SessionTable::new();
        let key = key_v6();
        let then = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            then,
            PROTO_UDP,
            0
        ));
        let _ = table.drain_deltas(8);
        table.last_gc_ns = then + 118_000_000_000;
        let expired = table.expire_stale(then + 120_000_000_000);
        assert_eq!(expired, 1);
        assert!(table.lookup(&key, then + 121_000_000_000, 0).is_none());
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
        assert_eq!(deltas[0].key, key);
    }

    #[test]
    fn expire_stale_entries_returns_helper_only_local_sessions() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let then = 1_000_000_000u64;
        let local_metadata = metadata();
        let local_decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                ..resolution()
            },
            nat: NatDecision::default(),
        };
        // Install with SyncImport origin to mark as peer-synced
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            local_decision,
            local_metadata.clone(),
            SessionOrigin::SyncImport,
            then,
            PROTO_TCP,
            0x10,
        ));
        table.last_gc_ns = then + 301_000_000_000;
        let expired = table.expire_stale_entries(then + 302_000_000_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].key, key);
        assert_eq!(expired[0].decision, local_decision);
        assert_eq!(expired[0].metadata, local_metadata);
        assert!(table.drain_deltas(8).is_empty());
    }

    #[test]
    fn take_synced_local_only_removes_helper_local_sessions() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let local_metadata = metadata();
        let local_decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                ..resolution()
            },
            nat: NatDecision::default(),
        };
        // Install with SyncImport origin so it's considered peer-synced
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            local_decision,
            local_metadata.clone(),
            SessionOrigin::SyncImport,
            now,
            PROTO_TCP,
            0x10,
        ));
        let removed = table
            .take_synced_local(&key)
            .expect("local session removed");
        assert_eq!(removed.decision, local_decision);
        assert_eq!(removed.metadata, local_metadata);
        assert!(table.lookup(&key, now + 1_000_000, 0x10).is_none());

        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10,
        ));
        assert!(table.take_synced_local(&key).is_none());
        assert!(table.lookup(&key, now + 1_000_000, 0x10).is_some());
    }

    #[test]
    fn tcp_fin_keeps_session_until_closing_timeout() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10
        ));
        let _ = table.drain_deltas(8);
        let hit = table.lookup(&key, now + 1_000_000, TCP_FIN);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: metadata(),
            })
        );
        assert!(table.lookup(&key, now + 2_000_000, 0x10).is_some());
        table.last_gc_ns = now + TCP_CLOSING_TIMEOUT_NS;
        let expired = table.expire_stale(now + TCP_CLOSING_TIMEOUT_NS + 1_000_000_000);
        assert_eq!(expired, 1);
        assert!(
            table
                .lookup(&key, now + TCP_CLOSING_TIMEOUT_NS + 2_000_000_000, 0)
                .is_none()
        );
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
        assert_eq!(deltas[0].key, key);
    }

    #[test]
    fn synced_sessions_do_not_emit_deltas() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let synced_meta = metadata();
        table.upsert_synced(
            key.clone(),
            decision(),
            synced_meta.clone(),
            now,
            PROTO_TCP,
            0x10,
            false,
        );
        let hit = table.lookup(&key, now + 1_000_000, 0x10);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: synced_meta,
            })
        );
        assert!(table.drain_deltas(8).is_empty());
        let _ = table.lookup(&key, now + 2_000_000, TCP_FIN);
        assert!(table.drain_deltas(8).is_empty());
    }

    #[test]
    fn upsert_synced_does_not_clobber_live_local_session() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let mut live = metadata();
        live.fabric_ingress = true;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            live.clone(),
            now,
            PROTO_TCP,
            0x10,
        ));
        let synced_meta = metadata();
        table.upsert_synced(
            key.clone(),
            SessionDecision {
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    ..NatDecision::default()
                },
                ..decision()
            },
            synced_meta,
            now + 1_000_000,
            PROTO_TCP,
            0x10,
            false,
        );
        let hit = table
            .lookup(&key, now + 2_000_000, 0x10)
            .expect("live session");
        assert_eq!(hit.metadata, live);
        assert_eq!(hit.decision, decision());
    }

    #[test]
    fn upsert_synced_can_replace_live_local_session_when_allowed() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let live = metadata();
        assert!(table.install_with_protocol(key.clone(), decision(), live, now, PROTO_TCP, 0x10,));
        let synced_meta = metadata();
        let synced_decision = SessionDecision {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            ..decision()
        };
        assert!(table.upsert_synced(
            key.clone(),
            synced_decision,
            synced_meta.clone(),
            now + 1_000_000,
            PROTO_TCP,
            0x10,
            true,
        ));
        let hit = table
            .lookup(&key, now + 2_000_000, 0x10)
            .expect("synced session");
        assert_eq!(hit.metadata, synced_meta);
        assert_eq!(hit.decision, synced_decision);
    }

    #[test]
    fn promote_synced_forward_session_emits_open_delta() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let synced_meta = metadata();
        table.upsert_synced(key.clone(), decision(), synced_meta, now, PROTO_TCP, 0x10, false);
        let promoted = metadata();
        assert!(table.promote_synced_with_origin(
            &key,
            decision(),
            promoted.clone(),
            SessionOrigin::SharedPromote,
            now + 1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let hit = table.lookup(&key, now + 2_000_000, 0x10);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: promoted.clone(),
            })
        );
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Open);
        assert_eq!(deltas[0].key, key);
        assert_eq!(deltas[0].metadata, promoted);
    }

    #[test]
    fn promote_synced_reverse_session_stays_quiet() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = 1_000_000_000u64;
        let mut synced_meta = metadata();
        synced_meta.is_reverse = true;
        table.upsert_synced(key.clone(), decision(), synced_meta, now, PROTO_TCP, 0x10, false);
        let mut promoted = metadata();
        promoted.is_reverse = true;
        assert!(table.promote_synced_with_origin(
            &key,
            decision(),
            promoted.clone(),
            SessionOrigin::SharedPromote,
            now + 1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let hit = table.lookup(&key, now + 2_000_000, 0x10);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: promoted,
            })
        );
        assert!(table.drain_deltas(8).is_empty());
    }

    #[test]
    fn demote_owner_rg_marks_forward_and_reverse_entries_synced() {
        let mut table = SessionTable::new();
        let now = 1_000_000_000u64;
        let key_a = key_v4();
        let key_b = SessionKey {
            src_port: 42425,
            ..key_v4()
        };
        let key_other = SessionKey {
            src_port: 42426,
            ..key_v4()
        };
        let mut metadata_a = metadata();
        metadata_a.owner_rg_id = 1;
        let mut metadata_b = metadata();
        metadata_b.owner_rg_id = 1;
        metadata_b.is_reverse = true;
        let mut metadata_other = metadata();
        metadata_other.owner_rg_id = 2;
        assert!(table.install_with_protocol(
            key_a.clone(),
            decision(),
            metadata_a,
            now,
            PROTO_TCP,
            0x10,
        ));
        assert!(table.install_with_protocol(
            key_b.clone(),
            decision(),
            metadata_b,
            now,
            PROTO_TCP,
            0x10,
        ));
        assert!(table.install_with_protocol(
            key_other.clone(),
            decision(),
            metadata_other.clone(),
            now,
            PROTO_TCP,
            0x10,
        ));

        assert_eq!(table.demote_owner_rg(1).len(), 2);

        // Verify demoted sessions have peer-synced origin
        let mut a_origin = None;
        let mut b_origin = None;
        let mut other_origin = None;
        table.iter_with_origin(|key, _decision, _metadata, origin| {
            if key == &key_a {
                a_origin = Some(origin);
            } else if key == &key_b {
                b_origin = Some(origin);
            } else if key == &key_other {
                other_origin = Some(origin);
            }
        });
        assert!(a_origin.expect("key_a exists").is_peer_synced());
        assert!(b_origin.expect("key_b exists").is_peer_synced());
        assert!(
            !other_origin.expect("key_other exists").is_peer_synced(),
            "other RG should remain local"
        );
        assert_eq!(
            table
                .lookup(&key_other, now + 1_000_000, 0x10)
                .expect("other rg")
                .metadata,
            metadata_other
        );
    }

    #[test]
    fn owner_rg_session_keys_track_insert_update_and_delete() {
        let mut table = SessionTable::new();
        let now = 1_000_000_000u64;
        let key = key_v4();
        let mut metadata_rg1 = metadata();
        metadata_rg1.owner_rg_id = 1;
        let mut metadata_rg2 = metadata();
        metadata_rg2.owner_rg_id = 2;

        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata_rg1.clone(),
            now,
            PROTO_TCP,
            0x10,
        ));
        assert_eq!(table.owner_rg_session_keys(&[1]), vec![key.clone()]);

        assert!(table.refresh_for_ha_activation(
            &key,
            decision(),
            metadata_rg2.clone(),
            now + 1_000_000,
            0x10,
        ));
        assert!(table.owner_rg_session_keys(&[1]).is_empty());
        assert_eq!(table.owner_rg_session_keys(&[2]), vec![key.clone()]);

        table.delete(&key);
        assert!(table.owner_rg_session_keys(&[2]).is_empty());
    }

    #[test]
    fn reply_match_finds_tcp_snat_reverse_tuple() {
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42424,
            dst_port: 5201,
        };
        let reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 42424,
        };
        assert!(reply_matches_forward_session(
            &forward,
            NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                ..NatDecision::default()
            },
            &reply,
        ));
    }

    #[test]
    fn reply_match_finds_icmp_snat_reverse_tuple() {
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 0x1234,
            dst_port: 0,
        };
        assert!(reply_matches_forward_session(
            &forward,
            NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                ..NatDecision::default()
            },
            &reply,
        ));
    }

    #[test]
    fn find_forward_nat_match_uses_reverse_index() {
        let mut table = SessionTable::new();
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42424,
            dst_port: 5201,
        };
        let reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 42424,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_dst: None,
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .find_forward_nat_match(&reply)
            .expect("forward nat match");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_nat_match(&reply).is_none());
    }

    #[test]
    fn find_forward_nat_match_uses_canonical_reverse_index() {
        let mut table = SessionTable::new();
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42424,
            dst_port: 5201,
        };
        let canonical_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            src_port: 5201,
            dst_port: 42424,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .find_forward_nat_match(&canonical_reply)
            .expect("canonical reverse match");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_nat_match(&canonical_reply).is_none());
    }

    #[test]
    fn reverse_canonical_key_keeps_icmp_identifier_position() {
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let reply = reverse_canonical_key(&forward, NatDecision::default());
        assert_eq!(reply.src_ip, IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)));
        assert_eq!(reply.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
        assert_eq!(reply.src_port, 0x1234);
        assert_eq!(reply.dst_port, 0);
    }

    #[test]
    fn find_forward_nat_match_uses_canonical_reverse_index_for_icmp() {
        let mut table = SessionTable::new();
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let canonical_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_ICMP,
            0
        ));

        let hit = table
            .find_forward_nat_match(&canonical_reply)
            .expect("icmp canonical reverse match");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_nat_match(&canonical_reply).is_none());
    }

    #[test]
    fn find_forward_wire_match_uses_translated_forward_index() {
        let mut table = SessionTable::new();
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42528,
            dst_port: 5201,
        };
        let translated = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 42528,
            dst_port: 5201,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(42528),
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .find_forward_wire_match(&translated)
            .expect("forward wire match");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_wire_match(&translated).is_none());
    }

    #[test]
    fn lookup_uses_translated_reverse_alias() {
        let mut table = SessionTable::new();
        let reverse_wire = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42)),
            src_port: 5201,
            dst_port: 42424,
        };
        let reverse_canonical = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            src_port: 5201,
            dst_port: 42424,
        };
        let mut reverse_metadata = metadata();
        reverse_metadata.is_reverse = true;
        let reverse_decision = SessionDecision {
            resolution: resolution(),
            nat: NatDecision {
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        };
        assert!(table.install_with_protocol(
            reverse_wire.clone(),
            reverse_decision,
            reverse_metadata.clone(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .lookup(&reverse_canonical, 1_001_000_000, 0x10)
            .expect("translated reverse alias");
        assert_eq!(hit.decision, reverse_decision);
        assert_eq!(hit.metadata, reverse_metadata);

        table.delete(&reverse_wire);
        assert!(
            table
                .lookup(&reverse_canonical, 1_002_000_000, 0x10)
                .is_none()
        );
    }

    #[test]
    fn dnat_port_in_reverse_wire_key() {
        // Forward: client:54321 -> external:80, DNAT rewrites dst to internal:8080
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 54321,
            dst_port: 80,
        };
        let nat = NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        };
        // Reply from internal:8080 -> client:54321
        let expected_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            src_port: 8080,
            dst_port: 54321,
        };
        assert!(reply_matches_forward_session(
            &forward,
            nat,
            &expected_reply
        ));
    }

    #[test]
    fn dnat_plus_snat_ports_in_reverse_key() {
        // Forward: client:54321 -> external:80
        // DNAT: dst -> internal:8080, SNAT: src -> egress_ip
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 54321,
            dst_port: 80,
        };
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            rewrite_src_port: None,
            rewrite_dst_port: Some(8080),
            nat64: false,
            nptv6: false,
        };
        // Reply: internal:8080 -> egress:54321
        let expected_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 8080,
            dst_port: 54321,
        };
        assert!(reply_matches_forward_session(
            &forward,
            nat,
            &expected_reply
        ));
    }

    #[test]
    fn icmp_port_handling_unchanged_with_dnat_ports() {
        // ICMP ignores port rewriting even if NatDecision has port fields set
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 0x1234,
            dst_port: 0,
        };
        let nat = NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        };
        // ICMP reverse: ports stay the same (ICMP has no port semantics)
        let expected_reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 0x1234,
            dst_port: 0,
        };
        assert!(reply_matches_forward_session(
            &forward,
            nat,
            &expected_reply
        ));
    }

    #[test]
    fn find_forward_nat_match_with_dnat_port_rewrite() {
        let mut table = SessionTable::new();
        // Forward: client:54321 -> external:80 with DNAT to internal:8080
        let forward = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 54321,
            dst_port: 80,
        };
        // Reply from internal:8080 -> client:54321
        let reply = SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            src_port: 8080,
            dst_port: 54321,
        };
        let nat = NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        };
        let decision = SessionDecision {
            resolution: resolution(),
            nat,
        };
        assert!(table.install_with_protocol(
            forward.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ));

        let hit = table
            .find_forward_nat_match(&reply)
            .expect("forward nat match with port");
        assert_eq!(hit.key, forward);
        assert_eq!(hit.decision.nat, nat);

        table.delete(&hit.key);
        assert!(table.find_forward_nat_match(&reply).is_none());
    }

    #[test]
    fn configurable_tcp_timeout_changes_session_expiry() {
        let mut table = SessionTable::new();
        table.set_timeouts(SessionTimeouts::from_seconds(60, 0, 0));
        let key = key_v4();
        let now = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10,
        ));
        // Session should expire after 60s (configured), not 300s (default)
        table.last_gc_ns = now + 59_000_000_000;
        let expired = table.expire_stale(now + 59_000_000_000 + SESSION_GC_INTERVAL_NS);
        assert_eq!(expired, 0, "session should not expire before 60s");

        table.last_gc_ns = now + 61_000_000_000;
        let expired = table.expire_stale(now + 61_000_000_000 + SESSION_GC_INTERVAL_NS);
        assert_eq!(expired, 1, "session should expire after 60s");
    }

    #[test]
    fn configurable_udp_timeout_changes_session_expiry() {
        let mut table = SessionTable::new();
        table.set_timeouts(SessionTimeouts::from_seconds(0, 120, 0));
        let key = key_v6();
        let now = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_UDP,
            0,
        ));
        // Should not expire at 60s (the old default)
        table.last_gc_ns = now + 61_000_000_000;
        let expired = table.expire_stale(now + 61_000_000_000 + SESSION_GC_INTERVAL_NS);
        assert_eq!(expired, 0, "session should not expire before 120s");

        // Should expire after 120s
        table.last_gc_ns = now + 121_000_000_000;
        let expired = table.expire_stale(now + 121_000_000_000 + SESSION_GC_INTERVAL_NS);
        assert_eq!(expired, 1, "session should expire after 120s");
    }

    #[test]
    fn default_timeouts_match_original_values() {
        let t = SessionTimeouts::default();
        assert_eq!(t.tcp_established_ns, 300_000_000_000);
        assert_eq!(t.udp_ns, 60_000_000_000);
        assert_eq!(t.icmp_ns, 60_000_000_000);
    }

    #[test]
    fn from_seconds_zero_uses_default() {
        let t = SessionTimeouts::from_seconds(0, 0, 0);
        assert_eq!(t.tcp_established_ns, DEFAULT_TCP_SESSION_TIMEOUT_NS);
        assert_eq!(t.udp_ns, DEFAULT_UDP_SESSION_TIMEOUT_NS);
        assert_eq!(t.icmp_ns, DEFAULT_ICMP_SESSION_TIMEOUT_NS);
    }

    #[test]
    fn from_seconds_overrides_values() {
        let t = SessionTimeouts::from_seconds(120, 30, 5);
        assert_eq!(t.tcp_established_ns, 120_000_000_000);
        assert_eq!(t.udp_ns, 30_000_000_000);
        assert_eq!(t.icmp_ns, 5_000_000_000);
    }

    #[test]
    fn iter_with_idle_reports_idle_time() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_time = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_time,
            PROTO_TCP,
            0x10,
        ));

        let now = install_time + 5_000_000_000; // 5 seconds later
        let mut found = false;
        table.iter_with_idle(now, |k, _decision, _metadata, idle_ns| {
            if k == &key {
                assert_eq!(idle_ns, 5_000_000_000);
                found = true;
            }
        });
        assert!(found, "session should be found in iter_with_idle");
    }

    #[test]
    fn iter_with_idle_reflects_last_seen_update() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let install_time = 1_000_000_000u64;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_time,
            PROTO_TCP,
            0x10,
        ));
        // Touch the session 3 seconds later
        let touch_time = install_time + 3_000_000_000;
        let _ = table.lookup(&key, touch_time, 0x10);

        // Check idle time 5 seconds after install (2 seconds after last touch)
        let now = install_time + 5_000_000_000;
        let mut idle = 0u64;
        table.iter_with_idle(now, |k, _, _, idle_ns| {
            if k == &key {
                idle = idle_ns;
            }
        });
        assert_eq!(idle, 2_000_000_000, "idle should be 2s since last touch");
    }

    #[test]
    fn refresh_local_skips_peer_synced_entries() {
        let mut table = SessionTable::new();
        let key = key_v4();
        // Install with SyncImport origin (peer-synced)
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::SyncImport,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let new_decision = SessionDecision {
            resolution: ForwardingResolution {
                egress_ifindex: 99,
                ..decision().resolution
            },
            ..decision()
        };
        // refresh_local should return false for peer-synced sessions
        assert!(!table.refresh_local(
            &key,
            new_decision,
            metadata(),
            2_000_000,
            0x10,
        ));
        assert_eq!(table.owner_rg_session_keys(&[1]), vec![key.clone()]);
        // session should still have original decision
        let lookup = table.lookup(&key, 3_000_000, 0x10).expect("session");
        assert_ne!(lookup.decision.resolution.egress_ifindex, 99);
    }

    #[test]
    fn refresh_for_ha_activation_updates_peer_synced_entries() {
        let mut table = SessionTable::new();
        let key = key_v4();
        // Install with SyncImport origin (peer-synced)
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::SyncImport,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let new_decision = SessionDecision {
            resolution: ForwardingResolution {
                egress_ifindex: 99,
                ..decision().resolution
            },
            ..decision()
        };
        // refresh_for_ha_activation should succeed even for peer-synced sessions
        assert!(table.refresh_for_ha_activation(
            &key,
            new_decision,
            metadata(),
            2_000_000,
            0x10,
        ));
        // session should now have updated decision
        let lookup = table.lookup(&key, 3_000_000, 0x10).expect("session");
        assert_eq!(lookup.decision.resolution.egress_ifindex, 99);
    }
}
