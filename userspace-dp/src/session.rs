use crate::afxdp::ForwardingResolution;
use crate::nat::NatDecision;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

const SESSION_GC_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_SESSIONS: usize = 131072;
const TCP_SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const ICMP_SESSION_TIMEOUT: Duration = Duration::from_secs(15);
const OTHER_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SESSION_DELTAS: usize = 4096;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

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
    last_seen: Instant,
    expires_after: Duration,
    closing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionDecision {
    pub(crate) resolution: ForwardingResolution,
    pub(crate) nat: NatDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: String,
    pub(crate) egress_zone: String,
    pub(crate) owner_rg_id: i32,
    pub(crate) is_reverse: bool,
    pub(crate) synced: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionLookup {
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
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
}

pub(crate) struct SessionTable {
    sessions: HashMap<SessionKey, SessionEntry>,
    deltas: VecDeque<SessionDelta>,
    last_gc: Instant,
    max_sessions: usize,
    expired: u64,
    create_drops: u64,
    delta_drops: u64,
    delta_drained: u64,
}

impl SessionTable {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            deltas: VecDeque::with_capacity(MAX_SESSION_DELTAS.min(256)),
            last_gc: Instant::now(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            expired: 0,
            create_drops: 0,
            delta_drops: 0,
            delta_drained: 0,
        }
    }

    pub fn expire_stale(&mut self, now: Instant) -> u64 {
        if now.duration_since(self.last_gc) < SESSION_GC_INTERVAL {
            return 0;
        }
        self.last_gc = now;
        let stale = self
            .sessions
            .iter()
            .filter_map(|(key, entry)| {
                if now.duration_since(entry.last_seen) > entry.expires_after {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for key in &stale {
            if let Some(entry) = self.sessions.remove(key) {
                if !entry.metadata.is_reverse && !entry.metadata.synced {
                    self.push_delta(SessionDelta {
                        kind: SessionDeltaKind::Close,
                        key: key.clone(),
                        decision: entry.decision,
                        metadata: entry.metadata,
                    });
                }
            }
        }
        let expired = stale.len() as u64;
        self.expired = self.expired.saturating_add(expired);
        expired
    }

    pub fn lookup(
        &mut self,
        key: &SessionKey,
        now: Instant,
        tcp_flags: u8,
    ) -> Option<SessionLookup> {
        self.sessions.get_mut(key).map(|entry| {
            if matches!(key.protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
                entry.closing = true;
            }
            entry.last_seen = now;
            entry.expires_after = if matches!(key.protocol, PROTO_TCP) && entry.closing {
                TCP_CLOSING_TIMEOUT
            } else {
                session_timeout(key.protocol, tcp_flags)
            };
            SessionLookup {
                decision: entry.decision,
                metadata: entry.metadata.clone(),
            }
        })
    }

    pub fn install_with_protocol(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now: Instant,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        if self.sessions.len() >= self.max_sessions {
            self.create_drops = self.create_drops.saturating_add(1);
            return false;
        }
        self.sessions.insert(
            key.clone(),
            SessionEntry {
                decision,
                metadata: metadata.clone(),
                last_seen: now,
                expires_after: session_timeout(protocol, tcp_flags),
                closing: matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0,
            },
        );
        if !metadata.is_reverse && !metadata.synced {
            self.push_delta(SessionDelta {
                kind: SessionDeltaKind::Open,
                key,
                decision,
                metadata,
            });
        }
        true
    }

    pub fn upsert_synced(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now: Instant,
        protocol: u8,
        tcp_flags: u8,
    ) {
        self.sessions.insert(
            key,
            SessionEntry {
                decision,
                metadata,
                last_seen: now,
                expires_after: session_timeout(protocol, tcp_flags),
                closing: matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0,
            },
        );
    }

    pub fn delete(&mut self, key: &SessionKey) {
        self.sessions.remove(key);
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

    fn push_delta(&mut self, delta: SessionDelta) {
        if self.deltas.len() >= MAX_SESSION_DELTAS {
            self.delta_drops = self.delta_drops.saturating_add(1);
            return;
        }
        self.deltas.push_back(delta);
    }
}

fn session_timeout(protocol: u8, tcp_flags: u8) -> Duration {
    match protocol {
        PROTO_TCP => {
            if (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
                TCP_CLOSING_TIMEOUT
            } else {
                TCP_SESSION_TIMEOUT
            }
        }
        PROTO_UDP => UDP_SESSION_TIMEOUT,
        PROTO_ICMP | PROTO_ICMPV6 => ICMP_SESSION_TIMEOUT,
        _ => OTHER_SESSION_TIMEOUT,
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
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
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
            ingress_zone: "lan".to_string(),
            egress_zone: "wan".to_string(),
            owner_rg_id: 1,
            is_reverse: false,
            synced: false,
        }
    }

    #[test]
    fn session_lookup_hits_after_install() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = Instant::now();
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10
        ));
        let hit = table.lookup(&key, now + Duration::from_millis(1), 0x10);
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
        let then = Instant::now() - Duration::from_secs(120);
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            then,
            PROTO_UDP,
            0
        ));
        let _ = table.drain_deltas(8);
        table.last_gc = Instant::now() - Duration::from_secs(2);
        let expired = table.expire_stale(Instant::now());
        assert_eq!(expired, 1);
        assert!(table.lookup(&key, Instant::now(), 0).is_none());
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
        assert_eq!(deltas[0].key, key);
    }

    #[test]
    fn tcp_fin_keeps_session_until_closing_timeout() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = Instant::now();
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x10
        ));
        let _ = table.drain_deltas(8);
        let hit = table.lookup(&key, now + Duration::from_millis(1), TCP_FIN);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: metadata(),
            })
        );
        assert!(
            table
                .lookup(&key, now + Duration::from_millis(2), 0x10)
                .is_some()
        );
        table.last_gc = now + TCP_CLOSING_TIMEOUT;
        let expired = table.expire_stale(now + TCP_CLOSING_TIMEOUT + Duration::from_secs(1));
        assert_eq!(expired, 1);
        assert!(table.lookup(&key, now + TCP_CLOSING_TIMEOUT + Duration::from_secs(2), 0).is_none());
        let deltas = table.drain_deltas(8);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
        assert_eq!(deltas[0].key, key);
    }

    #[test]
    fn synced_sessions_do_not_emit_deltas() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = Instant::now();
        let mut synced = metadata();
        synced.synced = true;
        table.upsert_synced(
            key.clone(),
            decision(),
            synced.clone(),
            now,
            PROTO_TCP,
            0x10,
        );
        let hit = table.lookup(&key, now + Duration::from_millis(1), 0x10);
        assert_eq!(
            hit,
            Some(SessionLookup {
                decision: decision(),
                metadata: synced,
            })
        );
        assert!(table.drain_deltas(8).is_empty());
        let _ = table.lookup(&key, now + Duration::from_millis(2), TCP_FIN);
        assert!(table.drain_deltas(8).is_empty());
    }
}
