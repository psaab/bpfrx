use crate::afxdp::ForwardingResolution;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const SESSION_GC_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_SESSIONS: usize = 131072;
const TCP_SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const ICMP_SESSION_TIMEOUT: Duration = Duration::from_secs(15);
const OTHER_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
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
    resolution: ForwardingResolution,
    last_seen: Instant,
    expires_after: Duration,
}

pub(crate) struct SessionTable {
    sessions: HashMap<SessionKey, SessionEntry>,
    last_gc: Instant,
    max_sessions: usize,
    expired: u64,
    create_drops: u64,
}

impl SessionTable {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            last_gc: Instant::now(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            expired: 0,
            create_drops: 0,
        }
    }

    pub fn expire_stale(&mut self, now: Instant) -> u64 {
        if now.duration_since(self.last_gc) < SESSION_GC_INTERVAL {
            return 0;
        }
        self.last_gc = now;
        let before = self.sessions.len();
        self.sessions
            .retain(|_, entry| now.duration_since(entry.last_seen) <= entry.expires_after);
        let expired = before.saturating_sub(self.sessions.len()) as u64;
        self.expired = self.expired.saturating_add(expired);
        expired
    }

    pub fn lookup(
        &mut self,
        key: &SessionKey,
        now: Instant,
        tcp_flags: u8,
    ) -> Option<ForwardingResolution> {
        let remove_after =
            matches!(key.protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0;
        let result = self.sessions.get_mut(key).map(|entry| {
            entry.last_seen = now;
            entry.expires_after = session_timeout(key.protocol, tcp_flags);
            entry.resolution
        });
        if remove_after {
            let _ = self.sessions.remove(key);
        }
        result
    }

    pub fn install_with_protocol(
        &mut self,
        key: SessionKey,
        resolution: ForwardingResolution,
        now: Instant,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        if self.sessions.len() >= self.max_sessions {
            self.create_drops = self.create_drops.saturating_add(1);
            return false;
        }
        self.sessions.insert(
            key,
            SessionEntry {
                resolution,
                last_seen: now,
                expires_after: session_timeout(protocol, tcp_flags),
            },
        );
        true
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

    #[test]
    fn session_lookup_hits_after_install() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = Instant::now();
        assert!(table.install_with_protocol(key.clone(), resolution(), now, PROTO_TCP, 0x10));
        let hit = table.lookup(&key, now + Duration::from_millis(1), 0x10);
        assert_eq!(hit, Some(resolution()));
    }

    #[test]
    fn session_expire_removes_stale_entries() {
        let mut table = SessionTable::new();
        let key = key_v6();
        let then = Instant::now() - Duration::from_secs(120);
        assert!(table.install_with_protocol(key.clone(), resolution(), then, PROTO_UDP, 0));
        table.last_gc = Instant::now() - Duration::from_secs(2);
        let expired = table.expire_stale(Instant::now());
        assert_eq!(expired, 1);
        assert!(table.lookup(&key, Instant::now(), 0).is_none());
    }

    #[test]
    fn tcp_fin_removes_session_after_lookup() {
        let mut table = SessionTable::new();
        let key = key_v4();
        let now = Instant::now();
        assert!(table.install_with_protocol(key.clone(), resolution(), now, PROTO_TCP, 0x10));
        let hit = table.lookup(&key, now + Duration::from_millis(1), TCP_FIN);
        assert_eq!(hit, Some(resolution()));
        assert!(
            table
                .lookup(&key, now + Duration::from_millis(2), 0x10)
                .is_none()
        );
    }
}
