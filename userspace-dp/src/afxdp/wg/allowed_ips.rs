//! AllowedIPs LPM table.
//!
//! WireGuard's AllowedIPs is a longest-prefix-match table from
//! `IpAddr → peer`. It is used by the WG reference implementation
//! for **both** directions:
//!
//! - Outbound: pick which peer to encrypt to from the inner dst IP.
//! - Inbound: verify the decrypted inner src IP belongs to the
//!   peer whose key decrypted the packet.
//!
//! In **xpf** we deliberately use it only for the second purpose.
//! The forwarding decision tells dispatch.rs which peer to encrypt
//! to (via the `wg_peer_pubkey` field on `TunnelEndpoint`), so the
//! outbound LPM is never consulted. This eliminates the
//! cryptokey-routing flaw that PR #1492 r11 was tripped up by:
//! overlapping AllowedIPs across peers can never route plaintext
//! to the wrong session.
//!
//! Implementation: a flat sorted-by-prefix-length-descending list.
//! AllowedIPs is reconciled at config-commit time, not on the hot
//! path, so a linear scan is fine and avoids the trie-allocation
//! storms that bit #923's prefix-set code at large fanout. The
//! scan is also branch-predictable and cache-friendly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A single AllowedIPs entry: `(prefix, prefix_len, peer_index)`.
/// `peer_index` is an opaque handle into `WgEngine::peers`; the
/// engine maps it back to the peer pubkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    prefix: PrefixBits,
    prefix_len: u8,
    peer_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrefixBits {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Debug, Default, Clone)]
pub(crate) struct AllowedIps {
    /// Sorted by `prefix_len` descending so the first match wins.
    /// IPv4 and IPv6 entries are interleaved — `lookup` dispatches
    /// on the query family.
    entries: Vec<Entry>,
}

impl AllowedIps {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Insert a CIDR for a peer. Re-sorts. Slow path only.
    pub(crate) fn insert(&mut self, cidr: ipnet::IpNet, peer_index: u32) {
        let entry = match cidr {
            ipnet::IpNet::V4(net) => Entry {
                prefix: PrefixBits::V4(net.network().octets()),
                prefix_len: net.prefix_len(),
                peer_index,
            },
            ipnet::IpNet::V6(net) => Entry {
                prefix: PrefixBits::V6(net.network().octets()),
                prefix_len: net.prefix_len(),
                peer_index,
            },
        };
        // Replace exact-prefix duplicates; this keeps reconciliation
        // idempotent across config refreshes.
        self.entries.retain(|e| !(e.prefix == entry.prefix && e.prefix_len == entry.prefix_len));
        self.entries.push(entry);
        self.entries.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    /// Remove every entry for a peer. Used when the peer is dropped
    /// from the config snapshot.
    pub(crate) fn remove_peer(&mut self, peer_index: u32) {
        self.entries.retain(|e| e.peer_index != peer_index);
    }

    /// Longest-prefix-match lookup. Returns the peer_index of the
    /// most specific covering prefix, or `None` if no entry covers
    /// `addr`.
    pub(crate) fn lookup(&self, addr: IpAddr) -> Option<u32> {
        match addr {
            IpAddr::V4(ip) => self.lookup_v4(ip),
            IpAddr::V6(ip) => self.lookup_v6(ip),
        }
    }

    fn lookup_v4(&self, ip: Ipv4Addr) -> Option<u32> {
        let bytes = ip.octets();
        // Entries are sorted by prefix_len descending. First match wins.
        for entry in &self.entries {
            if let PrefixBits::V4(prefix) = entry.prefix {
                if prefix_matches(&bytes, &prefix, entry.prefix_len) {
                    return Some(entry.peer_index);
                }
            }
        }
        None
    }

    fn lookup_v6(&self, ip: Ipv6Addr) -> Option<u32> {
        let bytes = ip.octets();
        for entry in &self.entries {
            if let PrefixBits::V6(prefix) = entry.prefix {
                if prefix_matches(&bytes, &prefix, entry.prefix_len) {
                    return Some(entry.peer_index);
                }
            }
        }
        None
    }

    /// Verify that `addr` is covered by *some* prefix belonging to
    /// `peer_index`. This is the gate used on decap: after we know
    /// which peer decrypted the packet, we check the inner src IP
    /// against that peer's AllowedIPs.
    ///
    /// Returns true on a match. Returns false if no entry for
    /// `peer_index` covers `addr` — in which case the packet must
    /// be dropped.
    pub(crate) fn matches_for_peer(&self, addr: IpAddr, peer_index: u32) -> bool {
        match self.lookup(addr) {
            Some(idx) => idx == peer_index,
            None => false,
        }
    }
}

fn prefix_matches(addr: &[u8], prefix: &[u8], len: u8) -> bool {
    let full_bytes = (len / 8) as usize;
    if addr[..full_bytes] != prefix[..full_bytes] {
        return false;
    }
    let bits = len % 8;
    if bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - bits);
    (addr[full_bytes] & mask) == (prefix[full_bytes] & mask)
}

#[cfg(test)]
mod allowed_ips_tests {
    use super::*;
    use std::str::FromStr;

    fn net(s: &str) -> ipnet::IpNet {
        ipnet::IpNet::from_str(s).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn longest_prefix_wins() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("10.1.0.0/16"), 2);
        t.insert(net("10.1.2.0/24"), 3);
        assert_eq!(t.lookup(ip("10.1.2.5")), Some(3));
        assert_eq!(t.lookup(ip("10.1.3.5")), Some(2));
        assert_eq!(t.lookup(ip("10.2.0.5")), Some(1));
        assert_eq!(t.lookup(ip("11.0.0.0")), None);
    }

    #[test]
    fn ipv6_lookup() {
        let mut t = AllowedIps::new();
        t.insert(net("2001:db8::/32"), 1);
        t.insert(net("2001:db8:1::/48"), 2);
        assert_eq!(t.lookup(ip("2001:db8:1::1")), Some(2));
        assert_eq!(t.lookup(ip("2001:db8:2::1")), Some(1));
        assert_eq!(t.lookup(ip("2001:db9::1")), None);
    }

    #[test]
    fn matches_for_peer_rejects_wrong_peer() {
        // The core safety property: a peer's AllowedIPs gate must
        // reject inner src IPs that belong to a *different* peer.
        // This is what the inbound side relies on.
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/24"), 1);
        t.insert(net("10.0.1.0/24"), 2);
        assert!(t.matches_for_peer(ip("10.0.0.5"), 1));
        assert!(!t.matches_for_peer(ip("10.0.0.5"), 2));
        assert!(t.matches_for_peer(ip("10.0.1.5"), 2));
        assert!(!t.matches_for_peer(ip("10.0.1.5"), 1));
        // No matching prefix → reject for any peer.
        assert!(!t.matches_for_peer(ip("10.1.0.5"), 1));
    }

    #[test]
    fn duplicate_insert_replaces() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("10.0.0.0/8"), 2);
        // Same prefix, different peer — the latter wins.
        assert_eq!(t.lookup(ip("10.1.1.1")), Some(2));
    }

    #[test]
    fn remove_peer_clears_entries() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("192.168.0.0/16"), 1);
        t.insert(net("172.16.0.0/12"), 2);
        t.remove_peer(1);
        assert_eq!(t.lookup(ip("10.1.1.1")), None);
        assert_eq!(t.lookup(ip("192.168.1.1")), None);
        assert_eq!(t.lookup(ip("172.16.1.1")), Some(2));
    }

    #[test]
    fn slash_zero_matches_everything() {
        let mut t = AllowedIps::new();
        t.insert(net("0.0.0.0/0"), 9);
        t.insert(net("10.0.0.0/8"), 1);
        // /8 wins for 10/8
        assert_eq!(t.lookup(ip("10.0.0.1")), Some(1));
        // /0 catches everything else
        assert_eq!(t.lookup(ip("8.8.8.8")), Some(9));
    }
}
