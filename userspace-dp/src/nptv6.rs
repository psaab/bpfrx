//! NPTv6 (RFC 6296) stateless IPv6-to-IPv6 prefix translation.
//!
//! Each rule maps an internal /48 or /64 prefix to an external prefix.
//! A precomputed *adjustment* value ensures checksum neutrality so that
//! no L4 checksum update is required after translation.
//!
//! Translation algorithm:
//! - Rewrite the prefix words (3 for /48, 4 for /64).
//! - Adjust the next word (word[3] for /48, word[4] for /64) using
//!   ones-complement arithmetic to maintain checksum neutrality.
//! - If the adjusted word becomes 0xFFFF, replace with 0x0000.

use crate::Nptv6RuleSnapshot;
use std::net::Ipv6Addr;

/// A parsed NPTv6 rule with precomputed adjustment.
#[derive(Clone, Debug)]
pub(crate) struct Nptv6Rule {
    /// Prefix words to write into the address (3 for /48, 4 for /64).
    pub(crate) internal_prefix: [u16; 4],
    pub(crate) external_prefix: [u16; 4],
    /// Precomputed checksum-neutral adjustment (RFC 6296 Section 3.1).
    pub(crate) adjustment: u16,
    /// Number of prefix words to rewrite: 3 for /48, 4 for /64.
    pub(crate) prefix_words: usize,
}

/// Aggregated NPTv6 state built from config snapshots.
#[derive(Clone, Debug, Default)]
pub(crate) struct Nptv6State {
    /// Rules for inbound translation (external dst -> internal dst).
    /// Indexed by external prefix.
    inbound: Vec<Nptv6Rule>,
    /// Rules for outbound translation (internal src -> external src).
    /// Indexed by internal prefix.
    outbound: Vec<Nptv6Rule>,
}

/// Compute the RFC 6296 adjustment value.
///
/// `adjustment = ones_complement_sum(internal_prefix) - ones_complement_sum(external_prefix)`
///
/// This matches the BPF implementation in `xpf_nat.h`.
fn compute_adjustment(internal: &[u16], external: &[u16], prefix_words: usize) -> u16 {
    let mut isum: u32 = 0;
    let mut esum: u32 = 0;
    for i in 0..prefix_words {
        isum += internal[i] as u32;
        esum += external[i] as u32;
    }
    // Fold to 16-bit ones-complement
    while isum > 0xFFFF {
        isum = (isum & 0xFFFF) + (isum >> 16);
    }
    while esum > 0xFFFF {
        esum = (esum & 0xFFFF) + (esum >> 16);
    }
    // adjustment = internal_sum - external_sum (ones-complement subtraction)
    // In ones-complement: a - b = a + ~b
    let mut adj: u32 = isum + (!esum & 0xFFFF);
    while adj > 0xFFFF {
        adj = (adj & 0xFFFF) + (adj >> 16);
    }
    adj as u16
}

/// Apply an adjustment to a 16-bit word using ones-complement arithmetic.
/// Returns the adjusted word, with 0xFFFF mapped to 0x0000 per RFC 6296.
#[inline]
fn adjust_word(word: u16, adj: u16) -> u16 {
    let mut sum: u32 = word as u32 + adj as u32;
    // Fold carry
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    let result = sum as u16;
    if result == 0xFFFF { 0x0000 } else { result }
}

/// Extract 16-bit words from an Ipv6Addr.
fn ipv6_to_words(addr: &Ipv6Addr) -> [u16; 8] {
    let octets = addr.octets();
    let mut words = [0u16; 8];
    for i in 0..8 {
        words[i] = u16::from_be_bytes([octets[i * 2], octets[i * 2 + 1]]);
    }
    words
}

/// Reconstruct an Ipv6Addr from 16-bit words.
fn words_to_ipv6(words: &[u16; 8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    for i in 0..8 {
        let bytes = words[i].to_be_bytes();
        octets[i * 2] = bytes[0];
        octets[i * 2 + 1] = bytes[1];
    }
    Ipv6Addr::from(octets)
}

/// Parse a prefix string like "2001:db8:1::/48" into ([u16; 4], prefix_len).
/// Returns None if parsing fails or prefix length is not /48 or /64.
fn parse_prefix(s: &str) -> Option<([u16; 4], usize)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let prefix_len: u8 = parts[1].parse().ok()?;
    let prefix_words = match prefix_len {
        48 => 3,
        64 => 4,
        _ => return None,
    };
    let addr: Ipv6Addr = parts[0].parse().ok()?;
    let words = ipv6_to_words(&addr);
    let mut prefix = [0u16; 4];
    for i in 0..prefix_words {
        prefix[i] = words[i];
    }
    Some((prefix, prefix_words))
}

impl Nptv6State {
    /// Build from config snapshot NPTv6 rules.
    pub(crate) fn from_snapshots(snaps: &[Nptv6RuleSnapshot]) -> Self {
        let mut state = Nptv6State::default();
        for snap in snaps {
            let (internal_prefix, iwords) = match parse_prefix(&snap.internal_prefix) {
                Some(v) => v,
                None => continue,
            };
            let (external_prefix, ewords) = match parse_prefix(&snap.external_prefix) {
                Some(v) => v,
                None => continue,
            };
            // Both prefixes must have the same length.
            if iwords != ewords {
                continue;
            }
            let adjustment = compute_adjustment(&internal_prefix, &external_prefix, iwords);

            let rule = Nptv6Rule {
                internal_prefix,
                external_prefix,
                adjustment,
                prefix_words: iwords,
            };

            // Inbound: match external prefix on dst, rewrite to internal.
            state.inbound.push(rule.clone());
            // Outbound: match internal prefix on src, rewrite to external.
            state.outbound.push(rule);
        }
        state
    }

    /// Translate an inbound packet's destination address.
    /// If `dst` matches an external prefix, rewrites it in-place to the
    /// internal prefix and returns `true`.
    pub(crate) fn translate_inbound(&self, dst: &mut Ipv6Addr) -> bool {
        let mut words = ipv6_to_words(dst);
        for rule in &self.inbound {
            if prefix_matches(&words, &rule.external_prefix, rule.prefix_words) {
                // Rewrite prefix words to internal prefix.
                for i in 0..rule.prefix_words {
                    words[i] = rule.internal_prefix[i];
                }
                // Adjust the word after the prefix: inbound uses ~adjustment.
                let adj_word = if rule.prefix_words >= 4 { 4 } else { 3 };
                let inv_adj = !rule.adjustment; // ones-complement NOT
                words[adj_word] = adjust_word(words[adj_word], inv_adj);
                *dst = words_to_ipv6(&words);
                return true;
            }
        }
        false
    }

    /// Translate an outbound packet's source address.
    /// If `src` matches an internal prefix, rewrites it in-place to the
    /// external prefix and returns `true`.
    pub(crate) fn translate_outbound(&self, src: &mut Ipv6Addr) -> bool {
        let mut words = ipv6_to_words(src);
        for rule in &self.outbound {
            if prefix_matches(&words, &rule.internal_prefix, rule.prefix_words) {
                // Rewrite prefix words to external prefix.
                for i in 0..rule.prefix_words {
                    words[i] = rule.external_prefix[i];
                }
                // Adjust the word after the prefix: outbound uses adjustment directly.
                let adj_word = if rule.prefix_words >= 4 { 4 } else { 3 };
                words[adj_word] = adjust_word(words[adj_word], rule.adjustment);
                *src = words_to_ipv6(&words);
                return true;
            }
        }
        false
    }

    /// Returns true if there are any NPTv6 rules configured.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_empty(&self) -> bool {
        self.inbound.is_empty()
    }

    /// Returns all external prefixes as (prefix_addr, prefix_len) pairs.
    #[allow(dead_code)]
    pub(crate) fn external_prefixes(&self) -> Vec<(Ipv6Addr, u8)> {
        self.inbound
            .iter()
            .map(|rule| {
                let mut words = [0u16; 8];
                for i in 0..rule.prefix_words {
                    words[i] = rule.external_prefix[i];
                }
                let prefix_len = (rule.prefix_words * 16) as u8;
                (words_to_ipv6(&words), prefix_len)
            })
            .collect()
    }
}

/// Check if the first `prefix_words` 16-bit words of `addr_words` match `prefix`.
#[inline]
fn prefix_matches(addr_words: &[u16; 8], prefix: &[u16; 4], prefix_words: usize) -> bool {
    for i in 0..prefix_words {
        if addr_words[i] != prefix[i] {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[path = "nptv6_tests.rs"]
mod tests;

