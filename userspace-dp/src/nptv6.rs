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
//!
//! Two module invariants the rest of the crate relies on:
//!
//! * **Fail CLOSED on an unparseable config rule (#2240).**
//!   [`Nptv6State::try_from_snapshots`] rejects the whole snapshot (returning a
//!   [`crate::policy::SnapshotIntegrityError`]) on an empty/malformed prefix, an
//!   unsupported prefix length (not /48 or /64), or a mismatched internal/
//!   external prefix-length pair — one bad rule fails the snapshot rather than
//!   being silently filtered. The pre-fix parser silently `continue`d past a bad
//!   rule, and the Go dataplane compiler then deleted stale entries over only
//!   the VALID subset, so editing one previously-good rule into an invalid one
//!   tore down its working translation with no replacement. The apply preflight
//!   keeps the previous live forwarding state on this Err. This is the
//!   helper-boundary backstop to the Go commit-time gate
//!   (`pkg/config/compiler_nat.go`, #2240), consistent with the
//!   #2124/#2142/#2173/#2212 fail-closed family.
//! * **Reject overlapping prefixes — deterministic translation (#2241).**
//!   `translate_inbound`/`translate_outbound` resolve a match by FIRST hit in
//!   insertion order with no longest-prefix-match. Two rules whose prefixes
//!   overlap in the same direction (e.g. a /48 and a nested /64) would make the
//!   translation identity depend purely on rule order. `try_from_snapshots`
//!   rejects an overlapping pair so resolution stays deterministic. The Go
//!   commit-time gate (#2241) is primary; this is the helper-boundary backstop.

use crate::Nptv6RuleSnapshot;
use crate::policy::SnapshotIntegrityError;
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
    // #2380: the Go commit-time validator (validateNPTv6Strict in
    // pkg/config/compiler_nat.go) rejects a prefix with any bit set beyond the
    // prefix length, so a snapshot reaching the helper must already be
    // host-bits-clean. This debug_assert is a fail-on-revert tripwire: if the
    // Go gate is ever weakened, the next NPTv6 snapshot in a debug build will
    // abort here instead of silently discarding the extra words. Release
    // builds keep the historical masking behavior (the words are dropped).
    debug_assert!(
        words[prefix_words..8].iter().all(|&w| w == 0),
        "nptv6 prefix {s} has host bits set beyond /{prefix_len} \
         (Go commit gate should have rejected this)"
    );
    let mut prefix = [0u16; 4];
    for i in 0..prefix_words {
        prefix[i] = words[i];
    }
    Some((prefix, prefix_words))
}

impl Nptv6State {
    /// Build from config snapshot NPTv6 rules, failing CLOSED on an
    /// unparseable / unsupported / mismatched rule (#2240) and on overlapping
    /// prefixes (#2241).
    ///
    /// In a retired-eBPF world (#1373) the userspace helper is the enforcement
    /// plane. The pre-fix parser silently `continue`d past a bad rule, and the
    /// Go dataplane compiler then called `DeleteStaleNPTv6(written)` over only
    /// the VALID subset — so editing one previously-good rule into an invalid
    /// one removed its working translation entry with no replacement installed,
    /// silently disabling a working translation. The primary gate is the Go
    /// commit-time validation (`pkg/config/compiler_nat.go`, #2240); this is the
    /// helper-boundary backstop, consistent with the #2124/#2142/#2173/#2212
    /// fail-closed family.
    ///
    /// On any unparseable rule or overlapping pair this returns a
    /// `SnapshotIntegrityError`; the apply preflight
    /// (`forwarding_build`/`reconcile`/`refresh`) then keeps the previous live
    /// forwarding state rather than installing a narrower / nondeterministic
    /// NPTv6 config.
    pub(crate) fn try_from_snapshots(
        snaps: &[Nptv6RuleSnapshot],
    ) -> Result<Self, SnapshotIntegrityError> {
        let mut state = Nptv6State::default();
        // Track (prefix, prefix_words, rule_name) to reject overlaps (#2241).
        let mut internal_seen: Vec<([u16; 4], usize, String)> = Vec::with_capacity(snaps.len());
        let mut external_seen: Vec<([u16; 4], usize, String)> = Vec::with_capacity(snaps.len());
        for snap in snaps {
            let (internal_prefix, iwords) = match parse_prefix(&snap.internal_prefix) {
                Some(v) => v,
                None => {
                    return Err(SnapshotIntegrityError::Nptv6UnparseableRule {
                        rule_name: snap.name.clone(),
                        field: format!(
                            "internal/nptv6 prefix {:?} (must be a valid IPv6 /48 or /64)",
                            snap.internal_prefix
                        ),
                    });
                }
            };
            let (external_prefix, ewords) = match parse_prefix(&snap.external_prefix) {
                Some(v) => v,
                None => {
                    return Err(SnapshotIntegrityError::Nptv6UnparseableRule {
                        rule_name: snap.name.clone(),
                        field: format!(
                            "external/match prefix {:?} (must be a valid IPv6 /48 or /64)",
                            snap.external_prefix
                        ),
                    });
                }
            };
            // Both prefixes must have the same length.
            if iwords != ewords {
                return Err(SnapshotIntegrityError::Nptv6UnparseableRule {
                    rule_name: snap.name.clone(),
                    field: format!(
                        "prefix lengths must match (internal {:?} vs external {:?})",
                        snap.internal_prefix, snap.external_prefix
                    ),
                });
            }
            // #2241: reject overlapping prefixes in either direction so the
            // first-match dataplane resolution stays deterministic. Outbound
            // matches on the internal prefix; inbound matches on the external
            // prefix; check each independently.
            if let Some(prev) =
                find_overlap(&internal_seen, &internal_prefix, iwords)
            {
                return Err(SnapshotIntegrityError::Nptv6OverlappingPrefix {
                    first_rule: prev,
                    second_rule: snap.name.clone(),
                    direction: "outbound (internal)",
                });
            }
            if let Some(prev) =
                find_overlap(&external_seen, &external_prefix, ewords)
            {
                return Err(SnapshotIntegrityError::Nptv6OverlappingPrefix {
                    first_rule: prev,
                    second_rule: snap.name.clone(),
                    direction: "inbound (external)",
                });
            }
            internal_seen.push((internal_prefix, iwords, snap.name.clone()));
            external_seen.push((external_prefix, ewords, snap.name.clone()));

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
        Ok(state)
    }

    /// Infallible test convenience wrapper over [`try_from_snapshots`] (#2240).
    /// Panics on a snapshot integrity error, which valid test snapshots never
    /// produce. Production builds the state through `try_from_snapshots` so an
    /// unparseable rule or an overlapping pair rejects the snapshot and keeps
    /// the previous live state.
    #[cfg(test)]
    pub(crate) fn from_snapshots(snaps: &[Nptv6RuleSnapshot]) -> Self {
        Self::try_from_snapshots(snaps)
            .expect("test snapshot must not produce an NPTv6 integrity error")
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

/// #2241: returns the name of an already-seen rule whose prefix OVERLAPS the
/// candidate prefix, or `None` if there is no overlap. Two prefixes overlap
/// when one is a prefix of the other — i.e. their first `min(words_a, words_b)`
/// 16-bit words are equal. This covers identical /48-/48, identical /64-/64, and
/// a /48 nesting a /64 (the case that makes first-match resolution
/// order-dependent). Each direction (internal for outbound, external for
/// inbound) is checked independently by the caller.
fn find_overlap(
    seen: &[([u16; 4], usize, String)],
    candidate: &[u16; 4],
    candidate_words: usize,
) -> Option<String> {
    for (prefix, words, name) in seen {
        let common = candidate_words.min(*words);
        if candidate[..common] == prefix[..common] {
            return Some(name.clone());
        }
    }
    None
}

#[cfg(test)]
#[path = "nptv6_tests.rs"]
mod tests;

