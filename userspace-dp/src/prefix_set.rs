//! #923: adaptive IP prefix set for policy address matching.
//!
//! Replaces the linear `nets.iter().any(|net| net.contains(ip))`
//! scan in `policy.rs` with a three-variant enum:
//!
//! - `MatchAny` — covers every address. Constructed when the input
//!   prefix list is empty (legacy `source_addresses: ["any"]`,
//!   `destination_addresses: []`, or all-malformed-input cases all
//!   collapse here) OR when any input prefix has length 0 (`/0`,
//!   `::/0`).
//! - `Linear(Vec)` — 1..=16 prefixes; cache-friendly linear scan.
//! - `Trie` — >16 prefixes; uncompressed binary radix tree. Walk
//!   the IP MSB→LSB bit-by-bit, short-circuit on the first node
//!   whose `covers` flag is set.
//!
//! The semantics are exactly the legacy `nets_match_v4/v6`:
//! "match if any prefix in the set covers the IP". No
//! longest-prefix tiebreak is performed; this is a boolean-only
//! membership test.

use crate::prefix::{PrefixV4, PrefixV6};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Threshold below which a `Linear` variant is used. See
/// `docs/pr/923-policy-prefix-set/plan.md` §"Threshold rationale".
/// 16 is a starting tunable; the companion bench
/// `benches/prefix_set_lookup.rs` gates the worst-case build cost
/// (`Box<TrieNode>` allocation footprint for 256 random /32
/// prefixes) at p95 ≤ 2 ms — it does NOT sweep thresholds yet.
/// A threshold-sweep + lookup-cost microbench is a follow-up if
/// the constant turns out to be poorly tuned in production traces.
pub(crate) const PREFIX_SET_LINEAR_MAX: usize = 16;

/// IPv4 prefix membership set. See module docs.
#[derive(Debug, Clone)]
pub(crate) enum PrefixSetV4 {
    MatchAny,
    Linear(Vec<PrefixV4>),
    Trie(PrefixTrieV4),
}

#[derive(Debug, Clone)]
pub(crate) enum PrefixSetV6 {
    MatchAny,
    Linear(Vec<PrefixV6>),
    Trie(PrefixTrieV6),
}

impl PrefixSetV4 {
    /// Build a `PrefixSetV4` from a vector of prefixes.
    ///
    /// - Empty input → `MatchAny` (legacy behavior — `is_empty()`
    ///   on the old `Vec<PrefixV4>` was treated as "match everything").
    /// - Any prefix with length 0 (`0.0.0.0/0`) → `MatchAny`. The
    ///   trie path never sets `covers` on the root, so we shortcut.
    /// - Up to `PREFIX_SET_LINEAR_MAX` prefixes → `Linear`.
    /// - More → `Trie`.
    pub(crate) fn from_prefixes(prefixes: Vec<PrefixV4>) -> Self {
        if prefixes.is_empty() {
            return Self::MatchAny;
        }
        if prefixes.iter().any(|p| p.prefix_len() == 0) {
            return Self::MatchAny;
        }
        if prefixes.len() <= PREFIX_SET_LINEAR_MAX {
            Self::Linear(prefixes)
        } else {
            let mut trie = PrefixTrieV4::default();
            for p in &prefixes {
                trie.insert(p);
            }
            Self::Trie(trie)
        }
    }

    /// Returns true iff some prefix in the set covers `ip`.
    #[inline]
    pub(crate) fn contains(&self, ip: Ipv4Addr) -> bool {
        match self {
            Self::MatchAny => true,
            Self::Linear(v) => v.iter().any(|p| p.contains(ip)),
            Self::Trie(t) => t.contains(ip),
        }
    }

    /// Set cardinality (count of unique terminal prefixes), used
    /// only for the `forwarding_build.rs:467` debug-log readout.
    /// Two intentional changes vs the legacy `Vec::len()`:
    /// - `MatchAny` reports 0 (matches the legacy "empty Vec ⇒ 0"
    ///   read; new path is `["any"]` or all-malformed-input or any
    ///   `/0` collapse).
    /// - `Trie` reports the deduped count: inserting the same
    ///   prefix N times yields size 1, not N. Linear preserves the
    ///   raw input length.
    /// Debug-only; not on any data-path.
    pub(crate) fn prefix_count(&self) -> usize {
        match self {
            Self::MatchAny => 0,
            Self::Linear(v) => v.len(),
            Self::Trie(t) => t.size,
        }
    }
}

impl PrefixSetV6 {
    pub(crate) fn from_prefixes(prefixes: Vec<PrefixV6>) -> Self {
        if prefixes.is_empty() {
            return Self::MatchAny;
        }
        if prefixes.iter().any(|p| p.prefix_len() == 0) {
            return Self::MatchAny;
        }
        if prefixes.len() <= PREFIX_SET_LINEAR_MAX {
            Self::Linear(prefixes)
        } else {
            let mut trie = PrefixTrieV6::default();
            for p in &prefixes {
                trie.insert(p);
            }
            Self::Trie(trie)
        }
    }

    #[inline]
    pub(crate) fn contains(&self, ip: Ipv6Addr) -> bool {
        match self {
            Self::MatchAny => true,
            Self::Linear(v) => v.iter().any(|p| p.contains(ip)),
            Self::Trie(t) => t.contains(ip),
        }
    }

    pub(crate) fn prefix_count(&self) -> usize {
        match self {
            Self::MatchAny => 0,
            Self::Linear(v) => v.len(),
            Self::Trie(t) => t.size,
        }
    }
}

impl Default for PrefixSetV4 {
    fn default() -> Self {
        Self::MatchAny
    }
}

impl Default for PrefixSetV6 {
    fn default() -> Self {
        Self::MatchAny
    }
}

// -------------------------------------------------------------
// Uncompressed binary trie (NOT Patricia — no path compression).
// -------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub(crate) struct PrefixTrieV4 {
    root: TrieNode,
    size: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PrefixTrieV6 {
    root: TrieNode,
    size: usize,
}

#[derive(Debug, Clone, Default)]
struct TrieNode {
    /// True iff some inserted prefix has its END at this node
    /// (depth equals the prefix's `prefix_len`). Lookup short-
    /// circuits on the first `covers == true` along the bit walk.
    covers: bool,
    /// Children indexed by next bit (0 or 1).
    children: [Option<Box<TrieNode>>; 2],
}

impl PrefixTrieV4 {
    fn insert(&mut self, prefix: &PrefixV4) {
        let bits = u32::from(prefix.addr());
        let depth = prefix.prefix_len() as usize;
        // /0 is filtered to MatchAny by `from_prefixes` before any
        // call to insert(). In release a /0 insert is a no-op
        // because the loop body runs zero iterations and `node`
        // remains the root — root.covers gets set, but `contains()`
        // never inspects root.covers (it always descends a child
        // first), so a private bypass-insert of /0 would NOT match
        // all. Behaviour is "silently ineffective", not unsafe.
        debug_assert!(depth > 0, "/0 must be filtered to MatchAny");
        let mut node = &mut self.root;
        for i in 0..depth {
            // MSB-first walk: bit at depth `i` is bit `31 - i`.
            let bit = ((bits >> (31 - i)) & 1) as usize;
            node = node.children[bit].get_or_insert_with(Box::default);
        }
        if !node.covers {
            self.size += 1;
        }
        node.covers = true;
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        let bits = u32::from(ip);
        let mut node = &self.root;
        // Skip root: any covering prefix has length ≥ 1 and lives
        // at depth ≥ 1. (See insert() for the /0-was-filtered note.)
        for i in 0..32 {
            let bit = ((bits >> (31 - i)) & 1) as usize;
            match node.children[bit].as_deref() {
                Some(next) => {
                    if next.covers {
                        return true;
                    }
                    node = next;
                }
                None => return false,
            }
        }
        false
    }
}

impl PrefixTrieV6 {
    fn insert(&mut self, prefix: &PrefixV6) {
        let bits = u128::from(prefix.addr());
        let depth = prefix.prefix_len() as usize;
        // See PrefixTrieV4::insert for the ::/0 filtering note.
        debug_assert!(depth > 0, "::/0 must be filtered to MatchAny");
        let mut node = &mut self.root;
        for i in 0..depth {
            let bit = ((bits >> (127 - i)) & 1) as usize;
            node = node.children[bit].get_or_insert_with(Box::default);
        }
        if !node.covers {
            self.size += 1;
        }
        node.covers = true;
    }

    fn contains(&self, ip: Ipv6Addr) -> bool {
        let bits = u128::from(ip);
        let mut node = &self.root;
        // Skip root: any covering prefix has length ≥ 1. See
        // PrefixTrieV4::contains.
        for i in 0..128 {
            let bit = ((bits >> (127 - i)) & 1) as usize;
            match node.children[bit].as_deref() {
                Some(next) => {
                    if next.covers {
                        return true;
                    }
                    node = next;
                }
                None => return false,
            }
        }
        false
    }
}

#[cfg(test)]
#[path = "prefix_set_tests.rs"]
mod tests;

