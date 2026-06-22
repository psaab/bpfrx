//! NAT64 (RFC 6052 / RFC 7915) stateless IPv4↔IPv6 translation for the
//! userspace dataplane.
//!
//! ## ICMP error translation (#2219)
//!
//! Both directions translate ICMP *error* messages, not only echo
//! request/reply: Destination-Unreachable, Time-Exceeded, Parameter-Problem,
//! and Packet-Too-Big↔Fragmentation-Needed (with the 20-byte MTU adjustment for
//! the NAT64 header-size delta, clamped to the IPv6 minimum link MTU on the
//! v4→v6 side) per the RFC 7915 §4.2 (v4→v6) and §5.2 (v6→v4) type/code maps.
//! An ICMP error carries the original (return-direction) packet quoted inside
//! it, so the EMBEDDED IP header (+leading L4 bytes) is also NAT64-translated:
//! its addresses are mapped v6↔v4 and its lengths/checksum fixed, because the
//! embedded packet is the return-direction tuple a receiver matches the error
//! against. Without this, PMTUD blackholes (a server's Fragmentation-Needed
//! never reaches the v6 client) and traceroute shows no hops across NAT64.
//! The embedded packet is translated through a fixed stack scratch buffer
//! ([`MAX_EMBEDDED_LEN`]) — NO per-packet heap allocation, consistent with the
//! zero-alloc invariant below. Types with no IPv4/IPv6 analogue (NDP, MLD,
//! ICMPv4 redirect/source-quench, etc.) are dropped, not mistranslated.
//!
//! Two module invariants the rest of the crate relies on:
//!
//! * **No per-packet heap allocation on the translate hot path (#2211).** The
//!   v6↔v4 translators have an allocation-free core
//!   ([`write_v6_to_v4_into`] / [`write_v4_to_v6_into`]) that writes the
//!   translated L3 directly into a caller-provided buffer, and the
//!   pseudo-header L4 checksum is STREAMED (no per-call `Vec`). The frame
//!   builders ([`build_nat64_v6_to_v4_frame`] / [`build_nat64_v4_to_v6_frame`])
//!   make exactly ONE output allocation — the `TxRequest.bytes` the TX path
//!   requires — and translate straight into its tail, eliminating the former
//!   intermediate L3 `Vec`, the pseudo-header `Vec`s, and the double L4 copy.
//!   The `translate_v6_to_v4` / `translate_v4_to_v6` `Vec`-returning wrappers
//!   are `#[cfg(test)]`-only: the differential tests use them to assert the
//!   `_into` cores are byte-identical to an owned-`Vec` translation. They are
//!   NOT on the forwarding hot path and are absent from the release build.
//! * **Fail CLOSED on an unparseable config rule (#2212).**
//!   [`Nat64State::try_from_snapshots`] rejects the whole snapshot (returning a
//!   [`crate::policy::SnapshotIntegrityError`]) on an empty/malformed/non-/96
//!   prefix or a pool address that is neither a bare IPv4 nor a `/32` host —
//!   one bad pool entry fails the rule rather than being silently filtered. The
//!   apply preflight then keeps the previous live forwarding state. This is the
//!   helper-boundary backstop to the Go commit-time gate
//!   (`pkg/config/compiler_nat.go`, #2173), consistent with the
//!   #2124/#2142/#2173/#2175 fail-closed family. The pre-fix parser silently
//!   `continue`d/`filter_map`ped bad input, which could leave a prefix present
//!   with an emptied pool — `allocate_v4_source` then returns `None` and NAT64
//!   forward translation silently stops (a fail-open in the retired-eBPF
//!   enforcement plane).

use crate::NAT64RuleSnapshot;
use crate::nat::NatDecision;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

/// NAT64 prefix configuration — one per `security nat nat64` rule.
#[derive(Debug)]
pub(crate) struct Nat64Prefix {
    /// First 96 bits of the NAT64 prefix (e.g. 64:ff9b::).
    pub(crate) prefix_bytes: [u8; 12],
    /// IPv4 source pool addresses for SNAT.
    pub(crate) pool_v4: Vec<Ipv4Addr>,
    /// Round-robin index for pool allocation (atomic for thread safety).
    pool_index: AtomicUsize,
}

impl Clone for Nat64Prefix {
    fn clone(&self) -> Self {
        Self {
            prefix_bytes: self.prefix_bytes,
            pool_v4: self.pool_v4.clone(),
            pool_index: AtomicUsize::new(self.pool_index.load(Ordering::Relaxed)),
        }
    }
}

/// Aggregated NAT64 state built from config snapshots.
#[derive(Clone, Debug, Default)]
pub(crate) struct Nat64State {
    pub(crate) prefixes: Vec<Nat64Prefix>,
    /// Mirrors the global `security nat natv6v4 no-v6-frag-header` option. When
    /// set, the IPv6->IPv4 translator emits a fragmentable (DF=0, non-atomic)
    /// IPv4 packet per RFC 7915 5.1 rather than the default DF=1 atomic framing.
    /// The option is configured once at the natv6v4 level; the Go side
    /// replicates it onto every NAT64 rule snapshot, so any rule carrying it
    /// enables it globally.
    pub(crate) no_v6_frag_header: bool,
}

/// Reverse-direction state stored with NAT64 sessions so IPv4 replies can be
/// translated back to IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Nat64ReverseInfo {
    pub(crate) orig_src_v6: Ipv6Addr,
    pub(crate) orig_dst_v6: Ipv6Addr,
}

/// Tri-state result of a NAT64 destination lookup (#2291).
///
/// The pre-fix lookup collapsed "prefix matched but no source could be
/// allocated" into "no NAT64 match" (a bare `Option<...>` whose `None`
/// meant both), so a matched-but-unallocatable destination fell through to
/// ordinary IPv6 route lookup on the SYNTHETIC NAT64 destination
/// (`64:ff9b::a.b.c.d`). With a permissive default IPv6 route present, that
/// silently leaked untranslated synthetic-destination traffic upstream — a
/// fail-OPEN at the NAT64 boundary.
///
/// Splitting the result into three states lets the caller fail CLOSED on the
/// unallocatable case (drop + counter) while still routing genuinely
/// non-matching IPv6 normally. Consistent with the project's fail-closed
/// family (#2124/#2142/#2173/#2175).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Nat64Match {
    /// The destination does not match any configured NAT64 prefix — continue
    /// ordinary IPv6 route lookup. This is the ONLY arm that routes as IPv6.
    NoPrefixMatch,
    /// A prefix matched AND a source IPv4 was allocated — translate.
    MatchReady {
        /// Index of the matched NAT64 prefix in `prefixes`.
        prefix_idx: usize,
        /// IPv4 destination extracted from the synthetic NAT64 address.
        dst_v4: Ipv4Addr,
        /// Allocated IPv4 SNAT source from the matched prefix's pool.
        snat_v4: Ipv4Addr,
        /// Original synthetic IPv6 destination (kept for the reverse path).
        dst_v6: Ipv6Addr,
    },
    /// A prefix matched but NO IPv4 source could be allocated (empty /
    /// exhausted pool — a legitimate wire state the Go side emits for a
    /// no-source-pool rule). The packet MUST be dropped, not routed as IPv6.
    MatchUnavailable,
}

/// Parse a NAT64 source-pool IPv4 address that may carry a canonical host
/// mask (`x.x.x.x/32`). Address-range expansion stamps `/32` on every pool
/// IP and `Ipv4Addr::from_str` rejects CIDR, so the mask is stripped before
/// parse (#2123). The pool holds exact host source addresses, so only a bare
/// address or the host mask (`/32`) is accepted; a non-host mask (`/24`) or
/// garbage suffix returns `None` and is filtered, surfacing a misconfigured
/// entry rather than silently coercing it to a host address.
fn parse_pool_v4(s: &str) -> Option<Ipv4Addr> {
    let mut parts = s.splitn(2, '/');
    let addr: Ipv4Addr = parts.next()?.parse().ok()?;
    match parts.next() {
        None => Some(addr),
        Some("32") => Some(addr),
        Some(_) => None,
    }
}

impl Nat64State {
    /// Build from config snapshot NAT64 rules, failing CLOSED on an
    /// unparseable rule (#2212).
    ///
    /// In a retired-eBPF world (#1373) the userspace helper is the enforcement
    /// plane. The pre-fix parser silently `continue`d past a bad prefix and
    /// `filter_map`ped malformed pool entries away, so a mixed-version control
    /// plane, a serialization bug, or a missed Go validation edge could install
    /// a NAT64 rule whose prefix is present but whose pool is silently empty —
    /// `allocate_v4_source` then returns `None` and NAT64 forward translation
    /// stops with no failure surfaced. The primary gate is the Go commit-time
    /// validation (`pkg/config/compiler_nat.go`, #2173, host-mask + pool
    /// representability); this is the helper-boundary backstop, consistent with
    /// the #2124/#2142/#2173/#2175 fail-closed family.
    ///
    /// On any unparseable rule this returns a `SnapshotIntegrityError`; the
    /// apply preflight (`forwarding_build`/`reconcile`/`refresh`) then keeps the
    /// previous live forwarding state rather than installing a narrower NAT64
    /// config. An empty pool that is genuinely UNCONFIGURED (no `pool_addresses`
    /// on the wire — the legitimate "no source-pool" state the Go side emits)
    /// is NOT an error: only a pool that was non-empty on the wire but parsed to
    /// empty (every entry dropped) is rejected — that is the exact silent
    /// pool-narrowing fail-open this guards against.
    pub(crate) fn try_from_snapshots(
        snaps: &[NAT64RuleSnapshot],
    ) -> Result<Self, crate::policy::SnapshotIntegrityError> {
        use crate::policy::SnapshotIntegrityError;
        let mut prefixes = Vec::with_capacity(snaps.len());
        // The natv6v4 no-v6-frag-header option is global; the Go side stamps it
        // onto every rule snapshot. Treat the state as enabled if any rule
        // carries the flag (they all carry the same value in practice).
        let no_v6_frag_header = snaps.iter().any(|s| s.no_v6_frag_header);
        for snap in snaps {
            // Every NAT64 rule on the wire is enabled (the Go side skips
            // empty-prefix rules in buildNAT64Snapshots), so an empty prefix
            // here is anomalous: fail closed rather than silently dropping it.
            if snap.prefix.is_empty() {
                return Err(SnapshotIntegrityError::Nat64UnparseableRule {
                    rule_name: snap.name.clone(),
                    field: "prefix (empty)".to_string(),
                });
            }
            // Parse "64:ff9b::/96" — extract the prefix address and verify /96.
            let parts: Vec<&str> = snap.prefix.split('/').collect();
            match parts.get(1).and_then(|s| s.parse::<u8>().ok()) {
                Some(96) => {}
                // Only /96 is supported by the translator today; a different
                // length (or a missing/garbage mask) was silently dropped
                // pre-fix, leaving the rule absent at the dataplane.
                _ => {
                    return Err(SnapshotIntegrityError::Nat64UnparseableRule {
                        rule_name: snap.name.clone(),
                        field: format!("prefix {:?} (only /96 is supported)", snap.prefix),
                    });
                }
            }
            let addr: Ipv6Addr = match parts[0].parse() {
                Ok(a) => a,
                Err(_) => {
                    return Err(SnapshotIntegrityError::Nat64UnparseableRule {
                        rule_name: snap.name.clone(),
                        field: format!("prefix address {:?}", parts[0]),
                    });
                }
            };
            let octets = addr.octets();
            let mut prefix_bytes = [0u8; 12];
            prefix_bytes.copy_from_slice(&octets[..12]);
            // Pool addresses may carry a canonical host mask: an
            // address-range source pool (`address A to B`) is expanded by
            // the Go compiler into per-IP `/32` entries (#2123), and
            // `Ipv4Addr::from_str` rejects CIDR notation. Strip the host mask
            // before parse so range-form pools are not silently dropped,
            // leaving pool_v4 empty and NAT64 forward translation
            // non-functional. A non-host mask (`/24`) or garbage suffix is
            // unparseable: fail CLOSED (#2212) — one bad pool entry rejects the
            // whole rule rather than silently narrowing the pool.
            let mut pool_v4 = Vec::with_capacity(snap.pool_addresses.len());
            for s in &snap.pool_addresses {
                match parse_pool_v4(s) {
                    Some(addr) => pool_v4.push(addr),
                    None => {
                        return Err(SnapshotIntegrityError::Nat64UnparseableRule {
                            rule_name: snap.name.clone(),
                            field: format!("source-pool address {:?}", s),
                        });
                    }
                }
            }
            prefixes.push(Nat64Prefix {
                prefix_bytes,
                pool_v4,
                pool_index: AtomicUsize::new(0),
            });
        }
        Ok(Self {
            prefixes,
            no_v6_frag_header,
        })
    }

    /// Infallible test/legacy convenience wrapper over [`try_from_snapshots`]
    /// (#2212). Panics on a snapshot integrity error, which valid test
    /// snapshots never produce. Production builds the state through
    /// `try_from_snapshots` so an unparseable rule rejects the snapshot and
    /// keeps the previous live state.
    #[cfg(test)]
    pub(crate) fn from_snapshots(snaps: &[NAT64RuleSnapshot]) -> Self {
        Self::try_from_snapshots(snaps).expect("test snapshot must not produce a NAT64 integrity error")
    }

    /// Returns true if any NAT64 prefixes are configured.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_active(&self) -> bool {
        !self.prefixes.is_empty()
    }

    /// Check if an IPv6 destination matches any NAT64 prefix.
    /// Returns (prefix_index, extracted_ipv4_dest) on match.
    pub(crate) fn match_ipv6_dest(&self, dst: Ipv6Addr) -> Option<(usize, Ipv4Addr)> {
        let octets = dst.octets();
        for (idx, prefix) in self.prefixes.iter().enumerate() {
            if octets[..12] == prefix.prefix_bytes {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return Some((idx, v4));
            }
        }
        None
    }

    /// Tri-state NAT64 destination lookup (#2291).
    ///
    /// Returns [`Nat64Match::NoPrefixMatch`] when `dst` matches no configured
    /// prefix (the caller continues IPv6 routing), [`Nat64Match::MatchReady`]
    /// when a prefix matched and a source IPv4 was allocated (translate), or
    /// [`Nat64Match::MatchUnavailable`] when a prefix matched but the pool
    /// could not yield a source (caller MUST drop, never route the synthetic
    /// IPv6 destination upstream). This is the fail-closed replacement for the
    /// `match_ipv6_dest(...).and_then(allocate_v4_source)` chain that
    /// collapsed the unallocatable case into "no match".
    pub(crate) fn classify_ipv6_dest(&self, dst: Ipv6Addr) -> Nat64Match {
        match self.match_ipv6_dest(dst) {
            None => Nat64Match::NoPrefixMatch,
            Some((prefix_idx, dst_v4)) => match self.allocate_v4_source(prefix_idx) {
                Some(snat_v4) => Nat64Match::MatchReady {
                    prefix_idx,
                    dst_v4,
                    snat_v4,
                    dst_v6: dst,
                },
                None => Nat64Match::MatchUnavailable,
            },
        }
    }

    /// Round-robin allocation of an IPv4 source address from the pool.
    pub(crate) fn allocate_v4_source(&self, prefix_idx: usize) -> Option<Ipv4Addr> {
        let prefix = self.prefixes.get(prefix_idx)?;
        if prefix.pool_v4.is_empty() {
            return None;
        }
        let idx = prefix.pool_index.fetch_add(1, Ordering::Relaxed);
        let addr = prefix.pool_v4[idx % prefix.pool_v4.len()];
        Some(addr)
    }

    /// Create a NAT64 forward decision: IPv6 packet → IPv4 translated.
    /// `snat_v4` is the SNAT pool address, `dst_v4` is extracted from the prefix.
    pub(crate) fn forward_decision(snat_v4: Ipv4Addr, dst_v4: Ipv4Addr) -> NatDecision {
        NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_v4)),
            rewrite_dst: Some(IpAddr::V4(dst_v4)),
            rewrite_src_port: None,
            rewrite_dst_port: None,
            nat64: true,
            nptv6: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Packet translation functions
// ---------------------------------------------------------------------------

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

// ICMPv6 error message types (RFC 4443).
const ICMPV6_DEST_UNREACHABLE: u8 = 1;
const ICMPV6_PACKET_TOO_BIG: u8 = 2;
const ICMPV6_TIME_EXCEEDED: u8 = 3;
const ICMPV6_PARAMETER_PROBLEM: u8 = 4;

// ICMPv4 error message types (RFC 792).
const ICMP_DEST_UNREACHABLE: u8 = 3;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_PARAMETER_PROBLEM: u8 = 12;

/// Lower bound a Packet-Too-Big MTU is clamped to when it crosses the NAT64
/// boundary. The IPv6 minimum link MTU (RFC 8200) — a translated v6 client
/// must never be told to use a path MTU below this.
const IPV6_MIN_MTU: u32 = 1280;

/// Upper bound an IPv6 Packet-Too-Big MTU is clamped to when translated to an
/// IPv4 Fragmentation-Needed Next-Hop-MTU. The v4 datagram is 20 bytes smaller
/// than the v6 one it was translated from (40-byte v6 header vs 20-byte v4
/// header), so a v6 path-MTU `M` corresponds to a v4 next-hop MTU of `M - 20`
/// (RFC 7915 5.2). Subtracting 20 keeps the advertised v4 MTU consistent with
/// the smaller translated datagram.
const NAT64_HEADER_DELTA: u32 = 20;

use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use std::sync::atomic::AtomicU32;

/// Maximum embedded (quoted) original-packet bytes the ICMP-error translator
/// processes. RFC 4443 lets an ICMPv6 error quote "as much of the invoking
/// packet as possible" up to the IPv6 minimum MTU (1280). The translated
/// embedded packet is built into a fixed stack scratch buffer — NO per-packet
/// heap allocation (#2211) — sized for the v6 worst case; v4→v6 embedded
/// translation grows the header by 20 bytes, so the scratch headroom must cover
/// `1280 + 20`.
const MAX_EMBEDDED_LEN: usize = 1280 + NAT64_HEADER_DELTA as usize;

/// Process-global IPv4 Fragment Identification generator for translated,
/// *fragmentable* (DF=0) IPv6->IPv4 packets.
///
/// Whenever this translator emits a DF=0 (non-atomic) datagram it draws the
/// Identification from a per-translator generator, as RFC 7915 5.1 prescribes
/// for the no-Fragment-Header case. RFC 6864 4.1 then *requires* that a source
/// emitting non-atomic datagrams (DF=0) MUST NOT repeat the ID for a given
/// source/destination/protocol tuple within one Maximum Datagram Lifetime. A
/// constant ID (e.g. 0) violates that: if a downstream router fragments two
/// such datagrams between the same hosts, their fragments share an ID and
/// reassemble incorrectly. A monotonically incrementing counter is a
/// conforming, cheap generator. Atomic datagrams (DF=1) are exempt — RFC 6864
/// lets them carry any ID, so the default DF=1 path keeps ID=0.
///
/// Note this generator only governs the *Identification* value. WHEN DF is
/// cleared is a deliberate LOCAL policy (the operator-gated
/// `no-v6-frag-header` option), not the size-driven DF selection RFC 7915 5.1
/// itself describes (clear DF only when the translated IPv4 packet is <= 1260
/// bytes); see `translate_v6_to_v4`.
static NAT64_FRAG_ID: AtomicU32 = AtomicU32::new(0);

/// Return the next non-zero 16-bit Fragment Identification value for a
/// fragmentable translated datagram. The value cycles over the full non-zero
/// 16-bit space `1..=65535` with no two consecutive values equal WITHIN the
/// 65535-value cycle (the value after 65535 is 1, a jump, not a repeat).
/// Skipping 0 keeps the all-zero ID reserved (by convention) for the atomic
/// DF=1 path.
///
/// CAVEAT: at the outer `AtomicU32` counter wrap — once per 2^32 fragmentable
/// translations — two ADJACENT values do collide: `(2^32 - 1) % 65535 == 0`
/// and the wrapped `0 % 65535 == 0` both map to ID 1. This is deliberately
/// accepted (#2014 r3, Codex+AGY): IPv4's 16-bit Identification inherently
/// repeats every 65535 packets regardless, so one extra adjacent duplicate per
/// ~4.3e9 translations is operationally negligible and not worth replacing the
/// lock-free `fetch_add` with a CAS/modulo-65535 counter that would bounce a
/// cache line on this path.
fn next_frag_id() -> u16 {
    // Relaxed is sufficient: we only need a distinct, non-repeating sequence,
    // not ordering against other memory. Map the monotonic 32-bit counter onto
    // 1..=65535 via `(raw % 65535) + 1`. This is what makes the sequence
    // collision-free for RFC 6864 4.1: a naive `truncate-to-u16 then remap 0->1`
    // maps BOTH raw=0 and raw=1 to 1, so two back-to-back DF=0 translations
    // would share an Identification (and the same dup recurs at every 16-bit
    // wrap). `% 65535 + 1` instead yields 1,2,...,65535,1,2,... — every adjacent
    // pair differs.
    let raw = NAT64_FRAG_ID.fetch_add(1, Ordering::Relaxed);
    map_frag_id(raw)
}

/// Pure mapping from a monotonic 32-bit counter value to the 1..=65535
/// Identification space. Factored out of `next_frag_id` so the cycle invariant
/// (non-zero, in-range, no consecutive duplicates within the 65535-value cycle
/// — see the `next_frag_id` caveat for the accepted 2^32-boundary edge) can be
/// unit-tested deterministically without touching the process-global counter.
#[inline]
fn map_frag_id(raw: u32) -> u16 {
    (raw % 65535) as u16 + 1
}

/// Translate an IPv6 packet to IPv4 (forward direction: client→server).
///
/// Input: `packet` starts at L3 (IPv6 header), not Ethernet.
/// `snat_v4` = pool IPv4 source, `dst_v4` = extracted destination.
///
/// `no_v6_frag_header` mirrors the `security nat natv6v4 no-v6-frag-header`
/// option and selects between two DF policies. This is a deliberate LOCAL,
/// option-gated choice — NOT the literal RFC 7915 5.1 algorithm, which keys DF
/// off the *translated* IPv4 size (clear DF only when the result is <= 1260
/// bytes). The two modes are:
///   * `false` (the default): emit an *atomic* datagram — set the
///     Don't-Fragment (DF) flag and leave Identification at 0 (RFC 6864 4.1
///     permits any ID for an atomic datagram).
///   * `true`: clear DF so the packet stays fragmentable in transit (the
///     operator opts into this when downstream PMTU handling needs it).
///
/// Whichever mode clears DF, the Identification MUST stay consistent with it: a
/// DF=0 datagram is non-atomic, so RFC 6864 4.1 forbids a constant/repeated ID
/// and RFC 7915 5.1 prescribes drawing it from a per-translator generator
/// (`next_frag_id`) so a downstream fragmenter produces reassemblable fragments
/// rather than colliding on a constant ID.
///
/// Returns the translated IPv4 packet (L3 only, no Ethernet header).
///
/// Allocating convenience wrapper over [`write_v6_to_v4_into`]. Hot-path
/// callers (the frame builders) write straight into a reserved output buffer
/// with the `_into` core to avoid this per-packet `Vec` (#2211); this wrapper
/// is `#[cfg(test)]`-only — the differential tests use it to assert the `_into`
/// core is byte-identical to an owned-`Vec` translation. No production caller
/// allocates an owned NAT64 packet, so gating it on test keeps the release
/// build free of a dead-code path.
#[cfg(test)]
pub(crate) fn translate_v6_to_v4(
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    // Worst case (no shrink relative to input): 20-byte IPv4 header + the IPv6
    // L4 payload. The IPv6 input is `40 + payload_len`, so `20 + payload_len`
    // never exceeds the input length; sizing to the input length is a safe
    // upper bound, then we truncate to the exact written length.
    let mut out = vec![0u8; packet.len()];
    let written = write_v6_to_v4_into(&mut out, packet, snat_v4, dst_v4, no_v6_frag_header)?;
    out.truncate(written);
    Some(out)
}

/// Walk the IPv6 extension-header chain of an L3-relative IPv6 packet to find
/// the terminal transport header (#2290).
///
/// Returns `(l4_offset, l4_protocol)` where `l4_offset` is the byte offset of
/// the real transport header (TCP/UDP/ICMPv6/...) measured from the start of
/// the IPv6 header, and `l4_protocol` is its protocol number. Walks
/// Hop-by-Hop (0), Routing (43), Destination Options (60), AH (51), and
/// Fragment (44) headers, bounded to 6 iterations (RFC 8200 §4.1 — a
/// fixed-order chain rarely exceeds a handful). No-Next-Header (59) and a
/// chain that runs off the end of the packet return `None`.
///
/// This is the NAT64 translator's own bounded walk; it deliberately does NOT
/// reach into `crate::afxdp` (which itself depends on `crate::nat64`). It
/// mirrors `afxdp::frame::inspect::packet_rel_l4_offset_and_protocol`; the
/// unification onto a single shared walker is tracked separately (#2292) and
/// is not a prerequisite for this fix.
///
/// The returned offset is only the START of the L4 header; the caller is
/// responsible for the non-first-fragment check (a non-first fragment carries
/// NO L4 header at this offset — its bytes are payload).
fn ipv6_l4_offset_and_protocol(packet: &[u8]) -> Option<(usize, u8)> {
    if packet.len() < 40 {
        return None;
    }
    let mut protocol = packet[6];
    let mut offset = 40usize;
    for _ in 0..6 {
        match protocol {
            // Hop-by-Hop / Routing / Destination Options: length in 8-byte
            // units, NOT counting the first 8 bytes (RFC 8200).
            0 | 43 | 60 => {
                let opt = packet.get(offset..offset + 2)?;
                protocol = opt[0];
                offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                if packet.len() < offset {
                    return None;
                }
            }
            // Authentication Header: length in 4-byte units, "minus 2"
            // (RFC 4302 §2.2).
            51 => {
                let opt = packet.get(offset..offset + 2)?;
                protocol = opt[0];
                offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                if packet.len() < offset {
                    return None;
                }
            }
            // Fragment header: fixed 8 bytes.
            44 => {
                let frag = packet.get(offset..offset + 8)?;
                protocol = frag[0];
                offset = offset.checked_add(8)?;
                if packet.len() < offset {
                    return None;
                }
            }
            // No Next Header — no transport to translate.
            59 => return None,
            // Terminal: a real upper-layer protocol.
            _ => return Some((offset, protocol)),
        }
    }
    Some((offset, protocol))
}

/// Is this L3-relative IPv6 packet a NON-first fragment (#2290)?
///
/// Walks the (bounded) extension-header chain looking for a Fragment header
/// (44). Returns `true` iff a fragment header is present AND its fragment
/// offset (upper 13 bits of bytes 2-3, mask `0xFFF8`, RFC 8200 §4.5) is
/// non-zero. A non-first fragment carries no L4 header, so its payload bytes
/// must NOT be read as L4 — the translators fail closed on it. First/atomic
/// fragments (offset 0) and packets without a fragment header return `false`.
/// Mirrors `afxdp::frame::inspect::ipv6_is_non_first_fragment`.
fn ipv6_is_non_first_fragment(packet: &[u8]) -> bool {
    if packet.len() < 40 {
        return false;
    }
    let mut protocol = packet[6];
    let mut offset = 40usize;
    for _ in 0..6 {
        match protocol {
            0 | 43 | 60 => {
                let Some(opt) = packet.get(offset..offset + 2) else {
                    return false;
                };
                protocol = opt[0];
                let Some(next) = offset.checked_add((usize::from(opt[1]) + 1) * 8) else {
                    return false;
                };
                offset = next;
                if packet.len() < offset {
                    return false;
                }
            }
            51 => {
                let Some(opt) = packet.get(offset..offset + 2) else {
                    return false;
                };
                protocol = opt[0];
                let Some(next) = offset.checked_add((usize::from(opt[1]) + 2) * 4) else {
                    return false;
                };
                offset = next;
                if packet.len() < offset {
                    return false;
                }
            }
            44 => {
                let Some(frag) = packet.get(offset..offset + 8) else {
                    return false;
                };
                let frag_off = u16::from_be_bytes([frag[2], frag[3]]) & 0xFFF8;
                return frag_off != 0;
            }
            59 => return false,
            _ => return false,
        }
    }
    false
}

/// Allocation-free IPv6→IPv4 translation: write the translated IPv4 L3 packet
/// directly into `dst` and return the number of bytes written (#2211).
///
/// `dst` must be at least `20 + ipv6_payload_len` bytes; on a too-small buffer
/// the function returns `None` without writing a partial frame. Behavior is
/// byte-identical to the previous `Vec`-allocating translator: same header
/// fields, same DF/Identification policy, same checksums — the only change is
/// the output destination and the elimination of the intermediate L3 `Vec`
/// plus the pseudo-header `Vec`.
pub(crate) fn write_v6_to_v4_into(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
) -> Option<usize> {
    if packet.len() < 40 {
        return None;
    }
    // IPv6 header fields.
    // Full 8-bit traffic class (DSCP[7:2] | ECN[1:0]) straddling bytes 0-1 of
    // the IPv6 header. Copied verbatim into the IPv4 TOS byte below per the
    // RFC 7915 §5 default (DSCP copied, ECN copied verbatim — NAT64 is
    // stateless translation, not RFC 6040 tunnel encapsulation).
    let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let hop_limit = packet[7];

    if hop_limit <= 1 {
        return None; // TTL expired
    }

    // #2290: walk the IPv6 extension-header chain to learn the terminal L4
    // offset and protocol instead of assuming L4 at byte 40 / reading the
    // raw next-header. A packet carrying Hop-by-Hop / Routing / Dest-Opts /
    // AH / Fragment before its transport header was previously dropped as
    // "unsupported protocol" even though it is legal RFC 8200 input.
    let (l4_offset, l4_protocol) = ipv6_l4_offset_and_protocol(packet)?;

    // A non-first fragment has NO L4 header at `l4_offset` — its bytes are
    // payload. Reading them as a transport header (and translating) would
    // corrupt the datagram, so fail closed (drop).
    if ipv6_is_non_first_fragment(packet) {
        return None;
    }

    // Map protocol from the terminal L4, not the raw next-header.
    let ipv4_protocol = match l4_protocol {
        PROTO_ICMPV6 => PROTO_ICMP,
        PROTO_TCP | PROTO_UDP => l4_protocol,
        _ => return None, // Unsupported protocol
    };

    // The L4 region starts at the walked offset and ends at the IPv6
    // payload boundary (`40 + payload_len`). The ext-header bytes between
    // byte 40 and `l4_offset` are stripped by NAT64: RFC 7915 §5.1 maps the
    // IPv6 packet to an IPv4 packet carrying only the transport payload,
    // dropping the (non-translatable) IPv6 extension headers.
    let l4_end = 40usize.checked_add(payload_len)?;
    if l4_offset > l4_end {
        return None; // ext-header chain overran the advertised payload
    }
    let l4_payload = packet.get(l4_offset..l4_end)?;
    let new_ttl = hop_limit - 1;

    // The L4 length is normally unchanged, but an ICMP *error* message embeds
    // the original (return-direction) packet, which is itself NAT64-translated
    // v6->v4 and so SHRINKS by 20 bytes. The translated L4 therefore never
    // exceeds the input L4, so reserving `20 + l4_payload.len()` is a safe upper
    // bound; the exact written length is computed below.
    let max_total_len = 20usize + l4_payload.len();
    let out = dst.get_mut(..max_total_len)?;

    // Build IPv4 header (total length + checksum patched after the L4 length is
    // known, since an ICMP-error translation can shrink the L4).
    out[0] = 0x45; // version=4, IHL=5
    out[1] = traffic_class; // DSCP/ECN copied from IPv6 traffic class (RFC 7915 §5)
    // DF policy is the option-gated LOCAL choice (not the size-driven RFC 7915
    // 5.1 selection). Either way the flags+frag-offset word (bytes 6-7) and the
    // Identification field (bytes 4-5) must stay mutually consistent:
    //   * Default (DF=1, 0x4000): an *atomic* datagram (non-fragmentable).
    //     RFC 6864 4.1 permits any ID for an atomic datagram, so leave ID=0.
    //   * no-v6-frag-header (DF=0, 0x0000): a *fragmentable* (non-atomic)
    //     datagram. A non-atomic datagram MUST carry a non-zero Identification
    //     from a per-translator generator (RFC 7915 5.1 / RFC 6864 4.1) so a
    //     downstream fragmenter does not collide distinct datagrams on a
    //     constant ID. Pinning ID=0 here while clearing DF was the bug fixed in
    //     #2008 H16.
    let (frag_word, identification): (u16, u16) = if no_v6_frag_header {
        (0x0000, next_frag_id())
    } else {
        (0x4000, 0)
    };
    out[4..6].copy_from_slice(&identification.to_be_bytes()); // identification
    out[6..8].copy_from_slice(&frag_word.to_be_bytes()); // flags + frag offset
    out[8] = new_ttl;
    out[9] = ipv4_protocol;
    out[10..12].copy_from_slice(&[0, 0]); // header checksum = 0 (computed below)
    out[12..16].copy_from_slice(&snat_v4.octets());
    out[16..20].copy_from_slice(&dst_v4.octets());

    // Translate the L4 region into the output and learn its final length.
    let l4_len = if l4_protocol == PROTO_ICMPV6 {
        // The embedded (quoted) original packet is the RETURN-direction packet:
        // its addresses are the outer error's addresses swapped, so v6->v4 the
        // embedded src maps to `dst_v4` and the embedded dst maps to `snat_v4`.
        let embedded = EmbeddedV6ToV4 {
            mapped_embedded_src: dst_v4,
            mapped_embedded_dst: snat_v4,
        };
        translate_icmpv6_message_to_icmpv4(&mut out[20..], l4_payload, &embedded)?
    } else {
        // Non-ICMP: copy L4 payload verbatim (single copy).
        out[20..max_total_len].copy_from_slice(l4_payload);
        l4_payload.len()
    };

    let ipv4_total_len = 20 + l4_len;
    out[2..4].copy_from_slice(&(ipv4_total_len as u16).to_be_bytes());

    // Recompute L4 checksum (pseudo-header changes from IPv6 to IPv4). ICMPv4
    // does not use a pseudo-header, so its checksum is recomputed inside
    // `translate_icmpv6_message_to_icmpv4`; the generic helper still rewrites it
    // identically and is a no-op for the already-correct ICMP case.
    recompute_l4_checksum_after_nat64_v6_to_v4(&mut out[..ipv4_total_len], ipv4_protocol)?;

    // Compute IPv4 header checksum.
    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());

    Some(ipv4_total_len)
}

/// Translate an IPv4 packet to IPv6 (reverse direction: server→client reply).
///
/// Input: `packet` starts at L3 (IPv4 header), not Ethernet.
/// `dst_v6` is the original IPv6 client source, `src_v6` is the NAT64 prefix
/// + original IPv4 server address (i.e. orig_dst_v6 for the reply src).
///
/// Returns the translated IPv6 packet (L3 only, no Ethernet header).
///
/// Allocating convenience wrapper over [`write_v4_to_v6_into`]; see the
/// `_into` core for the hot-path, allocation-free entry point (#2211).
/// `#[cfg(test)]`-only (the differential byte-identity tests), like its
/// v6->v4 twin — no production caller allocates an owned NAT64 packet.
#[cfg(test)]
pub(crate) fn translate_v4_to_v6(
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<Vec<u8>> {
    // IPv4→IPv6 grows the outer header by 20 bytes (40-byte v6 header vs the
    // 20-byte v4 header). An ICMP-error message ALSO grows its embedded quoted
    // packet by another 20 bytes (the embedded v4 header expands to a v6
    // header). The worst-case output is therefore `packet.len() + 40`. Allocate
    // that upper bound, then truncate to the exact written length.
    let mut out = vec![0u8; packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    let written = write_v4_to_v6_into(&mut out, packet, src_v6, dst_v6)?;
    out.truncate(written);
    Some(out)
}

/// Allocation-free IPv4→IPv6 translation: write the translated IPv6 L3 packet
/// directly into `dst` and return the number of bytes written (#2211).
///
/// `dst` must be at least `40 + (ipv4_total_len - ihl)` bytes; on a too-small
/// buffer the function returns `None` without writing a partial frame.
/// Behavior is byte-identical to the previous `Vec`-allocating translator.
pub(crate) fn write_v4_to_v6_into(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<usize> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    // IPv4 TOS byte (DSCP[7:2] | ECN[1:0]) — copied verbatim into the IPv6
    // traffic class below per the RFC 7915 §4 default (DSCP copied, ECN copied
    // verbatim — NAT64 is stateless translation, not RFC 6040 encapsulation).
    let tos = packet[1];
    let ttl = packet[8];
    if ttl <= 1 {
        return None; // TTL expired
    }
    let protocol = packet[9];
    // Trim the L4 payload to the IPv4 Total Length field rather than the end
    // of the slice. The caller passes the whole L3-onward frame, which may
    // include Ethernet padding appended to reach the 60/64-byte minimum frame
    // size (common for TCP ACKs, DNS replies, short HTTP). Copying that padding
    // into the IPv6 packet inflates payload_len and poisons the recomputed L4
    // checksum, so the receiver drops the reply. This mirrors the forward path
    // (translate_v6_to_v4) which trims to the IPv6 payload_len field.
    //
    // total_len is attacker/driver-controlled, so clamp safely: a malformed
    // header could advertise a length shorter than the IPv4 header or longer
    // than the bytes we actually received.
    let ipv4_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ipv4_total_len < ihl || ipv4_total_len > packet.len() {
        return None;
    }
    let l4_payload = packet.get(ihl..ipv4_total_len)?;

    // Map protocol.
    let next_header = match protocol {
        PROTO_ICMP => PROTO_ICMPV6,
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };

    let new_hop_limit = ttl - 1;

    // Build the 40-byte IPv6 header. The 8-bit traffic class straddles bytes
    // 0-1: TC[7:4] in the low nibble of byte 0 (alongside the version=6 nibble)
    // and TC[3:0] in the high nibble of byte 1 (alongside the flow-label high
    // nibble, left at 0). Mirrors apply_dscp_rewrite_to_frame in
    // afxdp/frame/mod.rs:133-134. The caller's buffer may be reused (a TX UMEM
    // frame), so write every byte of the IPv6 header explicitly rather than
    // relying on a zero-initialized destination: zero byte 1's low nibble +
    // bytes 2-3 (the flow label). The payload-length field (bytes 4-5) is
    // patched after the L4 length is known — an ICMP-error translation grows
    // the embedded packet by 20 bytes.
    let hdr = dst.get_mut(..40)?;
    hdr[0] = 0x60 | (tos >> 4); // version=6 | TC[7:4]
    hdr[1] = (tos & 0x0f) << 4; // TC[3:0] | flow-label high nibble (0)
    hdr[2] = 0; // flow label
    hdr[3] = 0; // flow label
    hdr[6] = next_header;
    hdr[7] = new_hop_limit;
    hdr[8..24].copy_from_slice(&src_v6.octets());
    hdr[24..40].copy_from_slice(&dst_v6.octets());

    // Translate the L4 region into the output tail and learn its final length.
    // `get_mut(40..)` only borrows the space actually present in `dst`; the
    // ICMP-error path may need up to 20 bytes more than the input L4 (embedded
    // packet growth), so the frame builder over-allocates by 20.
    let l4_dst = dst.get_mut(40..)?;
    let l4_len = if protocol == PROTO_ICMP {
        // The embedded (quoted) original packet is the RETURN-direction packet:
        // its addresses are the outer error's addresses swapped. v4->v6 the
        // embedded src (our SNAT pool v4) maps to the original v6 client
        // (`dst_v6`), and the embedded dst (the v4 server) maps to the NAT64
        // prefix + server address — the prefix being the top 96 bits of the
        // outer translated source (`src_v6` = prefix::server).
        let mut prefix_bytes = [0u8; 12];
        prefix_bytes.copy_from_slice(&src_v6.octets()[..12]);
        let embedded = EmbeddedV4ToV6 {
            mapped_embedded_src: dst_v6,
            prefix_bytes,
        };
        translate_icmpv4_message_to_icmpv6(l4_dst, l4_payload, &embedded)?
    } else {
        // Non-ICMP: copy L4 payload verbatim (single copy).
        l4_dst.get_mut(..l4_payload.len())?.copy_from_slice(l4_payload);
        l4_payload.len()
    };

    let ipv6_total_len = 40 + l4_len;
    dst[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());

    // Recompute L4 checksum (pseudo-header changes from IPv4 to IPv6).
    recompute_l4_checksum_after_nat64_v4_to_v6(&mut dst[..ipv6_total_len], next_header)?;

    Some(ipv6_total_len)
}

/// Map an ICMPv6 error type/code to its ICMPv4 equivalent per RFC 7915 §5.2.
/// Returns `None` for ICMPv6 types that have no IPv4 mapping (e.g. NDP, MLD —
/// which are link-local and never cross the translator) so the caller drops
/// them rather than emitting a malformed ICMPv4 error.
///
/// Packet-Too-Big (type 2) is handled separately by the caller because it also
/// rewrites the MTU field, so it is intentionally absent here.
fn map_icmpv6_error_to_icmpv4(icmpv6_type: u8, icmpv6_code: u8) -> Option<(u8, u8)> {
    match icmpv6_type {
        ICMPV6_DEST_UNREACHABLE => {
            // RFC 7915 5.2: ICMPv6 Destination Unreachable codes map onto the
            // ICMPv4 Destination Unreachable code space.
            let v4_code = match icmpv6_code {
                0 => 1, // no route to destination       -> host unreachable
                1 => 10, // communication administratively prohibited
                //          -> communication with destination host
                //             administratively prohibited
                2 => 1, // beyond scope of source address -> host unreachable
                3 => 1, // address unreachable            -> host unreachable
                4 => 3, // port unreachable               -> port unreachable
                _ => return None,
            };
            Some((ICMP_DEST_UNREACHABLE, v4_code))
        }
        ICMPV6_TIME_EXCEEDED => {
            // RFC 7915 5.2: Time Exceeded (3) maps 1:1 with its code preserved
            // (0 = hop limit exceeded, 1 = fragment reassembly time exceeded).
            Some((ICMP_TIME_EXCEEDED, icmpv6_code))
        }
        ICMPV6_PARAMETER_PROBLEM => {
            // RFC 7915 5.2: Parameter Problem.
            match icmpv6_code {
                // code 0 (erroneous header field) -> ICMPv4 Parameter Problem
                // code 0 (pointer indicates the error). The embedded-pointer
                // remap (RFC 7915 Figure 6) is not performed; the pointer is a
                // best-effort hint, and Junos/vSRX parity does not depend on it.
                0 => Some((ICMP_PARAMETER_PROBLEM, 0)),
                // code 1 (unrecognized Next Header) -> ICMPv4 Destination
                // Unreachable / Protocol Unreachable.
                1 => Some((ICMP_DEST_UNREACHABLE, 2)),
                // code 2 (unrecognized IPv6 option) is silently dropped per
                // RFC 7915 — it has no IPv4 analogue.
                _ => None,
            }
        }
        _ => None,
    }
}

/// Map an ICMPv4 error type/code to its ICMPv6 equivalent per RFC 7915 §4.2.
/// Returns `None` for ICMPv4 types/codes that have no IPv6 mapping so the
/// caller drops them. Fragmentation-Needed (type 3 code 4) is handled
/// separately by the caller because it rewrites the MTU field.
fn map_icmpv4_error_to_icmpv6(icmpv4_type: u8, icmpv4_code: u8) -> Option<(u8, u8)> {
    match icmpv4_type {
        ICMP_DEST_UNREACHABLE => {
            // RFC 7915 4.2: ICMPv4 Destination Unreachable codes map onto the
            // ICMPv6 Destination Unreachable / Packet Too Big code space.
            // (code 4, Fragmentation Needed, is handled by the caller — it
            // becomes Packet Too Big with an MTU rewrite.)
            let mapped = match icmpv4_code {
                0 => (ICMPV6_DEST_UNREACHABLE, 0), // net unreachable -> no route
                1 => (ICMPV6_DEST_UNREACHABLE, 0), // host unreachable -> no route
                2 => (ICMPV6_PARAMETER_PROBLEM, 1), // protocol unreachable ->
                //  parameter problem, unrecognized Next Header
                3 => (ICMPV6_DEST_UNREACHABLE, 4), // port unreachable -> port unreachable
                5 => (ICMPV6_DEST_UNREACHABLE, 0), // source route failed -> no route
                6 => (ICMPV6_DEST_UNREACHABLE, 0), // dest network unknown -> no route
                7 => (ICMPV6_DEST_UNREACHABLE, 0), // dest host unknown -> no route
                8 => (ICMPV6_DEST_UNREACHABLE, 0), // src host isolated -> no route
                11 => (ICMPV6_DEST_UNREACHABLE, 0), // net unreachable for TOS -> no route
                12 => (ICMPV6_DEST_UNREACHABLE, 0), // host unreachable for TOS -> no route
                9 | 10 | 13 | 15 => (ICMPV6_DEST_UNREACHABLE, 1), // admin prohibited
                _ => return None,
            };
            Some(mapped)
        }
        ICMP_TIME_EXCEEDED => {
            // RFC 7915 4.2: Time Exceeded (11) maps 1:1 with its code preserved.
            Some((ICMPV6_TIME_EXCEEDED, icmpv4_code))
        }
        ICMP_PARAMETER_PROBLEM => {
            // RFC 7915 4.2: Parameter Problem (12).
            match icmpv4_code {
                // code 0 (pointer indicates error) and code 2 (bad length) ->
                // ICMPv6 Parameter Problem, erroneous header field.
                0 | 2 => Some((ICMPV6_PARAMETER_PROBLEM, 0)),
                // code 1 (missing required option) has no IPv6 analogue.
                _ => None,
            }
        }
        _ => return None,
    }
}

/// Address mapping for the embedded (quoted) packet of an ICMPv6 error being
/// translated v6->v4. The embedded packet is the RETURN-direction original
/// packet whose addresses are the outer error's addresses swapped, so both
/// embedded addresses are known constants derived from the outer translation —
/// no NAT64 prefix arithmetic is needed in this direction (the outer src/dst v4
/// already carry the fully-mapped values).
struct EmbeddedV6ToV4 {
    /// IPv4 the embedded IPv6 source maps to.
    mapped_embedded_src: Ipv4Addr,
    /// IPv4 the embedded IPv6 destination maps to.
    mapped_embedded_dst: Ipv4Addr,
}

/// Address mapping for the embedded (quoted) packet of an ICMPv4 error being
/// translated v4->v6. The embedded packet is the RETURN-direction original
/// packet: its IPv4 source (our SNAT pool) maps to the original v6 client
/// (`mapped_embedded_src`); its IPv4 destination (the v4 server) maps to the
/// NAT64 prefix + that destination (`prefix_bytes` :: dst-v4).
struct EmbeddedV4ToV6 {
    /// IPv6 the embedded IPv4 source maps to (the original v6 client).
    mapped_embedded_src: Ipv6Addr,
    /// NAT64 /96 prefix the embedded IPv4 destination is composed onto.
    prefix_bytes: [u8; 12],
}

/// Translate a complete ICMPv6 message (`src`, starting at the ICMPv6 type
/// byte) into ICMPv4 in `dst`, returning the written ICMPv4 message length.
///
/// Handles echo request/reply (length unchanged) AND error messages
/// (Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem)
/// per RFC 7915 §5.2 — for an error the leading 8-byte ICMP header is followed
/// by the quoted original packet, whose embedded IPv6 header is NAT64-translated
/// to IPv4 (addresses mapped, lengths/checksums fixed). The ICMPv4 checksum is
/// computed here (ICMPv4 has no pseudo-header), so the caller's generic
/// recompute is a consistent no-op over the already-correct value.
///
/// Allocation-free: the embedded packet is translated through a fixed stack
/// scratch buffer (`MAX_EMBEDDED_LEN`), never the heap (#2211). `None` aborts
/// the frame (drop) for an untranslatable type/code or a malformed/oversized
/// embedded packet.
fn translate_icmpv6_message_to_icmpv4(
    dst: &mut [u8],
    src: &[u8],
    embedded: &EmbeddedV6ToV4,
) -> Option<usize> {
    if src.len() < 4 {
        return None;
    }
    let icmpv6_type = src[0];
    let icmpv6_code = src[1];

    match icmpv6_type {
        ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY => {
            // Echo: length preserved, only type/code change.
            let out = dst.get_mut(..src.len())?;
            out.copy_from_slice(src);
            out[0] = if icmpv6_type == ICMPV6_ECHO_REQUEST {
                ICMP_ECHO_REQUEST
            } else {
                ICMP_ECHO_REPLY
            };
            out[1] = 0;
            finalize_icmpv4_checksum(out);
            Some(out.len())
        }
        ICMPV6_PACKET_TOO_BIG => {
            // An ICMP error always carries the full 8-byte header (type/code/
            // checksum + the 4-byte rest-of-header). `src` is packet data, so
            // reject a truncated header before indexing the MTU word.
            if src.len() < 8 {
                return None;
            }
            // RFC 7915 5.2: ICMPv6 Packet Too Big (type 2) -> ICMPv4
            // Destination Unreachable / Fragmentation Needed (type 3 code 4).
            // The 4-byte "unused" word of an ICMPv6 PTB carries the MTU; the
            // ICMPv4 Fragmentation-Needed instead carries the Next-Hop MTU in
            // its low 16 bits (bytes 6-7), with bytes 4-5 unused (RFC 1191).
            let mtu = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
            // The translated v4 datagram is 20 bytes smaller than the v6 one, so
            // advertise an MTU 20 bytes smaller (clamped to a sane 16-bit range
            // and never below the v4 minimum). RFC 7915 5.2.
            let v4_mtu = mtu.saturating_sub(NAT64_HEADER_DELTA).clamp(68, 0xffff) as u16;
            write_icmpv4_error_with_embedded(
                dst,
                src,
                ICMP_DEST_UNREACHABLE,
                4,
                [0, 0, (v4_mtu >> 8) as u8, v4_mtu as u8],
                embedded,
            )
        }
        ICMPV6_DEST_UNREACHABLE | ICMPV6_TIME_EXCEEDED | ICMPV6_PARAMETER_PROBLEM => {
            let (v4_type, v4_code) = map_icmpv6_error_to_icmpv4(icmpv6_type, icmpv6_code)?;
            // RFC 7915 5.2: the 4-byte rest-of-header is ZEROED for these
            // types. Time-Exceeded / Dest-Unreach carry an unused word (zero
            // is correct on the wire). The ICMPv6 Parameter-Problem pointer is
            // intentionally NOT remapped to an ICMPv4 pointer (see
            // map_icmpv6_error_to_icmpv4), so it is dropped to zero rather than
            // translated.
            write_icmpv4_error_with_embedded(
                dst, src, v4_type, v4_code, [0, 0, 0, 0], embedded,
            )
        }
        _ => None, // NDP, MLD, etc. — never crosses the translator.
    }
}

/// Translate a complete ICMPv4 message (`src`, starting at the ICMPv4 type
/// byte) into ICMPv6 in `dst`, returning the written ICMPv6 message length.
///
/// The v6->v4 twin of [`translate_icmpv6_message_to_icmpv4`]; same contract.
/// The ICMPv6 checksum is NOT computed here (it needs the IPv6 pseudo-header):
/// the caller's `recompute_l4_checksum_after_nat64_v4_to_v6` finishes it over
/// the full message, so this leaves the checksum field zeroed.
fn translate_icmpv4_message_to_icmpv6(
    dst: &mut [u8],
    src: &[u8],
    embedded: &EmbeddedV4ToV6,
) -> Option<usize> {
    if src.len() < 4 {
        return None;
    }
    let icmpv4_type = src[0];
    let icmpv4_code = src[1];

    match icmpv4_type {
        ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY => {
            let out = dst.get_mut(..src.len())?;
            out.copy_from_slice(src);
            out[0] = if icmpv4_type == ICMP_ECHO_REQUEST {
                ICMPV6_ECHO_REQUEST
            } else {
                ICMPV6_ECHO_REPLY
            };
            out[1] = 0;
            // Checksum is recomputed by the caller (needs the v6 pseudo-header).
            out[2..4].copy_from_slice(&[0, 0]);
            Some(out.len())
        }
        ICMP_DEST_UNREACHABLE if icmpv4_code == 4 => {
            // An ICMP error always carries the full 8-byte header; reject a
            // truncated header before indexing the Next-Hop MTU word.
            if src.len() < 8 {
                return None;
            }
            // RFC 7915 4.2: ICMPv4 Fragmentation Needed (type 3 code 4) ->
            // ICMPv6 Packet Too Big (type 2). The Next-Hop MTU is in the low
            // 16 bits (bytes 6-7) of the ICMPv4 rest-of-header (RFC 1191); the
            // ICMPv6 PTB carries the MTU as a full 32-bit word (bytes 4-7).
            let v4_mtu = u16::from_be_bytes([src[6], src[7]]) as u32;
            // The translated v6 datagram is 20 bytes larger than the v4 one, so
            // the v6 path MTU is 20 bytes larger; clamp to the v6 minimum link
            // MTU (1280) so a v6 client is never told to go below it.
            let v6_mtu = v4_mtu.saturating_add(NAT64_HEADER_DELTA).max(IPV6_MIN_MTU);
            write_icmpv6_error_with_embedded(
                dst,
                src,
                ICMPV6_PACKET_TOO_BIG,
                0,
                v6_mtu.to_be_bytes(),
                embedded,
            )
        }
        ICMP_DEST_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM => {
            let (v6_type, v6_code) = map_icmpv4_error_to_icmpv6(icmpv4_type, icmpv4_code)?;
            write_icmpv6_error_with_embedded(
                dst, src, v6_type, v6_code, [0, 0, 0, 0], embedded,
            )
        }
        _ => None,
    }
}

/// Build an ICMPv4 error message (8-byte header + translated embedded packet)
/// in `dst` from the ICMPv6 error `src`. `rest_of_header` is the 4-byte word
/// after type/code/checksum. Returns the written length, or `None` on a
/// malformed/oversized embedded packet.
fn write_icmpv4_error_with_embedded(
    dst: &mut [u8],
    src: &[u8],
    v4_type: u8,
    v4_code: u8,
    rest_of_header: [u8; 4],
    embedded: &EmbeddedV6ToV4,
) -> Option<usize> {
    // The quoted original packet starts after the 8-byte ICMPv6 error header.
    let embedded_in = src.get(8..)?;
    // Translate the embedded IPv6 header (+leading L4) into a stack scratch
    // buffer — no heap alloc on the hot path (#2211).
    let mut scratch = [0u8; MAX_EMBEDDED_LEN];
    let embedded_len = translate_embedded_v6_to_v4(&mut scratch, embedded_in, embedded)?;

    let total = 8 + embedded_len;
    let out = dst.get_mut(..total)?;
    out[0] = v4_type;
    out[1] = v4_code;
    out[2..4].copy_from_slice(&[0, 0]); // checksum (computed below)
    out[4..8].copy_from_slice(&rest_of_header);
    out[8..total].copy_from_slice(&scratch[..embedded_len]);
    finalize_icmpv4_checksum(out);
    Some(total)
}

/// Build an ICMPv6 error message (8-byte header + translated embedded packet)
/// in `dst` from the ICMPv4 error `src`. The ICMPv6 checksum is left zeroed —
/// the caller recomputes it with the IPv6 pseudo-header.
fn write_icmpv6_error_with_embedded(
    dst: &mut [u8],
    src: &[u8],
    v6_type: u8,
    v6_code: u8,
    rest_of_header: [u8; 4],
    embedded: &EmbeddedV4ToV6,
) -> Option<usize> {
    let embedded_in = src.get(8..)?;
    let mut scratch = [0u8; MAX_EMBEDDED_LEN];
    let embedded_len = translate_embedded_v4_to_v6(&mut scratch, embedded_in, embedded)?;

    let total = 8 + embedded_len;
    let out = dst.get_mut(..total)?;
    out[0] = v6_type;
    out[1] = v6_code;
    out[2..4].copy_from_slice(&[0, 0]); // checksum recomputed by caller
    out[4..8].copy_from_slice(&rest_of_header);
    out[8..total].copy_from_slice(&scratch[..embedded_len]);
    Some(total)
}

/// Translate the embedded (quoted) IPv6 header + leading L4 bytes of an ICMPv6
/// error into IPv4, writing into `dst` and returning the written length.
///
/// RFC 7915 §5.2: the embedded packet is translated like a normal v6->v4 packet
/// but with the embedded addresses' pre-computed mappings. The embedded L4 is
/// quoted (often truncated to 8 bytes), so its own checksum is left unchanged —
/// it is informational and a receiver does not validate the quoted L4 checksum.
/// The embedded packet is bounded to `MAX_EMBEDDED_LEN`; an oversized or
/// truncated-below-the-IPv6-header quote returns `None`.
fn translate_embedded_v6_to_v4(
    dst: &mut [u8],
    embedded: &[u8],
    map: &EmbeddedV6ToV4,
) -> Option<usize> {
    if embedded.len() < 40 {
        return None; // need a full IPv6 header to translate
    }
    // Clamp the quoted bytes to the scratch capacity (a hostile or large quote
    // must not overflow the fixed buffer); a clamp shortens the quote, which is
    // always legal for an ICMP error.
    let quote_in = &embedded[..embedded.len().min(MAX_EMBEDDED_LEN)];

    let payload_len = u16::from_be_bytes([quote_in[4], quote_in[5]]) as usize;
    let hop_limit = quote_in[7];
    let traffic_class = ((quote_in[0] & 0x0f) << 4) | (quote_in[1] >> 4);

    // #2290: walk the quoted IPv6 packet's extension-header chain to find the
    // terminal L4 offset/protocol rather than assuming L4 at byte 40. The
    // quote is frequently truncated (often to 8 bytes of L4), so the walk may
    // run off the end of `quote_in`; in that case `ipv6_l4_offset_and_protocol`
    // returns `None` and we fail closed — the same drop the outer translator
    // takes — rather than misreading ext-header bytes as a transport header.
    let (l4_offset, l4_protocol) = ipv6_l4_offset_and_protocol(quote_in)?;

    // A non-first fragment carries no L4 header — its bytes are payload. Do
    // not read them as L4 (drop), matching the outer translator (#2290).
    if ipv6_is_non_first_fragment(quote_in) {
        return None;
    }

    // Map protocol (same set the outer translator supports) from the terminal
    // L4. An embedded packet carrying an unsupported protocol can't be
    // faithfully translated -> drop.
    let ipv4_protocol = match l4_protocol {
        PROTO_ICMPV6 => PROTO_ICMP,
        PROTO_TCP | PROTO_UDP => l4_protocol,
        _ => return None,
    };

    // The quoted L4 starts at the walked offset and runs to the end of the
    // advertised IPv6 payload (`40 + payload_len`), capped by the bytes
    // actually quoted. The IPv6 extension headers between byte 40 and
    // `l4_offset` are stripped, mirroring the outer translation.
    let payload_end = 40usize.checked_add(payload_len)?;
    let quoted_end = payload_end.min(quote_in.len());
    if l4_offset > quoted_end {
        return None; // ext-header chain overran the quoted bytes
    }
    let l4 = quote_in.get(l4_offset..quoted_end)?;
    let l4_len = l4.len();

    let total = 20 + l4_len;
    let out = dst.get_mut(..total)?;
    out[0] = 0x45;
    out[1] = traffic_class;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[4..6].copy_from_slice(&[0, 0]); // identification (quoted header)
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    out[8] = hop_limit; // embedded hop limit copied verbatim (NOT decremented)
    out[9] = ipv4_protocol;
    out[10..12].copy_from_slice(&[0, 0]); // header checksum (computed below)
    out[12..16].copy_from_slice(&map.mapped_embedded_src.octets());
    out[16..20].copy_from_slice(&map.mapped_embedded_dst.octets());
    out[20..total].copy_from_slice(l4);

    // If the embedded protocol is ICMPv6, fix the embedded ICMP type byte so the
    // quoted v4 packet is internally consistent (the quoted L4 checksum is left
    // as-is — it is not validated by a receiver). Only the leading type/code are
    // touched; a fuller embedded-ICMP translation is unnecessary for the quote.
    if l4_protocol == PROTO_ICMPV6 && l4_len >= 2 {
        if let Some((t, c)) = embedded_icmpv6_type_to_icmpv4(out[20]) {
            out[20] = t;
            out[21] = c;
        }
    }

    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
    Some(total)
}

/// Translate the embedded (quoted) IPv4 header + leading L4 bytes of an ICMPv4
/// error into IPv6, writing into `dst` and returning the written length. The
/// v6->v4 twin of [`translate_embedded_v6_to_v4`]; same quote/checksum policy.
fn translate_embedded_v4_to_v6(
    dst: &mut [u8],
    embedded: &[u8],
    map: &EmbeddedV4ToV6,
) -> Option<usize> {
    if embedded.len() < 20 {
        return None;
    }
    let ihl = ((embedded[0] & 0x0f) as usize) * 4;
    if ihl < 20 || embedded.len() < ihl {
        return None;
    }
    let quote_in = &embedded[..embedded.len().min(MAX_EMBEDDED_LEN - NAT64_HEADER_DELTA as usize)];
    let tos = quote_in[1];
    let ttl = quote_in[8];
    let protocol = quote_in[9];
    let total_len_field = u16::from_be_bytes([quote_in[2], quote_in[3]]) as usize;

    let next_header = match protocol {
        PROTO_ICMP => PROTO_ICMPV6,
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };

    // Quoted L4 bytes after the IPv4 header, capped by the advertised total
    // length and what was actually quoted.
    let end = total_len_field.clamp(ihl, quote_in.len());
    let l4 = quote_in.get(ihl..end)?;
    let l4_len = l4.len();

    let total = 40 + l4_len;
    let out = dst.get_mut(..total)?;
    out[0] = 0x60 | (tos >> 4);
    out[1] = (tos & 0x0f) << 4;
    out[2] = 0;
    out[3] = 0;
    out[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
    out[6] = next_header;
    out[7] = ttl; // embedded hop limit copied verbatim (NOT decremented)
    // Embedded src (our SNAT pool v4) -> original v6 client.
    out[8..24].copy_from_slice(&map.mapped_embedded_src.octets());
    // Embedded dst (the v4 server) -> NAT64 prefix :: dst-v4.
    out[24..36].copy_from_slice(&map.prefix_bytes);
    out[36..40].copy_from_slice(&quote_in[16..20]);
    out[40..total].copy_from_slice(l4);

    if protocol == PROTO_ICMP && l4_len >= 2 {
        if let Some((t, c)) = embedded_icmpv4_type_to_icmpv6(out[40]) {
            out[40] = t;
            out[41] = c;
        }
    }
    Some(total)
}

/// Best-effort embedded ICMPv6->ICMPv4 type/code remap for the quoted L4 of an
/// embedded packet (echo only, which is the realistic embedded-ICMP case for a
/// PMTUD/traceroute error quoting a ping). Returns `None` to leave the byte
/// untouched for anything else — the quoted L4 is informational.
fn embedded_icmpv6_type_to_icmpv4(t: u8) -> Option<(u8, u8)> {
    match t {
        ICMPV6_ECHO_REQUEST => Some((ICMP_ECHO_REQUEST, 0)),
        ICMPV6_ECHO_REPLY => Some((ICMP_ECHO_REPLY, 0)),
        _ => None,
    }
}

/// Best-effort embedded ICMPv4->ICMPv6 type/code remap (echo only); twin of
/// [`embedded_icmpv6_type_to_icmpv4`].
fn embedded_icmpv4_type_to_icmpv6(t: u8) -> Option<(u8, u8)> {
    match t {
        ICMP_ECHO_REQUEST => Some((ICMPV6_ECHO_REQUEST, 0)),
        ICMP_ECHO_REPLY => Some((ICMPV6_ECHO_REPLY, 0)),
        _ => None,
    }
}

/// Zero then recompute the ICMPv4 checksum (no pseudo-header) over `icmp`.
fn finalize_icmpv4_checksum(icmp: &mut [u8]) {
    if icmp.len() < 4 {
        return;
    }
    icmp[2..4].copy_from_slice(&[0, 0]);
    let sum = checksum16(icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
}

/// Recompute L4 checksum after IPv6→IPv4 translation.
fn recompute_l4_checksum_after_nat64_v6_to_v4(packet: &mut [u8], protocol: u8) -> Option<()> {
    if packet.len() < 20 {
        return None;
    }
    // Read IP addresses before taking mutable borrow of L4 portion.
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let l4 = &mut packet[20..];
    match protocol {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            // RFC 768 / RFC 1624: in IPv4 UDP a checksum field of 0x0000 is the
            // reserved "no checksum present" sentinel. A genuinely computed
            // checksum of zero MUST be transmitted as 0xFFFF (all-ones) so the
            // receiver still validates it. `checksum16_ipv4_pseudo` returns the
            // final one's-complement value, so a 0x0000 here is a real computed
            // checksum, not an internal sentinel. Mirrors the v4->v6 UDP arm.
            let final_sum = if sum == 0 { 0xFFFF } else { sum };
            l4[6..8].copy_from_slice(&final_sum.to_be_bytes());
        }
        PROTO_ICMP => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv4 does NOT use pseudo-header — checksum over ICMP message only.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16(l4);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

/// Recompute L4 checksum after IPv4→IPv6 translation.
fn recompute_l4_checksum_after_nat64_v4_to_v6(packet: &mut [u8], next_header: u8) -> Option<()> {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    let l4 = &mut packet[40..];
    match next_header {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            // UDP over IPv6: zero checksum is illegal, but if it computes to 0
            // the standard says use 0xFFFF.
            let final_sum = if sum == 0 { 0xFFFF } else { sum };
            l4[6..8].copy_from_slice(&final_sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv6 DOES use pseudo-header.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Add `bytes` into a running one's-complement 16-bit partial sum. Mirrors
/// the scalar reference in `afxdp/frame/checksum.rs::checksum16_add_bytes`
/// so the pseudo-header checksum can be accumulated by streaming the
/// pseudo-header fields and the L4 payload directly, with NO intermediate
/// `Vec` allocation per packet (#2211). The fold result is bit-identical to
/// building a contiguous buffer and running `checksum16` over it because
/// 16-bit one's-complement addition is associative across the concatenation.
#[inline]
fn checksum16_add(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add((last as u32) << 8);
    }
    sum
}

/// Fold a running partial sum into the final one's-complement 16-bit value.
/// Identical fold to `checksum16`'s tail so streaming and buffer-building
/// produce the same checksum.
#[inline]
fn checksum16_fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 pseudo-header + L4 checksum, streamed (no per-packet `Vec`, #2211).
fn checksum16_ipv4_pseudo(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add(sum, &src.octets());
    sum = checksum16_add(sum, &dst.octets());
    sum = checksum16_add(sum, &[0, protocol]);
    sum = checksum16_add(sum, &(payload.len() as u16).to_be_bytes());
    sum = checksum16_add(sum, payload);
    checksum16_fold(sum)
}

/// IPv6 pseudo-header + L4 checksum, streamed (no per-packet `Vec`, #2211).
fn checksum16_ipv6_pseudo(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add(sum, &src.octets());
    sum = checksum16_add(sum, &dst.octets());
    sum = checksum16_add(sum, &(payload.len() as u32).to_be_bytes());
    sum = checksum16_add(sum, &[0, 0, 0, next_header]);
    sum = checksum16_add(sum, payload);
    checksum16_fold(sum)
}

// ---------------------------------------------------------------------------
// Frame building helpers for NAT64
// ---------------------------------------------------------------------------

/// Build a complete Ethernet + IPv4 frame from an Ethernet + IPv6 frame.
/// Used for forward NAT64 (IPv6→IPv4): frame shrinks by 20 bytes.
///
/// `eth_dst`, `eth_src` are the new L2 addresses for the forwarded frame.
/// `vlan_id` is inserted if > 0.
pub(crate) fn build_nat64_v6_to_v4_frame(
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    // Find L3 offset.
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    // Single output allocation (the unavoidable `TxRequest.bytes`): IPv6→IPv4
    // shrinks the L3 by 20 bytes, so the IPv4 frame can never exceed
    // `eth_len + ipv6_packet.len()`. Allocate that upper bound, write the
    // translated IPv4 L3 directly into the tail with the allocation-free
    // `_into` core (no intermediate L3 `Vec`, no second copy — #2211), then
    // truncate to the exact length.
    let mut out = vec![0u8; eth_len + ipv6_packet.len()];
    write_eth_header(&mut out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written =
        write_v6_to_v4_into(&mut out[eth_len..], ipv6_packet, snat_v4, dst_v4, no_v6_frag_header)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// Build a complete Ethernet + IPv6 frame from an Ethernet + IPv4 frame.
/// Used for reverse NAT64 (IPv4→IPv6): frame grows by 20 bytes.
///
/// `src_v6` and `dst_v6` are the restored IPv6 addresses.
pub(crate) fn build_nat64_v4_to_v6_frame(
    frame: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv4_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    // Single output allocation (the unavoidable `TxRequest.bytes`): IPv4→IPv6
    // grows the outer L3 header by 20 bytes (40-byte IPv6 header vs 20-byte IPv4
    // header). An ICMP-error message ALSO grows its embedded quoted packet by
    // another 20 bytes (#2219), so the worst-case IPv6 frame is
    // `eth_len + ipv4_packet.len() + 40`. Allocate that upper bound, write the
    // translated IPv6 L3 directly into the tail with the allocation-free `_into`
    // core (no intermediate L3 `Vec`, no second copy — #2211), then truncate to
    // the exact length.
    let mut out = vec![0u8; eth_len + ipv4_packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    write_eth_header(&mut out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_into(&mut out[eth_len..], ipv4_packet, src_v6, dst_v6)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// Find the L3 offset by checking Ethernet type/VLAN.
///
/// #2150: a single 0x88a8 (802.1ad) tag carries the same 4-byte
/// TPID+TCI layout as 0x8100, so the L3 header sits at offset 18, not
/// 14. The previous `== 0x8100` check treated a 0x88a8-tagged frame as
/// untagged (l3=14) and read the IP header 4 bytes into the VLAN tag,
/// corrupting any NAT64 translation of a provider-tagged frame. This
/// now matches the canonical L2 contract
/// (`afxdp/frame/inspect.rs::frame_l3_offset`,
/// `afxdp/cos/ecn.rs::ethernet_l3`, `afxdp/parser.rs::parse_eth_offsets`).
fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(ethertype, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return None;
        }
        Some(18)
    } else {
        Some(14)
    }
}

/// Write Ethernet header (with optional VLAN tag) into the beginning of `buf`.
fn write_eth_header(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) -> Option<()> {
    if vlan_id > 0 {
        if buf.len() < 18 {
            return None;
        }
        buf[..6].copy_from_slice(&dst);
        buf[6..12].copy_from_slice(&src);
        buf[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        buf[14..16].copy_from_slice(&vlan_id.to_be_bytes());
        buf[16..18].copy_from_slice(&ether_type.to_be_bytes());
    } else {
        if buf.len() < 14 {
            return None;
        }
        buf[..6].copy_from_slice(&dst);
        buf[6..12].copy_from_slice(&src);
        buf[12..14].copy_from_slice(&ether_type.to_be_bytes());
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "nat64_tests.rs"]
mod tests;
