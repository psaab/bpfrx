// Pool-mode SNAT port allocator + persistent lease state machine.
//
// #2852 Phase 1 (lock-free port claim): the port-ownership state is no
// longer serialized behind the single `Mutex<PortAllocatorLiveState>`.
// Per-pool-address occupancy is an atomic bitmap (`AddressOccupancy`,
// `Vec<AtomicU64>` + an atomic fresh-port cursor); a CAS on the bit IS the
// port-ownership token (a set bit cannot be re-claimed), replacing the
// pre-#2852 `owner_by_translated` / `addr_index_by_translated` maps and the
// per-address `next_port_offset_by_addr` cursor. The port CLAIM (the
// contended hot path in `allocate_translation`) is therefore lock-free: a
// non-persistent new flow claims its port with zero global-mutex contention
// and takes the (retained) mutex only for the tiny `live_by_flow`
// insert/reuse-check/exact-cap-check critical section. The microbench
// `benches/snat_allocator.rs` (results in docs/research/2852-portalloc/)
// proved the pre-Phase-1 single mutex negative-scales (2.87M->0.62M
// allocs/sec, M=1->8); Phase 1 is 1.4-1.6x at M=6/8.
//
// What stays under `Mutex<PortAllocatorLiveState>`: the flow map
// (`live_by_flow`), the persistent-lease lifecycle (`persistent_by_source` +
// the two expiration indexes), and `gc_counter`. Phase 2 (hash-sharding
// those maps, deferred) is only warranted if the residual map mutex is the
// next bottleneck.
//
// F4 (global tracked-flow cap): kept EXACT with no overshoot. The cap is
// `live_by_flow.len()` re-checked under the tiny insert mutex, where the map
// length is authoritative — so it never overshoots and a tiny pool near
// capacity is NOT falsely exhausted. This is strictly better than the
// microbench's atomic `fetch_add`-reserve model (which surfaced an M-in-
// flight overshoot on tiny pools): that overshoot only exists when the cap
// is checked OUTSIDE any lock (the Phase-2 sharded world); Phase 1 keeps the
// maps under one mutex, so the exact `len()` check is available and used.
//
// FIFO recycle (#3011): freed ports still recycle oldest-first to spread
// reuse across the upstream 2MSL/TIME_WAIT window. The queue is a per-ADDRESS
// `Mutex<VecDeque<u16>>` (`AddressOccupancy::recycle`) — a much smaller,
// per-address critical section than the pre-#2852 global mutex, and it
// preserves the EXACT `push_back`/`pop_front` ordering the #3011 tests pin
// (a fully lock-free MPMC recycle ring is a Phase-2 option; `crossbeam` is
// not a dependency and a hand-rolled lock-free ring is not worth the risk on
// this hot NAT path). Lock ordering is always global -> recycle (the recycle
// mutex is innermost, never held while acquiring the global mutex), so there
// is no deadlock (plan F5 is sidestepped entirely: Phase 1 has no two-map-
// shard path).
//
// Port claim (AddressOccupancy::claim) collision handling (#3047):
// - Sequential phase: the monotonic per-address cursor is probed FORWARD,
//   one offset at a time (a bounded CAS hands each fresh offset to exactly
//   one claimer and never advances past the range), until a free port is
//   CAS-claimed or the range is genuinely exhausted. A single collision with
//   an out-of-band occupant (a persistent lease or an HA-synced install
//   whose bit sits at the cursor's offset) advances past it instead of
//   aborting the whole allocation (062-05). The common case claims on the
//   first probe.
// - Recycled phase: when the sequential range is spent, recycled ports are
//   drained FIFO (oldest-freed first, pop_front) so a just-freed port is the
//   LAST to be reassigned — this spreads port reuse across the upstream's
//   2MSL/TIME_WAIT window instead of immediately recycling the most recent
//   port (#3011). A popped port whose bit is already set is RETAINED (re-
//   queued at the back), never discarded, so a transient collision cannot
//   permanently shrink the reusable pool (062-10). The retain buffer
//   allocates lazily only when a collision actually occurs.
//
// Aggregate construction budget (#6812): `PortAllocator::new` is the memory
// heavyweight — one `AddressOccupancy` word array per pool address, sized to
// the port range (one bit per port slot). Construction is therefore gated
// TWICE upstream in `source.rs`: the Go #5877 strict commit gate rejects an
// over-budget config outright, and `resolve_pool_allocators` enforces the
// same budgets (pool count / total addresses / total port slots, charged
// per distinct allocator key, reuse-before-build, nothing built for a
// failed pool) at this apply boundary — the final backstop for a tolerated
// (lenient-load / peer-synced) or hand-crafted snapshot. Three full-range
// /16 pools would otherwise materialise 12,683,575,296 bitmap bits
// (~1.48 GiB) during apply.
//
// Cross-submodule visibility (per #1542 plan v3):
// - PortAllocator and PortAllocatorSnapshot are pub(crate) at definition
//   (re-exported by nat/mod.rs).
// - PortAllocator's state-machine methods (try_next_port, address_index,
//   allocate_translation, release_flow, rollback_flow, snapshot) are
//   pub(super) so source.rs / status.rs can drive them.
// - Live state struct + the fields that white-box tests inspect
//   (persistent_by_source, lease_expirations, lease_expirations_by_addr) are
//   pub(super). Port-ownership is inspected via the `#[cfg(test)]` debug
//   accessors (debug_is_port_occupied / debug_recycled_ports /
//   debug_set_cursor / debug_set_recycled / debug_occupied_count).
// - PersistentLease + its fields are pub(super) for the same reason.
// - The remaining types (LiveAllocation, AddressOccupancy, PortAllocatorShared
//   and its private fields, GC constants, capacity/sticky helpers) stay
//   fully private to this file.

use super::source::SourceNatFlowKey;
use rustc_hash::FxHashMap;
use std::collections::{BTreeSet, VecDeque};
use std::hash::Hasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
// #4800: both are now used unconditionally by `PortAllocator::lock_live`
// (previously `MutexGuard` was test-only, for `debug_live`).
use std::sync::{MutexGuard, TryLockError};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

pub(super) const NS_PER_SEC: u64 = 1_000_000_000;
const MAX_SOURCE_NAT_POOL_TRACKED_FLOWS: usize = 262_144;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PersistentSourceKey {
    pub(super) protocol: u8,
    pub(super) src_ip: IpAddr,
    pub(super) src_port: u16,
    /// #2397: remote (destination) endpoint scope. `None` => the lease is
    /// reusable by ANY remote host (`persistent-nat permit-any-remote-host`).
    /// `Some((dst_ip, dst_port))` => the lease is bound to the original remote
    /// endpoint (the disabled-flag / Junos target-host[-port] mode): a second
    /// flow from the same local source to a DIFFERENT remote 5-tuple keys to a
    /// distinct lease and therefore gets a distinct translated mapping.
    pub(super) remote: Option<(IpAddr, u16)>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct TranslatedTuple {
    pub(super) ip: IpAddr,
    pub(super) port: u16,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum PoolAddressFamily<'a> {
    V4(&'a [Ipv4Addr]),
    V6(&'a [Ipv6Addr]),
}

impl PoolAddressFamily<'_> {
    fn len(self) -> usize {
        match self {
            Self::V4(addrs) => addrs.len(),
            Self::V6(addrs) => addrs.len(),
        }
    }

    fn ip_at(self, index: usize) -> IpAddr {
        match self {
            Self::V4(addrs) => IpAddr::V4(addrs[index]),
            Self::V6(addrs) => IpAddr::V6(addrs[index]),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LiveAllocation {
    translated: TranslatedTuple,
    persistent_key: Option<PersistentSourceKey>,
    // #2852 F7: the pool-address index this translation was claimed on, stored
    // in the record so release is O(1) — the pre-#2852 `addr_index_by_translated`
    // reverse map is gone (the occupancy bitmap is per-address, so freeing the
    // bit needs the address index, and reading it off the record avoids a map
    // lookup). For a persistent flow the authoritative index is on the lease;
    // this copy mirrors it so the non-persistent / deterministic release paths
    // are uniform.
    addr_index: usize,
    // #4559: a deterministic CGNAT block allocation. Its port is NOT pushed onto
    // the per-address recycle queue on release (`free`-path `recycle = false`) —
    // the deterministic claim scans its subscriber block against the occupancy
    // bitmap directly, so a freed port becomes claimable again the moment its
    // bit clears. Recycling it too would let the queue grow without bound across
    // per-subscriber flow churn (a deterministic-only pool never drains the
    // recycle queue). `false` for every round-robin/persistent allocation
    // (unchanged behaviour).
    deterministic: bool,
    // #5269: an address-only occupancy token (port no-translation / port-less
    // source NAT). No pool PORT is consumed on the occupancy bitmap — the packet
    // keeps its own source port on the wire — so release must NOT free a port
    // bit; instead it clears the reverse-identity entry in `address_only_owners`.
    // `false` for every PAT / deterministic / persistent allocation.
    address_only: bool,
}

/// #5269: reverse-identity ownership key for an address-only (port
/// no-translation / port-less) source-NAT translation. The reverse conntrack
/// demux keys a reply on (protocol, translated source IP, translated source
/// port, remote IP, remote port); two forward flows that would produce the SAME
/// reverse identity cannot coexist because their replies are indistinguishable,
/// so the allocator grants each identity to exactly ONE flow and denies a
/// genuinely-colliding second flow as exhaustion. `translated_port` is the
/// PRESERVED source port for a port-bearing protocol, or 0 for a port-less
/// protocol (GRE/ESP/AH/...). This is the address-only analogue of the PAT
/// occupancy bit: PAT keeps `(pool_addr, port)` unique by handing out a fresh
/// port; address-only cannot move the port, so it enforces uniqueness on the
/// full reverse identity instead.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct AddressOnlyReverseKey {
    pub(super) protocol: u8,
    pub(super) translated_ip: IpAddr,
    pub(super) translated_port: u16,
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
}

/// #4559: IPv4 deterministic CGNAT (mode 1) block-allocation parameters,
/// precomputed by the Go compiler and carried on the source-NAT rule. The
/// mapping is `subscriber internal IPv4 -> fixed (external pool IP, port
/// block)`, reversible from `(external IP, port)` back to the subscriber with
/// NO per-flow state (the whole point of deterministic NAT: lawful-intercept /
/// CGN audit without per-connection logging). Reproduces the retired-eBPF
/// `nat_pool_alloc_deterministic_v4` logic (pkg/dataplane/compiler_nat.go /
/// the deleted bpf/xdp/xdp_policy.c) in the userspace dataplane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeterministicV4 {
    /// Ports per subscriber block (Junos `block-size`).
    pub(crate) block_size: u16,
    /// Blocks each external pool address carries
    /// (`(port_high - port_low + 1) / block_size`).
    pub(crate) blocks_per_ip: u16,
    /// Subscriber-CIDR network address, host-order u32.
    pub(crate) host_base: u32,
    /// Subscriber count in the host CIDR (`1 << (32 - prefix_len)`).
    pub(crate) host_count: u32,
}

/// #4559: map a subscriber IPv4 to its deterministic `(ip_idx, block_idx)`.
/// `ip_idx` selects the external pool address; `block_idx` selects the port
/// block within that address. Returns `None` when the subscriber is outside the
/// configured host range or the parameters are degenerate (`blocks_per_ip == 0`
/// / `block_size == 0`) — the caller fails the allocation closed rather than
/// silently round-robining a subscriber that has no reserved block.
pub(crate) fn deterministic_indices_v4(
    params: &DeterministicV4,
    src: Ipv4Addr,
) -> Option<(usize, u32)> {
    let bpi = params.blocks_per_ip as u32;
    if bpi == 0 || params.block_size == 0 {
        return None;
    }
    let src_h = u32::from(src);
    if src_h < params.host_base {
        return None;
    }
    let sub_idx = src_h - params.host_base;
    if sub_idx >= params.host_count {
        return None;
    }
    let ip_idx = (sub_idx / bpi) as usize;
    let block_idx = sub_idx % bpi;
    Some((ip_idx, block_idx))
}

/// #5660: O(1) reverse index for a deterministic-NAT external pool. Maps each
/// external pool IPv4 address to its position in the ordered `pool_v4` list —
/// the SAME index the forward path selects with `pool_v4[ip_idx]`. It replaces
/// the reverse path's `pool_v4.iter().position()` linear scan (up to
/// `MAX_POOL_PREFIX_HOSTS` = 65536 addresses) with a single hash lookup.
///
/// The pool is an ARBITRARY, possibly non-contiguous ordered address list (the
/// NAT64 path builds it by parsing configured pool strings, and a source-NAT
/// pool may span several disjoint ranges), so `ip_idx` is a POSITION in the
/// list, not an arithmetic offset from a base — a direct `translated_ip -
/// pool_base` subtraction would be wrong. Build this ONCE at prefix/rule build
/// time with [`build_pool_reverse_index`] and reuse it for every reverse
/// lookup; rebuilding it per lookup is O(N) again (and allocates). First
/// occurrence of a (pathologically) duplicated pool address wins, exactly
/// mirroring the `position()` first-match semantics it replaces.
pub(crate) type PoolReverseIndex = FxHashMap<Ipv4Addr, u32>;

/// #5660: build the [`PoolReverseIndex`] from an ordered deterministic-NAT
/// external pool. First-match wins for a duplicated address (matches the
/// `position()` scan this replaces).
pub(crate) fn build_pool_reverse_index(pool_v4: &[Ipv4Addr]) -> PoolReverseIndex {
    let mut index = FxHashMap::default();
    index.reserve(pool_v4.len());
    for (idx, &addr) in pool_v4.iter().enumerate() {
        index.entry(addr).or_insert(idx as u32);
    }
    index
}

/// #4559: reverse a deterministic translated `(external pool IP, port)` back to
/// the subscriber's internal IPv4 with NO per-flow state — the CGN-compliance
/// property that motivates deterministic NAT. `pool_index` is the pool's O(1)
/// reverse index ([`build_pool_reverse_index`], keyed by the same ordered
/// external-address list the forward path indexes); `port_low` is the pool's
/// low port. Returns `None` when the tuple does not fall in the deterministic
/// space (unknown external IP, port below `port_low`, or a block/subscriber
/// index out of range).
pub(crate) fn reverse_deterministic_v4(
    params: &DeterministicV4,
    pool_index: &PoolReverseIndex,
    port_low: u16,
    translated_ip: Ipv4Addr,
    translated_port: u16,
) -> Option<Ipv4Addr> {
    if params.block_size == 0 {
        return None;
    }
    let ip_idx = *pool_index.get(&translated_ip)?;
    if translated_port < port_low {
        return None;
    }
    let offset = (translated_port - port_low) as u32;
    let block_idx = offset / params.block_size as u32;
    if block_idx >= params.blocks_per_ip as u32 {
        return None;
    }
    let sub_idx = ip_idx
        .checked_mul(params.blocks_per_ip as u32)?
        .checked_add(block_idx)?;
    if sub_idx >= params.host_count {
        return None;
    }
    let host = params.host_base.checked_add(sub_idx)?;
    Some(Ipv4Addr::from(host))
}

/// #4559: IPv6-subscriber deterministic CGNAT (mode 2, NAPT64) block-allocation
/// parameters. An IPv6 subscriber deterministically maps to a fixed external
/// IPv4 pool address + port block, reversible from `(external IPv4, port)` back
/// to the subscriber's IPv6 prefix with NO per-flow state — the same
/// lawful-intercept / CGN-audit property as mode 1, but for the v6→v4 (NAT64)
/// direction. Reproduces the retired-eBPF `nat_pool_alloc_deterministic_v6`
/// logic (the deleted bpf/xdp/xdp_policy.c). The difference from mode 1 is the
/// subscriber-index derivation: the 32-bit word AFTER the configured IPv6
/// prefix (`/32` → octet offset 4, `/64` → octet offset 8) is the subscriber
/// index, not an IPv4 host offset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeterministicV6 {
    /// Ports per subscriber block (Junos `block-size`).
    pub(crate) block_size: u16,
    /// Blocks each external pool address carries
    /// (`(port_high - port_low + 1) / block_size`), computed against the fixed
    /// NAT64 translated-port range so block boundaries align with the allocator.
    pub(crate) blocks_per_ip: u16,
    /// IPv6 subscriber-prefix length: 32 or 64. Selects the subscriber-index
    /// word offset (32 → octets[4..8], 64 → octets[8..12]).
    pub(crate) host_prefix_len: u8,
    /// IPv6 subscriber-CIDR network base, network-order octets. Forward
    /// extraction reads the subscriber word off `src` at the prefix-selected
    /// offset relative to this base; the reverse path reconstructs it.
    pub(crate) host_base: [u8; 16],
    /// Maximum subscriber index the pool can serve
    /// (`pool_v4.len() * blocks_per_ip`). An IPv6 subscriber word extends far
    /// beyond pool capacity, so — unlike mode 1's CIDR-derived count — this is
    /// bounded by the pool, computed at `Nat64Prefix` build time from the parsed
    /// pool. A subscriber beyond it fails the allocation closed.
    pub(crate) host_count: u32,
}

/// #4559: byte offset of the 32-bit subscriber-index word for a mode-2 prefix
/// length. `/64` → octets[8..12] (the word after a /64 prefix), everything else
/// (only `/32` is otherwise built) → octets[4..8]. Mirrors the retired-eBPF
/// `host_prefix_len == 64 ? +8 : +4` split.
fn deterministic_v6_word_offset(host_prefix_len: u8) -> usize {
    if host_prefix_len == 64 { 8 } else { 4 }
}

/// #4559: map an IPv6 subscriber to its deterministic `(ip_idx, block_idx)` for
/// mode 2 (NAPT64). `ip_idx` selects the external IPv4 pool address; `block_idx`
/// selects the port block within it. The subscriber index is the host-order
/// 32-bit word AFTER the configured prefix minus the base's same word. Returns
/// `None` when the subscriber is below the base, beyond the pool-bounded
/// `host_count`, or the parameters are degenerate — the caller fails the
/// allocation closed rather than silently round-robining.
///
/// #4863: the source MUST lie inside the configured subscriber prefix. The
/// subscriber index is derived only from the 32-bit word at `off`, so a source
/// in a DIFFERENT prefix that happens to share that word would otherwise be
/// accepted and mapped into the in-prefix subscriber's fixed block — and the
/// stateless `reverse_deterministic_v6` (which reconstructs from `host_base`)
/// would then attribute the external `(IPv4, port)` to the WRONG subscriber
/// (cross-tenant block assignment + a lying reverse map). Reject any source
/// whose prefix bytes before the subscriber word differ from `host_base`. For
/// a /32 the checked prefix is `octets[0..4]`, for a /64 `octets[0..8]` — the
/// bytes at `off` are exactly the configured prefix length. This is a
/// drop-only tightening: an in-prefix source is unaffected.
pub(crate) fn deterministic_indices_v6(
    params: &DeterministicV6,
    src: Ipv6Addr,
) -> Option<(usize, u32)> {
    let bpi = params.blocks_per_ip as u32;
    if bpi == 0 || params.block_size == 0 {
        return None;
    }
    let off = deterministic_v6_word_offset(params.host_prefix_len);
    let src_octets = src.octets();
    // #4863: fail closed for any source outside the configured subscriber
    // prefix. The subscriber word alone does not identify the tenant — the
    // prefix bytes before it must match the configured base exactly, else a
    // colliding subscriber word in a different prefix would steal an in-prefix
    // subscriber's block and be reverse-mapped to the wrong subscriber.
    if src_octets[..off] != params.host_base[..off] {
        return None;
    }
    let src_word = u32::from_be_bytes([
        src_octets[off],
        src_octets[off + 1],
        src_octets[off + 2],
        src_octets[off + 3],
    ]);
    let base_word = u32::from_be_bytes([
        params.host_base[off],
        params.host_base[off + 1],
        params.host_base[off + 2],
        params.host_base[off + 3],
    ]);
    if src_word < base_word {
        return None;
    }
    let sub_idx = src_word - base_word;
    if sub_idx >= params.host_count {
        return None;
    }
    let ip_idx = (sub_idx / bpi) as usize;
    let block_idx = sub_idx % bpi;
    Some((ip_idx, block_idx))
}

/// #4559: reverse a deterministic translated `(external IPv4 pool address,
/// port)` back to the subscriber's IPv6 prefix with NO per-flow state — the
/// CGN-compliance property that motivates deterministic NAPT64. `pool_index` is
/// the prefix's O(1) reverse index ([`build_pool_reverse_index`], keyed by the
/// same ordered external-address list the forward path indexes); `port_low` is
/// the allocator's low port. The recovered address is the subscriber PREFIX
/// (network base + subscriber word, trailing interface-identifier bytes left as
/// the base's — zero for a network base): the deterministic unit is the
/// subscriber prefix, not the full /128 host. Returns `None` when the tuple
/// does not fall in the deterministic space.
pub(crate) fn reverse_deterministic_v6(
    params: &DeterministicV6,
    pool_index: &PoolReverseIndex,
    port_low: u16,
    translated_ip: Ipv4Addr,
    translated_port: u16,
) -> Option<Ipv6Addr> {
    if params.block_size == 0 {
        return None;
    }
    let ip_idx = *pool_index.get(&translated_ip)?;
    if translated_port < port_low {
        return None;
    }
    let offset = (translated_port - port_low) as u32;
    let block_idx = offset / params.block_size as u32;
    if block_idx >= params.blocks_per_ip as u32 {
        return None;
    }
    let sub_idx = ip_idx
        .checked_mul(params.blocks_per_ip as u32)?
        .checked_add(block_idx)?;
    if sub_idx >= params.host_count {
        return None;
    }
    let off = deterministic_v6_word_offset(params.host_prefix_len);
    let base_word = u32::from_be_bytes([
        params.host_base[off],
        params.host_base[off + 1],
        params.host_base[off + 2],
        params.host_base[off + 3],
    ]);
    let sub_word = base_word.checked_add(sub_idx)?;
    let mut octets = params.host_base;
    octets[off..off + 4].copy_from_slice(&sub_word.to_be_bytes());
    Some(Ipv6Addr::from(octets))
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PersistentLease {
    pub(super) translated: TranslatedTuple,
    pub(super) addr_index: usize,
    pub(super) expires_at_ns: u64,
    pub(super) timeout_ns: u64,
    pub(super) active_flows: u32,
    pub(super) completed_flows: u64,
    // Rollback needs per-activation completion state, not a comparison
    // against lifetime completion counters. The latter can saturate over
    // long-lived persistent leases and make a fresh completion invisible.
    pub(super) activation_saw_completion: bool,
    pub(super) activation_previous_expires_at_ns: u64,
    pub(super) activation_had_previous_lease: bool,
    // #6041: an ADDRESS-ONLY persistent lease (`persistent-nat` + `port
    // no-translation` / a port-less protocol). It pins a public ADDRESS across
    // the permit scope but consumes NO pool port — `translated.port` carries the
    // FIRST flow's preserved source port for status/debug only and is never a
    // bit on the occupancy bitmap. So every lease teardown site
    // (`reuse_existing_lease_locked` expired, `rollback_flow` remove-lease,
    // `reclaim_expired_lease_locked` GC) MUST skip `free_translated_port` when
    // this is set — there is no port bit to free, and freeing address `port`
    // would clear a DIFFERENT flow's PAT bit that happens to share the offset.
    // Per-flow reverse-identity collision ownership (#5269) is still tracked in
    // `address_only_owners`, minted/cleared per flow, independent of the lease.
    // `false` for every port-translating PAT lease (unchanged behaviour).
    pub(super) address_only: bool,
}

#[derive(Debug, Default)]
pub(super) struct PortAllocatorLiveState {
    live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>,
    pub(super) persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
    pub(super) lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
    pub(super) lease_expirations_by_addr: Vec<BTreeSet<(u64, PersistentSourceKey)>>,
    // #5269: address-only occupancy tokens — the translated reverse identity of a
    // `port no-translation` / port-less flow mapped to its owning FORWARD flow.
    // Populated by `reserve_address_only` (which denies a second flow that would
    // claim an already-owned identity) and cleared by `release_flow` /
    // `rollback_flow` for an `address_only` `LiveAllocation`. Distinct from the
    // per-address occupancy bitmap, which tracks PAT port ownership.
    address_only_owners: FxHashMap<AddressOnlyReverseKey, SourceNatFlowKey>,
    gc_counter: u32,
}

impl PortAllocatorLiveState {
    fn new(addr_count: usize) -> Self {
        Self {
            lease_expirations_by_addr: vec![BTreeSet::new(); addr_count],
            ..Self::default()
        }
    }
}

/// #2852 Phase 1: per-pool-address atomic occupancy for lock-free port claim.
///
/// `words` is the occupancy bitmap (bit set => that port offset is claimed);
/// a `fetch_or` CAS is the sole port-ownership arbiter and replaces the
/// pre-#2852 `owner_by_translated` map. `cursor` is the monotonic fresh-port
/// hand-out counter (the pre-#2852 `next_port_offset_by_addr`). `recycle` is
/// the #3011 FIFO reuse ring, behind a per-ADDRESS mutex (never the global
/// allocator mutex). `port_low`/`range` map ports to bit offsets.
#[derive(Debug)]
struct AddressOccupancy {
    words: Vec<AtomicU64>,
    cursor: AtomicU32,
    recycle: Mutex<VecDeque<u16>>,
    port_low: u16,
    range: u32,
}

impl AddressOccupancy {
    fn new(port_low: u16, range: u32) -> Self {
        let nwords = (range as usize).div_ceil(64);
        let mut words = Vec::with_capacity(nwords);
        for _ in 0..nwords {
            words.push(AtomicU64::new(0));
        }
        Self {
            words,
            cursor: AtomicU32::new(0),
            recycle: Mutex::new(VecDeque::new()),
            port_low,
            range,
        }
    }

    #[inline]
    fn offset_of(&self, port: u16) -> Option<u32> {
        if port < self.port_low {
            return None;
        }
        let off = (port - self.port_low) as u32;
        (off < self.range).then_some(off)
    }

    /// Map a bitmap `offset` back to its wire port. #5660: the offset is
    /// range-checked before the `u32 -> u16` narrowing so an out-of-range value
    /// is REJECTED (`None`) rather than silently truncated into a valid-looking
    /// but WRONG port. `offset < range` guarantees `port_low + offset <=
    /// port_high <= u16::MAX`, so the cast neither truncates nor overflows; a
    /// bare `offset as u16` would wrap (e.g. `65536 + k` -> `k`) and forge a
    /// port `port_low + k` inside the pool. Callers on the claim path already
    /// hold `offset < range`, so this returns `Some` for every legitimate claim.
    #[inline]
    fn port_of(&self, offset: u32) -> Option<u16> {
        if offset >= self.range {
            return None;
        }
        Some(self.port_low + offset as u16)
    }

    /// CAS-set the bit at `offset`. Returns true iff this call transitioned it
    /// 0 -> 1 (the caller now owns the port). The set bit is the ownership
    /// token: a held bit cannot be re-claimed, so no separate owner-identity
    /// check is needed, and it is ABA-safe because the bit is never cleared
    /// between a claim and its legitimate free.
    #[inline]
    fn claim_offset(&self, offset: u32) -> bool {
        let w = (offset / 64) as usize;
        let mask = 1u64 << (offset % 64);
        self.words[w].fetch_or(mask, Ordering::AcqRel) & mask == 0
    }

    /// Clear the bit at `offset`. Returns true iff it was set (1 -> 0).
    #[inline]
    fn free_offset(&self, offset: u32) -> bool {
        let w = (offset / 64) as usize;
        let mask = 1u64 << (offset % 64);
        self.words[w].fetch_and(!mask, Ordering::Release) & mask != 0
    }

    #[inline]
    fn is_occupied(&self, offset: u32) -> bool {
        let w = (offset / 64) as usize;
        let mask = 1u64 << (offset % 64);
        self.words[w].load(Ordering::Acquire) & mask != 0
    }

    /// Claim the next free port: forward-probe the monotonic fresh cursor
    /// (#3047 skip-occupied-out-of-band), then drain the FIFO recycle ring
    /// (#3011, retain-on-collision 062-10). Lock-free w.r.t. the global
    /// allocator mutex (it takes only the per-address recycle mutex, and only
    /// once the fresh range is spent). Returns the claimed PORT, or None when
    /// this address is genuinely full.
    fn claim(&self) -> Option<u16> {
        // Sequential phase: hand out fresh offsets in ascending order, one per
        // claimer via a bounded CAS. The cursor never exceeds `range`, so it
        // does not grow unboundedly once the fresh range is spent.
        loop {
            let cur = self.cursor.load(Ordering::Relaxed);
            if cur >= self.range {
                break;
            }
            if self
                .cursor
                .compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                // Another claimer advanced the cursor; re-read and retry.
                continue;
            }
            // We own the right to try offset `cur`. Its bit is normally clear
            // (fresh), but an out-of-band occupant (reserve/persistent/HA) may
            // have set it — then CAS fails and we advance to the next offset.
            if self.claim_offset(cur) {
                // `cur < self.range` (checked above), so `port_of` is `Some`.
                return self.port_of(cur);
            }
        }

        // Recycled phase: FIFO drain (oldest-freed first). A popped port whose
        // bit is already set collided with an out-of-band occupant and is
        // RETAINED (re-queued at the back), never discarded (062-10). The
        // retain buffer allocates lazily only on an actual collision.
        let mut recycle = self.recycle.lock().unwrap_or_else(|e| e.into_inner());
        let mut retained: Vec<u16> = Vec::new();
        let mut claimed = None;
        while let Some(port) = recycle.pop_front() {
            match self.offset_of(port) {
                Some(offset) if self.claim_offset(offset) => {
                    claimed = Some(port);
                    break;
                }
                // Out-of-range (stale) ports are dropped; occupied ports are
                // retained so a transient collision cannot shrink the pool.
                Some(_) => retained.push(port),
                None => {}
            }
        }
        if !retained.is_empty() {
            recycle.extend(retained);
        }
        claimed
    }

    /// Free `port`, pushing it onto the FIFO recycle ring (push_back) so it is
    /// reused oldest-first (#3011). Returns true iff the bit was set.
    fn free_recycle(&self, port: u16) -> bool {
        let Some(offset) = self.offset_of(port) else {
            return false;
        };
        if !self.free_offset(offset) {
            return false;
        }
        self.recycle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(port);
        true
    }

    /// Free `port` WITHOUT recycling it (#4559 deterministic path — the bit is
    /// the only reuse gate, and a deterministic-only pool never drains the
    /// recycle queue). Returns true iff the bit was set.
    fn free_no_recycle(&self, port: u16) -> bool {
        match self.offset_of(port) {
            Some(offset) => self.free_offset(offset),
            None => false,
        }
    }

    /// Reserve a SPECIFIC port (CAS-set its exact bit). Returns true iff the
    /// bit transitioned 0 -> 1 (the caller now owns it); false when the port
    /// is out of range or already owned (do-not-steal).
    fn reserve(&self, port: u16) -> bool {
        match self.offset_of(port) {
            Some(offset) => self.claim_offset(offset),
            None => false,
        }
    }

    /// Count of currently-occupied ports on this address (popcount over the
    /// bitmap). Cold path (snapshot / tests only).
    fn occupied_count(&self) -> usize {
        self.words
            .iter()
            .map(|w| w.load(Ordering::Relaxed).count_ones() as usize)
            .sum()
    }
}

/// Run bounded lease-expiration GC every N release_flow calls.
const GC_PERIOD: u32 = 10;
pub(super) const ALLOCATION_GC_BUDGET: usize = 8;
const RELEASE_GC_BUDGET: usize = 64;
const PRESSURE_GC_BUDGET: usize = 64;
/// #4676: leases reclaimed per short `live` critical section by the chunked
/// opportunistic GC (`gc_expired_chunked`). The sweep drops the alloc mutex
/// and frees the reclaimed ports on the lock-free occupancy bitmap between
/// chunks, so a concurrent `allocate_translation` map-insert is not blocked
/// for the full sweep. Sized to `ALLOCATION_GC_BUDGET` so the hot-path amortized
/// GC (budget 8) is a single chunk (no extra lock churn) while the larger
/// release/idle budgets (64) yield the mutex several times.
const GC_CHUNK: usize = 8;

#[derive(Debug)]
struct PortAllocatorShared {
    /// One atomic counter per pool address, used for the stateless round-robin
    /// `try_next_port` (address-only / `port no-translation` paths). Separate
    /// from `occupancy` (which tracks flow-keyed pool-mode PAT allocation).
    counters: Vec<AtomicU32>,
    /// Index for IPv4 round-robin address selection.
    addr_counter_v4: AtomicU32,
    /// Index for IPv6 round-robin address selection.
    addr_counter_v6: AtomicU32,
    /// #2852 Phase 1: lock-free per-address occupancy bitmap + recycle ring.
    /// One entry per pool address; the port claim/free run WITHOUT the global
    /// `live` mutex.
    occupancy: Vec<AddressOccupancy>,
    live: Mutex<PortAllocatorLiveState>,
    allocations_total: AtomicU64,
    reuses_total: AtomicU64,
    exhaustion_total: AtomicU64,
    /// #4800: production acquisitions of the `live` mutex (allocate /
    /// reserve / release / rollback / GC), and the subset of those that
    /// found the mutex already held. Together they give the contention
    /// RATIO for the residual Phase-1 (#2852) map mutex, which is the only
    /// form in which "is the NAT allocator the new-flow bottleneck?" has an
    /// answer: a raw acquisition rate says nothing without the denominator.
    ///
    /// Counted by `lock_live()`, which try-locks first — the LOCK on the
    /// uncontended path costs exactly one CAS, the same as `lock()` did. It is
    /// not free, though: the acquisition counter is bumped unconditionally, so
    /// an uncontended acquisition is 2 relaxed atomic RMWs where it used to be
    /// 1. The contended path pays one further relaxed increment on top of a
    /// block that was already going to happen.
    ///
    /// Deliberately NOT counted: `snapshot()` (the ~1s status poll that
    /// READS these counters — the observer must not appear in its own
    /// observation) and the `debug_*` test/diagnostic accessors.
    live_lock_acquisitions: AtomicU64,
    live_lock_contended: AtomicU64,
    max_tracked_flows: usize,
    /// #4676 test seam: counts how many times `gc_expired_chunked` acquired the
    /// `live` mutex. A std `Mutex` is non-reentrant, so N > 1 acquisitions over
    /// a single sweep is proof the sweep RELEASED the lock between chunks (you
    /// cannot re-acquire a lock you still hold). Reverting the chunking to a
    /// single critical section collapses this to 1.
    #[cfg(test)]
    gc_lock_acquisitions: AtomicUsize,
}

/// Bounded pool-mode SNAT allocator.
///
/// Address selection uses atomics for stable round-robin/sticky starting
/// points; port ownership is a lock-free per-address occupancy bitmap so ports
/// are not reused while sessions are alive, and only the flow map + persistent
/// leases are guarded by the per-pool mutex (#2852 Phase 1). Persistent NAT
/// leases are keyed by source tuple and retained until their inactivity timeout
/// after the last live flow releases them.
#[derive(Clone, Debug)]
pub(crate) struct PortAllocator {
    shared: Arc<PortAllocatorShared>,
    pub(crate) port_low: u16,
    pub(crate) port_high: u16,
}

impl Default for PortAllocator {
    fn default() -> Self {
        Self {
            shared: Arc::new(PortAllocatorShared {
                counters: Vec::new(),
                addr_counter_v4: AtomicU32::new(0),
                addr_counter_v6: AtomicU32::new(0),
                occupancy: Vec::new(),
                live: Mutex::new(PortAllocatorLiveState::default()),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                live_lock_acquisitions: AtomicU64::new(0),
                live_lock_contended: AtomicU64::new(0),
                max_tracked_flows: 0,
                #[cfg(test)]
                gc_lock_acquisitions: AtomicUsize::new(0),
            }),
            port_low: 1024,
            port_high: 65535,
        }
    }
}

impl PortAllocator {
    pub(crate) fn new(num_addresses: usize, port_low: u16, port_high: u16) -> Self {
        let counters = (0..num_addresses).map(|_| AtomicU32::new(0)).collect();
        let range = if port_low == 0 || port_high == 0 || port_low > port_high {
            0
        } else {
            (port_high as u32) - (port_low as u32) + 1
        };
        let occupancy = (0..num_addresses)
            .map(|_| AddressOccupancy::new(port_low, range))
            .collect();
        let max_tracked_flows = allocator_capacity(num_addresses, port_low, port_high)
            .min(MAX_SOURCE_NAT_POOL_TRACKED_FLOWS);
        Self {
            shared: Arc::new(PortAllocatorShared {
                counters,
                addr_counter_v4: AtomicU32::new(0),
                addr_counter_v6: AtomicU32::new(0),
                occupancy,
                live: Mutex::new(PortAllocatorLiveState::new(num_addresses)),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                live_lock_acquisitions: AtomicU64::new(0),
                live_lock_contended: AtomicU64::new(0),
                max_tracked_flows,
                #[cfg(test)]
                gc_lock_acquisitions: AtomicUsize::new(0),
            }),
            port_low,
            port_high,
        }
    }

    /// #4800: acquire the residual `live` map mutex, counting acquisitions
    /// and the subset that had to block.
    ///
    /// `try_lock()` first: on an uncontended mutex that is a single CAS —
    /// exactly what `lock()` was already doing — so the LOCK ITSELF costs what
    /// it always did. The acquisition counter is bumped UNCONDITIONALLY, so an
    /// uncontended acquisition is 2 relaxed atomic read-modify-writes where it
    /// used to be 1; "unchanged" would be false, though both are relaxed,
    /// untimed and allocation-free. Only when the CAS fails (another worker
    /// holds the map mutex) do we bump `live_lock_contended` and fall through
    /// to the blocking `lock()`, which was going to happen regardless.
    ///
    /// Poison policy is preserved verbatim from the call sites this
    /// replaces (`unwrap_or_else(|e| e.into_inner())`): a worker that
    /// panicked mid-mutation must not strand every subsequent allocation.
    /// `try_lock` reports poison only when the mutex is FREE, so the
    /// blocking arm still has to handle it.
    ///
    /// Every production allocate / reserve / release / rollback / GC site
    /// goes through here. `snapshot()` deliberately does NOT — it is the
    /// ~1s status poll that reads these very counters, and counting it
    /// would inject the observer into the observation.
    fn lock_live(&self) -> MutexGuard<'_, PortAllocatorLiveState> {
        self.shared
            .live_lock_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        match self.shared.live.try_lock() {
            Ok(guard) => return guard,
            Err(TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {}
        }
        self.shared
            .live_lock_contended
            .fetch_add(1, Ordering::Relaxed);
        self.shared.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// White-box access to the live state for tests. NOT for production
    /// callers — they should use the typed `allocate_translation` /
    /// `release_flow` / `rollback_flow` / `snapshot` entry points. Port
    /// ownership is inspected via the dedicated debug accessors below (the
    /// bitmap lives outside this mutex).
    #[cfg(test)]
    pub(super) fn debug_live(&self) -> MutexGuard<'_, PortAllocatorLiveState> {
        self.shared.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Test-only: total occupancy-bitmap WORDS across every pool address.
    /// The #6812 aggregate-budget tests assert a refused / failed pool
    /// materialised ZERO words (no eager bitmap) while an admitted pool
    /// carries `addresses x div_ceil(port_range, 64)` — the direct white-box
    /// proof the bitmap was (or was not) allocated.
    #[cfg(test)]
    pub(super) fn debug_occupancy_words(&self) -> usize {
        self.shared.occupancy.iter().map(|o| o.words.len()).sum()
    }

    /// Test-only: identity of the shared allocator state, for proving a
    /// re-apply REUSED the previous allocator (same Arc) instead of building
    /// a fresh bitmap (#6812 reuse-before-build).
    #[cfg(test)]
    pub(super) fn debug_shared_identity(&self) -> usize {
        Arc::as_ptr(&self.shared) as usize
    }

    /// Test-only: mark a translated tuple as owned (set its occupancy bit)
    /// without advancing the sequential cursor. Models an out-of-band occupant
    /// (a persistent lease or an HA-synced install) sitting inside the
    /// sequential port range — the precondition for the #3047 collision paths.
    /// `_translated_ip` is retained for call-site clarity; the bitmap is keyed
    /// by `addr_index`.
    #[cfg(test)]
    pub(super) fn debug_seed_owner(&self, addr_index: usize, _translated_ip: IpAddr, port: u16) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            occ.reserve(port);
        }
    }

    /// Test-only: clear a synthetic owner seeded via `debug_seed_owner`
    /// (clear its occupancy bit) without pushing the port onto the recycle
    /// queue.
    #[cfg(test)]
    pub(super) fn debug_clear_owner(&self, addr_index: usize, _translated_ip: IpAddr, port: u16) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            occ.free_no_recycle(port);
        }
    }

    /// Test-only: is `port` currently occupied on pool address `addr_index`?
    #[cfg(test)]
    pub(super) fn debug_is_port_occupied(&self, addr_index: usize, port: u16) -> bool {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => match occ.offset_of(port) {
                Some(offset) => occ.is_occupied(offset),
                None => false,
            },
            None => false,
        }
    }

    /// Test-only: map a bitmap `offset` to its port on pool address
    /// `addr_index`, exercising the #5660 range-checked `port_of`. Returns
    /// `None` for an unknown address OR an out-of-range offset (the value a bare
    /// `offset as u16` would silently truncate).
    #[cfg(test)]
    pub(super) fn debug_port_of(&self, addr_index: usize, offset: u32) -> Option<u16> {
        self.shared
            .occupancy
            .get(addr_index)
            .and_then(|occ| occ.port_of(offset))
    }

    /// Test-only: total occupied ports across all pool addresses.
    #[cfg(test)]
    pub(super) fn debug_occupied_count(&self) -> usize {
        self.shared
            .occupancy
            .iter()
            .map(AddressOccupancy::occupied_count)
            .sum()
    }

    /// Test-only: snapshot the FIFO recycle queue for pool address `addr_index`.
    #[cfg(test)]
    pub(super) fn debug_recycled_ports(&self, addr_index: usize) -> Vec<u16> {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => occ
                .recycle
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .copied()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Test-only: replace the FIFO recycle queue for pool address `addr_index`.
    #[cfg(test)]
    pub(super) fn debug_set_recycled(&self, addr_index: usize, ports: Vec<u16>) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            *occ.recycle.lock().unwrap_or_else(|e| e.into_inner()) = VecDeque::from(ports);
        }
    }

    /// Test-only: set the monotonic fresh-port cursor for pool address
    /// `addr_index` (e.g. push it past the range to force the recycle phase).
    #[cfg(test)]
    pub(super) fn debug_set_cursor(&self, addr_index: usize, offset: u32) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            occ.cursor.store(offset, Ordering::Relaxed);
        }
    }

    /// Test-only: drive the #4676 chunked opportunistic GC directly (the same
    /// entry point the hot allocation path and the periodic release path use),
    /// so a white-box test can assert both the reclaim result and the seam
    /// (`debug_gc_lock_acquisitions`).
    #[cfg(test)]
    pub(super) fn debug_gc_expired_chunked(&self, now_ns: u64, budget: usize) -> usize {
        self.gc_expired_chunked(now_ns, budget)
    }

    /// Test-only: how many times `gc_expired_chunked` has acquired the `live`
    /// mutex. Because a std `Mutex` is non-reentrant, a value > 1 over a single
    /// sweep is direct proof the sweep RELEASED the lock between chunks.
    #[cfg(test)]
    pub(super) fn debug_gc_lock_acquisitions(&self) -> usize {
        self.shared.gc_lock_acquisitions.load(Ordering::Relaxed)
    }

    /// Pick a pool address index for the current address family.
    pub(super) fn address_index(
        &self,
        src_ip: IpAddr,
        family_offset: usize,
        family_len: usize,
        address_persistent: bool,
    ) -> usize {
        if family_len == 0 {
            return 0;
        }
        if address_persistent {
            return family_offset + sticky_pool_index(src_ip, family_len);
        }
        let counter = match src_ip {
            IpAddr::V4(_) => &self.shared.addr_counter_v4,
            IpAddr::V6(_) => &self.shared.addr_counter_v6,
        };
        let idx = counter.fetch_add(1, Ordering::Relaxed);
        family_offset + ((idx as usize) % family_len)
    }

    /// Allocate the next port for the given address index, reporting
    /// unusable allocator state to the caller instead of producing a
    /// no-op translation.
    pub(super) fn try_next_port(
        &self,
        addr_index: usize,
    ) -> Result<u16, super::source::SourceNatFailureReason> {
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(super::source::SourceNatFailureReason::InvalidPortRange);
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || addr_index >= self.shared.counters.len() {
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        let counter = &self.shared.counters[addr_index];
        let val = counter.fetch_add(1, Ordering::Relaxed);
        Ok(self.port_low + (val % range) as u16)
    }

    /// Free a translated port's occupancy bit. `recycle` pushes the port onto
    /// the FIFO reuse ring (#3011); the deterministic path passes `false`.
    /// Returns true iff the bit was set.
    fn free_translated_port(&self, addr_index: usize, port: u16, recycle: bool) -> bool {
        let Some(occ) = self.shared.occupancy.get(addr_index) else {
            return false;
        };
        if recycle {
            occ.free_recycle(port)
        } else {
            occ.free_no_recycle(port)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn allocate_translation(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(super::source::SourceNatFailureReason::InvalidPortRange);
        }
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(super::source::SourceNatFailureReason::WrongAddressFamily);
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || self.shared.max_tracked_flows == 0 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        // ---- Non-persistent hot path: lock-free port claim, tiny map lock. ----
        //
        // The port claim (forward-probe cursor + bitmap CAS + FIFO recycle) runs
        // WITHOUT the global mutex; the mutex is taken only for the tiny
        // reuse-check + exact-cap-check + `live_by_flow` insert critical section.
        // A GC-of-expired-leases-first pass is preserved for the near-capacity
        // case by falling through to `allocate_translation_locked` when every
        // target address's bitmap is full (the fast, non-GC'd view).
        if !persistent_nat {
            let start_abs =
                self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
            let start_rel = start_abs.saturating_sub(family_offset);
            let address_attempts = if address_persistent { 1 } else { family_len };
            for offset in 0..address_attempts {
                let rel = (start_rel + offset) % family_len;
                let abs = family_offset + rel;
                let Some(occ) = self.shared.occupancy.get(abs) else {
                    continue;
                };
                let Some(port) = occ.claim() else {
                    continue;
                };
                let translated = TranslatedTuple {
                    ip: family_addresses.ip_at(rel),
                    port,
                };
                // #4676: run the amortized expiry GC OFF the insert critical
                // section — chunked, the alloc mutex released between batches,
                // reclaimed ports freed lock-free. GC touches only the
                // persistent-lease maps + occupancy while the insert CS below
                // touches only `live_by_flow`, so the two are disjoint and the
                // insert CS stays genuinely tiny (the port is already claimed on
                // the lock-free bitmap, so GC here is opportunistic cleanup, not
                // load-bearing for this allocation).
                self.gc_expired_chunked(now_ns, ALLOCATION_GC_BUDGET);
                let mut live = self.lock_live();
                if let Some(existing) = live.live_by_flow.get(&flow) {
                    // Idempotent re-entry for an already-allocated flow (a second
                    // packet racing session install). Give back the port we just
                    // claimed and return the existing translation.
                    let existing = existing.translated;
                    self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
                    drop(live);
                    self.free_translated_port(abs, port, true);
                    return Ok(existing);
                }
                if live.live_by_flow.len() >= self.shared.max_tracked_flows {
                    // Exact cap (F4): `live_by_flow.len()` under the mutex is
                    // authoritative — no overshoot. Give back the claimed port.
                    self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                    drop(live);
                    self.free_translated_port(abs, port, true);
                    return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
                }
                live.live_by_flow.insert(
                    flow,
                    LiveAllocation {
                        translated,
                        persistent_key: None,
                        addr_index: abs,
                        deterministic: false,
                        address_only: false,
                    },
                );
                self.shared
                    .allocations_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(translated);
            }
            // Every target address's bitmap was full on the fast (non-GC'd)
            // view. Fall through to the pressured, GC-first locked path.
        }

        self.allocate_translation_locked(
            flow,
            family_addresses,
            family_offset,
            address_persistent,
            persistent_nat,
            persistent_nat_permit,
            persistent_nat_timeout_ns,
            now_ns,
        )
    }

    /// The persistent-NAT path (lease decision + claim MUST be atomic so two
    /// flows sharing a lease cannot both claim a port) and the non-persistent
    /// near-capacity pressure fallback (bounded expiry GC per address, then
    /// retry). Both hold the global mutex; the port claim uses the same lock-
    /// free bitmap (correctness is unaffected by whether the mutex is held).
    #[allow(clippy::too_many_arguments)]
    fn allocate_translation_locked(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let family_len = family_addresses.len();
        let mut live = self.lock_live();
        self.gc_expired_locked(&mut live, now_ns, ALLOCATION_GC_BUDGET);

        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        let persistent_key =
            persistent_nat.then(|| flow.persistent_source_key(persistent_nat_permit));
        if let Some(key) = persistent_key {
            if let Some(translated) = self.reuse_existing_lease_locked(
                &mut live,
                key,
                flow,
                persistent_nat_timeout_ns,
                now_ns,
            ) {
                return Ok(translated);
            }
        }

        let start_abs =
            self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
        let start_rel = start_abs.saturating_sub(family_offset);
        let address_attempts = if address_persistent { 1 } else { family_len };
        for offset in 0..address_attempts {
            let rel = (start_rel + offset) % family_len;
            let abs = family_offset + rel;
            if abs >= self.shared.occupancy.len() {
                continue;
            }
            let translated_ip = family_addresses.ip_at(rel);
            if persistent_key.is_some()
                && live.persistent_by_source.len() >= self.shared.max_tracked_flows
            {
                // Lease-table pressure is also budgeted. A full persistent
                // table gets one global PRESSURE_GC_BUDGET pass before this
                // address attempt is treated as unavailable.
                self.gc_expired_locked(&mut live, now_ns, PRESSURE_GC_BUDGET);
                if live.persistent_by_source.len() >= self.shared.max_tracked_flows {
                    continue;
                }
            }

            let mut port = self.shared.occupancy[abs].claim();
            if port.is_none() {
                // Pressure handling is budgeted, not strict O(1). A
                // non-address-persistent full family can visit each
                // family-compatible address and run at most
                // PRESSURE_GC_BUDGET expiry checks for that selected
                // address before declaring exhaustion.
                self.gc_expired_for_addr_locked(&mut live, abs, now_ns, PRESSURE_GC_BUDGET);
                port = self.shared.occupancy[abs].claim();
            }
            let Some(port) = port else {
                continue;
            };
            let translated = TranslatedTuple {
                ip: translated_ip,
                port,
            };
            if let Some(key) = persistent_key {
                let expires_at_ns =
                    now_ns.saturating_add(persistent_nat_timeout_ns.max(NS_PER_SEC));
                live.persistent_by_source.insert(
                    key,
                    PersistentLease {
                        translated,
                        addr_index: abs,
                        expires_at_ns,
                        timeout_ns: persistent_nat_timeout_ns.max(NS_PER_SEC),
                        active_flows: 1,
                        completed_flows: 0,
                        activation_saw_completion: false,
                        activation_previous_expires_at_ns: 0,
                        activation_had_previous_lease: false,
                        address_only: false,
                    },
                );
            }
            live.live_by_flow.insert(
                flow,
                LiveAllocation {
                    translated,
                    persistent_key,
                    addr_index: abs,
                    deterministic: false,
                    address_only: false,
                },
            );
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(translated);
        }

        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(super::source::SourceNatFailureReason::AllocatorExhausted)
    }

    /// #2397 persistent-NAT lease reuse, run under the live-state lock as the
    /// first persistent-key step of `allocate_translation_locked`.
    ///
    /// When a lease already exists for `key`:
    ///   - a still-valid lease (an active flow, or one whose inactivity timeout
    ///     has not yet elapsed) is REUSED — on the 0 -> 1 active-flow edge its
    ///     activation-rollback bookkeeping is re-armed and its old expiry index
    ///     entry is dropped, its inactivity expiry is pushed out, the flow is
    ///     recorded in `live_by_flow`, `reuses_total` is bumped, and the reused
    ///     translated tuple is returned as `Some(_)` (the caller returns it
    ///     directly);
    ///   - an expired lease is torn down (expiry index entry removed, translated
    ///     tuple released, lease dropped) and `None` is returned so the caller
    ///     falls through to a fresh allocation.
    ///
    /// Returns `None` when no lease exists for `key` or the lease was expired and
    /// reclaimed.
    fn reuse_existing_lease_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        key: PersistentSourceKey,
        flow: SourceNatFlowKey,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
    ) -> Option<TranslatedTuple> {
        if !live.persistent_by_source.contains_key(&key) {
            return None;
        }
        let mut reusable = None;
        let mut expired = None;
        let mut remove_expiry = None;
        if let Some(lease) = live.persistent_by_source.get_mut(&key) {
            if lease.active_flows > 0 || lease.expires_at_ns > now_ns {
                let translated = lease.translated;
                let addr_index = lease.addr_index;
                if lease.active_flows == 0 {
                    remove_expiry = Some((addr_index, lease.expires_at_ns));
                    lease.activation_saw_completion = false;
                    lease.activation_previous_expires_at_ns = lease.expires_at_ns;
                    lease.activation_had_previous_lease = true;
                }
                lease.active_flows = lease.active_flows.saturating_add(1);
                let expires_at_ns =
                    now_ns.saturating_add(persistent_nat_timeout_ns.max(NS_PER_SEC));
                lease.expires_at_ns = expires_at_ns;
                reusable = Some((translated, addr_index));
            } else {
                expired = Some((
                    lease.translated,
                    lease.addr_index,
                    lease.expires_at_ns,
                    lease.address_only,
                ));
            }
        }
        if let Some((addr_index, expires_at_ns)) = remove_expiry {
            Self::remove_lease_expiration_locked(live, addr_index, expires_at_ns, key);
        }
        if let Some((translated, addr_index)) = reusable {
            live.live_by_flow.insert(
                flow,
                LiveAllocation {
                    translated,
                    persistent_key: Some(key),
                    addr_index,
                    deterministic: false,
                    address_only: false,
                },
            );
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Some(translated);
        }
        if let Some((translated, addr_index, expires_at_ns, address_only)) = expired {
            Self::remove_lease_expiration_locked(live, addr_index, expires_at_ns, key);
            // #6041: an address-only lease owns no pool port, so there is no bit
            // to free — its per-flow reverse-identity tokens were already cleared
            // when each flow released (the lease is idle here). Freeing
            // `translated.port` would clear an UNRELATED PAT flow's bit that
            // happens to share the offset.
            if !address_only {
                self.free_translated_port(addr_index, translated.port, true);
            }
            live.persistent_by_source.remove(&key);
        }
        None
    }

    fn insert_lease_expiration_locked(
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        expires_at_ns: u64,
        key: PersistentSourceKey,
    ) {
        live.lease_expirations.insert((expires_at_ns, key));
        if let Some(by_addr) = live.lease_expirations_by_addr.get_mut(addr_index) {
            by_addr.insert((expires_at_ns, key));
        }
    }

    fn remove_lease_expiration_locked(
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        expires_at_ns: u64,
        key: PersistentSourceKey,
    ) {
        live.lease_expirations.remove(&(expires_at_ns, key));
        if let Some(by_addr) = live.lease_expirations_by_addr.get_mut(addr_index) {
            by_addr.remove(&(expires_at_ns, key));
        }
    }

    pub(super) fn release_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        now_ns: u64,
    ) -> bool {
        let mut live = self.lock_live();
        let Some(existing) = live.live_by_flow.get(&flow).copied() else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        live.live_by_flow.remove(&flow);
        // #6041: the address-only reverse-identity token (#5269) is orthogonal to
        // the persistent lease. Clear THIS flow's ownership first — it exists for
        // BOTH a non-persistent address-only flow AND an address-only PERSISTENT
        // flow (`persistent_key = Some` AND `address_only = true`). No pool port
        // bit was claimed for any address-only flow, so nothing is freed on the
        // occupancy bitmap. The key mirrors what `reserve_address_only` /
        // `reserve_address_only_persistent` inserted (stored translated tuple +
        // the flow's remote endpoint).
        if existing.address_only {
            live.address_only_owners.remove(&AddressOnlyReverseKey {
                protocol: flow.protocol,
                translated_ip: existing.translated.ip,
                translated_port: existing.translated.port,
                dst_ip: flow.dst_ip,
                dst_port: flow.dst_port,
            });
        }
        if let Some(key) = existing.persistent_key {
            let mut refresh_expiry = None;
            if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                lease.completed_flows = lease.completed_flows.saturating_add(1);
                lease.activation_saw_completion = true;
                lease.active_flows = lease.active_flows.saturating_sub(1);
                if lease.active_flows == 0 {
                    let old_expires_at_ns = lease.expires_at_ns;
                    let expires_at_ns = now_ns.saturating_add(lease.timeout_ns);
                    lease.expires_at_ns = expires_at_ns;
                    refresh_expiry = Some((lease.addr_index, old_expires_at_ns, expires_at_ns));
                }
            }
            if let Some((addr_index, old_expires_at_ns, expires_at_ns)) = refresh_expiry {
                Self::remove_lease_expiration_locked(&mut live, addr_index, old_expires_at_ns, key);
                Self::insert_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
            }
        } else if !existing.address_only {
            // Non-persistent (or deterministic) flow owns its port outright:
            // free the bit, recycling it unless it is a deterministic block
            // port (#4559). The persistent case keeps the port/address on the
            // lease until the lease itself is torn down; the address-only case
            // (handled above) never claimed a port bit to free.
            self.free_translated_port(
                existing.addr_index,
                translated.port,
                !existing.deterministic,
            );
        }
        live.gc_counter = live.gc_counter.wrapping_add(1);
        let run_gc = live.gc_counter % GC_PERIOD == 0;
        // #4676: drop the release guard BEFORE the periodic idle-lease sweep so
        // the (up to RELEASE_GC_BUDGET) sweep runs chunked with the alloc mutex
        // released between batches instead of blocking concurrent allocations
        // for the whole sweep. The release mutations above are already committed
        // under this guard, so the GC re-locking a fresh guard observes them.
        drop(live);
        if run_gc {
            self.gc_expired_chunked(now_ns, RELEASE_GC_BUDGET);
        }
        true
    }

    pub(super) fn rollback_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        now_ns: u64,
    ) -> bool {
        let mut live = self.lock_live();
        let Some(existing) = live.live_by_flow.get(&flow).copied() else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        live.live_by_flow.remove(&flow);
        // #6041: clear this flow's address-only reverse-identity token first
        // (present for both a #5269 non-persistent and a #6041 persistent
        // address-only flow); it is independent of the lease refcount below and
        // no pool port bit is ever freed for an address-only flow.
        if existing.address_only {
            live.address_only_owners.remove(&AddressOnlyReverseKey {
                protocol: flow.protocol,
                translated_ip: existing.translated.ip,
                translated_port: existing.translated.port,
                dst_ip: flow.dst_ip,
                dst_port: flow.dst_port,
            });
        }
        if let Some(key) = existing.persistent_key {
            let mut remove_lease = false;
            let mut insert_expiry = None;
            if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                lease.active_flows = lease.active_flows.saturating_sub(1);
                if lease.active_flows == 0 {
                    if lease.activation_saw_completion {
                        let expires_at_ns = now_ns.saturating_add(lease.timeout_ns);
                        lease.expires_at_ns = expires_at_ns;
                        insert_expiry = Some((lease.addr_index, expires_at_ns));
                    } else if lease.activation_had_previous_lease {
                        lease.expires_at_ns = lease.activation_previous_expires_at_ns;
                        insert_expiry = Some((lease.addr_index, lease.expires_at_ns));
                    } else {
                        remove_lease = true;
                    }
                }
            }
            if remove_lease {
                live.persistent_by_source.remove(&key);
                // #6041: an address-only lease holds no pool port bit — only a
                // PAT lease frees its port when the fresh-activation rollback
                // removes it.
                if !existing.address_only {
                    self.free_translated_port(existing.addr_index, translated.port, true);
                }
            }
            if let Some((addr_index, expires_at_ns)) = insert_expiry {
                Self::insert_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
            }
        } else if !existing.address_only {
            self.free_translated_port(
                existing.addr_index,
                translated.port,
                !existing.deterministic,
            );
        }
        true
    }

    /// #4559: allocate a deterministic CGNAT port from the subscriber's fixed
    /// block. The external pool IP and the port block are a pure function of the
    /// subscriber's internal IPv4 address (`deterministic_indices_v4`), so the
    /// `(external IP, port)` → subscriber reverse mapping needs no per-flow log.
    /// A live flow re-allocates its existing tuple (reuse); a fresh flow claims
    /// the first free port in `[port_start, port_end]` via the occupancy bitmap
    /// (collision-free CAS). Unlike round-robin PAT this does NOT touch the
    /// per-address fresh cursor, the recycle queue, or persistent leases — a
    /// deterministic pool is mutually exclusive with persistent-nat /
    /// address-persistent (enforced at commit). Returns the subscriber-out-of-
    /// range / exhaustion failure to the caller instead of silently falling back
    /// to round-robin.
    pub(super) fn allocate_deterministic_v4(
        &self,
        flow: SourceNatFlowKey,
        pool_v4: &[Ipv4Addr],
        params: DeterministicV4,
        src: Ipv4Addr,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        use super::source::SourceNatFailureReason;
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(SourceNatFailureReason::InvalidPortRange);
        }
        let (ip_idx, block_idx) = deterministic_indices_v4(&params, src)
            .ok_or(SourceNatFailureReason::DeterministicSubscriberOutOfRange)?;
        if ip_idx >= pool_v4.len() || ip_idx >= self.shared.occupancy.len() {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let translated_ip = IpAddr::V4(pool_v4[ip_idx]);
        // Block boundaries: [port_low + block_idx*block_size,
        // that + block_size - 1], clamped to port_high. Widths align with the Go
        // compiler because both use the SAME defaulted port range.
        let port_start = self.port_low as u32 + block_idx * params.block_size as u32;
        if port_start > self.port_high as u32 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let port_end = (port_start + params.block_size as u32 - 1).min(self.port_high as u32);

        let mut live = self.lock_live();
        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        // Claim the first free port in the subscriber's block. The block is small
        // (typically a few thousand ports) and this is the cold path (first
        // packet of a flow), so a linear CAS probe is fine.
        for p in port_start..=port_end {
            let port = p as u16;
            if self.shared.occupancy[ip_idx].reserve(port) {
                let translated = TranslatedTuple {
                    ip: translated_ip,
                    port,
                };
                live.live_by_flow.insert(
                    flow,
                    LiveAllocation {
                        translated,
                        persistent_key: None,
                        addr_index: ip_idx,
                        deterministic: true,
                        address_only: false,
                    },
                );
                self.shared
                    .allocations_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(translated);
            }
        }
        // Every port in the subscriber's block is live — the block is full.
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(SourceNatFailureReason::AllocatorExhausted)
    }

    /// #4559: allocate a deterministic CGNAT port for a NAPT64 (mode 2) flow
    /// from the IPv6 subscriber's fixed block. Structurally identical to
    /// [`allocate_deterministic_v4`] — a live flow re-allocates its tuple, a
    /// fresh flow claims the first free port in the subscriber's block via the
    /// occupancy bitmap (collision-free, RFC 6146 BIB), and the freed port is
    /// not recycled onto the per-address queue — differing ONLY in the
    /// subscriber-index derivation ([`deterministic_indices_v6`]: the 32-bit
    /// word after the IPv6 prefix). The external IPv4 pool address and the port
    /// block are a pure function of the subscriber's IPv6 prefix, so
    /// [`reverse_deterministic_v6`] recovers it from `(external IPv4, port)`
    /// with no per-flow log. An out-of-range subscriber fails closed.
    pub(super) fn allocate_deterministic_v6(
        &self,
        flow: SourceNatFlowKey,
        pool_v4: &[Ipv4Addr],
        params: DeterministicV6,
        src: Ipv6Addr,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        use super::source::SourceNatFailureReason;
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(SourceNatFailureReason::InvalidPortRange);
        }
        let (ip_idx, block_idx) = deterministic_indices_v6(&params, src)
            .ok_or(SourceNatFailureReason::DeterministicSubscriberOutOfRange)?;
        if ip_idx >= pool_v4.len() || ip_idx >= self.shared.occupancy.len() {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let translated_ip = IpAddr::V4(pool_v4[ip_idx]);
        // Block boundaries mirror the v4 path: [port_low + block_idx*block_size,
        // that + block_size - 1], clamped to port_high. The NAT64 allocator's
        // port_low/port_high are the fixed NAT64 translated-port range, the same
        // range the Go builder computes blocks_per_ip against, so boundaries
        // align.
        let port_start = self.port_low as u32 + block_idx * params.block_size as u32;
        if port_start > self.port_high as u32 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let port_end = (port_start + params.block_size as u32 - 1).min(self.port_high as u32);

        let mut live = self.lock_live();
        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        for p in port_start..=port_end {
            let port = p as u16;
            if self.shared.occupancy[ip_idx].reserve(port) {
                let translated = TranslatedTuple {
                    ip: translated_ip,
                    port,
                };
                live.live_by_flow.insert(
                    flow,
                    LiveAllocation {
                        translated,
                        persistent_key: None,
                        addr_index: ip_idx,
                        deterministic: true,
                        address_only: false,
                    },
                );
                self.shared
                    .allocations_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(translated);
            }
        }
        // Every port in the subscriber's block is live — the block is full.
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(SourceNatFailureReason::AllocatorExhausted)
    }

    /// #4388: reserve a SPECIFIC translated `(ip, port)` for `flow` WITHOUT
    /// running the round-robin allocator, so a peer-synced session's NAT pool
    /// port is marked allocated in this node's LOCAL allocator. Without this,
    /// the standby never learns that the active node handed `(pool_ip, port)`
    /// to a synced session (the standby imports the pre-computed NAT decision;
    /// it never calls `allocate_translation`), so post-failover a fresh local
    /// flow could `allocate_translation` the SAME `(pool_ip, port)` — two
    /// sessions colliding on one NAT source tuple (reply mis-delivery / session
    /// hijack surface).
    ///
    /// The reservation sets the occupancy bit (the ownership token) and records
    /// `live_by_flow` using the synced session's flow key, so:
    ///   - the fresh cursor skips the port when it later reaches that offset
    ///     (the #3047 forward-probe), and
    ///   - the EXISTING teardown path (`release_flow` / `rollback_flow` via
    ///     `release_source_nat_allocation`, already called for every reaped or
    ///     delete-synced session) frees it with the SAME flow key — no new
    ///     release site is needed.
    ///
    /// Idempotent: re-reserving the same `(flow, translated)` (a synced-session
    /// refresh) is a no-op that returns `true`. Returns `false` and leaves the
    /// incumbent untouched if the port is already owned by a DIFFERENT live
    /// allocation (the bit is set — a local flow raced ahead of the sync on the
    /// standby); the caller then tries the next pool rule.
    ///
    /// #5178: `deterministic` mirrors the ACTIVE node's allocation mode for this
    /// synced flow — `true` when the reservation belongs to a deterministic
    /// CGNAT (mode 1) / NAPT64 (mode 2) pool, `false` for round-robin PAT. It is
    /// stored on the `LiveAllocation` so the SAME `release_flow`/`rollback_flow`
    /// teardown frees a deterministic reservation via `free_no_recycle` (the bit
    /// is the only reuse gate) instead of pushing it onto the per-address recycle
    /// `VecDeque`. Before #5178 this was hardcoded `false`, so a standby running
    /// a deterministic pool tagged every synced reservation non-deterministic and
    /// leaked each released port into a recycle queue the deterministic
    /// allocation path never drains — unbounded standby memory growth under
    /// synced-session churn. Matches the non-HA deterministic release contract
    /// (#4559): a deterministic-only pool never grows the recycle queue.
    pub(super) fn reserve_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        addr_index: usize,
        deterministic: bool,
    ) -> bool {
        if addr_index >= self.shared.occupancy.len() {
            return false;
        }
        let mut live = self.lock_live();
        // A refresh of the same synced flow: if it already holds this exact
        // translated tuple, it is reserved — nothing to do. If the tuple
        // changed (should not happen on a stable sync), drop the stale
        // reservation first so we do not leak the old port's bit. Honour the
        // stale reservation's own mode (#5178): a deterministic reservation is
        // freed WITHOUT recycling, matching its release path.
        if let Some(existing) = live.live_by_flow.get(&flow).copied() {
            if existing.translated == translated {
                return true;
            }
            live.live_by_flow.remove(&flow);
            self.free_translated_port(
                existing.addr_index,
                existing.translated.port,
                !existing.deterministic,
            );
        }
        // Never steal a port owned by a DIFFERENT live allocation: the bit CAS
        // fails when the port is already occupied, so `reserve` returns false
        // and we leave the incumbent (and the caller falls through to the next
        // rule). The synced decision is authoritative on the wire, but on a
        // healthy standby the owning RG is passive so no local flow should hold
        // the port; if one does, not stealing is the safe choice.
        if !self.shared.occupancy[addr_index].reserve(translated.port) {
            return false;
        }
        live.live_by_flow.insert(
            flow,
            LiveAllocation {
                translated,
                persistent_key: None,
                addr_index,
                deterministic,
                address_only: false,
            },
        );
        true
    }

    /// #5269: mint an ADDRESS-ONLY occupancy token for a `port no-translation`
    /// or port-less source-NAT flow. Unlike PAT ([`allocate_translation`]) no
    /// pool PORT is consumed — the packet keeps its own source port on the wire
    /// — but the translated REVERSE identity (protocol, chosen pool address,
    /// PRESERVED source port, remote endpoint) is claimed so a SECOND flow that
    /// would map to the SAME public reverse tuple is DENIED as exhaustion
    /// instead of silently receiving an unowned duplicate whose replies the
    /// reverse (1:N) index cannot disambiguate.
    ///
    /// The FIRST flow owns the identity and succeeds; a genuinely-colliding
    /// second flow (same pool address, same preserved port, same remote — for a
    /// port-less protocol, same pool address + remote) fails closed, mirroring
    /// how a full port-translating pool reports exhaustion and the vSRX
    /// address-only / persistent capacity limit. A NON-colliding address-only
    /// flow (different preserved port, pool address, or remote) mints its own
    /// token and succeeds.
    ///
    /// The token is recorded in `live_by_flow` (flagged `address_only`) AND in
    /// `address_only_owners`, so the EXISTING teardown path
    /// (`release_flow`/`rollback_flow` via `release_source_nat_allocation`,
    /// already called for every reaped or delete-synced session) frees it — no
    /// new delete site. Idempotent: a second packet of the SAME flow returns its
    /// existing translated tuple.
    pub(super) fn reserve_address_only(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let translated = TranslatedTuple {
            ip: translated_ip,
            // Port-bearing protocols preserve their source port; a port-less
            // protocol carries 0 here. This value is NOT written to the wire
            // (the caller leaves `rewrite_src_port` unset); it keys the reverse
            // identity and lets the SAME `release_flow` free the token.
            port: flow.src_port,
        };
        let rkey = AddressOnlyReverseKey {
            protocol: flow.protocol,
            translated_ip,
            translated_port: flow.src_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        };
        let mut live = self.lock_live();
        // Idempotent re-entry: a second packet of the same flow (racing session
        // install) reuses its first decision rather than re-keying.
        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        // Collision: the reverse identity is already owned by a DIFFERENT flow.
        // Two flows sharing one public reverse tuple cannot coexist (their
        // replies are indistinguishable), so deny the second — the address-only
        // capacity limit. `flow` is not in `live_by_flow` here (checked above),
        // so any existing owner is necessarily a different flow.
        if live.address_only_owners.contains_key(&rkey) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        live.address_only_owners.insert(rkey, flow);
        live.live_by_flow.insert(
            flow,
            LiveAllocation {
                translated,
                persistent_key: None,
                // No pool-port bit is claimed for an address-only token, so the
                // occupancy address index is irrelevant to its release.
                addr_index: 0,
                deterministic: false,
                address_only: true,
            },
        );
        self.shared
            .allocations_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(translated)
    }

    /// #6226: reserve a non-deterministic, non-persistent ADDRESS-ONLY token
    /// probing the WHOLE pool from the round-robin start, mirroring the
    /// port-translating [`allocate_translation`] loop.
    ///
    /// The pre-#6226 caller picked ONE round-robin address via [`address_index`]
    /// and called [`reserve_address_only`] on it — a single probe that returned
    /// `AllocatorExhausted` (→ drop) the moment that one address's reverse
    /// identity collided for this remote, even though a SIBLING pool address was
    /// free for the same remote. The shared round-robin counter is oblivious to
    /// per-remote occupancy, so an unrelated flow advancing it trivially lands a
    /// later flow on an already-owned address. This loops from the caller's
    /// round-robin start (`start_abs`, already resolved via [`address_index`] so
    /// the counter is advanced EXACTLY ONCE per flow — same as the old single
    /// probe) across every pool address and mints the token on the FIRST address
    /// whose reverse identity is free; it fails as exhaustion ONLY when EVERY
    /// pool address collides for this remote.
    ///
    /// `address_persistent` keeps the single-probe contract for sticky-by-source
    /// pools (`address_attempts == 1`): the sticky address is intentional, not
    /// round-robin, so it is not rotated away from on a collision. The
    /// deterministic-CGNAT (#5341) and address-only persistent-NAT (#6041)
    /// branches are untouched — they correctly single-probe their chosen address.
    ///
    /// The minted token is byte-identical to [`reserve_address_only`]'s
    /// (`translated = (chosen address, preserved source port)`, `address_only =
    /// true`, `persistent_key = None`, `addr_index = 0`), so the SAME
    /// `release_flow`/`rollback_flow` teardown frees it — no new leak, no new
    /// delete site. Idempotent re-entry (a racing second packet of the same
    /// flow) returns the existing translation regardless of the round-robin
    /// start.
    pub(super) fn reserve_address_only_roundrobin(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        start_abs: usize,
        address_persistent: bool,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(super::source::SourceNatFailureReason::WrongAddressFamily);
        }
        let start_rel = start_abs.saturating_sub(family_offset) % family_len;
        // Sticky-by-source pools single-probe their chosen address; round-robin
        // pools rotate through the whole pool (mirrors `allocate_translation`).
        let address_attempts = if address_persistent { 1 } else { family_len };

        let mut live = self.lock_live();
        // Idempotent re-entry: a second packet of the same flow (racing session
        // install) reuses its first decision rather than re-keying.
        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        // Global flow-table cap (the address-only token lives in `live_by_flow`);
        // one successful probe inserts exactly one entry, so check it once here.
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        // Probe each pool address from the round-robin start; the FIRST whose
        // reverse identity is free for this remote wins.
        for offset in 0..address_attempts {
            let rel = (start_rel + offset) % family_len;
            let translated_ip = family_addresses.ip_at(rel);
            let rkey = AddressOnlyReverseKey {
                protocol: flow.protocol,
                translated_ip,
                translated_port: flow.src_port,
                dst_ip: flow.dst_ip,
                dst_port: flow.dst_port,
            };
            if live.address_only_owners.contains_key(&rkey) {
                // This address's reverse identity is owned by a DIFFERENT flow
                // for this remote — try the next sibling instead of dropping.
                continue;
            }
            let translated = TranslatedTuple {
                ip: translated_ip,
                // Port-bearing protocols preserve their source port; a port-less
                // protocol carries 0. NOT written to the wire (the caller leaves
                // `rewrite_src_port` unset); it keys the reverse identity and lets
                // the SAME `release_flow` free the token.
                port: flow.src_port,
            };
            live.address_only_owners.insert(rkey, flow);
            live.live_by_flow.insert(
                flow,
                LiveAllocation {
                    translated,
                    persistent_key: None,
                    // No pool-port bit is claimed for an address-only token.
                    addr_index: 0,
                    deterministic: false,
                    address_only: true,
                },
            );
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(translated);
        }
        // Every pool address's reverse identity is already owned by a different
        // flow for this remote — genuine address-only exhaustion.
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(super::source::SourceNatFailureReason::AllocatorExhausted)
    }

    /// #6041: reserve an ADDRESS-ONLY PERSISTENT-NAT lease for a `port
    /// no-translation` (or port-less) flow whose pool also configures
    /// `persistent-nat`. Unlike [`reserve_address_only`] (the per-flow #5269
    /// collision token with NO lease) this PINS a public pool ADDRESS across the
    /// configured permit scope: every flow keyed to the same
    /// [`PersistentSourceKey`] reuses the SAME public address for the lease's
    /// lifetime, so persistence no longer depends on the global
    /// `address-persistent` hash (the #5819/#6041 defect the fail-closed reject
    /// stood in for). No pool PORT is consumed — the packet keeps its own source
    /// port on the wire — so the lease records `address_only = true` and every
    /// lease teardown site skips `free_translated_port`.
    ///
    /// Lifecycle mirrors the port-translating persistent lease
    /// ([`allocate_translation_locked`] + [`reuse_existing_lease_locked`]):
    ///   - a live/valid lease REUSES its pinned address, bumps `active_flows`,
    ///     re-arms the activation-rollback bookkeeping on the 0->1 edge, drops
    ///     its idle expiry-index entry, and pushes the inactivity expiry out;
    ///   - an EXPIRED idle lease is torn down (NO port to free) and a fresh
    ///     address is picked via [`address_index`];
    ///   - no lease => a fresh address is picked and a new lease created.
    ///
    /// The #5269 reverse-identity collision guard still runs PER FLOW: THIS
    /// flow's `(protocol, chosen address, preserved source port, remote)` token
    /// is claimed in `address_only_owners` and DENIED as exhaustion if a
    /// DIFFERENT flow already owns it (two flows sharing one public reverse tuple
    /// cannot coexist). On a collision the lease is left untouched. The token AND
    /// the lease refcount are torn down PER FLOW by the SAME teardown path
    /// (`release_flow`/`rollback_flow`) — no new delete site. Idempotent: a
    /// second packet of the same flow returns its existing translated tuple.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn reserve_address_only_persistent(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(super::source::SourceNatFailureReason::WrongAddressFamily);
        }
        let key = flow.persistent_source_key(persistent_nat_permit);
        let timeout_ns = persistent_nat_timeout_ns.max(NS_PER_SEC);

        let mut live = self.lock_live();
        self.gc_expired_locked(&mut live, now_ns, ALLOCATION_GC_BUDGET);

        // Idempotent re-entry: a second packet of the same flow reuses its first
        // decision rather than re-keying / double-counting the lease refcount.
        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        // Resolve the lease's pinned address: reuse a still-valid lease, tear down
        // an expired-idle one, else pick fresh.
        let mut reuse_addr: Option<(IpAddr, usize)> = None;
        let mut expired: Option<(usize, u64)> = None;
        if let Some(lease) = live.persistent_by_source.get(&key).copied() {
            if lease.active_flows > 0 || lease.expires_at_ns > now_ns {
                reuse_addr = Some((lease.translated.ip, lease.addr_index));
            } else {
                expired = Some((lease.addr_index, lease.expires_at_ns));
            }
        }
        if let Some((addr_index, expires_at_ns)) = expired {
            // Idle + past its inactivity window: drop it (an address-only lease
            // holds NO port bit to free) so a fresh address is picked below.
            Self::remove_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
            live.persistent_by_source.remove(&key);
        }

        let reusing = reuse_addr.is_some();
        let (translated_ip, addr_index) = match reuse_addr {
            Some((ip, idx)) => (ip, idx),
            None => {
                let abs =
                    self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
                let rel = abs.saturating_sub(family_offset) % family_len;
                (family_addresses.ip_at(rel), family_offset + rel)
            }
        };

        // #5269 reverse-identity collision guard for THIS flow, checked BEFORE any
        // lease mutation so a denied flow leaves the lease untouched. The
        // preserved source port keys the reverse identity (0 for a port-less
        // protocol); it is never written to the wire (the caller leaves
        // `rewrite_src_port` unset).
        let rkey = AddressOnlyReverseKey {
            protocol: flow.protocol,
            translated_ip,
            translated_port: flow.src_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        };
        if live.address_only_owners.contains_key(&rkey) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        // Lease-table pressure cap for a FRESH lease, mirroring
        // `allocate_translation_locked`: one bounded GC pass, then treat a still-
        // full table as exhaustion.
        if !reusing && live.persistent_by_source.len() >= self.shared.max_tracked_flows {
            self.gc_expired_locked(&mut live, now_ns, PRESSURE_GC_BUDGET);
            if live.persistent_by_source.len() >= self.shared.max_tracked_flows {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
            }
        }

        let translated = TranslatedTuple {
            ip: translated_ip,
            port: flow.src_port,
        };
        let expires_at_ns = now_ns.saturating_add(timeout_ns);

        // Commit this flow's reverse-identity token (freed per flow on teardown).
        live.address_only_owners.insert(rkey, flow);

        if reusing {
            // Bump the existing lease. On the 0->1 active-flow edge re-arm the
            // activation-rollback bookkeeping and drop the stale idle expiry-index
            // entry (an ACTIVE lease is not indexed). Always push the inactivity
            // expiry out.
            let mut remove_expiry = None;
            if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                if lease.active_flows == 0 {
                    remove_expiry = Some((lease.addr_index, lease.expires_at_ns));
                    lease.activation_saw_completion = false;
                    lease.activation_previous_expires_at_ns = lease.expires_at_ns;
                    lease.activation_had_previous_lease = true;
                }
                lease.active_flows = lease.active_flows.saturating_add(1);
                lease.expires_at_ns = expires_at_ns;
            }
            if let Some((idx, old_expires_at_ns)) = remove_expiry {
                Self::remove_lease_expiration_locked(&mut live, idx, old_expires_at_ns, key);
            }
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
        } else {
            live.persistent_by_source.insert(
                key,
                PersistentLease {
                    translated,
                    addr_index,
                    expires_at_ns,
                    timeout_ns,
                    active_flows: 1,
                    completed_flows: 0,
                    activation_saw_completion: false,
                    activation_previous_expires_at_ns: 0,
                    activation_had_previous_lease: false,
                    address_only: true,
                },
            );
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
        }

        live.live_by_flow.insert(
            flow,
            LiveAllocation {
                translated,
                persistent_key: Some(key),
                addr_index,
                deterministic: false,
                address_only: true,
            },
        );
        Ok(translated)
    }

    /// Test-only: snapshot the address-only reverse-identity ownership map so a
    /// white-box test can assert the reverse index resolves each public tuple to
    /// exactly one owning forward flow (#5269).
    #[cfg(test)]
    pub(super) fn debug_address_only_owners(
        &self,
    ) -> Vec<(AddressOnlyReverseKey, SourceNatFlowKey)> {
        let live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        live.address_only_owners
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    pub(super) fn snapshot(&self) -> PortAllocatorSnapshot {
        let live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        let live_flows = live.live_by_flow.len() as u64;
        let persistent_leases = live.persistent_by_source.len() as u64;
        drop(live);
        // used_ports is the total set bits across the lock-free occupancy
        // bitmaps (popcount). Cold path (1/s status poll), so recomputing it
        // rather than maintaining a hot-path atomic is fine.
        let used_ports: u64 = self
            .shared
            .occupancy
            .iter()
            .map(|occ| occ.occupied_count() as u64)
            .sum();
        PortAllocatorSnapshot {
            live_flows,
            used_ports,
            persistent_leases,
            max_tracked_flows: self.shared.max_tracked_flows as u64,
            allocations_total: self.shared.allocations_total.load(Ordering::Relaxed),
            reuses_total: self.shared.reuses_total.load(Ordering::Relaxed),
            exhaustion_total: self.shared.exhaustion_total.load(Ordering::Relaxed),
            live_lock_acquisitions_total: self
                .shared
                .live_lock_acquisitions
                .load(Ordering::Relaxed),
            live_lock_contended_total: self.shared.live_lock_contended.load(Ordering::Relaxed),
        }
    }

    /// #4676: run the opportunistic global expiry GC WITHOUT holding the alloc
    /// mutex across the whole sweep.
    ///
    /// The sweep is chunked: each chunk collects up to `GC_CHUNK` expired
    /// leases from the global expiration index under a SHORT `live` critical
    /// section (the map mutations that MUST be serialized), releases the guard,
    /// then frees those ports on the lock-free occupancy bitmap
    /// (`AddressOccupancy::free_recycle`, a `fetch_and` + per-address recycle
    /// push) with `live` NOT held. Releasing `live` between chunks lets a
    /// concurrent `allocate_translation` acquire the mutex for its tiny
    /// `live_by_flow` insert instead of blocking for the full sweep — the
    /// Phase-1 (#2852) residual this addresses.
    ///
    /// Safety: each reclaim stays idempotent. Under the short CS the lease is
    /// re-checked (`active_flows == 0 && expires_at_ns` matches) before removal,
    /// so a concurrent `release_flow`/`rollback_flow` that refreshed or bumped
    /// the lease is skipped. The port bit is the ownership token and stays SET
    /// from lease removal until we free it, so a concurrent `claim()` cannot
    /// re-hand-out the port in the gap (no double-claim); once freed it returns
    /// to the pool. `budget` bounds total reclaims (amortized GC). This is
    /// disjoint from the caller's insert CS: GC touches only
    /// `persistent_by_source` + the expiration indexes + occupancy, never
    /// `live_by_flow`, so running it in its own lock scope is behaviorally
    /// equivalent to the pre-#4676 nested call.
    fn gc_expired_chunked(&self, now_ns: u64, budget: usize) -> usize {
        if now_ns == 0 || budget == 0 {
            return 0;
        }
        let mut reclaimed = 0;
        let mut freed: Vec<(usize, u16)> = Vec::new();
        while reclaimed < budget {
            let chunk = (budget - reclaimed).min(GC_CHUNK);
            freed.clear();
            let collected = {
                let mut live = self.lock_live();
                #[cfg(test)]
                self.shared
                    .gc_lock_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                self.collect_expired_global_locked(&mut live, now_ns, chunk, &mut freed)
                // `live` guard dropped here, BEFORE the lock-free port frees
                // below and BEFORE the loop re-acquires it for the next chunk.
            };
            for &(addr_index, port) in &freed {
                self.free_translated_port(addr_index, port, true);
            }
            reclaimed += collected;
            if collected < chunk {
                // A short chunk means the expired frontier is exhausted (the
                // earliest remaining lease is not yet expired, or the index is
                // empty). Stop instead of re-locking for a guaranteed-empty
                // chunk. Any lease that expires later is reclaimed by a
                // subsequent amortized GC pass — GC is opportunistic, never the
                // sole reclaim path.
                break;
            }
        }
        reclaimed
    }

    /// Nested (guard-held) global expiry GC for the near-capacity pressure
    /// fallback in `allocate_translation_locked`, where `live` is held across
    /// the whole claim+insert and cannot be released mid-flight. Shares the
    /// `collect_expired_global_locked` primitive with the chunked path; the
    /// only difference is that the reclaimed ports are freed inline while the
    /// caller still holds `live` (unchanged pre-#4676 behavior).
    fn gc_expired_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        now_ns: u64,
        budget: usize,
    ) -> usize {
        let mut freed: Vec<(usize, u16)> = Vec::new();
        let reclaimed = self.collect_expired_global_locked(live, now_ns, budget, &mut freed);
        for (addr_index, port) in freed {
            self.free_translated_port(addr_index, port, true);
        }
        reclaimed
    }

    /// Nested (guard-held) per-address expiry GC for the pressure fallback.
    /// Same guard-held free discipline as `gc_expired_locked`.
    fn gc_expired_for_addr_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        now_ns: u64,
        budget: usize,
    ) -> usize {
        let mut freed: Vec<(usize, u16)> = Vec::new();
        let reclaimed =
            self.collect_expired_for_addr_locked(live, addr_index, now_ns, budget, &mut freed);
        for (addr_index, port) in freed {
            self.free_translated_port(addr_index, port, true);
        }
        reclaimed
    }

    /// Collect up to `budget` expired idle leases from the GLOBAL expiration
    /// index under a HELD `live` guard: pop the earliest-expiring entries,
    /// remove them from `persistent_by_source` and both expiration indexes, and
    /// record each reclaimed lease's `(addr_index, port)` in `freed` for the
    /// caller to release on the lock-free occupancy bitmap. Returns the count
    /// collected. Does NOT touch the occupancy bitmap — port release is
    /// deferred so it need not be serialized behind the alloc mutex (#4676).
    fn collect_expired_global_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        now_ns: u64,
        budget: usize,
        freed: &mut Vec<(usize, u16)>,
    ) -> usize {
        if now_ns == 0 || budget == 0 {
            return 0;
        }
        let mut reclaimed = 0;
        for _ in 0..budget {
            let Some((expires_at_ns, key)) = live.lease_expirations.iter().next().copied() else {
                break;
            };
            if expires_at_ns > now_ns {
                break;
            }
            live.lease_expirations.remove(&(expires_at_ns, key));
            if let Some(lease) = live.persistent_by_source.get(&key).copied() {
                if let Some(by_addr) = live.lease_expirations_by_addr.get_mut(lease.addr_index) {
                    by_addr.remove(&(expires_at_ns, key));
                }
            }
            if self.reclaim_expired_lease_locked(live, key, expires_at_ns, freed) {
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Per-address variant of `collect_expired_global_locked`: pops from
    /// `lease_expirations_by_addr[addr_index]` (and mirrors the removal into the
    /// global index). Records reclaimed ports into `freed`.
    fn collect_expired_for_addr_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        now_ns: u64,
        budget: usize,
        freed: &mut Vec<(usize, u16)>,
    ) -> usize {
        if now_ns == 0 || budget == 0 || addr_index >= live.lease_expirations_by_addr.len() {
            return 0;
        }
        let mut reclaimed = 0;
        for _ in 0..budget {
            let Some((expires_at_ns, key)) = live.lease_expirations_by_addr[addr_index]
                .iter()
                .next()
                .copied()
            else {
                break;
            };
            if expires_at_ns > now_ns {
                break;
            }
            live.lease_expirations_by_addr[addr_index].remove(&(expires_at_ns, key));
            live.lease_expirations.remove(&(expires_at_ns, key));
            if self.reclaim_expired_lease_locked(live, key, expires_at_ns, freed) {
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Remove one expired idle lease from `persistent_by_source` under a HELD
    /// `live` guard and RECORD its `(addr_index, port)` in `freed` — it does NOT
    /// clear the occupancy bit (the caller frees the collected ports, possibly
    /// after dropping `live`, keeping the lock-free bitmap op off the alloc
    /// mutex, #4676). Re-checks the lease is still idle and its expiry still
    /// matches so a concurrent refresh/rollback is not clobbered. Returns true
    /// iff a lease was reclaimed.
    fn reclaim_expired_lease_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        key: PersistentSourceKey,
        expires_at_ns: u64,
        freed: &mut Vec<(usize, u16)>,
    ) -> bool {
        let Some(lease) = live.persistent_by_source.get(&key).copied() else {
            return false;
        };
        if lease.active_flows != 0 || lease.expires_at_ns != expires_at_ns {
            return false;
        }
        // The lease still exists and is idle: its occupancy bit is still set
        // (no other allocation could have claimed it while the lease held it —
        // the bit is the ownership token). Remove the lease and record its port
        // so the caller frees it (recycle). Because the bit stays set until that
        // free, a concurrent claim cannot re-hand-out the port even after the
        // lease is gone from the map.
        live.persistent_by_source.remove(&key);
        // #6041: an address-only persistent lease holds no pool port bit — its
        // reverse-identity tokens were cleared per flow on release — so there is
        // nothing to free on the occupancy bitmap. A PAT lease records its port.
        if !lease.address_only {
            freed.push((lease.addr_index, lease.translated.port));
        }
        true
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PortAllocatorSnapshot {
    pub(crate) live_flows: u64,
    pub(crate) used_ports: u64,
    pub(crate) persistent_leases: u64,
    pub(crate) max_tracked_flows: u64,
    pub(crate) allocations_total: u64,
    pub(crate) reuses_total: u64,
    pub(crate) exhaustion_total: u64,
    /// #4800: `live` map-mutex acquisitions on the production
    /// allocate/reserve/release/rollback/GC paths, and the subset that
    /// blocked. Read as a ratio: `contended / acquisitions` is the NAT
    /// allocator's share of new-flow-install serialization, and the pair
    /// is what lets a connection-rate run say "the residual Phase-1
    /// (#2852) mutex saturated" instead of guessing from a flat
    /// allocations/sec curve. See `PortAllocator::lock_live`.
    pub(crate) live_lock_acquisitions_total: u64,
    pub(crate) live_lock_contended_total: u64,
}

pub(super) fn allocator_capacity(num_addresses: usize, port_low: u16, port_high: u16) -> usize {
    if num_addresses == 0 || port_low == 0 || port_high == 0 || port_low > port_high {
        return 0;
    }
    let ports = (u64::from(port_high) - u64::from(port_low)) + 1;
    ports
        .saturating_mul(num_addresses as u64)
        .min(usize::MAX as u64) as usize
}

/// Map a source IP to a sticky pool-address slot for `address-persistent`
/// SNAT.
///
/// This is a load-distribution hash, not a security primitive: it only needs
/// to be deterministic (same source IP → same slot for a given pool size),
/// well-distributed across the pool, and cheap. It runs on the SNAT
/// *allocation* path (first flow for an address-persistent source), so under
/// connection churn a crypto hash is wasted work. We use a seeded FxHash
/// (`rustc_hash`, already a dependency for the allocator's hash maps) instead
/// of SHA-256 (#2349).
///
/// Stability scope: the mapping is computed live and is never persisted to
/// disk or synced across HA — `persistent_by_source` is an in-memory map — so
/// the only contract is same-source→same-slot within a process lifetime, and
/// identical results across nodes running the same binary. The `-v2` seed is a
/// hash-quality salt, not a cross-restart stability guarantee. Swapping the
/// hash (SHA-256 → FxHash) changes which pool address a given source lands on;
/// that is safe because existing sessions keep their already-allocated address
/// and only new flows pick up the new mapping.
pub(super) fn sticky_pool_index(src_ip: IpAddr, pool_len: usize) -> usize {
    if pool_len <= 1 {
        return 0;
    }

    let mut hasher = rustc_hash::FxHasher::default();
    // Seed with a fixed salt so the distribution does not key purely on the
    // raw IP bytes (FxHash of a small contiguous run can correlate adjacent
    // addresses).
    hasher.write(b"xpf-userspace-snat-address-persistent-v2");
    match src_ip {
        IpAddr::V4(addr) => {
            hasher.write_u8(4);
            hasher.write(&addr.octets());
        }
        IpAddr::V6(addr) => {
            hasher.write_u8(6);
            hasher.write(&addr.octets());
        }
    }
    (hasher.finish() % pool_len as u64) as usize
}
