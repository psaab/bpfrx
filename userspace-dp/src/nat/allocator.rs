// Pool-mode SNAT port allocator + persistent lease state machine.
//
// All translated-tuple ownership, live-flow tracking, persistent-lease
// lifecycle, expiration indexes, rollback bookkeeping, and recycled-port
// state lives in this file. The single `Mutex<PortAllocatorLiveState>`
// serializes every structural mutation; relaxed atomics on the round-robin
// counters and totals are correct only because the mutex provides
// happens-before for the user-visible state.
//
// Cross-submodule visibility (per #1542 plan v3):
// - PortAllocator and PortAllocatorSnapshot are pub(crate) at definition
//   (re-exported by nat/mod.rs).
// - PortAllocator's state-machine methods (try_next_port, address_index,
//   allocate_translation, release_flow, rollback_flow, snapshot) are
//   pub(super) so source.rs / status.rs can drive them.
// - Live state struct + the five fields that white-box tests inspect
//   (persistent_by_source, lease_expirations, lease_expirations_by_addr,
//   addr_index_by_translated, recycled_ports_by_addr) are pub(super).
// - PersistentLease + its fields are pub(super) for the same reason.
// - The remaining types (AllocationOwner, LiveAllocation, PortAllocatorShared
//   and its private fields, GC constants, capacity/sticky helpers) stay
//   fully private to this file.

use super::source::SourceNatFlowKey;
use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

pub(super) const NS_PER_SEC: u64 = 1_000_000_000;
const MAX_SOURCE_NAT_POOL_TRACKED_FLOWS: usize = 262_144;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PersistentSourceKey {
    pub(super) protocol: u8,
    pub(super) src_ip: IpAddr,
    pub(super) src_port: u16,
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

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum AllocationOwner {
    Flow(SourceNatFlowKey),
    Persistent(PersistentSourceKey),
}

#[derive(Clone, Copy, Debug)]
struct LiveAllocation {
    translated: TranslatedTuple,
    persistent_key: Option<PersistentSourceKey>,
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
}

#[derive(Debug, Default)]
pub(super) struct PortAllocatorLiveState {
    live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>,
    owner_by_translated: FxHashMap<TranslatedTuple, AllocationOwner>,
    pub(super) addr_index_by_translated: FxHashMap<TranslatedTuple, usize>,
    pub(super) persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
    pub(super) lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
    pub(super) lease_expirations_by_addr: Vec<BTreeSet<(u64, PersistentSourceKey)>>,
    next_port_offset_by_addr: Vec<u32>,
    pub(super) recycled_ports_by_addr: Vec<Vec<u16>>,
    gc_counter: u32,
}

impl PortAllocatorLiveState {
    fn new(addr_count: usize) -> Self {
        Self {
            lease_expirations_by_addr: vec![BTreeSet::new(); addr_count],
            next_port_offset_by_addr: vec![0; addr_count],
            recycled_ports_by_addr: vec![Vec::new(); addr_count],
            ..Self::default()
        }
    }
}

/// Run bounded lease-expiration GC every N release_flow calls.
const GC_PERIOD: u32 = 10;
pub(super) const ALLOCATION_GC_BUDGET: usize = 8;
const RELEASE_GC_BUDGET: usize = 64;
const PRESSURE_GC_BUDGET: usize = 64;

#[derive(Debug)]
struct PortAllocatorShared {
    /// One atomic counter per pool address, used for round-robin port allocation.
    counters: Vec<AtomicU32>,
    /// Index for IPv4 round-robin address selection.
    addr_counter_v4: AtomicU32,
    /// Index for IPv6 round-robin address selection.
    addr_counter_v6: AtomicU32,
    live: Mutex<PortAllocatorLiveState>,
    allocations_total: AtomicU64,
    reuses_total: AtomicU64,
    exhaustion_total: AtomicU64,
    max_tracked_flows: usize,
}

/// Bounded pool-mode SNAT allocator.
///
/// Address selection uses atomics for stable round-robin/sticky starting
/// points; live translated tuple ownership is tracked under a per-pool mutex
/// so ports are not reused while sessions are alive. Persistent NAT leases are
/// keyed by source tuple and retained until their inactivity timeout after the
/// last live flow releases them.
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
                live: Mutex::new(PortAllocatorLiveState::default()),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                max_tracked_flows: 0,
            }),
            port_low: 1024,
            port_high: 65535,
        }
    }
}

impl PortAllocator {
    pub(crate) fn new(num_addresses: usize, port_low: u16, port_high: u16) -> Self {
        let counters = (0..num_addresses).map(|_| AtomicU32::new(0)).collect();
        let max_tracked_flows = allocator_capacity(num_addresses, port_low, port_high)
            .min(MAX_SOURCE_NAT_POOL_TRACKED_FLOWS);
        Self {
            shared: Arc::new(PortAllocatorShared {
                counters,
                addr_counter_v4: AtomicU32::new(0),
                addr_counter_v6: AtomicU32::new(0),
                live: Mutex::new(PortAllocatorLiveState::new(num_addresses)),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                max_tracked_flows,
            }),
            port_low,
            port_high,
        }
    }

    /// White-box access to the live state for tests. NOT for production
    /// callers — they should use the typed `allocate_translation` /
    /// `release_flow` / `rollback_flow` / `snapshot` entry points.
    #[cfg(test)]
    pub(super) fn debug_live(&self) -> MutexGuard<'_, PortAllocatorLiveState> {
        self.shared.live.lock().unwrap_or_else(|e| e.into_inner())
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn allocate_translation(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
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

        let mut live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        self.gc_expired_locked(&mut live, now_ns, ALLOCATION_GC_BUDGET);

        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        let persistent_key = persistent_nat.then(|| flow.persistent_source_key());
        if let Some(key) = persistent_key {
            if live.persistent_by_source.contains_key(&key) {
                let mut reusable = None;
                let mut expired = None;
                let mut remove_expiry = None;
                if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                    if lease.active_flows > 0 || lease.expires_at_ns > now_ns {
                        let translated = lease.translated;
                        if lease.active_flows == 0 {
                            remove_expiry = Some(lease.expires_at_ns);
                            lease.activation_saw_completion = false;
                            lease.activation_previous_expires_at_ns = lease.expires_at_ns;
                            lease.activation_had_previous_lease = true;
                        }
                        lease.active_flows = lease.active_flows.saturating_add(1);
                        let expires_at_ns =
                            now_ns.saturating_add(persistent_nat_timeout_ns.max(NS_PER_SEC));
                        lease.expires_at_ns = expires_at_ns;
                        reusable = Some(translated);
                    } else {
                        expired = Some((lease.translated, lease.addr_index, lease.expires_at_ns));
                    }
                }
                if let Some(expires_at_ns) = remove_expiry {
                    if let Some(addr_index) = live
                        .persistent_by_source
                        .get(&key)
                        .map(|lease| lease.addr_index)
                    {
                        Self::remove_lease_expiration_locked(
                            &mut live,
                            addr_index,
                            expires_at_ns,
                            key,
                        );
                    }
                }
                if let Some(translated) = reusable {
                    live.live_by_flow.insert(
                        flow,
                        LiveAllocation {
                            translated,
                            persistent_key: Some(key),
                        },
                    );
                    self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
                    return Ok(translated);
                }
                if let Some((translated, addr_index, expires_at_ns)) = expired {
                    Self::remove_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
                    self.release_translated_locked(&mut live, translated);
                    live.persistent_by_source.remove(&key);
                }
            }
        }

        let start_abs =
            self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
        let start_rel = start_abs.saturating_sub(family_offset);
        let address_attempts = if address_persistent { 1 } else { family_len };
        for offset in 0..address_attempts {
            let rel = (start_rel + offset) % family_len;
            let abs = family_offset + rel;
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

            let mut translated =
                self.claim_free_port_locked(&mut live, abs, translated_ip, flow, persistent_key);
            if translated.is_none() {
                // Pressure handling is budgeted, not strict O(1). A
                // non-address-persistent full family can visit each
                // family-compatible address and run at most
                // PRESSURE_GC_BUDGET expiry checks for that selected
                // address before declaring exhaustion.
                self.gc_expired_for_addr_locked(&mut live, abs, now_ns, PRESSURE_GC_BUDGET);
                translated = self.claim_free_port_locked(
                    &mut live,
                    abs,
                    translated_ip,
                    flow,
                    persistent_key,
                );
            }
            let Some(translated) = translated else {
                continue;
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
                    },
                );
            }
            live.live_by_flow.insert(
                flow,
                LiveAllocation {
                    translated,
                    persistent_key,
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

    fn claim_free_port_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        translated_ip: IpAddr,
        flow: SourceNatFlowKey,
        persistent_key: Option<PersistentSourceKey>,
    ) -> Option<TranslatedTuple> {
        if addr_index >= self.shared.counters.len() {
            return None;
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        let next_offset = &mut live.next_port_offset_by_addr[addr_index];
        if *next_offset < range {
            let port = self.port_low + *next_offset as u16;
            *next_offset += 1;
            let translated = TranslatedTuple {
                ip: translated_ip,
                port,
            };
            if self.assign_owner_locked(live, addr_index, translated, flow, persistent_key) {
                return Some(translated);
            }
        }

        while let Some(port) = live.recycled_ports_by_addr[addr_index].pop() {
            let translated = TranslatedTuple {
                ip: translated_ip,
                port,
            };
            if self.assign_owner_locked(live, addr_index, translated, flow, persistent_key) {
                return Some(translated);
            }
        }
        None
    }

    fn assign_owner_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        translated: TranslatedTuple,
        flow: SourceNatFlowKey,
        persistent_key: Option<PersistentSourceKey>,
    ) -> bool {
        if live.owner_by_translated.contains_key(&translated) {
            return false;
        }
        let owner = persistent_key
            .map(AllocationOwner::Persistent)
            .unwrap_or(AllocationOwner::Flow(flow));
        live.owner_by_translated.insert(translated, owner);
        live.addr_index_by_translated.insert(translated, addr_index);
        true
    }

    fn release_translated_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        translated: TranslatedTuple,
    ) -> bool {
        if live.owner_by_translated.remove(&translated).is_none() {
            return false;
        }
        let Some(addr_index) = live.addr_index_by_translated.remove(&translated) else {
            return true;
        };
        if addr_index >= live.recycled_ports_by_addr.len() {
            return true;
        }
        if translated.port < self.port_low || translated.port > self.port_high {
            return true;
        }
        live.recycled_ports_by_addr[addr_index].push(translated.port);
        true
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
        let mut live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        let Some(existing) = live.live_by_flow.get(&flow).copied() else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        live.live_by_flow.remove(&flow);
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
        } else {
            self.release_translated_locked(&mut live, translated);
        }
        live.gc_counter = live.gc_counter.wrapping_add(1);
        if live.gc_counter % GC_PERIOD == 0 {
            self.gc_expired_locked(&mut live, now_ns, RELEASE_GC_BUDGET);
        }
        true
    }

    pub(super) fn rollback_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        now_ns: u64,
    ) -> bool {
        let mut live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        let Some(existing) = live.live_by_flow.get(&flow).copied() else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        live.live_by_flow.remove(&flow);
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
                self.release_translated_locked(&mut live, translated);
            }
            if let Some((addr_index, expires_at_ns)) = insert_expiry {
                Self::insert_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
            }
        } else {
            self.release_translated_locked(&mut live, translated);
        }
        true
    }

    pub(super) fn snapshot(&self) -> PortAllocatorSnapshot {
        let live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        PortAllocatorSnapshot {
            live_flows: live.live_by_flow.len() as u64,
            used_ports: live.owner_by_translated.len() as u64,
            persistent_leases: live.persistent_by_source.len() as u64,
            max_tracked_flows: self.shared.max_tracked_flows as u64,
            allocations_total: self.shared.allocations_total.load(Ordering::Relaxed),
            reuses_total: self.shared.reuses_total.load(Ordering::Relaxed),
            exhaustion_total: self.shared.exhaustion_total.load(Ordering::Relaxed),
        }
    }

    fn gc_expired_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        now_ns: u64,
        budget: usize,
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
            if self.release_expired_lease_locked(live, key, expires_at_ns) {
                reclaimed += 1;
            }
        }
        reclaimed
    }

    fn gc_expired_for_addr_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        now_ns: u64,
        budget: usize,
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
            if self.release_expired_lease_locked(live, key, expires_at_ns) {
                reclaimed += 1;
            }
        }
        reclaimed
    }

    fn release_expired_lease_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        key: PersistentSourceKey,
        expires_at_ns: u64,
    ) -> bool {
        let Some(lease) = live.persistent_by_source.get(&key).copied() else {
            return false;
        };
        if lease.active_flows != 0 || lease.expires_at_ns != expires_at_ns {
            return false;
        }
        let translated = lease.translated;
        live.persistent_by_source.remove(&key);
        match live.owner_by_translated.get(&translated) {
            Some(AllocationOwner::Persistent(owner)) if *owner == key => {
                self.release_translated_locked(live, translated)
            }
            _ => false,
        }
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
}

fn allocator_capacity(num_addresses: usize, port_low: u16, port_high: u16) -> usize {
    if num_addresses == 0 || port_low == 0 || port_high == 0 || port_low > port_high {
        return 0;
    }
    let ports = (u64::from(port_high) - u64::from(port_low)) + 1;
    ports
        .saturating_mul(num_addresses as u64)
        .min(usize::MAX as u64) as usize
}

pub(super) fn sticky_pool_index(src_ip: IpAddr, pool_len: usize) -> usize {
    if pool_len <= 1 {
        return 0;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"xpf-userspace-snat-address-persistent-v1");
    match src_ip {
        IpAddr::V4(addr) => {
            hasher.update([4]);
            hasher.update(addr.octets());
        }
        IpAddr::V6(addr) => {
            hasher.update([6]);
            hasher.update(addr.octets());
        }
    }
    let digest = hasher.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(first) % pool_len as u64) as usize
}
