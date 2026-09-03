//! #8121: export/import for an IDLE persistent-NAT lease.
//!
//! #7360 reconstructs a persistent lease on the standby by deriving it from the
//! synced sessions that hold it. That reaches every lease with live flows —
//! which is every lease session sync can observe, since a lease is learned FROM
//! a session. An idle lease (`active_flows == 0`, `expires_at_ns > now_ns`) has
//! no session to be derived from, yet on the active node it is still live and
//! still reusable: `reuse_existing_lease_locked` admits it on
//! `active_flows > 0 || expires_at_ns > now_ns`. That population is what this
//! module carries.
//!
//! # Four things a lease record must not do
//!
//! 1. **Never carry `active_flows`.** The standby installs a strict SUBSET of
//!    what the active sends (#6600 `RejectedReserve`, #5674 `RejectedCapacity`,
//!    #2170 stale-generation, #7188's discriminator withhold). A carried count
//!    credits the lease for sessions this node does not hold, so it never
//!    reaches zero, never enters `lease_expirations`, and no GC path can
//!    reclaim it. An imported idle lease starts at 0 — legitimately, which is
//!    what makes this a different record shape rather than an extension of the
//!    session one.
//!
//! 2. **Never carry `expires_at_ns` verbatim.** It is derived from
//!    `monotonic_nanos()` (`CLOCK_MONOTONIC`), which is boot-relative and
//!    node-local: a node up ten days reads a value sent by a node up one hour
//!    as long expired. The record carries REMAINING lifetime and the receiver
//!    computes `now_ns + remaining_ns` — the #7095 hazard class.
//!
//! 3. **Never carry `addr_index`.** It is a POSITION in the pool address list,
//!    and the same position is the same address only while both nodes hold
//!    identical pool ordering. The record carries the translated ADDRESS and
//!    the receiver resolves the index locally, refusing a lease whose address
//!    its own pool does not contain. Same hazard class as 2, one level over.
//!
//! 4. **Never install a lease without claiming its port.** An idle lease still
//!    HOLDS its occupancy bit — the bit is freed on the EXPIRY path
//!    (`free_translated_port` in `reuse_existing_lease_locked`'s expired arm),
//!    not when the last flow closes, which is precisely why the tuple is still
//!    reusable. Installing the lease without the bit would let a local flow
//!    mint the same `(address, port)` — the duplicate translated identity this
//!    allocator exists to prevent — and would then have the lease's own expiry
//!    free a bit belonging to that other flow. So the import claims the bit and
//!    REFUSES the lease if it cannot.

// PART 1 OF #8121. This is the helper core — the two operations and every
// invariant that makes them safe. Nothing calls it yet: the cluster transport
// that drives it (a `syncMsgPersistentNatLease` record type in `pkg/cluster`,
// plus the control-socket commands that reach these two methods) is part 2, and
// #8121 stays OPEN until it lands.
//
// The split is deliberate rather than convenient. Every hazard in this feature
// lives HERE — the local refcount, the two node-local quantities that must not
// be carried, and the occupancy bit — and each one is now pinned by a
// mutation-bound test. A transport built on an unsettled core would have to be
// re-reviewed when the core moved.
#![allow(dead_code)]

use super::allocator::{PersistentLease, PersistentSourceKey, PortAllocator, TranslatedTuple};
use std::net::IpAddr;

/// One idle lease, in the shape a peer can act on: identity and lifetime only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdleLeaseRecord {
    pub(crate) protocol: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) src_port: u16,
    /// `None` => `permit-any-remote-host`; `Some` => bound to that remote.
    pub(crate) remote: Option<(IpAddr, u16)>,
    /// The translated ADDRESS, never the pool index (see module note 3).
    pub(crate) translated_ip: IpAddr,
    pub(crate) translated_port: u16,
    /// #6041: an address-only lease owns no occupancy bit.
    pub(crate) address_only: bool,
    /// REMAINING lifetime, never an absolute deadline (see module note 2).
    pub(crate) remaining_ns: u64,
    pub(crate) timeout_ns: u64,
}

/// What an import did. Every refusal is named rather than folded into a bool,
/// because they have different operator remedies: a busy port means the two
/// nodes disagree about who owns an identity, while an unknown address just
/// means config has not converged yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdleLeaseImport {
    Installed,
    /// A lease already exists for this source. The LOCAL one wins — it may hold
    /// live flows this node is forwarding, and those outrank a remote idle
    /// record by definition.
    SkippedExisting,
    /// Already expired by the time it arrived (or sent with no lifetime left).
    SkippedExpired,
    /// This node's pool does not contain the translated address.
    SkippedUnknownAddress,
    /// The occupancy bit is already held here, so installing the lease would
    /// duplicate a translated identity (module note 4).
    SkippedPortBusy,
}

impl PortAllocator {
    /// Every lease that is idle AND still inside its persistence timeout — the
    /// population #7360 cannot reach. A lease with live flows is deliberately
    /// NOT exported: the peer rebuilds it from the sessions themselves, and
    /// sending both would race two mechanisms onto one key.
    pub(crate) fn export_idle_leases(&self, now_ns: u64) -> Vec<IdleLeaseRecord> {
        let live = self.lock_live();
        live.persistent_by_source
            .iter()
            .filter(|(_, lease)| lease.active_flows == 0 && lease.expires_at_ns > now_ns)
            .map(|(key, lease)| IdleLeaseRecord {
                protocol: key.protocol,
                src_ip: key.src_ip,
                src_port: key.src_port,
                remote: key.remote,
                translated_ip: lease.translated.ip,
                translated_port: lease.translated.port,
                address_only: lease.address_only,
                remaining_ns: lease.expires_at_ns.saturating_sub(now_ns),
                timeout_ns: lease.timeout_ns,
            })
            .collect()
    }

    /// Install one exported idle lease. `pool_addresses` is this node's pool
    /// for the owning rule, in its own order — the record's address is resolved
    /// against it rather than trusting a carried index.
    pub(crate) fn import_idle_lease(
        &self,
        rec: &IdleLeaseRecord,
        pool_addresses: &[IpAddr],
        now_ns: u64,
    ) -> IdleLeaseImport {
        if rec.remaining_ns == 0 {
            return IdleLeaseImport::SkippedExpired;
        }
        let Some(addr_index) = pool_addresses.iter().position(|a| *a == rec.translated_ip) else {
            return IdleLeaseImport::SkippedUnknownAddress;
        };
        let key = PersistentSourceKey {
            protocol: rec.protocol,
            src_ip: rec.src_ip,
            src_port: rec.src_port,
            remote: rec.remote,
        };
        let mut live = self.lock_live();
        if live.persistent_by_source.contains_key(&key) {
            return IdleLeaseImport::SkippedExisting;
        }
        // Module note 4: take the occupancy bit BEFORE installing, and refuse
        // rather than install a lease over an identity someone else holds.
        if !rec.address_only {
            match self.try_claim_translated_port(addr_index, rec.translated_port) {
                None => return IdleLeaseImport::SkippedUnknownAddress,
                Some(false) => return IdleLeaseImport::SkippedPortBusy,
                Some(true) => {}
            }
        }
        let expires_at_ns = now_ns.saturating_add(rec.remaining_ns);
        live.persistent_by_source.insert(
            key,
            PersistentLease {
                translated: TranslatedTuple {
                    ip: rec.translated_ip,
                    port: rec.translated_port,
                },
                addr_index,
                expires_at_ns,
                timeout_ns: rec.timeout_ns,
                // Module note 1: rebuilt locally, and legitimately zero here.
                active_flows: 0,
                completed_flows: 0,
                activation_saw_completion: false,
                activation_previous_expires_at_ns: 0,
                activation_had_previous_lease: false,
                address_only: rec.address_only,
            },
        );
        // Without this the lease is invisible to GC and outlives what the
        // active held — the acceptance criterion's third bullet.
        PortAllocator::insert_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
        IdleLeaseImport::Installed
    }
}
