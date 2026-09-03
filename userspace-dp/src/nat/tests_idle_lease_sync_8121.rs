//! #8121: idle persistent-NAT lease export/import.

use super::allocator::{NatHolder, PoolAddressFamily, PortAllocator, TranslatedTuple};
use super::idle_lease_sync_8121::{IdleLeaseImport, IdleLeaseRecord};
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use std::net::{IpAddr, Ipv4Addr};

const TCP: u8 = 6;
const TIMEOUT_NS: u64 = 300 * 1_000_000_000;

/// A MULTI-address pool. The acceptance criteria call for this specifically:
/// with a single-address pool an address assertion passes by construction, so
/// the real assertion has to be on the PORT.
fn pool() -> [Ipv4Addr; 3] {
    [
        "203.0.113.1".parse().unwrap(),
        "203.0.113.2".parse().unwrap(),
        "203.0.113.3".parse().unwrap(),
    ]
}

fn flow(src: &str, sport: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: TCP,
        src_ip: src.parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: sport,
        dst_port: 443,
    }
}

fn mint_persistent(
    alloc: &PortAllocator,
    addrs: &[Ipv4Addr],
    f: SourceNatFlowKey,
    now_ns: u64,
) -> TranslatedTuple {
    alloc
        .allocate_translation(
            f,
            PoolAddressFamily::V4(addrs),
            0,
            false,
            true,
            PersistentNatPermit::TargetHostPort,
            TIMEOUT_NS,
            now_ns,
            NatHolder::Untracked,
        )
        .expect("a fresh persistent allocation must succeed")
}

fn ipv4_pool(addrs: &[Ipv4Addr]) -> Vec<IpAddr> {
    addrs.iter().copied().map(IpAddr::V4).collect()
}

/// The acceptance criterion: a client whose flows all closed shortly BEFORE the
/// failover, but within the persistence timeout, keeps its translated PORT on
/// the new primary.
///
/// A decoy client is interleaved so the port under test is not the only one the
/// allocator could hand back, and the pool is multi-address so the address
/// assertion is not true by construction.
#[test]
fn an_idle_lease_survives_export_and_import_and_keeps_the_port_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let decoy = flow("10.0.61.51", 40001);

    // ORDER IS LOAD-BEARING: the decoy mints FIRST, so the client's identity is
    // NOT the one a fresh allocator hands out first. Minted the other way round
    // this cell is mutation-INSENSITIVE — neutering the import would leave the
    // client's post-failover mint landing on that same first free
    // (address, port) by coincidence, and the assertion would pass while
    // proving nothing. Do not "tidy" this ordering.
    let theirs = mint_persistent(&active, &addrs, decoy, 1_000);
    let mine = mint_persistent(&active, &addrs, client, 1_000);
    assert_ne!(
        (mine.ip, mine.port),
        (theirs.ip, theirs.port),
        "setup: the decoy must hold a different identity or this proves nothing"
    );
    let virgin = PortAllocator::new(1, 1024, 65535);
    let first_free = mint_persistent(&virgin, &addrs, client, 1_000);
    assert_ne!(
        (mine.ip, mine.port),
        (first_free.ip, first_free.port),
        "setup: the identity under test must not be what a FRESH allocator \
         hands out first, or a neutered import passes this cell for free"
    );

    // Both clients go quiet: every flow closes, so both leases go IDLE while
    // still inside the 300s persistence timeout.
    assert!(active.release_flow(client, mine, 2_000, NatHolder::Untracked));
    assert!(active.release_flow(decoy, theirs, 2_000, NatHolder::Untracked));

    let exported = active.export_idle_leases(3_000);
    assert_eq!(exported.len(), 2, "both idle leases must be exported");

    // The standby's clock is unrelated to the active's — a far larger
    // CLOCK_MONOTONIC value, as a node with a longer uptime would have.
    let standby_now = 9_000_000_000_000_u64;
    let standby = PortAllocator::new(1, 1024, 65535);
    let local_pool = ipv4_pool(&addrs);
    for rec in &exported {
        assert_eq!(
            standby.import_idle_lease(rec, &local_pool, standby_now),
            IdleLeaseImport::Installed
        );
    }

    // The client comes back on the new primary. It must get its OWN previous
    // identity, not a fresh one and not the decoy's.
    let resumed = mint_persistent(&standby, &addrs, client, standby_now + 1_000);
    assert_eq!(
        (resumed.ip, resumed.port),
        (mine.ip, mine.port),
        "#8121: a client idle within the persistence timeout must keep its \
         translated port across the failover"
    );
}

/// A lease with LIVE flows is not exported: that population is #7360's, rebuilt
/// from the sessions themselves, and sending both would race two mechanisms
/// onto one key.
#[test]
fn a_lease_with_live_flows_is_not_exported_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let busy = flow("10.0.61.50", 40000);
    let idle = flow("10.0.61.51", 40001);
    let _held = mint_persistent(&active, &addrs, busy, 1_000);
    let released = mint_persistent(&active, &addrs, idle, 1_000);
    assert!(active.release_flow(idle, released, 2_000, NatHolder::Untracked));

    let exported = active.export_idle_leases(3_000);
    assert_eq!(
        exported.len(),
        1,
        "only the IDLE lease is this channel's population"
    );
    assert_eq!(exported[0].src_port, 40001);
}

/// Acceptance bullet 3: a rebuilt idle lease has `active_flows == 0` and is
/// GC-eligible at its carried expiry — reconstructing it must not create a
/// lease that outlives what the active held.
///
/// The expiry is computed from the RECEIVER's clock. The record carries
/// remaining lifetime precisely because `expires_at_ns` is `CLOCK_MONOTONIC`
/// and boot-relative: had the absolute value been carried, this lease would
/// read as expired ~9000 seconds ago on this node.
#[test]
fn an_imported_idle_lease_expires_on_the_receivers_clock_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let t = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, t, 2_000, NatHolder::Untracked));
    let rec = active.export_idle_leases(3_000).remove(0);
    // Sanity: the remaining lifetime is what was carried, not a deadline.
    assert!(
        rec.remaining_ns > 0 && rec.remaining_ns <= TIMEOUT_NS,
        "remaining must be a lifetime, got {}",
        rec.remaining_ns
    );

    let standby_now = 9_000_000_000_000_u64;
    let standby = PortAllocator::new(1, 1024, 65535);
    let local_pool = ipv4_pool(&addrs);
    assert_eq!(
        standby.import_idle_lease(&rec, &local_pool, standby_now),
        IdleLeaseImport::Installed
    );

    // CONTROL: still inside its lifetime, the lease is honoured.
    let kept = mint_persistent(&standby, &addrs, client, standby_now + 1_000);
    assert_eq!((kept.ip, kept.port), (t.ip, t.port), "control: still live");

    // GC eligibility is asserted on the LEASE, not on the identity a later mint
    // happens to get. A fresh mint on a fresh allocator lands on the same first
    // free (address, port) the original did, so an `assert_ne` there passes or
    // fails for reasons that have nothing to do with the lease — it is the
    // value the code falls back to.
    let fresh_node = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        fresh_node.import_idle_lease(&rec, &local_pool, standby_now),
        IdleLeaseImport::Installed
    );
    // Exported => it is idle (active_flows == 0, or it would not qualify) AND
    // still inside its lifetime on THIS node's clock.
    assert_eq!(
        fresh_node.export_idle_leases(standby_now + 1).len(),
        1,
        "an imported idle lease is idle and live on the receiver's clock"
    );
    // Past the carried remaining lifetime, measured from the RECEIVER's now,
    // it is no longer live. Had the absolute `expires_at_ns` been carried it
    // would have read as expired ~9000 s ago and failed the assertion above.
    assert_eq!(
        fresh_node
            .export_idle_leases(standby_now + rec.remaining_ns + 1)
            .len(),
        0,
        "#8121: an imported lease must not outlive the lifetime the active held"
    );
}

/// Module note 4. An idle lease still HOLDS its occupancy bit, so an import
/// that installed the lease without claiming the port would let a local flow
/// mint the same translated identity — and would then have the lease's own
/// expiry free a bit belonging to that other flow.
#[test]
fn an_import_refuses_rather_than_install_over_a_held_port_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let t = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, t, 2_000, NatHolder::Untracked));
    let rec = active.export_idle_leases(3_000).remove(0);

    // A standby where a LOCAL flow already holds that exact identity.
    let standby = PortAllocator::new(1, 1024, 65535);
    let local_pool = ipv4_pool(&addrs);
    let squatter = flow("10.0.61.99", 41000);
    assert!(
        standby.reserve_flow(
            squatter,
            TranslatedTuple {
                ip: rec.translated_ip,
                port: rec.translated_port,
            },
            local_pool
                .iter()
                .position(|a| *a == rec.translated_ip)
                .expect("pool contains it"),
            false,
            10_000,
            NatHolder::Untracked,
        ),
        "setup: the squatter must actually take the identity"
    );

    assert_eq!(
        standby.import_idle_lease(&rec, &local_pool, 11_000),
        IdleLeaseImport::SkippedPortBusy,
        "#8121: installing over a held identity would duplicate a translation \
         and later free someone else's occupancy bit"
    );
}

/// Module note 3. `addr_index` is a POSITION, so the record carries the
/// ADDRESS; a node whose pool does not contain it refuses rather than binding
/// the lease to whatever happens to sit at that index.
#[test]
fn an_import_refuses_an_address_this_pool_does_not_have_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let t = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, t, 2_000, NatHolder::Untracked));
    let rec = active.export_idle_leases(3_000).remove(0);

    let standby = PortAllocator::new(1, 1024, 65535);
    let different: Vec<IpAddr> = vec![
        "198.51.100.7".parse().unwrap(),
        "198.51.100.8".parse().unwrap(),
    ];
    assert_eq!(
        standby.import_idle_lease(&rec, &different, 11_000),
        IdleLeaseImport::SkippedUnknownAddress
    );

    // CONTROL: the same record against the RIGHT pool installs, so the refusal
    // above is attributable to the address and not to the record being junk.
    assert_eq!(
        standby.import_idle_lease(&rec, &ipv4_pool(&addrs), 11_000),
        IdleLeaseImport::Installed
    );
}

/// A local lease wins: it may hold live flows this node is forwarding, and
/// those outrank a remote idle record by definition.
#[test]
fn a_local_lease_is_not_overwritten_by_an_imported_one_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let t = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, t, 2_000, NatHolder::Untracked));
    let rec = active.export_idle_leases(3_000).remove(0);

    let standby = PortAllocator::new(1, 1024, 65535);
    let local_pool = ipv4_pool(&addrs);
    let _local = mint_persistent(&standby, &addrs, client, 10_000);
    assert_eq!(
        standby.import_idle_lease(&rec, &local_pool, 11_000),
        IdleLeaseImport::SkippedExisting
    );
}
