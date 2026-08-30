// #7212: the SAME-TICK, ALL-BINDING flow-cache eviction of a session revoked by
// a changed static interface INPUT filter.
//
// Without it the revoked 5-tuple keeps forwarding off a cached
// `RewriteDescriptor` with no session row — the #6457 failure mode, reached
// here by a different route. The two directions of one flow are routinely
// cached on DIFFERENT bindings, so evicting only the binding the revoking
// packet arrived on leaves the other direction live.

use super::*;
use crate::afxdp::flow_cache::{FlowCacheEntry, FlowCacheLookup, FlowCacheStamp};
use crate::ip_proto::PROTO_TCP;
use crate::nat::NatDecision;
use crate::session::{SessionDecision, SessionKey, SessionMetadata, SessionOrigin};
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU32;

const IF_A: i32 = 24;
const IF_B: i32 = 25;
const IF_C: i32 = 26;

fn epochs() -> [AtomicU32; MAX_RG_EPOCHS] {
    std::array::from_fn(|_| AtomicU32::new(0))
}

fn key(src_port: u16, dst_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

fn seed(binding: &mut BindingWorker, key: &SessionKey) {
    let ingress_ifindex = binding.ifindex;
    binding.flow.flow_cache.insert(FlowCacheEntry {
        key: key.clone(),
        ingress_ifindex,
        logical_ingress_ifindex: ingress_ifindex,
        descriptor: RewriteDescriptor {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            fabric_redirect: false,
            tx_vlan_id: 0,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            target_binding_index: None,
            input_filter_log: None,
            input_filter_counters: crate::filter::CachedFilterCounters::default(),
            tx_selection: CachedTxSelectionDescriptor::default(),
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        },
        decision: decision(),
        metadata: metadata(),
        stamp: FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 1,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        },
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
        neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
    });
}

fn hits(binding: &mut BindingWorker, key: &SessionKey, epochs: &[AtomicU32; MAX_RG_EPOCHS]) -> bool {
    let ingress_ifindex = binding.ifindex;
    binding
        .flow
        .flow_cache
        .lookup(
            key,
            FlowCacheLookup {
                ingress_ifindex,
                logical_ingress_ifindex: ingress_ifindex,
                config_generation: 1,
                fib_generation: 1,
            },
            0,
            epochs,
        )
        .is_some()
}

/// A revoked session's descriptor is evicted from EVERY binding of the worker,
/// not just the one the revoking packet arrived on.
///
/// The three-binding shape is the point: the forward and reverse halves of one
/// flow are cached on different bindings, so a loop narrowed to `current` would
/// leave the other direction forwarding a session that no longer exists. Both
/// the `left` slice (binding A) and the `right` slice (binding C) are populated,
/// so narrowing the walk in EITHER direction reds.
#[test]
fn revoked_session_flow_cache_slots_are_evicted_on_every_binding_7212() {
    let epochs = epochs();
    let mut a = BindingWorker::new_for_mirror_test(0, 0, IF_A, 0);
    let mut b = BindingWorker::new_for_mirror_test(1, 0, IF_B, 0);
    let mut c = BindingWorker::new_for_mirror_test(2, 0, IF_C, 0);
    let fwd = key(12345, 5201);
    let rev = key(5201, 12345);
    seed(&mut a, &fwd);
    seed(&mut b, &fwd);
    seed(&mut c, &rev);
    assert!(hits(&mut a, &fwd, &epochs));
    assert!(hits(&mut b, &fwd, &epochs));
    assert!(
        hits(&mut c, &rev, &epochs),
        "precondition: each binding serves its own cached descriptor"
    );

    let mut keys = vec![fwd.clone(), rev.clone()];
    invalidate_flow_cache_slots_for_revoked_sessions(
        std::slice::from_mut(&mut a),
        &mut b,
        std::slice::from_mut(&mut c),
        &mut keys,
    );

    assert!(
        !hits(&mut a, &fwd, &epochs),
        "the LEFT binding's slot must be evicted"
    );
    assert!(
        !hits(&mut b, &fwd, &epochs),
        "the CURRENT binding's slot must be evicted"
    );
    assert!(
        !hits(&mut c, &rev, &epochs),
        "the RIGHT binding's reverse-direction slot must be evicted"
    );
    assert!(
        keys.is_empty(),
        "the scratch vector must be drained so the caller can reuse its capacity"
    );
}

/// A DIFFERENT live flow on the same bindings is untouched. The eviction is
/// key-and-ifindex precise, and an over-broad `invalidate_all` would pass every
/// assertion above while flushing the whole cache on each revocation.
#[test]
fn revocation_eviction_leaves_other_flows_cached_7212() {
    let epochs = epochs();
    let mut a = BindingWorker::new_for_mirror_test(0, 0, IF_A, 0);
    let mut b = BindingWorker::new_for_mirror_test(1, 0, IF_B, 0);
    let revoked = key(12345, 5201);
    let bystander = key(12346, 5201);
    seed(&mut a, &revoked);
    seed(&mut a, &bystander);
    seed(&mut b, &bystander);

    let mut keys = vec![revoked.clone()];
    invalidate_flow_cache_slots_for_revoked_sessions(&mut [], &mut a, std::slice::from_mut(&mut b), &mut keys);

    assert!(!hits(&mut a, &revoked, &epochs));
    assert!(
        hits(&mut a, &bystander, &epochs),
        "a co-resident flow the filter still permits must keep its descriptor"
    );
    assert!(hits(&mut b, &bystander, &epochs));
}

/// An empty revocation list evicts nothing. The common case is every tick, and
/// the claim here is about the OUTCOME, not about the early return: an empty
/// `drain` over an empty vector is already a no-op, so no assertion can
/// distinguish the `is_empty()` guard from its absence. The guard is a
/// readability choice, and this cell pins only what is observable.
#[test]
fn no_revocations_evicts_nothing_7212() {
    let epochs = epochs();
    let mut a = BindingWorker::new_for_mirror_test(0, 0, IF_A, 0);
    let live = key(12345, 5201);
    seed(&mut a, &live);
    let mut keys: Vec<SessionKey> = Vec::new();
    invalidate_flow_cache_slots_for_revoked_sessions(&mut [], &mut a, &mut [], &mut keys);
    assert!(hits(&mut a, &live, &epochs));
}

/// The WIRING: `drain_revoked_flow_cache_keys` reads the keys the poll pass left
/// on the binding's scratch, evicts across every binding, and hands the emptied
/// vector back with its capacity.
///
/// The three cells above drive the eviction helper with a caller-supplied
/// vector, so they stay green if the take/restore around it is deleted — and
/// deleting it is exactly the mutation that matters: the revoked flow keeps
/// forwarding off a cached descriptor, and the scratch grows without bound
/// because nothing else clears it.
#[test]
fn revoked_keys_are_drained_from_the_bindings_own_scratch_7212() {
    let epochs = epochs();
    let mut a = BindingWorker::new_for_mirror_test(0, 0, IF_A, 0);
    let mut b = BindingWorker::new_for_mirror_test(1, 0, IF_B, 0);
    let revoked = key(12345, 5201);
    seed(&mut a, &revoked);
    seed(&mut b, &revoked);
    // The state a poll pass leaves behind.
    b.scratch.scratch_filter_revoked_keys.push(revoked.clone());
    let capacity_before = b.scratch.scratch_filter_revoked_keys.capacity();

    drain_revoked_flow_cache_keys(std::slice::from_mut(&mut a), &mut b, &mut []);

    assert!(
        !hits(&mut a, &revoked, &epochs),
        "the sibling binding's slot must be evicted from the SCRATCH contents"
    );
    assert!(!hits(&mut b, &revoked, &epochs));
    assert!(
        b.scratch.scratch_filter_revoked_keys.is_empty(),
        "the scratch must be emptied, or it grows without bound"
    );
    assert_eq!(
        b.scratch.scratch_filter_revoked_keys.capacity(),
        capacity_before,
        "and handed back with its capacity, not replaced by a fresh Vec"
    );
}
