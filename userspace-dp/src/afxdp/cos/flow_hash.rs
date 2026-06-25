// Per-queue flow-hash machinery for SFQ admission + promotion.
//
// `COS_FLOW_FAIR_BUCKETS` / `COS_FLOW_FAIR_BUCKET_MASK` live in
// `afxdp::types` because they size other types there (`FlowRrRing`,
// `CoSQueueRuntime` arrays); flow_hash imports them rather than
// owning them.

use crate::afxdp::types::{CoSPendingTxItem, CoSQueueRuntime, COS_FLOW_FAIR_BUCKET_MASK};
use crate::session::SessionKey;
use std::net::IpAddr;

/// XorShift-style mix step used by both the per-queue salt fallback
/// and the 5-tuple bucket hash. File-private — no callers outside
/// flow_hash.
#[inline(always)]
fn mix_cos_flow_bucket(seed: &mut u64, value: u64) {
    *seed ^= value
        .wrapping_add(0x9e3779b97f4a7c15)
        .wrapping_add(*seed << 6)
        .wrapping_add(*seed >> 2);
}

/// Draw a fresh per-queue hash salt from the kernel.
///
/// #2364: the OS-entropy draw (`getrandom(2)` with a CLOCK_MONOTONIC +
/// pid + stack-address fallback and a never-zero invariant) was hoisted
/// into `crate::hot_hash_seed::os_random_seed_u64` so the CoS SFQ seed
/// and the node-local hot-path hash seed share ONE audited entropy path
/// instead of two byte-identical copies. The never-zero contract that
/// `cos_flow_hash_seed_from_os_never_returns_zero` (and the downstream
/// `assert_ne!(flow_hash_seed, 0)`) depend on is enforced there.
pub(in crate::afxdp) fn cos_flow_hash_seed_from_os() -> u64 {
    crate::hot_hash_seed::os_random_seed_u64()
}

// #711: returns `u16` (was `u8`). With `COS_FLOW_FAIR_BUCKETS = 4096`
// the mask in `cos_flow_bucket_index` is 12 bits wide; a `u8` return
// would silently re-collapse the hash into 256 buckets and give no
// benefit from the bucket grow. Returning `u16` preserves the full
// hash width through the mask step.
#[inline(always)]
fn exact_cos_flow_bucket(queue_seed: u64, flow_key: Option<&SessionKey>) -> u16 {
    let Some(flow_key) = flow_key else {
        return 0;
    };
    let mut seed = queue_seed ^ (flow_key.protocol as u64) ^ ((flow_key.addr_family as u64) << 8);
    match flow_key.src_ip {
        IpAddr::V4(ip) => mix_cos_flow_bucket(&mut seed, u32::from(ip) as u64),
        IpAddr::V6(ip) => {
            for chunk in ip.octets().chunks_exact(8) {
                mix_cos_flow_bucket(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
            }
        }
    }
    match flow_key.dst_ip {
        IpAddr::V4(ip) => mix_cos_flow_bucket(&mut seed, u32::from(ip) as u64),
        IpAddr::V6(ip) => {
            for chunk in ip.octets().chunks_exact(8) {
                mix_cos_flow_bucket(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
            }
        }
    }
    mix_cos_flow_bucket(&mut seed, flow_key.src_port as u64);
    mix_cos_flow_bucket(&mut seed, flow_key.dst_port as u64);
    seed as u16
}

#[inline]
pub(in crate::afxdp) fn cos_item_flow_key(item: &CoSPendingTxItem) -> Option<&SessionKey> {
    match item {
        CoSPendingTxItem::Local(req) => req.flow_key.as_ref(),
        CoSPendingTxItem::Prepared(req) => req.flow_key.as_ref(),
    }
}

#[inline(always)]
pub(in crate::afxdp) fn cos_flow_bucket_index(
    queue_seed: u64,
    flow_key: Option<&SessionKey>,
) -> usize {
    usize::from(exact_cos_flow_bucket(queue_seed, flow_key)) & COS_FLOW_FAIR_BUCKET_MASK
}

/// Prospective distinct-flow count: current `active_flow_buckets` plus
/// one when the target bucket is currently empty (i.e. we are admitting
/// the first packet of a newly arriving flow). Both admission gates —
/// the per-flow clamp and the aggregate cap — must use this value so
/// they stay in lockstep. The original #704 bug was exactly this
/// denominator drifting: one gate bumped for the new flow, the other
/// did not, and the new flow's first packet got rejected at the
/// boundary. Keeping the formula in one place removes that class of
/// reintroduction risk.
#[inline]
pub(in crate::afxdp) fn cos_queue_prospective_active_flows(
    queue: &CoSQueueRuntime,
    flow_bucket: usize,
) -> u64 {
    // Non-flow-fair queues have effectively 1 flow (the whole queue is
    // a single FIFO from the per-flow share denominator's perspective).
    // This is the correct semantic, not an invariant escape — the gate
    // distinguishes it from the next branch below.
    if !queue.flow_fair() {
        return 1;
    }
    let ff = queue
        .flow_fair_state
        .as_ref()
        .expect("cos_queue_prospective_active_flows: flow_fair queue without flow_fair_state");
    u64::from(ff.active_flow_buckets)
        .saturating_add(u64::from(ff.flow_bucket_bytes[flow_bucket] == 0))
        .max(1)
}

#[cfg(test)]
#[path = "flow_hash_tests.rs"]
mod tests;
