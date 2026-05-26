// #1349: orchestrator for the worker-side CoS status snapshot.
// Extracted from the 268-LOC `build_worker_cos_statuses_from_maps`
// body that previously lived in cos.rs. The inner per-interface and
// per-queue accumulation is delegated to `super::interface_row` and
// `super::queue_row`; the binding-scoped #709/#748/#751 merge stays
// inline because folding it into a helper added a 5-arg call boundary
// for a 3-line gated conditional (round-1 PLAN-KILL counter-example).

use super::*;

pub(in crate::afxdp::worker) fn build_worker_cos_statuses(
    bindings: &[BindingWorker],
    forwarding: &ForwardingState,
) -> Vec<crate::protocol::CoSInterfaceStatus> {
    // #709: pair each cos_map with its owner-binding's live state so
    // the per-queue telemetry fields (drain_latency_hist, owner_pps,
    // ...) can be populated from the binding that actually did the
    // work.
    build_worker_cos_statuses_from_maps(
        bindings
            .iter()
            .map(|binding| (&binding.cos.cos_interfaces, Some(binding.live.as_ref()))),
        forwarding,
    )
}

pub(in crate::afxdp::worker) fn build_worker_cos_statuses_from_maps<'a, I>(
    cos_maps: I,
    forwarding: &ForwardingState,
) -> Vec<crate::protocol::CoSInterfaceStatus>
where
    I: IntoIterator<
        Item = (
            &'a FastMap<i32, CoSInterfaceRuntime>,
            Option<&'a BindingLiveState>,
        ),
    >,
{
    let mut interfaces = BTreeMap::<i32, crate::protocol::CoSInterfaceStatus>::new();
    let mut queue_maps = BTreeMap::<i32, BTreeMap<u8, crate::protocol::CoSQueueStatus>>::new();
    for (cos_map, binding_live) in cos_maps {
        // #709: snapshot the binding's owner-profile counters ONCE
        // per binding per scrape. The source is binding-scoped, so we
        // only surface it on an unambiguous queue row: exactly one
        // owner-local exact queue ACROSS THE WHOLE BINDING (all
        // interfaces it drains). Shared-exact, non-exact, and
        // multi-owner-local exact shapes — whether within one
        // interface or spread across interfaces — stay zero here
        // until the telemetry becomes queue-scoped.
        let binding_profile = binding_live.map(owner_profile_snapshot);
        let owner_profile_row = unique_owner_profile_row(cos_map, forwarding);
        for (&ifindex, root) in cos_map {
            let entry = interfaces.entry(ifindex).or_default();
            interface_row::accumulate_interface_root(entry, ifindex, root, forwarding);
            let interface_config = forwarding.cos.interfaces.get(&ifindex);
            let queue_map = queue_maps.entry(ifindex).or_default();
            for queue in &root.queues {
                let status = queue_map.entry(queue.queue_id()).or_default();
                status.queue_id = queue.queue_id();
                let queue_config = interface_config.and_then(|cfg| {
                    cfg.queues
                        .iter()
                        .find(|config| config.queue_id == queue.queue_id())
                });
                queue_row::accumulate_queue_row(status, queue, queue_config);
                // #709 / #748 / #751: the *binding-scoped* fields
                // (redirect_acquire_hist, owner_pps, peer_pps,
                // drain_noop_invocations) are surfaced only on the
                // single unambiguous owner-local exact queue row on
                // the whole binding. Producers don't know the target
                // queue at redirect time so these fields cannot be
                // queue-scoped and still stay truthful; any
                // shared-exact, non-exact, or multi-owner-local
                // shape keeps them at zero rather than surfacing a
                // binding-wide mixed profile under an arbitrary row.
                //
                // Kept inline (not extracted to a helper) because the
                // 3-line conditional reads cleaner than a 5-arg call
                // (Gemini round-1 PLAN-KILL counter-example).
                if owner_profile_row == Some((ifindex, queue.queue_id())) {
                    if let Some(profile) = binding_profile.as_ref() {
                        merge_binding_scoped_owner_profile(status, profile);
                    }
                }
            }
        }
    }
    finalize_interface_vec(interfaces, queue_maps)
}

/// Flatten the per-ifindex BTreeMaps into the on-wire
/// `Vec<CoSInterfaceStatus>`. Owns the `nonempty_queues` /
/// `runnable_queues` summaries and the final sort by
/// `(interface_name, ifindex)`.
fn finalize_interface_vec(
    interfaces: BTreeMap<i32, crate::protocol::CoSInterfaceStatus>,
    mut queue_maps: BTreeMap<i32, BTreeMap<u8, crate::protocol::CoSQueueStatus>>,
) -> Vec<crate::protocol::CoSInterfaceStatus> {
    let mut out = Vec::with_capacity(interfaces.len());
    for (ifindex, mut iface) in interfaces {
        if let Some(queue_map) = queue_maps.remove(&ifindex) {
            iface.queues = queue_map.into_values().collect();
            iface.nonempty_queues = iface
                .queues
                .iter()
                .filter(|queue| queue.queued_packets > 0 || queue.queued_bytes > 0)
                .count();
            iface.runnable_queues = iface
                .queues
                .iter()
                .filter(|queue| queue.runnable_instances > 0)
                .count();
        }
        out.push(iface);
    }
    out.sort_by(|a, b| {
        a.interface_name
            .cmp(&b.interface_name)
            .then(a.ifindex.cmp(&b.ifindex))
    });
    out
}
