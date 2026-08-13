// Binding/queue planning helpers (#6234 split out of the former
// monolithic `server/helpers.rs`).
//
// One cohesive correctness unit (server/README.md): the binding-settle
// predicates, the canonical same-plan hash key
// (`snapshot_binding_plan_key` and its JSON-canonicalizing helpers), and
// the RX-queue / binding replanner (`replan_queues`,
// `replan_bindings_from_candidates`, `effective_rx_queues`,
// `plan_key_rx_queues`, `include_userspace_binding_interface`). Hash
// ownership and layout ownership stay together so the same-plan skip and
// the produced layout can never disagree — the invariant fixed by
// #2915/#2916/#3007/#3175. Cold path only (control responses), no
// per-packet work. Bodies byte-for-byte identical to the pre-split
// source.

use super::{refresh_status, should_run_afxdp};
use crate::protocol::{BindingStatus, ConfigSnapshot, InterfaceSnapshot, QueueStatus};
use crate::server::ServerState;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) fn same_plan_apply_needs_binding_reconcile(
    state: &ServerState,
    previous_defer_workers: bool,
    next_defer_workers: bool,
) -> bool {
    if next_defer_workers || !should_run_afxdp(&state.status) {
        return false;
    }

    let runnable_bindings = state
        .status
        .bindings
        .iter()
        .filter(|binding| binding.registered && binding.ifindex > 0)
        .count();
    if runnable_bindings == 0 {
        return false;
    }
    if previous_defer_workers {
        return true;
    }

    let (_, planned_bindings) = state.afxdp.planned_counts();
    let live_bindings = state.afxdp.live_count();
    (planned_bindings < runnable_bindings || live_bindings < runnable_bindings)
        && state.status.bindings.iter().any(|binding| {
            binding.registered
                && binding.ifindex > 0
                && binding.last_error.is_empty()
                && (!binding.bound || !binding.xsk_registered)
        })
}

pub(crate) fn wait_for_binding_settle(state: &mut ServerState, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        refresh_status(state);
        if bindings_settled(&state.status.bindings) || Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn bindings_settled(bindings: &[BindingStatus]) -> bool {
    bindings.iter().all(|binding| {
        if !binding.registered {
            return !binding.bound && !binding.xsk_registered;
        }
        binding.ready || !binding.last_error.is_empty()
    })
}

#[cfg(test)]
pub(crate) fn same_binding_plan(current: &ConfigSnapshot, next: &ConfigSnapshot) -> bool {
    snapshot_binding_plan_key(current) == snapshot_binding_plan_key(next)
}

pub(crate) fn snapshot_binding_plan_key(snapshot: &ConfigSnapshot) -> String {
    let mut hasher = Sha256::new();
    update_snapshot_binding_plan_key(&mut hasher, snapshot);
    let digest = hasher.finalize();
    format!("sha256:{digest:x}")
}

fn update_snapshot_binding_plan_key(hasher: &mut Sha256, snapshot: &ConfigSnapshot) {
    let workers = snapshot
        .userspace
        .get("workers")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    let ring_entries = snapshot
        .userspace
        .get("ring_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    hash_update(hasher, &format!("workers={workers};ring={ring_entries};"));
    if let Some(shared_umem) = snapshot.userspace.get("shared_umem") {
        hash_update(hasher, "shared_umem=");
        update_canonical_json_hash(hasher, shared_umem);
        hash_update(hasher, ";");
    }
    for iface in snapshot
        .interfaces
        .iter()
        .filter(|iface| include_userspace_binding_interface(iface))
    {
        // #3091: `vlan_id` and `parent_linux_name` are now binding-plan inputs
        // — `replan_queues` dedups a VLAN-child netdev onto its physical parent
        // using exactly these two fields. The #2915 invariant requires every
        // field the planner reads to construct the layout to bump the plan key,
        // so re-parenting or VLAN-tag changes trigger a replan (never a stale
        // plan). Additive: an old Go binary that omits them serializes the
        // serde defaults (0 / ""), matching the non-VLAN physical case.
        //
        // #3007: hash the EFFECTIVE rx_queues, not the raw snapshot field. When
        // the snapshot carries the degenerate `rx_queues == 0` fallback,
        // `replan_queues` resolves the real queue count from sysfs
        // (`rx_queue_count`), and THAT count drives `queue_count`/the layout. The
        // plan key must hash the same resolved value, or an out-of-band channel
        // change (`ethtool -L <if> combined N`, no config commit) would leave the
        // snapshot at 0, keep the key identical, and take the same-plan-skip while
        // the planner would actually produce a different layout. For a nonzero
        // snapshot the resolved value equals the raw field (sysfs is not read), so
        // the key is byte-identical to the pre-#3007 hash for the normal case.
        //
        // #3175: for an ORPHAN VLAN child (parent NOT a candidate) the layout
        // re-keys onto the parent's hardware queue count, so `plan_key_rx_queues`
        // hashes `rx_queue_count(parent)` here too — otherwise the child's lone
        // software-queue count is hashed and an out-of-band `ethtool -L <parent>`
        // would not bump the key. The normal VLAN case (parent IS a candidate)
        // and physical ifaces keep the #3007 `effective_rx_queues` behavior.
        let resolved_linux_name = if iface.linux_name.is_empty() {
            linux_ifname(&iface.name)
        } else {
            iface.linux_name.clone()
        };
        let rx_queues = plan_key_rx_queues(snapshot, iface, &resolved_linux_name);
        hash_update(
            hasher,
            &format!(
                "iface={}/{}/{}/{}/{}/{}/{}/{};",
                iface.name,
                iface.linux_name,
                iface.ifindex,
                iface.parent_ifindex,
                rx_queues,
                iface.tunnel,
                iface.vlan_id,
                iface.parent_linux_name
            ),
        );
    }
    for fab in &snapshot.fabrics {
        // #3007: same effective-rx_queues resolution as the fabric candidate
        // loop in `replan_queues` — sysfs fallback when the snapshot is 0, then
        // `.max(1)` (fabric needs at least one TX queue). Keeps the key in lock
        // step with the value that drives the fabric candidate's queue count.
        let rx_queues = effective_rx_queues(fab.rx_queues, &fab.parent_linux_name).max(1);
        hash_update(
            hasher,
            &format!(
                "fabric={}/{}/{}/{};",
                fab.name, fab.parent_linux_name, fab.parent_ifindex, rx_queues
            ),
        );
    }
}

fn hash_update(hasher: &mut Sha256, input: &str) {
    hasher.update(input.as_bytes());
}

struct Sha256Writer<'a>(&'a mut Sha256);

impl Write for Sha256Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn update_json_encoded<T: serde::Serialize + ?Sized>(hasher: &mut Sha256, value: &T) {
    serde_json::to_writer(Sha256Writer(hasher), value)
        .expect("canonical JSON hashing uses an infallible writer");
}

fn update_canonical_json_hash(hasher: &mut Sha256, value: &serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            hash_update(hasher, "[");
            let mut items = values.iter().map(canonical_json_key).collect::<Vec<_>>();
            items.sort();
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    hash_update(hasher, ",");
                }
                hash_update(hasher, item);
            }
            hash_update(hasher, "]");
        }
        serde_json::Value::Object(values) => {
            hash_update(hasher, "{");
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (idx, (key, value)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    hash_update(hasher, ",");
                }
                update_json_encoded(hasher, key);
                hash_update(hasher, ":");
                update_canonical_json_hash(hasher, value);
            }
            hash_update(hasher, "}");
        }
        _ => update_json_encoded(hasher, value),
    }
}

fn canonical_json_key(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

fn write_canonical_json(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Array(values) => {
            out.push('[');
            let mut items = values.iter().map(canonical_json_key).collect::<Vec<_>>();
            items.sort();
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(item);
            }
            out.push(']');
        }
        serde_json::Value::Object(values) => {
            out.push('{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (idx, (key, value)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_canonical_json(value, out);
            }
            out.push('}');
        }
        _ => out.push_str(&serde_json::to_string(value).unwrap_or_default()),
    }
}

pub(crate) fn include_userspace_binding_interface(iface: &InterfaceSnapshot) -> bool {
    if iface.zone.is_empty() {
        return false;
    }
    if iface.tunnel {
        return false;
    }
    if !iface.local_fabric_member.is_empty() {
        return false;
    }
    let base = iface.name.split('.').next().unwrap_or(iface.name.as_str());
    if base.starts_with("fxp") || base.starts_with("em") || base.starts_with("fab") || base == "lo0"
    {
        return false;
    }
    !matches!(iface.zone.as_str(), "mgmt" | "control")
}

/// #3091: a VLAN-child interface (e.g. `reth0.80` → Linux netdev
/// `ge-0-0-2.80`) is a SOFTWARE VLAN device with a single RX queue. Its
/// VLAN-tagged frames are delivered on the PHYSICAL PARENT's hardware RX
/// queues (`ge-0-0-2`, 6 queues on the mlx5 VF), so the child must NOT enter
/// the queue planner's candidate list — its lone software queue would collapse
/// the per-interface `queue_count` min (see `replan_bindings_from_candidates`)
/// to 1, forcing a single worker and the ~6 Gbps forwarding regression. The
/// pre-existing #1921 `seen_linux` dedup misses VLAN children because the child
/// netdev name (`ge-0-0-2.80`) differs from the parent (`ge-0-0-2`).
///
/// Returns the parent Linux netdev name when `iface` is a distinct VLAN-child
/// netdev, else None (physical interfaces and non-VLAN units, whose
/// `parent_linux_name` is empty or equal to their own netdev, are handled by
/// the existing `seen_linux` dedup).
///
/// #2917 SSOT: this predicate is the single source of truth for the AF_XDP
/// VLAN-unit binding target across BOTH planes. The Go control plane mirrors it
/// exactly in `userspaceBindTargetNetdev`
/// (`pkg/dataplane/userspace/interfaces.go`), which feeds
/// `UserspaceBoundLinuxInterfaces` (the D3/RSS allowlist). A VLAN unit binds its
/// physical PARENT netdev on both planes; a non-VLAN unit binds its own netdev.
/// Keep the two implementations in lock-step — the Rust SSOT test
/// (`replan_queues_binds_vlan_unit_on_parent_netdev`, `main_tests.rs`) and the
/// Go cross-plane parity test (`snapshot_allowlist_test.go`) fail on divergence.
fn vlan_child_parent_netdev<'a>(iface: &'a InterfaceSnapshot, linux_name: &str) -> Option<&'a str> {
    if iface.vlan_id != 0
        && !iface.parent_linux_name.is_empty()
        && iface.parent_linux_name != linux_name
    {
        Some(iface.parent_linux_name.as_str())
    } else {
        None
    }
}

/// #3091: true when the physical netdev `parent` is itself a binding candidate
/// in this snapshot (a zoned, non-tunnel, non-VLAN data interface). When the
/// parent is a candidate, a VLAN child re-keyed onto it is fully covered by the
/// parent's per-queue XSKs (VLAN-tagged frames are captured on the parent's
/// hardware queues), so the child can be dropped from the candidate list.
fn snapshot_has_parent_candidate(snapshot: &ConfigSnapshot, parent: &str) -> bool {
    snapshot.interfaces.iter().any(|p| {
        if !include_userspace_binding_interface(p) {
            return false;
        }
        let p_linux = if p.linux_name.is_empty() {
            linux_ifname(&p.name)
        } else {
            p.linux_name.clone()
        };
        // The parent must be the physical netdev itself, not another VLAN
        // child that happens to share the name string.
        p_linux == parent && vlan_child_parent_netdev(p, &p_linux).is_none()
    })
}

/// #3175: resolve the rx_queue count the PLAN KEY must hash for `iface`,
/// mirroring exactly what `replan_queues`' candidate loop feeds the LAYOUT.
///
/// For an ORPHAN VLAN child — a VLAN unit whose physical parent is NOT itself a
/// binding candidate — `replan_queues` re-keys the child onto its parent netdev
/// and uses the parent's HARDWARE queue count (`rx_queue_count(parent)`), never
/// the child's lone software queue. The plan-key loop previously hashed the
/// child's own `effective_rx_queues`, so an out-of-band `ethtool -L <parent>
/// combined N` (no config commit) left the key unchanged → same-plan-skip →
/// stale layout. Hash the parent's count for the orphan case so the key follows
/// the layout, single-sourcing the resolution exactly as #3007 unified the
/// `rx_queues == 0` sysfs fallback.
///
/// The NORMAL VLAN case (parent IS a candidate) and physical/non-VLAN ifaces are
/// unchanged: the layout drops the normal VLAN child (it is covered by the
/// parent's own physical key entry), and physical ifaces use
/// `effective_rx_queues` exactly as before.
pub(crate) fn plan_key_rx_queues(
    snapshot: &ConfigSnapshot,
    iface: &InterfaceSnapshot,
    resolved_linux_name: &str,
) -> usize {
    if let Some(parent) = vlan_child_parent_netdev(iface, resolved_linux_name) {
        if !snapshot_has_parent_candidate(snapshot, parent) {
            // Orphan VLAN child: the layout re-keys onto the parent's hardware
            // queue count. Hash the same value so the key follows the layout.
            return rx_queue_count(parent);
        }
    }
    effective_rx_queues(iface.rx_queues, resolved_linux_name)
}

pub(crate) fn replan_queues(
    snapshot: Option<&ConfigSnapshot>,
    workers: usize,
    existing: &[BindingStatus],
) -> Vec<BindingStatus> {
    let mut candidates: Vec<(String, usize)> = Vec::new();
    let mut ifindex_by_name: BTreeMap<String, i32> = BTreeMap::new();
    let mut seen_linux: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(snapshot) = snapshot {
        for iface in &snapshot.interfaces {
            // #2915: the binding candidate decision is a single shared
            // invariant. The plan-key hash
            // (`update_snapshot_binding_plan_key`) and the Go authoritative
            // allowlist (`UserspaceBoundLinuxInterfaces`) both filter through
            // the binding exclusion contract — zoned, non-tunnel,
            // non-local-fabric, excluding fxp*/em*/fab*/lo0 and mgmt/control
            // zones. `replan_queues` MUST act on exactly that set; a
            // prefix-only `ge-*`/`xe-*`/`et-*` test (the pre-#2915 predicate)
            // let a `ge-*` netdev placed in a mgmt/control zone (or a
            // tunnel/local-fabric context) be planned as an AF_XDP binding
            // that neither the hash nor the control plane accounts for.
            if !include_userspace_binding_interface(iface) {
                continue;
            }
            let linux_name = if iface.linux_name.is_empty() {
                linux_ifname(&iface.name)
            } else {
                iface.linux_name.clone()
            };
            // #3091: dedup VLAN-child netdevs onto their physical parent. A
            // bondless-RETH WAN VLAN unit (`reth0.50`/`reth0.80` → Linux
            // `ge-0-0-2.50`/`ge-0-0-2.80`) is a software VLAN device with a
            // single RX queue, but its tagged frames arrive on the PARENT
            // netdev's hardware queues. Pushing it as a separate 1-queue
            // candidate collapses the `queue_count` min to 1 (single worker,
            // the #3091 ~6 Gbps regression). The #1921 `seen_linux` guard below
            // cannot catch this — the child netdev name differs from the parent.
            if let Some(parent) = vlan_child_parent_netdev(iface, &linux_name) {
                if snapshot_has_parent_candidate(snapshot, parent) {
                    // The parent's per-queue XSKs already capture this VLAN's
                    // tagged frames; skip the 1-queue child entirely.
                    continue;
                }
                // Orphan VLAN child (parent absent from the candidate set):
                // re-key onto the parent netdev using the parent's HARDWARE
                // queue count, never the child's single software queue, so it
                // still cannot collapse the min.
                let parent = parent.to_string();
                if seen_linux.contains(&parent) {
                    continue;
                }
                let rx_queues = rx_queue_count(&parent);
                if rx_queues > 0 {
                    let parent_ifindex = if iface.parent_ifindex > 0 {
                        iface.parent_ifindex
                    } else {
                        iface.ifindex
                    };
                    ifindex_by_name.insert(parent.clone(), parent_ifindex);
                    seen_linux.insert(parent.clone());
                    candidates.push((parent, rx_queues));
                }
                continue;
            }
            // #1921: dedup by Linux netdev. The snapshot lists BOTH the
            // physical interface (`ge-0/0/0`) and its unit (`ge-0/0/0.0`);
            // both start with `ge-` and (for a non-VLAN unit) resolve to the
            // SAME Linux netdev (`ge-0-0-0`). Without this guard each netdev
            // is pushed twice, so replan_bindings_from_candidates plans two
            // bindings per (ifindex, queue_id) — a guaranteed double-bind:
            // the second XSK bind on an already-bound queue returns EBUSY,
            // the queue never goes READY, and the shim drops all transit on
            // it (the virtio multi-queue forwarding outage). One XSK per
            // (netdev, queue) is the AF_XDP contract; collapse duplicates
            // here exactly as the fabric loop below already does.
            if seen_linux.contains(&linux_name) {
                continue;
            }
            // #3007: resolve the effective rx_queues ONCE (snapshot value if
            // nonzero, else sysfs). `snapshot_binding_plan_key` hashes the SAME
            // helper, so the dedup key can never disagree with the layout.
            let rx_queues = effective_rx_queues(iface.rx_queues, &linux_name);
            if rx_queues > 0 {
                ifindex_by_name.insert(linux_name.clone(), iface.ifindex);
                seen_linux.insert(linux_name.clone());
                candidates.push((linux_name, rx_queues));
            }
        }
        // Include fabric parent interfaces so the userspace DP can transmit
        // fabric-redirect packets via XSK TX (and receive fabric ingress).
        for fabric in &snapshot.fabrics {
            if fabric.parent_ifindex <= 0 || fabric.parent_linux_name.is_empty() {
                continue;
            }
            if seen_linux.contains(&fabric.parent_linux_name) {
                continue;
            }
            // #3007: same effective-rx_queues resolution + plan-key hash.
            let rx_queues = effective_rx_queues(fabric.rx_queues, &fabric.parent_linux_name);
            let rx_queues = rx_queues.max(1); // fabric needs at least 1 queue for TX
            ifindex_by_name.insert(fabric.parent_linux_name.clone(), fabric.parent_ifindex);
            seen_linux.insert(fabric.parent_linux_name.clone());
            candidates.push((fabric.parent_linux_name.clone(), rx_queues));
        }
    }
    replan_bindings_from_candidates(workers, existing, candidates, ifindex_by_name)
}

pub(crate) fn replan_bindings_from_candidates(
    workers: usize,
    existing: &[BindingStatus],
    candidates: Vec<(String, usize)>,
    ifindex_by_name: BTreeMap<String, i32>,
) -> Vec<BindingStatus> {
    let mut existing_by_slot = BTreeMap::new();
    for binding in existing {
        existing_by_slot.insert(binding.slot, binding.clone());
    }
    if candidates.is_empty() {
        return Vec::new();
    }
    let queue_count = candidates.iter().map(|(_, rx)| *rx).min().unwrap_or(0);
    // #6211 F2: worker ids are MINTED below as `queue_id % workers`, and the NAT
    // allocator records one holder BIT per worker id
    // (`nat::MAX_NAT_HOLDER_WORKERS`). An id too wide for that mask would set no
    // bit on reserve and clear no bit on release — self-consistent, but it
    // collapses that worker back to the pre-fix single-holder behaviour, freeing
    // a pool port while another worker still forwards through it. That is the
    // original over-release reintroduced through its own fix, so refuse the
    // whole plan instead: no bindings means no forwarding, which is fail-closed.
    //
    // Checked HERE and not against the raw `--workers` value. `queue_count` is
    // the per-interface RX-queue minimum, computed independently of `workers`,
    // and `queue_id < queue_count`, so the ids actually minted span
    // `[0, min(queue_count, workers))`. Capping `--workers` alone would REFUSE a
    // safe box — `--workers 200` on a 16-queue NIC mints ids 0..15 — while this
    // check refuses exactly the configurations that would mis-key a holder.
    let max_worker_id = queue_count.min(workers.max(1)).saturating_sub(1);
    if queue_count > 0 && max_worker_id >= crate::nat::MAX_NAT_HOLDER_WORKERS as usize {
        eprintln!(
            "replan_bindings: REFUSING plan — {} queues x {} workers mints worker_id {} \
             but the NAT holder mask tracks only {} workers (MAX_NAT_HOLDER_WORKERS); \
             an untracked worker would free a pool port another worker still holds",
            queue_count,
            workers,
            max_worker_id,
            crate::nat::MAX_NAT_HOLDER_WORKERS
        );
        return Vec::new();
    }
    let interfaces = candidates
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(queue_count * interfaces.len());
    let mut slot = 0u32;
    for queue_id in 0..queue_count {
        for iface in &interfaces {
            let mut binding = existing_by_slot.remove(&slot).unwrap_or_default();
            let had_existing = binding.last_change.is_some()
                || binding.registered
                || binding.armed
                || binding.ready
                || binding.bound
                || binding.xsk_registered;
            binding.slot = slot;
            binding.queue_id = queue_id as u32;
            binding.worker_id = (queue_id % workers.max(1)) as u32;
            binding.interface = iface.clone();
            binding.ifindex = *ifindex_by_name.get(iface).unwrap_or(&0);
            if binding.ifindex <= 0 {
                binding.registered = false;
                binding.armed = false;
                binding.ready = false;
            } else if !had_existing {
                binding.registered = true;
            }
            if binding.last_change.is_none() {
                binding.last_change = Some(Utc::now());
            }
            out.push(binding);
            slot += 1;
        }
    }
    out
}

pub(crate) fn summarize_queues(bindings: &[BindingStatus]) -> Vec<QueueStatus> {
    let mut by_queue: BTreeMap<u32, Vec<&BindingStatus>> = BTreeMap::new();
    for binding in bindings {
        by_queue.entry(binding.queue_id).or_default().push(binding);
    }
    let mut out = Vec::with_capacity(by_queue.len());
    for (queue_id, group) in by_queue {
        let worker_id = group.first().map(|b| b.worker_id).unwrap_or(0);
        let interfaces = group
            .iter()
            .map(|b| b.interface.clone())
            .collect::<Vec<_>>();
        let registered = !group.is_empty() && group.iter().all(|b| b.registered);
        let armed = !group.is_empty() && group.iter().all(|b| b.registered && b.armed);
        let ready = !group.is_empty() && group.iter().all(|b| b.registered && b.ready);
        let last_change = group.iter().filter_map(|b| b.last_change).max();
        out.push(QueueStatus {
            queue_id,
            worker_id,
            interfaces,
            registered,
            armed,
            ready,
            last_change,
        });
    }
    out
}

pub(crate) fn linux_ifname(name: &str) -> String {
    name.replace('/', "-")
}

/// Resolve the effective RX queue count that drives the binding layout: the
/// snapshot's `rx_queues` when nonzero, otherwise the live sysfs channel count
/// (`rx_queue_count`). This is the SINGLE resolution path consumed by BOTH the
/// queue planner (`replan_queues`) and the same-plan dedup key
/// (`update_snapshot_binding_plan_key`), so the key can never hash a value that
/// disagrees with the layout (#3007). For a nonzero snapshot sysfs is never
/// read, so the key stays byte-identical to the pre-#3007 hash for the normal
/// case; the 0 fallback (no committed count) folds the resolved sysfs count into
/// the key so an out-of-band `ethtool -L` channel change forces a replan.
pub(crate) fn effective_rx_queues(snapshot_rx_queues: usize, linux_name: &str) -> usize {
    if snapshot_rx_queues > 0 {
        snapshot_rx_queues
    } else {
        rx_queue_count(linux_name)
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only override for `rx_queue_count`, keyed by netdev name. Lets a
    /// test drive the sysfs-resolved queue count without a real
    /// `/sys/class/net/<if>/queues` tree. Thread-local, so parallel test
    /// threads never cross-contaminate.
    static RX_QUEUE_COUNT_OVERRIDE: std::cell::RefCell<std::collections::HashMap<String, usize>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

#[cfg(test)]
pub(crate) fn set_rx_queue_count_override(name: &str, count: usize) {
    RX_QUEUE_COUNT_OVERRIDE.with(|m| {
        m.borrow_mut().insert(name.to_string(), count);
    });
}

#[cfg(test)]
pub(crate) fn clear_rx_queue_count_override() {
    RX_QUEUE_COUNT_OVERRIDE.with(|m| m.borrow_mut().clear());
}

pub(crate) fn rx_queue_count(name: &str) -> usize {
    #[cfg(test)]
    {
        if let Some(count) = RX_QUEUE_COUNT_OVERRIDE.with(|m| m.borrow().get(name).copied()) {
            return count;
        }
    }
    let path = format!("/sys/class/net/{name}/queues");
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    let count = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|entry| entry.starts_with("rx-"))
        .count();
    count.max(1)
}
