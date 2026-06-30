// #1776 — one-shot `worker_loop` setup, extracted from
// loop_body/mod.rs (pure code motion per the converged v3.1 plan on
// research/1776-loop-body-decomp).
//
// Everything here runs EXACTLY ONCE per worker thread, before the
// main `loop {}` in `worker_loop`: thread pinning, cold-path TSC
// calibration, the initial ArcSwap `load_full`s, binding
// construction from plans, CoS fast-interface wiring, the
// interrupt-mode pollfd set, the BPF-map-FD cache, and the initial
// `cos_status` publish. The returned `WorkerLoopSetup` is
// destructured back into the same-named locals in `worker_loop`, so
// the loop body itself is textually unchanged.
//
// Cold by construction (`#[inline(never)]`): hoisting this out of
// `worker_loop` shrinks the hot function without adding any call
// boundary to the per-tick path.
//
// `use super::*;` chains through loop_body/mod.rs to worker/mod.rs —
// the same glob pattern lifecycle.rs and loop_body/mod.rs use.

use super::*;

use crate::afxdp::worker_runtime::current_tid;

/// Initial mutable state for the worker loop, produced once by
/// [`worker_loop_setup`]. Field order mirrors construction order in
/// the original inline setup block.
pub(super) struct WorkerLoopSetup {
    pub(super) ha_startup_grace_until_secs: u64,
    pub(super) validation: ValidationState,
    pub(super) forwarding: Arc<ForwardingState>,
    pub(super) cos_owner_worker_by_queue: Arc<BTreeMap<(i32, u8), u32>>,
    pub(super) cos_owner_live_by_queue: Arc<BTreeMap<(i32, u8), Arc<BindingLiveState>>>,
    pub(super) cos_shared_root_leases: Arc<BTreeMap<i32, Arc<SharedCoSRootLease>>>,
    pub(super) cos_shared_exact_backlogs: Arc<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>,
    pub(super) cos_shared_queue_leases: Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>,
    pub(super) cos_shared_queue_vtime_floors:
        Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>,
    pub(super) mirror_targets: Arc<MirrorTargetMap>,
    pub(super) sessions: SessionTable,
    pub(super) screen_state: ScreenState,
    pub(super) bindings: Vec<BindingWorker>,
    pub(super) binding_lookup: WorkerBindingLookup,
    pub(super) interrupt_poll_fds: Vec<libc::pollfd>,
    pub(super) session_map_fd: c_int,
    pub(super) conntrack_v4_fd: c_int,
    pub(super) conntrack_v6_fd: c_int,
    pub(super) last_cos_status_ns: u64,
}

/// One-shot worker setup (moved verbatim from the head of
/// `worker_loop`; only binding `mut`-ness and variable access
/// changed — statements, order, and side-effect sequence are
/// preserved).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn worker_loop_setup(
    worker_id: u32,
    binding_plans: Vec<BindingPlan>,
    shared_validation: &ArcSwap<ValidationState>,
    shared_forwarding: &ArcSwap<ForwardingState>,
    shared_cos_owner_worker_by_queue: &ArcSwap<BTreeMap<(i32, u8), u32>>,
    shared_cos_owner_live_by_queue: &ArcSwap<BTreeMap<(i32, u8), Arc<BindingLiveState>>>,
    shared_cos_root_leases: &ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>,
    shared_cos_exact_backlogs: &ArcSwap<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>,
    shared_cos_queue_leases: &ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>,
    shared_cos_queue_vtime_floors: &ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>,
    shared_mirror_targets: &ArcSwap<MirrorTargetMap>,
    poll_mode: crate::PollMode,
    cos_status: &ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>,
    runtime_atomics: &crate::afxdp::worker_runtime::WorkerRuntimeAtomics,
    cold_path_atomics: &crate::afxdp::cold_path_hist::WorkerColdPathAtomics,
) -> WorkerLoopSetup {
    pin_current_thread(worker_id);
    // #1620: per-worker cold-path TSC calibration. Runs ONCE at
    // worker_loop entry, AFTER pin_current_thread has pinned the
    // worker to its core (so the Instant↔TSC ratio reflects this
    // core's clock). The probe + calibrate together take ~10 ms
    // (one-shot 10 ms sleep window + ~80 µs of back-to-back rdtscp
    // pairs); workers calibrate concurrently across cores so the
    // wall-clock startup overhead stays at ~10 ms total.
    //
    // Per plan v4 §4.6: probe_clock_source runs once; calibration is
    // skipped (returning 0) when the clock source is not TSC, avoiding
    // redundant /proc/cpuinfo + /sys probes inside the calibrators.
    let cp_clock_source =
        crate::afxdp::cold_path_hist::probe_clock_source();
    let (cp_ns_per_tsc_q32, cp_wrapper_baseline) =
        if cp_clock_source == crate::afxdp::cold_path_hist::ClockSource::Tsc {
            let q32 =
                crate::afxdp::cold_path_hist::calibrate_ns_per_tsc_q32();
            let baseline =
                crate::afxdp::cold_path_hist::calibrate_wrapper_baseline_ns(
                    q32,
                );
            (q32, baseline)
        } else {
            (0, 0)
        };
    // Single-line startup log per worker (~6 lines total per daemon
    // startup). Goes to journald via stderr per project logging rules.
    eprintln!(
        "xpf-cold-path: worker={} clock_source={} ns_per_tsc_q32={} wrapper_ns_baseline={}",
        worker_id,
        cp_clock_source.as_str(),
        cp_ns_per_tsc_q32,
        cp_wrapper_baseline,
    );
    let ha_startup_grace_until_secs =
        (monotonic_nanos() / 1_000_000_000).saturating_add(TUNNEL_HA_STARTUP_GRACE_SECS);
    let validation = **shared_validation.load();
    let forwarding = shared_forwarding.load_full();
    let cos_owner_worker_by_queue = shared_cos_owner_worker_by_queue.load_full();
    let cos_owner_live_by_queue = shared_cos_owner_live_by_queue.load_full();
    let cos_shared_root_leases = shared_cos_root_leases.load_full();
    let cos_shared_exact_backlogs = shared_cos_exact_backlogs.load_full();
    let cos_shared_queue_leases = shared_cos_queue_leases.load_full();
    let cos_shared_queue_vtime_floors = shared_cos_queue_vtime_floors.load_full();
    let mirror_targets = shared_mirror_targets.load_full();
    let mut sessions = SessionTable::new();
    let mut screen_state = ScreenState::new();
    screen_state.update_profiles(forwarding.screen_profiles.clone());
    // #3082: thread the references-missing-profile set so the screen None
    // branch can WARN (still Pass) for the lenient/HA-sync fail-open.
    screen_state.update_missing_profiles(forwarding.screen_missing_profiles.clone());
    screen_state.update_syn_cookie_master_key(forwarding.syn_cookie_master_key);
    sessions.set_timeouts(forwarding.session_timeouts);
    // #3527: push the per-screened-zone half-open (`syn-flood timeout`)
    // overrides next to `set_timeouts`. Empty in the common case (no zone
    // configures a syn-flood timeout).
    sessions.set_opening_overrides(forwarding.session_opening_overrides.clone());
    // #2134: drive the per-IP session-limit OFF-gate from the applied
    // screen profiles. Off when no zone configures `limit-session`, so
    // install/remove counter maintenance is skipped for the ~99% case.
    sessions.set_session_limit_active(screen_state.any_session_limit_configured());
    let mut bindings = Vec::with_capacity(binding_plans.len());
    let (private_plans, shared_groups) = partition_binding_plans(binding_plans);
    for plan in private_plans {
        let live = plan.live.clone();
        match create_private_binding_from_plan(plan) {
            Ok(binding) => bindings.push(binding),
            Err(err) => {
                eprintln!("xpf-userspace-dp: private binding creation failed: {err}");
                live.set_error(err.to_string());
            }
        }
    }
    for (group_key, plans) in shared_groups {
        match create_shared_binding_group(&group_key, plans) {
            Ok(mut group_bindings) => bindings.append(&mut group_bindings),
            Err(err) => fallback_shared_group_to_private(err, &mut bindings),
        }
    }
    bindings.sort_by_key(|binding| (binding.queue_id, binding.ifindex, binding.slot));
    // #1620: install per-worker cold-path calibration into each
    // binding's worker-local counters. The calibration values are
    // shared across all bindings owned by this worker — they reflect
    // the worker thread's pinned core, not the binding identity.
    for binding in bindings.iter_mut() {
        binding.cold_path.ns_per_tsc_q32 = cp_ns_per_tsc_q32;
        binding.cold_path.wrapper_ns_baseline = cp_wrapper_baseline;
        binding.cold_path.clock_source = cp_clock_source;
    }
    // #1621: install the same calibration into the sibling atomics
    // so the first /metrics scrape sees q32 + clock_source even
    // before the first publish-tick fires. install_calibration writes
    // outside the cold_window_gen seqlock (calibration is set-once;
    // readers always observe a consistent value).
    cold_path_atomics.install_calibration(
        cp_ns_per_tsc_q32,
        cp_wrapper_baseline,
        cp_clock_source,
    );
    let binding_lookup = WorkerBindingLookup::from_bindings(&bindings);
    let cos_owner_live_by_tx_ifindex = build_worker_cos_owner_live_by_tx_ifindex(
        bindings
            .iter()
            .map(|binding| (binding.ifindex, binding.live.clone())),
    );
    let cos_fast_interfaces = build_worker_cos_fast_interfaces(
        forwarding.as_ref(),
        worker_id,
        &cos_owner_live_by_tx_ifindex,
        cos_owner_worker_by_queue.as_ref(),
        cos_owner_live_by_queue.as_ref(),
        cos_shared_root_leases.as_ref(),
        cos_shared_exact_backlogs.as_ref(),
        cos_shared_queue_leases.as_ref(),
        cos_shared_queue_vtime_floors.as_ref(),
    );
    for binding in bindings.iter_mut() {
        binding.cos.cos_fast_interfaces = cos_fast_interfaces.clone();
    }
    let interrupt_poll_fds = if poll_mode == crate::PollMode::Interrupt {
        bindings
            .iter()
            .map(|binding| libc::pollfd {
                fd: binding.xsk.device.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    // Cache BPF map FDs — they don't change during the worker's lifetime.
    let session_map_fd = bindings
        .first()
        .map(|binding| binding.bpf_maps.session_map_fd)
        .unwrap_or(-1);
    let conntrack_v4_fd = bindings
        .first()
        .map(|binding| binding.bpf_maps.conntrack_v4_fd)
        .unwrap_or(-1);
    let conntrack_v6_fd = bindings
        .first()
        .map(|binding| binding.bpf_maps.conntrack_v6_fd)
        .unwrap_or(-1);
    let last_cos_status_ns = monotonic_nanos();
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
        last_cos_status_ns,
    )));
    runtime_atomics.set_tid(current_tid());
    WorkerLoopSetup {
        ha_startup_grace_until_secs,
        validation,
        forwarding,
        cos_owner_worker_by_queue,
        cos_owner_live_by_queue,
        cos_shared_root_leases,
        cos_shared_exact_backlogs,
        cos_shared_queue_leases,
        cos_shared_queue_vtime_floors,
        mirror_targets,
        sessions,
        screen_state,
        bindings,
        binding_lookup,
        interrupt_poll_fds,
        session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
        last_cos_status_ns,
    }
}
