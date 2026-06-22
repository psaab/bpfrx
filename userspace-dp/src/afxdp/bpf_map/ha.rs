// Redundancy-group active-validation / liveness slot helpers.
//
// Pure code motion out of `bpf_map/mod.rs` (#2003): the XSK-slot and
// per-binding heartbeat-slot map writes that gate active-binding state
// now live here. These functions write the `xsks_map` and `heartbeat`
// BPF maps the XDP shim consults to decide whether a binding is live,
// so they back the HA "is this redundancy-group member active" check.
//
// Behaviour-preserving: signatures, side effects, error/log strings, and
// the `HEARTBEAT_UPDATE_INTERVAL_NS` / `HEARTBEAT_STALE_AFTER` gating are
// unchanged from the pre-split orchestrator. The orchestrator-level call
// sites resolve these via the `bpf_map` re-export, exactly as before.
//
// Precedent: the sibling `publish_conntrack.rs` split (#1356).

use super::*;

pub(in crate::afxdp) fn register_xsk_slot(
    map_fd: c_int,
    slot: u32,
    sock_fd: c_int,
) -> io::Result<()> {
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            (&slot as *const u32).cast::<c_void>(),
            (&sock_fd as *const c_int).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(in crate::afxdp) fn update_heartbeat_slot(
    map_fd: c_int,
    slot: u32,
    timestamp_ns: u64,
) -> io::Result<()> {
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            (&slot as *const u32).cast::<c_void>(),
            (&timestamp_ns as *const u64).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(in crate::afxdp) fn delete_xsk_slot(map_fd: c_int, slot: u32) -> io::Result<()> {
    let rc =
        unsafe { libbpf_sys::bpf_map_delete_elem(map_fd, (&slot as *const u32).cast::<c_void>()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(in crate::afxdp) fn delete_heartbeat_slot(map_fd: c_int, slot: u32) -> io::Result<()> {
    let rc =
        unsafe { libbpf_sys::bpf_map_delete_elem(map_fd, (&slot as *const u32).cast::<c_void>()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(in crate::afxdp) fn maybe_touch_heartbeat(binding: &mut BindingWorker, now_ns: u64) {
    // The fill ring is primed before bind, so the driver's initial NAPI
    // posts WQEs immediately. All queues should be ready to receive.
    // No xsk_rx_confirmed gating needed.
    let age_ns = now_ns.saturating_sub(binding.timers.last_heartbeat_update_ns);
    if age_ns < HEARTBEAT_UPDATE_INTERVAL_NS {
        return;
    }
    match touch_heartbeat(
        binding.bpf_maps.heartbeat_map_fd,
        binding.slot,
        &binding.live,
        now_ns,
    ) {
        Ok(()) => {
            if cfg!(feature = "debug-log") {
                thread_local! {
                    static HB_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                let age_ms = age_ns / 1_000_000;
                if age_ms > 1000 {
                    debug_log!(
                        "HB_UPDATE slot={} fd={} age={}ms now_ns={} LATE",
                        binding.slot,
                        binding.bpf_maps.heartbeat_map_fd,
                        age_ms,
                        now_ns,
                    );
                }
                HB_LOG_COUNT.with(|c| {
                    let n = c.get();
                    if n < 5 {
                        c.set(n + 1);
                        debug_log!(
                            "HB_UPDATE[{}] slot={} fd={} age={}ms now_ns={} OK",
                            n,
                            binding.slot,
                            binding.bpf_maps.heartbeat_map_fd,
                            age_ms,
                            now_ns,
                        );
                    }
                });
            }
            binding.timers.last_heartbeat_update_ns = now_ns;
        }
        Err(err) => {
            eprintln!(
                "HB_UPDATE_ERR slot={} fd={} age={}ms err={}",
                binding.slot,
                binding.bpf_maps.heartbeat_map_fd,
                age_ns / 1_000_000,
                err,
            );
            binding
                .live
                .set_error(format!("update heartbeat slot: {err}"));
        }
    }
}

pub(in crate::afxdp) fn touch_heartbeat(
    map_fd: c_int,
    slot: u32,
    live: &BindingLiveState,
    now_ns: u64,
) -> io::Result<()> {
    update_heartbeat_slot(map_fd, slot, now_ns)?;
    live.set_last_heartbeat_at(now_ns);
    Ok(())
}

/// Decide whether a worker's last heartbeat is fresh, comparing two
/// CLOCK_MONOTONIC nanosecond readings: `last_heartbeat_ns` is the value
/// the worker thread stamped into its `BindingLiveState` slot via
/// `set_last_heartbeat_at(now_ns)` (a `monotonic_nanos()` reading), and
/// `now_mono_ns` is the coordinator's own `monotonic_nanos()` reading
/// taken in `snapshot()`. Both come from the SAME process's monotonic
/// clock, so the subtraction is a true elapsed interval.
///
/// HA liveness MUST NOT use the wall clock (`Utc::now()`). A forward
/// CLOCK_REALTIME step (NTP `makestep`, manual `date -s`, VM
/// pause/resume) would make a wall-clock age jump past
/// `HEARTBEAT_STALE_AFTER` and falsely mark a healthy binding unready —
/// which the control plane can read as a hung worker and turn into a
/// spurious VRRP failover / route withdrawal (the Rust-dataplane sibling
/// of the Go control-plane bug fixed in #1792). CLOCK_MONOTONIC is
/// immune to clock steps, so this decision is step-safe.
///
/// `last_heartbeat_ns == 0` is the sentinel for "never stamped" (see
/// `monotonic_timestamp_to_datetime`) and is treated as not-fresh. A
/// backward monotonic anomaly (`now_mono_ns < last_heartbeat_ns`, which
/// cannot happen on a well-behaved CLOCK_MONOTONIC) is clamped by
/// `saturating_sub` to a zero age, i.e. treated as fresh — the
/// fail-safe direction for a liveness check.
pub(in crate::afxdp) fn heartbeat_fresh_mono(last_heartbeat_ns: u64, now_mono_ns: u64) -> bool {
    if last_heartbeat_ns == 0 {
        return false;
    }
    let age_ns = now_mono_ns.saturating_sub(last_heartbeat_ns);
    // Compare in the u128 domain so the threshold can never be silently
    // truncated by an `as u64` cast (HEARTBEAT_STALE_AFTER is 5s today, far
    // below u64::MAX ns, but this keeps the bound exact if it ever grows).
    u128::from(age_ns) <= HEARTBEAT_STALE_AFTER.as_nanos()
}
