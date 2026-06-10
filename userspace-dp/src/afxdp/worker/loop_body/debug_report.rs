// #1776 — cfg(debug-log) verbose periodic report + stall dump,
// extracted from loop_body/mod.rs (pure code motion per the converged
// v3.1 plan on research/1776-loop-body-decomp).
//
// This module holds ONLY the `debug-log`-feature subset of the
// per-second report block: the `DbgCounters` per-interval counter
// struct, the giant `DBG w{N}: ...` summary eprintln + degraded-path
// dump, and the stall detector + per-binding stall dump. The whole
// module is `#[cfg(feature = "debug-log")]`-gated at its `mod`
// declaration, so release builds compile none of it — zero release-
// path risk by construction.
//
// The ALWAYS-ON release parts of the original report block stay
// inline in mod.rs (Codex r2-3 partition): the per-report-tick
// `binding_summary` diagnostics build (statistics_v2 + SO_ERROR
// getsockopt syscalls), the per-second `BindingLiveState`
// publish/reset loop, and the always-on `dbg_last_report_ns`
// report-cadence timestamp.
//
// PERSISTENT debug state (plan v3.1 AGY CORRECTNESS-1): the report
// timestamp `dbg_last_report_ns` and the cross-interval stall
// baselines `stall_prev_fwd` / `stall_reported` are deliberately NOT
// fields of `DbgCounters` — they stay plain locals in `worker_loop`
// so the interval `DbgCounters::default()` reset cannot wipe them.
// `prev_rx_total` / `prev_fwd_total` are same-interval snapshots,
// taken in mod.rs from `dbg` BEFORE the interval reset and consumed
// by `check_and_dump_stall` in the same report tick.

use super::*;

/// Per-interval debug counters, zeroed each ~1s report tick via a
/// single `DbgCounters::default()` assignment (replaces the old
/// 40-line manual `dbg_* = 0` reset, which was a forget-a-counter
/// hazard). Accumulated from `DebugPollCounters` once per loop tick
/// by [`DbgCounters::accumulate`]; `tx_tcp_rst` is additionally fed
/// from per-binding `WorkerTelemetry` inside the binding_summary
/// build in mod.rs.
///
/// Field order mirrors the original `dbg_*` local declaration order.
#[derive(Default)]
pub(super) struct DbgCounters {
    pub(super) rx_total: u64,
    pub(super) tx_total: u64,
    pub(super) forward_total: u64,
    pub(super) local_total: u64,
    pub(super) session_hit: u64,
    pub(super) session_miss: u64,
    pub(super) session_create: u64,
    pub(super) no_route: u64,
    pub(super) missing_neigh: u64,
    /// #1651 B3: dead-host negative-cache fast-fail count.
    pub(super) neg_neigh_fast_fail: u64,
    pub(super) policy_deny: u64,
    pub(super) ha_inactive: u64,
    pub(super) no_egress_binding: u64,
    pub(super) build_fail: u64,
    pub(super) tx_err: u64,
    pub(super) metadata_err: u64,
    pub(super) disposition_other: u64,
    pub(super) enqueue_ok: u64,
    pub(super) enqueue_inplace: u64,
    pub(super) enqueue_direct: u64,
    pub(super) enqueue_copy: u64,
    pub(super) rx_from_trust: u64,
    pub(super) rx_from_wan: u64,
    pub(super) fwd_trust_to_wan: u64,
    pub(super) fwd_wan_to_trust: u64,
    pub(super) nat_snat: u64,
    pub(super) nat_dnat: u64,
    pub(super) nat_none: u64,
    pub(super) frame_build_none: u64,
    pub(super) rx_tcp_rst: u64,
    pub(super) tx_tcp_rst: u64,
    pub(super) rx_tcp_fin: u64,
    pub(super) rx_tcp_synack: u64,
    pub(super) rx_tcp_zero_window: u64,
    pub(super) fwd_tcp_fin: u64,
    pub(super) fwd_tcp_rst: u64,
    pub(super) fwd_tcp_zero_window: u64,
    pub(super) rx_bytes_total: u64,
    pub(super) tx_bytes_total: u64,
    pub(super) rx_oversized: u64,
    pub(super) rx_max_frame: u32,
    pub(super) tx_max_frame: u32,
    pub(super) seg_needed_but_none: u64,
}

impl DbgCounters {
    /// Fold one tick's `DebugPollCounters` into the running interval
    /// counters (moved verbatim from the post-poll `dbg_* +=
    /// dbg_poll.*` blocks).
    pub(super) fn accumulate(&mut self, dbg_poll: &DebugPollCounters) {
        self.rx_total += dbg_poll.rx;
        self.tx_total += dbg_poll.tx;
        self.forward_total += dbg_poll.forward;
        self.local_total += dbg_poll.local;
        self.session_hit += dbg_poll.session_hit;
        self.session_miss += dbg_poll.session_miss;
        self.session_create += dbg_poll.session_create;
        self.no_route += dbg_poll.no_route;
        self.missing_neigh += dbg_poll.missing_neigh;
        self.neg_neigh_fast_fail += dbg_poll.neg_neigh_fast_fail;
        self.policy_deny += dbg_poll.policy_deny;
        self.ha_inactive += dbg_poll.ha_inactive;
        self.no_egress_binding += dbg_poll.no_egress_binding;
        self.build_fail += dbg_poll.build_fail;
        self.tx_err += dbg_poll.tx_err;
        self.metadata_err += dbg_poll.metadata_err;
        self.disposition_other += dbg_poll.disposition_other;
        self.enqueue_ok += dbg_poll.enqueue_ok;
        self.enqueue_inplace += dbg_poll.enqueue_inplace;
        self.enqueue_direct += dbg_poll.enqueue_direct;
        self.enqueue_copy += dbg_poll.enqueue_copy;
        self.rx_from_trust += dbg_poll.rx_from_trust;
        self.rx_from_wan += dbg_poll.rx_from_wan;
        self.fwd_trust_to_wan += dbg_poll.fwd_trust_to_wan;
        self.fwd_wan_to_trust += dbg_poll.fwd_wan_to_trust;
        self.nat_snat += dbg_poll.nat_applied_snat;
        self.nat_dnat += dbg_poll.nat_applied_dnat;
        self.nat_none += dbg_poll.nat_applied_none;
        self.frame_build_none += dbg_poll.frame_build_none;
        self.rx_tcp_rst += dbg_poll.rx_tcp_rst;
        self.rx_tcp_fin += dbg_poll.rx_tcp_fin;
        self.rx_tcp_synack += dbg_poll.rx_tcp_synack;
        self.rx_tcp_zero_window += dbg_poll.rx_tcp_zero_window;
        self.fwd_tcp_fin += dbg_poll.fwd_tcp_fin;
        self.fwd_tcp_rst += dbg_poll.fwd_tcp_rst;
        self.fwd_tcp_zero_window += dbg_poll.fwd_tcp_zero_window;
        self.rx_bytes_total += dbg_poll.rx_bytes_total;
        self.tx_bytes_total += dbg_poll.tx_bytes_total;
        self.rx_oversized += dbg_poll.rx_oversized;
        if dbg_poll.rx_max_frame > self.rx_max_frame {
            self.rx_max_frame = dbg_poll.rx_max_frame;
        }
        if dbg_poll.tx_max_frame > self.tx_max_frame {
            self.tx_max_frame = dbg_poll.tx_max_frame;
        }
        self.seg_needed_but_none += dbg_poll.seg_needed_but_none;
    }
}

/// The per-second verbose summary eprintln + retained-shim degraded-
/// path dump (moved verbatim; `dbg_X` locals became `dbg.X` fields).
/// Called once per report interval, before the interval-counter
/// reset in mod.rs.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_periodic_report(
    worker_id: u32,
    elapsed: u64,
    dbg: &DbgCounters,
    session_count: usize,
    bindings: &[BindingWorker],
    binding_summary: &str,
) {
    let secs = elapsed as f64 / 1_000_000_000.0;
    eprintln!(
        "DBG w{}: {:.1}s rx={} tx={} fwd={} local={} sess_hit={} sess_miss={} sess_create={} \
         no_route={} miss_neigh={} neg_ff={} pol_deny={} ha_inact={} no_egress={} build_fail={} \
         tx_err={} meta_err={} other={} enq_ok={} enq_ip={} enq_dir={} enq_cp={} sessions={} \
         DIR:trust_rx={}/wan_rx={}/t2w={}/w2t={} NAT:snat={}/dnat={}/none={}/bld_none={} RST:rx={}/tx={} \
         SIZE:rx_avg={}/rx_max={}/tx_avg={}/tx_max={}/rx_over={}/seg_miss={} \
         TCP_RX:fin={}/synack={}/zwin={} TCP_FWD:fin={}/rst={}/zwin={} \
         CSUM:verified={}/bad_ip={}/bad_l4={} \
         SESS_BPF:verify_ok={}/verify_fail={}/bpf_entries={} bindings:{}",
        worker_id,
        secs,
        dbg.rx_total,
        dbg.tx_total,
        dbg.forward_total,
        dbg.local_total,
        dbg.session_hit,
        dbg.session_miss,
        dbg.session_create,
        dbg.no_route,
        dbg.missing_neigh,
        dbg.neg_neigh_fast_fail,
        dbg.policy_deny,
        dbg.ha_inactive,
        dbg.no_egress_binding,
        dbg.build_fail,
        dbg.tx_err,
        dbg.metadata_err,
        dbg.disposition_other,
        dbg.enqueue_ok,
        dbg.enqueue_inplace,
        dbg.enqueue_direct,
        dbg.enqueue_copy,
        session_count,
        dbg.rx_from_trust,
        dbg.rx_from_wan,
        dbg.fwd_trust_to_wan,
        dbg.fwd_wan_to_trust,
        dbg.nat_snat,
        dbg.nat_dnat,
        dbg.nat_none,
        dbg.frame_build_none,
        dbg.rx_tcp_rst,
        dbg.tx_tcp_rst,
        if dbg.rx_total > 0 {
            dbg.rx_bytes_total / dbg.rx_total
        } else {
            0
        },
        dbg.rx_max_frame,
        if dbg.enqueue_ok > 0 {
            dbg.tx_bytes_total / dbg.enqueue_ok
        } else {
            0
        },
        dbg.tx_max_frame,
        dbg.rx_oversized,
        dbg.seg_needed_but_none,
        dbg.rx_tcp_fin,
        dbg.rx_tcp_synack,
        dbg.rx_tcp_zero_window,
        dbg.fwd_tcp_fin,
        dbg.fwd_tcp_rst,
        dbg.fwd_tcp_zero_window,
        CSUM_VERIFIED_TOTAL.swap(0, Ordering::Relaxed),
        CSUM_BAD_IP_TOTAL.swap(0, Ordering::Relaxed),
        CSUM_BAD_L4_TOTAL.swap(0, Ordering::Relaxed),
        SESSION_PUBLISH_VERIFY_OK.swap(0, Ordering::Relaxed),
        SESSION_PUBLISH_VERIFY_FAIL.swap(0, Ordering::Relaxed),
        if let Some(b) = bindings.first() {
            count_bpf_session_entries(b.bpf_maps.session_map_fd)
        } else {
            0
        },
        binding_summary,
    );
    // Non-debug builds: no per-second stats dump (use debug-log feature for verbose output).
    // Print retained-shim degraded-path stats — tells us WHY
    // packets stop being redirected to XSK.
    if let Some(stats) = read_degraded_path_stats() {
        if !stats.is_empty() {
            let s: Vec<String> =
                stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
            eprintln!("DBG w{}: XDP_DEGRADED: {}", worker_id, s.join(" "));
        }
    }
}

/// Stall detector + per-binding stall dump (moved verbatim from the
/// `if cfg!(feature = "debug-log")` stall block; the persistent
/// cross-interval baselines `stall_prev_fwd` / `stall_reported` stay
/// locals in `worker_loop` and are threaded through as `&mut`).
///
/// `prev_rx_total` / `prev_fwd_total` are THIS interval's totals
/// (snapshotted in mod.rs before the interval-counter reset);
/// `stall_prev_fwd` is the PREVIOUS interval's fwd count.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn check_and_dump_stall(
    worker_id: u32,
    prev_rx_total: u64,
    prev_fwd_total: u64,
    stall_prev_fwd: &mut u64,
    stall_reported: &mut bool,
    session_count: usize,
    bindings: &[BindingWorker],
    sessions: &SessionTable,
) {
    if *stall_prev_fwd > 10 && prev_fwd_total == 0 && !*stall_reported {
        *stall_reported = true;
        eprintln!(
            "DBG STALL_DETECTED: w{} two_ago_fwd={} this_interval_fwd={} this_interval_rx={} sessions={}",
            worker_id, stall_prev_fwd, prev_fwd_total, prev_rx_total, session_count
        );
        // Dump comprehensive per-binding state at stall moment
        for (si, sb) in bindings.iter().enumerate() {
            use std::fmt::Write;
            let fill_p = sb.xsk.device.pending();
            let rx_a = sb.xsk.rx.available_relaxed();
            let ifl = sb.tx_pipeline.in_flight_prepared_recycles.len() as u32;
            let ptxp = sb.tx_pipeline.pending_tx_prepared.len() as u32;
            let ptxl = sb.tx_pipeline.pending_tx_local.len() as u32;
            let total = sb.tx_pipeline.pending_fill_frames.len() as u32
                + fill_p
                + rx_a
                + sb.tx_pipeline.free_tx_frames.len() as u32
                + sb.tx_pipeline.outstanding_tx
                + ifl
                + sb.scratch.scratch_recycle.len() as u32
                + ptxp;
            let raw = diagnose_raw_ring_state(sb.xsk.rx.as_raw_fd());
            let mut stall_line = format!(
                "DBG STALL_BINDING[{}]: if={} q={} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} ptxp={} ptxl={} total={}/{}",
                si,
                sb.ifindex,
                sb.queue_id,
                sb.tx_pipeline.pending_fill_frames.len(),
                fill_p,
                rx_a,
                sb.tx_pipeline.free_tx_frames.len(),
                sb.tx_pipeline.outstanding_tx,
                ifl,
                ptxp,
                ptxl,
                total,
                sb.umem.total_frames(),
            );
            if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) = raw {
                let _ = write!(
                    stall_line,
                    " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}"
                );
            }
            if let Ok(Some(stats)) = sb.xsk.device.statistics_v2().map(Some) {
                let _ = write!(
                    stall_line,
                    " xsk:drop={}/rfull={}/fempty={}/tempty={}",
                    stats.rx_dropped,
                    stats.rx_ring_full,
                    stats.rx_fill_ring_empty_descs,
                    stats.tx_ring_empty_descs
                );
            }
            eprintln!("{stall_line}");
        }
        // Dump all session keys for this worker
        let mut sess_dump = String::new();
        let mut count = 0;
        sessions.iter_with_origin(|key, decision, metadata, origin| {
            if count < 20 {
                use std::fmt::Write;
                let _ = write!(
                    sess_dump,
                    "\n  SESS: {}:{} -> {}:{} proto={} nat=({:?},{:?}) is_rev={} origin={}",
                    key.src_ip,
                    key.src_port,
                    key.dst_ip,
                    key.dst_port,
                    key.protocol,
                    decision.nat.rewrite_src,
                    decision.nat.rewrite_dst,
                    metadata.is_reverse,
                    origin.as_str(),
                );
                count += 1;
            }
        });
        if !sess_dump.is_empty() {
            eprintln!("DBG STALL_SESSIONS:{sess_dump}");
        }
        // Dump degraded-path stats at stall time.
        if let Some(stats) = read_degraded_path_stats() {
            if !stats.is_empty() {
                let s: Vec<String> =
                    stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                eprintln!("DBG STALL_DEGRADED: {}", s.join(" "));
            }
        }
        // Also dump BPF session count
        if let Some(b) = bindings.first() {
            eprintln!(
                "DBG STALL_BPF_SESSIONS: entries={}",
                count_bpf_session_entries(b.bpf_maps.session_map_fd)
            );
        }
    } else if prev_fwd_total > 0 {
        *stall_reported = false;
    }
    *stall_prev_fwd = prev_fwd_total;
}
