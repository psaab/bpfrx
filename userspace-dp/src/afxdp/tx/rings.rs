// #984 P2b: XSK kernel-ring discipline cluster, extracted from
// tx/mod.rs.
//
// Six items live here:
//   - `reap_tx_completions`: drain the XSK completion ring via
//     `device.complete()` and feed completed offsets to the stats
//     fold + per-offset cleanup.
//   - `drain_pending_fill`: refill the XSK fill ring via
//     `device.fill().insert(...)` + `commit()`.
//   - `maybe_wake_rx` / `maybe_wake_tx`: kernel-wakeup gates that
//     issue `sendto` after fill / TX submit (rate-limited per the
//     RX_WAKE_* / TX_WAKE_* constants in afxdp.rs).
//   - `recycle_completed_tx_offset` (file-private helper): per-offset
//     cleanup invoked from inside `reap_tx_completions`.
//   - `apply_prepared_recycle` (pub(super) for tx/mod.rs's cfg-test
//     re-export): `recycle_completed_tx_offset`'s
//     `PreparedTxRecycle` dispatcher.
//
// Single-writer (owner worker), all atomic ops `Ordering::Relaxed`.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::PreparedTxRecycle;
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{
    FILL_BATCH_SIZE, FILL_WAKE_SAFETY_INTERVAL_NS,
    RX_WAKE_IDLE_POLLS, RX_WAKE_MIN_INTERVAL_NS,
    TX_WAKE_MIN_INTERVAL_NS, XskBindMode,
};

use super::stats::{record_kick_latency, record_tx_completions_with_stamp};
use super::update_binding_debug_state;

pub(in crate::afxdp) fn reap_tx_completions(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> u32 {
    if binding.outstanding_tx == 0 {
        return 0;
    }
    let available = binding.device.available();
    if available == 0 {
        return 0;
    }
    let mut reaped = 0u32;
    binding.scratch_completed_offsets.clear();
    let mut completed = binding.device.complete(available);
    while let Some(offset) = completed.read() {
        binding.scratch_completed_offsets.push(offset);
        reaped += 1;
    }
    completed.release();
    drop(completed);
    // #812: completion stamp — single fresh `monotonic_nanos()` for
    // the entire reap batch (plan §3.1 completion-ts site). Amortised
    // one VDSO call per reap (worst-case ~15 ns / TX_BATCH_SIZE-packet
    // batch = ~0.23 ns/pkt at the post-#920 batch of 64;
    // ~15 ns/pkt on the `reaped == 1` partial-batch worst case —
    // same shape as the submit-stamp cost analysis in plan §3.4).
    let ts_completion = monotonic_nanos();
    // #812: delegate the per-offset fold to the shared helper so
    // tests exercising `record_tx_completions_with_stamp` cover the
    // exact production algorithm — NOT a test-only fake. See unit
    // pins under `#[cfg(test)]` below.
    record_tx_completions_with_stamp(
        &mut binding.tx_submit_ns,
        &binding.scratch_completed_offsets,
        ts_completion,
        &binding.live.owner_profile_owner,
    );
    for i in 0..binding.scratch_completed_offsets.len() {
        let offset = binding.scratch_completed_offsets[i];
        recycle_completed_tx_offset(binding, shared_recycles, offset);
    }
    binding.outstanding_tx = binding.outstanding_tx.saturating_sub(reaped);
    binding.dbg_completions_reaped += reaped as u64;
    binding
        .live
        .tx_completions
        .fetch_add(reaped as u64, Ordering::Relaxed);
    update_binding_debug_state(binding);
    reaped
}

pub(in crate::afxdp) fn drain_pending_fill(binding: &mut BindingWorker, now_ns: u64) -> bool {
    if binding.pending_fill_frames.is_empty() {
        return false;
    }
    let batch_size = binding.pending_fill_frames.len().min(FILL_BATCH_SIZE);
    binding.scratch_fill.clear();
    while binding.scratch_fill.len() < batch_size {
        let Some(offset) = binding.pending_fill_frames.pop_front() else {
            break;
        };
        // Poison the frame before submitting to fill ring — the kernel should
        // overwrite this with real packet data on RX. If we ever read back the
        // poison pattern in the RX path, it means the kernel recycled a
        // descriptor without writing packet data (stale/uninit frame).
        if cfg!(feature = "debug-log") {
            if let Some(frame) =
                unsafe { binding.umem.area().slice_mut_unchecked(offset as usize, 8) }
            {
                frame.copy_from_slice(&0xDEAD_BEEF_DEAD_BEEFu64.to_ne_bytes());
            }
        }
        binding.scratch_fill.push(offset);
    }
    if binding.scratch_fill.is_empty() {
        return false;
    }
    let inserted = {
        let mut fill = binding.device.fill(binding.scratch_fill.len() as u32);
        let inserted = fill.insert(binding.scratch_fill.iter().copied());
        fill.commit();
        inserted
    };
    if inserted == 0 {
        binding.dbg_fill_failed += binding.scratch_fill.len() as u64;
        for offset in binding.scratch_fill.drain(..).rev() {
            binding.pending_fill_frames.push_front(offset);
        }
        return false;
    }
    binding.dbg_fill_submitted += inserted as u64;
    if inserted < binding.scratch_fill.len() as u32 {
        binding.dbg_fill_failed += (binding.scratch_fill.len() as u32 - inserted) as u64;
        for offset in binding.scratch_fill.drain(inserted as usize..).rev() {
            binding.pending_fill_frames.push_front(offset);
        }
    }
    binding.scratch_fill.clear();
    // Only wake NAPI when the kernel signals it needs fill ring entries,
    // or as a safety net every FILL_WAKE_SAFETY_INTERVAL_NS to prevent
    // lost-wakeup stalls from the race between commit() and needs_wakeup.
    // Without the needs_wakeup gate, every drain triggers a sendto() syscall
    // (142K/sec at line rate), spending ~20% CPU in syscall entry/exit.
    if binding.device.needs_wakeup()
        || now_ns.saturating_sub(binding.last_rx_wake_ns) >= FILL_WAKE_SAFETY_INTERVAL_NS
    {
        maybe_wake_rx(binding, true, now_ns);
    }
    update_binding_debug_state(binding);
    true
}

pub(in crate::afxdp) fn maybe_wake_rx(binding: &mut BindingWorker, force: bool, now_ns: u64) {
    // After submitting fill ring entries, we must kick NAPI so the driver
    // consumes them and posts new RX WQEs. Without this, mlx5 increments
    // rx_xsk_buff_alloc_err and silently drops all incoming packets.
    //
    // poll(POLLIN) triggers xsk_poll → ndo_xsk_wakeup(XDP_WAKEUP_RX),
    // which makes the driver consume fill ring entries and post WQEs.
    // sendto() only triggers XDP_WAKEUP_TX (TX kick), NOT RX fill ring
    // processing — using sendto() for RX wake was the root cause of
    // fill ring starvation on idle interfaces with zero-copy mlx5.
    if !force {
        binding.empty_rx_polls = binding.empty_rx_polls.saturating_add(1);
        if binding.empty_rx_polls < RX_WAKE_IDLE_POLLS {
            return;
        }
        if now_ns.saturating_sub(binding.last_rx_wake_ns) < RX_WAKE_MIN_INTERVAL_NS {
            return;
        }
    }
    let fd = binding.device.as_raw_fd();
    // Use poll(POLLIN) for RX wakeup — triggers XDP_WAKEUP_RX.
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    if rc >= 0 {
        binding.dbg_rx_wake_sendto_ok += 1;
    } else {
        binding.dbg_rx_wake_sendto_err += 1;
        binding.dbg_rx_wake_sendto_errno = unsafe { *libc::__errno_location() };
    }
    // Also sendto for TX completions (needed for copy mode and TX kick).
    unsafe {
        libc::sendto(
            fd,
            core::ptr::null_mut(),
            0,
            libc::MSG_DONTWAIT,
            core::ptr::null_mut(),
            0,
        );
    }
    binding.dbg_rx_wakeups += 1;
    binding.live.rx_wakeups.fetch_add(1, Ordering::Relaxed);
    binding.last_rx_wake_ns = now_ns;
    binding.empty_rx_polls = 0;
}

fn apply_prepared_recycle(
    free_tx_frames: &mut VecDeque<u64>,
    shared_recycles: &mut Vec<(u32, u64)>,
    recycle: PreparedTxRecycle,
    offset: u64,
) {
    match recycle {
        PreparedTxRecycle::FreeTxFrame => free_tx_frames.push_back(offset),
        PreparedTxRecycle::FillOnSlot(slot) => shared_recycles.push((slot, offset)),
    }
}

fn recycle_completed_tx_offset(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
    offset: u64,
) {
    if let Some(recycle) = binding.in_flight_prepared_recycles.remove(&offset) {
        apply_prepared_recycle(
            &mut binding.free_tx_frames,
            shared_recycles,
            recycle,
            offset,
        );
    } else {
        binding.free_tx_frames.push_back(offset);
    }
}

pub(in crate::afxdp) fn maybe_wake_tx(binding: &mut BindingWorker, force: bool, now_ns: u64) {
    let bind_mode = XskBindMode::from_u8(binding.live.bind_mode.load(Ordering::Relaxed));
    if !bind_mode.is_zerocopy()
        || binding.tx.needs_wakeup()
        || force
        || now_ns.saturating_sub(binding.last_tx_wake_ns) >= TX_WAKE_MIN_INTERVAL_NS
    {
        // Use direct sendto() instead of binding.tx.wake() so we can capture errors.
        let fd = binding.tx.as_raw_fd();
        // #825 plan §3.3 site 1: two fresh `monotonic_nanos()` calls
        // bracket the `sendto` syscall. `now_ns` is caller-cached —
        // stale up to `IDLE_SPIN_ITERS * spin_cost` per #812 §3.1 R1
        // — so it is NOT suitable for measuring the kick cost; we
        // need fresh stamps to measure the syscall itself. Cost per
        // kick: ~30 ns VDSO (2 × ~15 ns) + the atomic fetch_adds in
        // `record_kick_latency` (≲15 ns), well within the §7 budget.
        let kick_start = monotonic_nanos();
        let rc = unsafe {
            libc::sendto(
                fd,
                core::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                core::ptr::null_mut(),
                0,
            )
        };
        let kick_end = monotonic_nanos();
        binding.dbg_sendto_calls += 1;
        // #825 plan §3.3 LOW-3 R1 sentinel, code-review R1 HIGH-1 hardening:
        // skip record unless (a) `kick_start != 0` AND (b) `kick_end >=
        // kick_start`. Both guards are required:
        //   - `kick_start != 0` catches the asymmetric failure mode where
        //     the first `monotonic_nanos()` call fails (returns 0) and the
        //     second succeeds — `kick_end - 0` would saturate bucket 15
        //     with a bogus-huge delta. It also drops the symmetric
        //     double-failure case (both 0) so a spurious bucket-0 record
        //     is not emitted on VDSO outage.
        //   - `kick_end >= kick_start` catches the backwards-clock /
        //     end-before-start case (wraparound in the `kick_end -
        //     kick_start` subtraction would otherwise saturate bucket
        //     15 with a bogus-huge delta). Both conditions must hold;
        //     this matches `record_tx_completions_with_stamp`'s
        //     `ts_completion >= ts_submit` precedent at :113-119.
        if kick_start != 0 && kick_end >= kick_start {
            let delta_ns = kick_end - kick_start;
            record_kick_latency(&binding.live.owner_profile_owner, delta_ns);
        }
        if rc < 0 {
            let errno = unsafe { *libc::__errno_location() };
            // EAGAIN/EWOULDBLOCK is normal for MSG_DONTWAIT; ENOBUFS means kernel dropped.
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                binding.dbg_sendto_eagain += 1;
                // #825 plan §3.3 site 1 / §5: parallel atomic to
                // `dbg_sendto_eagain` (which is worker-local and
                // never published). Counts outer `sendto` returns
                // where `errno ∈ {EAGAIN, EWOULDBLOCK}` — the
                // "ring pushed back" signal T1 (#819 §4.1) keys
                // off. `dbg_sendto_eagain` stays in place: the
                // worker-local debug-tick log at
                // `worker.rs:~1051` continues to work.
                binding
                    .live
                    .owner_profile_owner
                    .tx_kick_retry_count
                    .fetch_add(1, Ordering::Relaxed);
            } else if errno == libc::ENOBUFS {
                binding.dbg_sendto_enobufs += 1;
                if binding.dbg_sendto_enobufs <= 10 {
                    eprintln!(
                        "TX_ENOBUFS: slot={} if={} q={} outstanding_tx={} free_tx={}",
                        binding.slot,
                        binding.ifindex,
                        binding.queue_id,
                        binding.outstanding_tx,
                        binding.free_tx_frames.len(),
                    );
                }
            } else {
                binding.dbg_sendto_err += 1;
                if binding.dbg_sendto_err <= 5 {
                    eprintln!(
                        "DBG SENDTO_ERR: slot={} if={} q={} errno={} outstanding_tx={} free_tx={}",
                        binding.slot,
                        binding.ifindex,
                        binding.queue_id,
                        errno,
                        binding.outstanding_tx,
                        binding.free_tx_frames.len(),
                    );
                }
            }
        }
        binding.last_tx_wake_ns = now_ns;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_prepared_recycle_routes_fill_and_free_explicitly() {
        let mut free_tx_frames = VecDeque::new();
        let mut shared_recycles = Vec::new();

        apply_prepared_recycle(
            &mut free_tx_frames,
            &mut shared_recycles,
            PreparedTxRecycle::FreeTxFrame,
            41,
        );
        apply_prepared_recycle(
            &mut free_tx_frames,
            &mut shared_recycles,
            PreparedTxRecycle::FillOnSlot(7),
            42,
        );

        assert_eq!(free_tx_frames, VecDeque::from(vec![41]));
        assert_eq!(shared_recycles, vec![(7, 42)]);
    }

}
