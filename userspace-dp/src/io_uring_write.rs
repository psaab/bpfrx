//! Shared io_uring write loop for the slow path (TUN reinjection) and the
//! state writer (atomic config persistence).
//!
//! Both callers push a single `Write` SQE, then `submit_and_wait(1)`, then reap
//! exactly one CQE. The naive form (see #2297) has two defects when
//! `submit_and_wait` returns an error — overwhelmingly `EINTR`:
//!
//!   (a) Stale-CQE / offset corruption. `submit_and_wait` performs the
//!       `io_uring_enter` syscall, which SUBMITS the queued SQE to the kernel
//!       and THEN waits. The io-uring crate does not retry `EINTR`; if a signal
//!       interrupts the wait phase, the call returns `Err` with the SQE already
//!       in flight and the CQE unreaped. The next write on the same (reused)
//!       ring then reaps the LEFTOVER CQE — applying the previous write's
//!       byte count to the new buffer's `offset`, silently truncating or
//!       over-advancing.
//!
//!   (b) Use-after-free window. A non-SQPOLL ring still punts blocking writes
//!       to io-wq. If the caller returns `Err` and drops its buffer while that
//!       punted write is still in flight, the kernel reads freed userspace
//!       memory.
//!
//! ## #5800 — in-flight registry closes the retry-ceiling UAF
//!
//! The #2297 fix kept the SQE-in-flight invariant under normal operation, but
//! left one hole: the hard retry ceiling (`MAX_WAIT_RETRIES`) returned `Err`
//! WITHOUT proving the matching CQE was reaped or the SQE cancelled, and the
//! caller then freed the buffer while the kernel might still dereference it (a
//! UAF-class disclosure/corruption/crash under sustained signal/error pressure).
//! The tag also restarted at `1` every call, so an abandoned completion could
//! alias a later call's CQE.
//!
//! The fix moves ownership instead of weakening lifetime. A ring-owned
//! [`InflightRegistry`] OWNS the packet bytes and vends a ring-global
//! monotonically increasing `user_data`. [`write_all`] takes the buffer BY
//! VALUE; because moving a `Vec` preserves its heap allocation address, the SQE
//! pointer stays valid when the buffer is moved into the registry. On retry
//! exhaustion (or a fatal ring error) `write_all` returns
//! [`WriteResult::Deferred`] only AFTER the buffer has moved into the registry —
//! it is never freed while an SQE may reference it (invariant 1/5). Deferred
//! buffers are released only when ONE terminal state is observed:
//!
//!   * the matching write CQE is reaped ([`InflightRegistry::reap_ready`], run
//!     opportunistically at the top of every write and inside the reap loop), or
//!   * the ring is torn down and drained ([`InflightRegistry::drain_for_teardown`]
//!     submits an `AsyncCancel` per live entry and observes BOTH the cancel CQE
//!     AND the target write's terminal CQE before freeing — cancellation
//!     SUBMISSION alone is insufficient), or
//!   * the ring fd is closed: [`RingWriter`]'s field order drops the ring BEFORE
//!     the registry, so the kernel's teardown of the ring is INITIATED before
//!     any buffer is freed. This last one is a best-effort narrowing of the
//!     window, NOT a proof — see "What the fd close does and does not buy"
//!     below and the [`RingWriter`] field-order note.
//!
//! Ring-global ids (never restarting per call, [`InflightRegistry::alloc_id`])
//! close the stale-CQE aliasing hole; the id space is fail-closed on wrap
//! (invariant 3) — `alloc_id` returns `None` at exhaustion and `write_all`
//! refuses to submit rather than reuse a possibly-live id.
//!
//! ### What the fd close does and does not buy (#6168)
//!
//! The PRIMARY release is the SYNCHRONOUS [`InflightRegistry::drain_for_teardown`]:
//! it blocks in `submit_and_wait` until each target write's terminal CQE is
//! observed, and only then frees that write's buffer. That covers every
//! realistic teardown.
//!
//! The fd-close fallback is WEAKER than a synchronous barrier, and this comment
//! used to say otherwise. Closing the ring fd runs the kernel's
//! `io_uring_release`, which kills the ctx reference (nothing further can be
//! submitted) and then QUEUES `io_ring_exit_work` on a workqueue; that work item
//! is what actually cancels and waits for the in-flight ops. `close()` does NOT
//! block on it. So:
//!
//!   * GUARANTEED — Rust drops struct fields in declaration order, so the ring
//!     fd close (and with it the START of the kernel's cancellation) always
//!     happens BEFORE any registry buffer is freed. The ordering is
//!     deterministic and it strictly narrows the window.
//!   * NOT GUARANTEED — that the cancellation has FINISHED. `io_ring_exit_work`
//!     runs asynchronously, so a write already executing in io-wq can still be
//!     dereferencing a buffer at the instant the registry frees it. The fd close
//!     is not a synchronous io-wq barrier.
//!
//! That residual is ACCEPTED, not closed (#6168). Reaching it requires the drain
//! to fail first — its `MAX_WAIT_RETRIES` ceiling of 4096 consecutive failed
//! waits, or a fatally dead ring — with a write still mid-io-wq. And even there
//! it is strictly better than the pre-#5800 code, which freed the buffer on
//! EVERY retry ceiling with no drain at all.
//!
//! Closing the residual completely would mean RETAINING (leaking) an unproven
//! buffer at registry drop rather than freeing it — trading a narrow, hard-to-
//! reach lifetime hazard for an unconditional bounded leak on a path that has
//! already failed. #6168 weighed that and did not take it; if this comment and
//! the reachability argument above ever stop holding, that is the lever to pull.
//!
//! Error classification (two further defects, retained from #2477/#2478):
//!
//!   * #2477 — retry safety. On failure [`write_all`] reports whether a
//!     synchronous retry from offset 0 is safe. [`WriteResult::NothingWritten`]
//!     (submit-queue full, a kernel completion error, a zero-byte completion,
//!     id-space exhaustion) put nothing on the fd → safe to sync-retry, and the
//!     owned buffer is handed back so the caller can retry without re-allocating.
//!     [`WriteResult::Transferred`] (a packet-fd partial write) means bytes are
//!     already on the device → the caller MUST drop, never re-send.
//!   * #2478 — permanent-error fast-fail. [`reap_matching`] does not re-spin the
//!     submit/wait on a PERMANENT OS error (a bad/closed ring fd, EINVAL,
//!     EFAULT, …); [`is_permanent`] classifies the errno. A permanent error is
//!     reported as [`WriteResult::Deferred`] with `fatal_ring = true` (the buffer
//!     is retained pending teardown), transient ones retry after a `yield_now`.

use std::sync::atomic::{AtomicU64, Ordering};
use io_uring::{IoUring, opcode, types};
use std::io;

/// One reaped completion: the SQE's `user_data` and its `res` (negative is a
/// negated errno; non-negative is the byte count written).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Completion {
    pub user_data: u64,
    pub result: i32,
}

/// Abstraction over the ring operations the write loop needs. Implemented for
/// real `io_uring::IoUring` (see `IoUringPort`) and by test fakes so the
/// retry/drain/cancel logic is exercisable without a live io_uring.
pub(crate) trait RingPort {
    /// Push a `Write` SQE for `buf` at file `offset`, tagged with `user_data`.
    /// `offset` is `None` for stream writes (TUN) and `Some(n)` for positioned
    /// writes (regular files).
    fn push_write(
        &mut self,
        user_data: u64,
        buf: &[u8],
        offset: Option<u64>,
    ) -> Result<(), String>;

    /// Push an `AsyncCancel` SQE (tagged `user_data`) targeting the in-flight
    /// write whose `user_data == target`. Used only by teardown drain: it nudges
    /// the kernel to complete a still-outstanding write so its terminal CQE
    /// surfaces and its buffer can be released.
    fn push_cancel(&mut self, user_data: u64, target: u64) -> Result<(), String>;

    /// Submit any queued SQEs and wait for at least one completion. Mirrors
    /// `io_uring::IoUring::submit_and_wait(1)`: it may return
    /// `ErrorKind::Interrupted` (EINTR) with the SQE already in flight.
    fn submit_and_wait_one(&mut self) -> io::Result<()>;

    /// Pop the next ready completion, or `None` if the completion queue is
    /// currently empty.
    fn next_completion(&mut self) -> Option<Completion>;
}

/// Result of [`write_all`] / [`RingWriter::write`]. Every variant except
/// [`WriteResult::Deferred`] is TERMINAL for the buffer — the kernel holds no
/// further reference, so the owned `Vec<u8>` is handed back for the caller to
/// reuse or drop. `Deferred` means the op did NOT reach a terminal state: the
/// buffer has been moved into the ring's [`InflightRegistry`] and stays owned
/// there until a later reap or a teardown drain releases it.
#[derive(Debug)]
pub(crate) enum WriteResult {
    /// Every `data.len()` byte was written AND the matching CQE was reaped. The
    /// buffer is safe to drop or reuse.
    Done(Vec<u8>),
    /// Nothing reached the fd (submit-queue full, a kernel completion error, a
    /// zero-byte completion, or id-space exhaustion). A synchronous retry from
    /// offset 0 is safe; the buffer is handed back so the caller need not
    /// re-allocate.
    NothingWritten(Vec<u8>, String),
    /// Bytes ARE (or may be) on the device: a packet-fd short write placed
    /// `0 < n < len` bytes on the TUN as a truncated frame. The CQE was reaped
    /// so the buffer is terminal and handed back, but re-sending the whole
    /// packet would duplicate it — the caller MUST drop, never sync-retry.
    Transferred(Vec<u8>, String),
    /// The op did NOT reach a terminal state (retry-budget exhaustion or a fatal
    /// ring error). The buffer has been MOVED into the ring's registry (keyed by
    /// `id`) and stays owned there until its terminal CQE is reaped or the ring
    /// is torn down and drained. `fatal_ring` = the ring fd itself is dead → the
    /// caller should tear the ring down. The caller must NOT free the buffer and
    /// must NOT synchronously retry (the write may be in flight).
    Deferred {
        id: u64,
        message: String,
        fatal_ring: bool,
    },
}

/// A submitted write whose owned buffer the kernel may still reference. Held by
/// the ring-owned [`InflightRegistry`] from the moment a write is deferred until
/// its op reaches a terminal state. Moving this value (e.g. into the registry's
/// `Vec`) moves only the `Vec<u8>` handle — the heap bytes the SQE points at do
/// NOT move — so the kernel's pointer stays valid across the move.
struct InFlightWrite {
    id: u64,
    bytes: Vec<u8>,
}

/// Ring-owned registry of writes whose buffers must outlive every kernel
/// reference to them, plus the vendor of the ring-global `user_data` id.
///
/// Buffers are moved in ([`Self::defer`]) only when [`write_all`] must return
/// before its op reached a terminal state. They are released — the owned buffer
/// dropped — only when ONE terminal state is observed: the matching write CQE is
/// reaped ([`Self::reap_ready`]), or a teardown drain PROVES no kernel reference
/// remains ([`Self::drain_for_teardown`]). If the drain cannot prove it, the
/// entries survive until the registry itself drops — which [`RingWriter`]'s
/// field order puts after the ring fd close, a best-effort narrowing rather than
/// a proof (see the module doc, "What the fd close does and does not buy").
pub(crate) struct InflightRegistry {
    /// Next `user_data` to hand out. Monotonic from 1; 0 is the stale/uninit
    /// sentinel and is never a valid id. Fail-closed on wrap (invariant 3).
    next_id: u64,
    /// Owned buffers for writes still considered in flight.
    inflight: Vec<InFlightWrite>,
}

/// #7106: buffers this process has RETAINED rather than freed, because the
/// teardown drain could not prove the kernel was done with them. Cumulative and
/// process-global: a registry that leaks is being dropped, so a per-registry
/// counter would be destroyed with the thing it describes.
///
/// There is otherwise no operator-visible signal that a ring abandoned buffers
/// — the condition is silent by construction, since the whole point is that
/// nothing further will be heard about those writes.
pub(crate) static RETAINED_BUFFERS: AtomicU64 = AtomicU64::new(0);
/// Bytes held by [`RETAINED_BUFFERS`].
pub(crate) static RETAINED_BYTES: AtomicU64 = AtomicU64::new(0);

/// #7106: leak, rather than free, any entry the teardown drain could not prove
/// terminal.
///
/// ## Why leaking is the correct answer and not a cop-out
///
/// `drain_for_teardown` is the proof path: every buffer it releases has had its
/// target write's terminal CQE observed. What reaches this `Drop` is the
/// remainder — entries for which the kernel may STILL hold a pointer, because
/// the drain hit its `MAX_WAIT_RETRIES` ceiling or the ring went fatally dead.
///
/// Freeing those is a use-after-free waiting to happen. `RingWriter`'s field
/// order closes the ring fd before this registry drops, but `close()` does not
/// wait: `io_uring_release` only QUEUES `io_ring_exit_work`, so a write already
/// executing in io-wq can still be writing into that allocation at the instant
/// it returns to the allocator (#6168). Field order narrows the window; it is
/// not a barrier. Leaking removes the dependence on kernel teardown timing
/// entirely, which is the standard io_uring idiom for a buffer whose release
/// cannot be proven.
///
/// ## What it costs, measured
///
/// The registry accumulates one entry per DEFERRED write and is not bounded by
/// the ring's submission-queue depth (measured: 32 entries on the state ring,
/// whose SQ is 8). So the leak is unbounded in SIZE.
///
/// It is bounded in FREQUENCY, which is what makes the trade acceptable: a
/// `RingWriter` drops when its ring is retired to the sync fallback, and
/// `retire_ring_to_sync` does not re-promote (no flapping), so this runs at most
/// once per ring per process — on a ring already being abandoned as broken — or
/// at process exit, where a leak is irrelevant. A bounded number of leaks on an
/// already-failed path is a better trade than heap corruption by the kernel.
///
/// The unbounded accumulation itself is a separate, pre-existing concern: it is
/// a memory-growth vector during a storm whether or not anything leaks.
impl Drop for InflightRegistry {
    fn drop(&mut self) {
        if self.inflight.is_empty() {
            return;
        }
        let mut bytes = 0u64;
        let count = self.inflight.len() as u64;
        for entry in self.inflight.drain(..) {
            bytes += entry.bytes.len() as u64;
            // The allocation is deliberately never returned to the allocator:
            // the kernel may still write into it.
            std::mem::forget(entry);
        }
        RETAINED_BUFFERS.fetch_add(count, Ordering::Relaxed);
        RETAINED_BYTES.fetch_add(bytes, Ordering::Relaxed);
        eprintln!(
            "xpf-userspace-dp: io_uring teardown retained {count} unproven buffer(s)              ({bytes} bytes) — the kernel may still reference them, so they are              leaked rather than freed (#7106)"
        );
    }
}

/// Bound on wait retries so a pathological always-EINTR storm cannot wedge a
/// worker forever. EINTR under normal signal pressure resolves in one or two
/// retries; this ceiling is generous.
const MAX_WAIT_RETRIES: u32 = 4096;

impl InflightRegistry {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 1,
            inflight: Vec::new(),
        }
    }

    /// Hand out the next ring-global `user_data`. Returns `None` when the id
    /// space is exhausted (would wrap back through 0) — the caller then fails
    /// closed and does NOT submit, so a possibly-live id is never reused
    /// (invariant 3). At ~1e9 ids/s this takes ~584 years to reach.
    fn alloc_id(&mut self) -> Option<u64> {
        if self.next_id == 0 {
            // Wrapped past u64::MAX on a prior call — space exhausted.
            return None;
        }
        let id = self.next_id;
        // Advances to 0 after handing out u64::MAX; the next call fails closed.
        self.next_id = self.next_id.wrapping_add(1);
        Some(id)
    }

    /// Move an owned buffer into the registry (it stays owned until a terminal
    /// state releases it). Called only on the deferral path.
    fn defer(&mut self, slot: InFlightWrite) {
        self.inflight.push(slot);
    }

    /// Number of buffers still owned (in flight) — a test observability hook for
    /// asserting the deferral/teardown invariants without a live io_uring.
    #[cfg(test)]
    pub(crate) fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    /// Release the registry entry whose write id == `user_data`, dropping its
    /// owned buffer (the kernel is done with it). Returns true if an entry was
    /// released. A `user_data` matching no live entry is a true stale/leftover
    /// (or a cancel CQE) and is not our concern here.
    fn release_matching(&mut self, user_data: u64) -> bool {
        if let Some(pos) = self.inflight.iter().position(|e| e.id == user_data) {
            // swap_remove drops the InFlightWrite -> frees its buffer.
            self.inflight.swap_remove(pos);
            true
        } else {
            false
        }
    }

    /// Non-blocking: reap every completion currently ready, releasing the owned
    /// buffer of any deferred entry whose terminal CQE has surfaced and
    /// discarding true stale completions. Bounds registry growth after a
    /// transient storm and doubles as the pre-submit stale drain: called at the
    /// top of [`write_all`] and again inside [`reap_matching`] right after a new
    /// SQE is pushed (before the wait), where no CQE for the current id can yet
    /// exist so nothing of ours is consumed.
    fn reap_ready(&mut self, port: &mut dyn RingPort) {
        while let Some(cqe) = port.next_completion() {
            self.release_matching(cqe.user_data);
        }
    }

    /// Teardown drain (bounded). For every still-live entry, submit an
    /// `AsyncCancel` targeting its write id, then reap until BOTH the cancel's
    /// completion AND the target write's terminal CQE are observed — proving the
    /// kernel holds no further reference — before dropping the buffer. Releasing
    /// a buffer hinges on the TARGET WRITE's terminal CQE (cancellation
    /// SUBMISSION or even its own completion is insufficient). Bounded by
    /// `MAX_WAIT_RETRIES`; if the ceiling is hit, or the ring is fatally dead,
    /// the still-live entries are RETAINED (never freed early) — their buffers
    /// are freed only when the registry itself drops, which for [`RingWriter`]
    /// happens after the ring fd is closed. That ordering narrows the window but
    /// does not prove the kernel is done (#6168 — the fd close only STARTS an
    /// asynchronous `io_ring_exit_work`); this drain returning without releasing
    /// an entry is therefore the accepted residual, not a second proof.
    ///
    /// Returns the number of entries released by this drain (for tests).
    fn drain_for_teardown(&mut self, port: &mut dyn RingPort) -> usize {
        let start = self.inflight.len();
        if start == 0 {
            return 0;
        }

        // Snapshot the live write ids and submit one cancel per entry. Record
        // the cancel ids so their completions are recognised (and observed)
        // rather than mistaken for stale. The write ids are monotonic and never
        // reused, so a cancel can never target a reused id.
        let targets: Vec<u64> = self.inflight.iter().map(|e| e.id).collect();
        let mut pending_cancels: Vec<u64> = Vec::with_capacity(targets.len());
        for target in targets {
            match self.alloc_id() {
                Some(cancel_id) => {
                    if port.push_cancel(cancel_id, target).is_ok() {
                        pending_cancels.push(cancel_id);
                    }
                }
                // Id space exhausted: cannot cancel. Fall through to a best-
                // effort reap of any already-ready terminal CQEs.
                None => break,
            }
        }

        let mut waits = 0u32;
        while !self.inflight.is_empty() {
            // Reap everything ready: a write id releases its buffer; a cancel id
            // is marked observed; anything else is stale and discarded.
            while let Some(cqe) = port.next_completion() {
                if !self.release_matching(cqe.user_data) {
                    if let Some(pos) =
                        pending_cancels.iter().position(|c| *c == cqe.user_data)
                    {
                        pending_cancels.swap_remove(pos);
                    }
                }
            }
            if self.inflight.is_empty() {
                break;
            }
            match port.submit_and_wait_one() {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => {
                    if is_permanent(&err) {
                        // The ring fd is dead: no further CQE can surface. Retain
                        // the remaining entries — never free one here, where
                        // nothing has been proven. They free when the registry
                        // drops, after the ring fd close has started the kernel's
                        // teardown. That is the accepted best-effort residual,
                        // not a proof the kernel is done (#6168).
                        break;
                    }
                    std::thread::yield_now();
                }
            }
            waits += 1;
            if waits >= MAX_WAIT_RETRIES {
                break;
            }
        }
        start - self.inflight.len()
    }
}

/// `RingPort` adapter over a real `io_uring::IoUring`.
struct IoUringPort<'a> {
    ring: &'a mut IoUring,
    fd: i32,
}

impl RingPort for IoUringPort<'_> {
    fn push_write(
        &mut self,
        user_data: u64,
        buf: &[u8],
        offset: Option<u64>,
    ) -> Result<(), String> {
        let mut entry = opcode::Write::new(types::Fd(self.fd), buf.as_ptr(), buf.len() as _);
        if let Some(off) = offset {
            entry = entry.offset(off);
        }
        let entry = entry.build().user_data(user_data);
        // SAFETY: `buf` (owned by the caller's `InFlightWrite`) outlives the
        // completion. `write_all` either reaps the matching CQE before returning
        // OR moves the owning buffer into the ring's registry (#5800), so the
        // kernel never holds a dangling reference once we return to the caller.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| "io_uring submit queue full".to_string())
        }
    }

    fn push_cancel(&mut self, user_data: u64, target: u64) -> Result<(), String> {
        let entry = opcode::AsyncCancel::new(target).build().user_data(user_data);
        // SAFETY: AsyncCancel references only a `user_data` value, not user
        // memory, so there is no buffer-lifetime obligation for this SQE.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| "io_uring submit queue full (cancel)".to_string())
        }
    }

    fn submit_and_wait_one(&mut self) -> io::Result<()> {
        self.ring.submit_and_wait(1).map(|_| ())
    }

    fn next_completion(&mut self) -> Option<Completion> {
        self.ring.completion().next().map(|cqe| Completion {
            user_data: cqe.user_data(),
            result: cqe.result(),
        })
    }
}

/// A persistent io_uring plus its in-flight owned-buffer registry (#5800). Both
/// slow-path callers own one of these across their lifetime.
///
/// **Field order is load-bearing.** `ring` (field 0) drops BEFORE `inflight`
/// (field 1) — Rust drops struct fields in declaration order, so the ordering is
/// deterministic. Dropping `ring` closes the io_uring fd, which starts the
/// kernel's ring teardown: `io_uring_release` kills the ctx reference (nothing
/// further can be submitted) and queues `io_ring_exit_work`, the work item that
/// cancels and waits for the in-flight ops. Only THEN does `inflight` drop and
/// free any buffer the teardown drain could not prove terminal.
///
/// What that buys is a strictly narrowed window, NOT a barrier: `close()` does
/// not wait for `io_ring_exit_work`, so an op already running in io-wq may still
/// reference a buffer when `inflight` drops (#6168). The proof lives in the
/// synchronous [`InflightRegistry::drain_for_teardown`] this type's `Drop` runs
/// first; the field order is the fallback for the residual where that drain
/// hits its ceiling or the ring is dead. Do not reorder these fields — the
/// ordering costs nothing and it is the only thing narrowing that window.
pub(crate) struct RingWriter {
    ring: IoUring,
    inflight: InflightRegistry,
}

impl RingWriter {
    /// Create a ring with `entries` submission slots plus its registry.
    pub(crate) fn new(entries: u32) -> io::Result<Self> {
        Ok(Self {
            ring: IoUring::new(entries)?,
            inflight: InflightRegistry::new(),
        })
    }

    /// Write all of `data` to `fd`. `positioned` selects a file-offset write
    /// (regular file / state writer) vs. a stream write (TUN device). See
    /// [`WriteResult`] for the buffer-ownership contract of each variant.
    pub(crate) fn write(
        &mut self,
        fd: i32,
        data: Vec<u8>,
        positioned: bool,
        label: &str,
    ) -> WriteResult {
        let mut port = IoUringPort {
            ring: &mut self.ring,
            fd,
        };
        write_all(&mut port, &mut self.inflight, data, positioned, label)
    }
}

impl Drop for RingWriter {
    fn drop(&mut self) {
        // The bounded drain is the PROOF path: it submits cancels and blocks on
        // the target writes' terminal CQEs, so every buffer it releases is
        // provably unreferenced. If it hits its ceiling (or the ring is fatally
        // dead) it releases nothing and the stragglers are retained; the ring fd
        // then closes when `self.ring` drops immediately after this returns,
        // starting the kernel's ring teardown BEFORE `self.inflight` drops and
        // frees them. That ordering narrows the window but is not a barrier —
        // the fd close only queues `io_ring_exit_work` (#6168). Disjoint field
        // borrows let the drain hold `&mut ring` and `&mut inflight` at once
        // without moving out of `self`.
        let ring = &mut self.ring;
        let inflight = &mut self.inflight;
        let mut port = IoUringPort { ring, fd: -1 };
        inflight.drain_for_teardown(&mut port);
    }
}

/// Terminal error from [`reap_matching`]: the op did not reach a reaped terminal
/// state within the retry ceiling, or the ring returned a fatal error.
struct ReapError {
    message: String,
    /// The ring fd itself is dead (a permanent OS error) — the caller should
    /// tear it down. `false` = a transient/interrupt storm hit the ceiling; the
    /// ring is otherwise healthy.
    fatal_ring: bool,
}

/// Drive `port` to write all of `data`, advancing `offset` only by bytes a
/// completion that MATCHES our own submission reports. `positioned` selects a
/// file-offset write (state writer) vs. a stream write (TUN slow path).
///
/// The owned `data` buffer is parked in a local [`InFlightWrite`] so the SQE
/// references the exact allocation that can be moved — intact — into `reg` if
/// the op cannot be proven terminal before we must return (#5800). No return
/// path frees a buffer while an SQE may reference it: a reaped terminal state
/// hands the buffer back; a non-terminal state moves it into `reg`.
pub(crate) fn write_all(
    port: &mut dyn RingPort,
    reg: &mut InflightRegistry,
    data: Vec<u8>,
    positioned: bool,
    label: &str,
) -> WriteResult {
    // Reclaim any previously-deferred buffers whose terminal CQE has surfaced.
    reg.reap_ready(port);

    let mut offset = 0usize;
    // Park the owned buffer so the SQE points at the exact allocation we can
    // move into `reg` on deferral. A `Vec` move preserves the heap address, so
    // the SQE pointer stays valid across `reg.defer(slot)`.
    let mut slot = InFlightWrite {
        id: 0,
        bytes: data,
    };

    while offset < slot.bytes.len() {
        let id = match reg.alloc_id() {
            Some(id) => id,
            None => {
                // Id space exhausted (invariant 3): fail closed. Nothing was
                // submitted for this chunk, so nothing is on the fd — safe to
                // sync-retry, and we hand the buffer back.
                return WriteResult::NothingWritten(
                    slot.bytes,
                    format!("{label} io_uring user_data space exhausted"),
                );
            }
        };
        slot.id = id;
        let file_offset = if positioned { Some(offset as u64) } else { None };

        // A push failure means the SQE was never submitted — nothing is on the
        // fd, so a synchronous retry from offset 0 is safe (#2477).
        if let Err(e) = port.push_write(id, &slot.bytes[offset..], file_offset) {
            return WriteResult::NothingWritten(slot.bytes, e);
        }

        match reap_matching(port, reg, id, label) {
            Ok(res) => {
                if res < 0 {
                    // The kernel completion reported a write error: nothing was
                    // placed on the fd, so a synchronous retry from 0 is safe.
                    return WriteResult::NothingWritten(
                        slot.bytes,
                        format!(
                            "{label} io_uring write failed: {}",
                            io::Error::from_raw_os_error(-res)
                        ),
                    );
                }
                if res == 0 {
                    // Zero bytes transferred — safe to retry synchronously.
                    return WriteResult::NothingWritten(
                        slot.bytes,
                        format!("{label} io_uring short write: 0"),
                    );
                }
                let n = res as usize;
                // A non-positioned (stream-mode) write targets a packet-oriented
                // fd: the TUN slow path (#2407). One submission is one L3 packet;
                // a short count must NOT resubmit the remainder (that would inject
                // `data[n..]` as a SECOND malformed packet). Drop it. Because
                // `0 < n < len` bytes are ALREADY on the TUN, classify as
                // `Transferred` (the caller must not sync-retry — that would
                // re-send the whole packet, #2477). The CQE was reaped, so the
                // buffer is terminal and handed back. Positioned writes (a
                // regular file) are a true byte stream and DO resume from
                // `offset + n`.
                if !positioned && n < slot.bytes.len() {
                    let total = slot.bytes.len();
                    return WriteResult::Transferred(
                        slot.bytes,
                        format!(
                            "{label} io_uring short write on packet fd: wrote {n} of {total} bytes (packet dropped)"
                        ),
                    );
                }
                offset += n;
                // Loop for the next chunk (positioned resume). The next chunk
                // gets a fresh ring-global id, so a leftover CQE from this chunk
                // cannot be reused.
            }
            Err(ReapError {
                message,
                fatal_ring,
            }) => {
                // The op did NOT reach a reaped terminal state: the SQE may still
                // be in flight referencing `slot.bytes`. Move the buffer into the
                // ring's registry so it stays owned until its CQE is reaped or the
                // ring is torn down and drained. NEVER free it here (invariant
                // 1/4/5).
                let id = slot.id;
                reg.defer(slot);
                return WriteResult::Deferred {
                    id,
                    message,
                    fatal_ring,
                };
            }
        }
    }
    // All bytes written and reaped: the buffer is terminal, handed back.
    WriteResult::Done(slot.bytes)
}

/// True when `err` is a PERMANENT OS failure that a retry cannot recover from
/// (a bad/closed ring fd, an invalid argument, a faulting buffer). Retrying
/// these would just re-spin at 100% CPU through the `MAX_WAIT_RETRIES` ceiling
/// (#2478), so [`reap_matching`] returns immediately on them and marks the ring
/// fatal. EINTR/EAGAIN (and any unrecognised errno) are treated as TRANSIENT and
/// retried.
fn is_permanent(err: &io::Error) -> bool {
    match err.raw_os_error() {
        Some(e) => matches!(
            e,
            libc::EBADF        // ring fd closed / never valid
                | libc::EINVAL     // malformed submission / unsupported op
                | libc::EFAULT     // buffer/iovec points at unmapped memory
                | libc::ENXIO      // device/ring gone
                | libc::EBADFD     // ring in a bad state
                | libc::ENODEV     // backing device removed
                | libc::EOPNOTSUPP // op not supported by the ring
                | libc::EPERM      // not permitted — no point retrying
        ),
        // No errno (e.g. a non-OS io::Error) — treat as transient and let the
        // retry ceiling bound it rather than wedging on a misclassification.
        None => false,
    }
}

/// Submit the queued SQE and reap the completion whose `user_data == want`,
/// retrying the wait on `EINTR`/transient error so the in-flight SQE is never
/// abandoned. A completion whose `user_data` matches a DEFERRED registry entry
/// releases that entry's buffer; anything else non-matching is a true stale
/// leftover and is discarded — neither is ever mis-attributed to `want`.
///
/// A PERMANENT submit/wait error (bad ring fd, EINVAL, EFAULT, …) returns
/// immediately with `fatal_ring = true` instead of re-spinning through the
/// ceiling at 100% CPU (#2478); a TRANSIENT error yields the core before
/// retrying and, on ceiling exhaustion, returns `fatal_ring = false`. In BOTH
/// error cases the caller defers the buffer — it is never freed here.
fn reap_matching(
    port: &mut dyn RingPort,
    reg: &mut InflightRegistry,
    want: u64,
    label: &str,
) -> Result<i32, ReapError> {
    // Pre-submit drain: the SQE for `want` has been pushed but NOT yet submitted/
    // waited on, so nothing in the completion queue can carry `want`. Release any
    // deferred entry whose CQE is ready and discard leftovers so a stale CQE can
    // never be returned as ours. (`want` is a freshly allocated id, never in the
    // registry, so this cannot touch our own op.)
    reg.reap_ready(port);

    let mut waits = 0u32;

    loop {
        match port.submit_and_wait_one() {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                // EINTR: the SQE is already submitted (the enter syscall flushed
                // the SQ before sleeping). Retry the WAIT — the io-uring crate
                // recomputes to_submit from the now-empty SQ, so this is
                // wait-only and does not double-submit.
                waits += 1;
                if waits >= MAX_WAIT_RETRIES {
                    return Err(ReapError {
                        message: format!(
                            "{label} io_uring wait interrupted repeatedly ({waits} EINTR)"
                        ),
                        fatal_ring: false,
                    });
                }
                continue;
            }
            Err(err) => {
                // A PERMANENT error (bad/closed ring fd, EINVAL, EFAULT, …)
                // returns the SAME error on every retry. Looping on it just burns
                // a full core through the ceiling without making progress (#2478)
                // — fail fast and mark the ring fatal so the caller tears it down.
                if is_permanent(&err) {
                    return Err(ReapError {
                        message: format!("{label} io_uring permanent submit/wait error: {err}"),
                        fatal_ring: true,
                    });
                }
                // A TRANSIENT wait error (e.g. EAGAIN): the SQE may still be in
                // flight. Keep waiting rather than abandoning it — but yield the
                // core first so a burst does not tight-spin at 100% CPU before the
                // ceiling.
                std::thread::yield_now();
                waits += 1;
                if waits >= MAX_WAIT_RETRIES {
                    return Err(ReapError {
                        message: format!("{label} io_uring submit/wait: {err}"),
                        fatal_ring: false,
                    });
                }
                continue;
            }
        }

        // Reap whatever is ready, matching by user_data.
        while let Some(cqe) = port.next_completion() {
            if cqe.user_data == want {
                return Ok(cqe.result);
            }
            // Not ours: release a deferred registry buffer if it matches, else
            // discard the leftover. Either way keep looking for `want`.
            reg.release_matching(cqe.user_data);
        }
        // submit_and_wait(1) returned Ok but our completion was not among the
        // ready ones (only stale/deferred ones were). Wait again for ours.
        waits += 1;
        if waits >= MAX_WAIT_RETRIES {
            return Err(ReapError {
                message: format!("{label} io_uring completion never matched"),
                fatal_ring: false,
            });
        }
    }
}

#[cfg(test)]
#[path = "io_uring_write_tests.rs"]
mod tests;
