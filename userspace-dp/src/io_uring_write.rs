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
//! The fix here keeps the SQE-in-flight invariant the callers always assumed:
//! under normal operation the function does not return until every SQE it
//! submitted has been reaped. The sole escape hatch is a hard retry ceiling
//! (`MAX_WAIT_RETRIES`) that converts a pathological never-ending EINTR storm
//! into an `Err` so a worker cannot wedge forever; reaching it requires
//! thousands of consecutive interrupted/failed waits with the CQE still
//! unreaped, which is astronomically improbable. See the per-`Err` notes on
//! [`reap_matching`] for what each ceiling return implies for the buffer.
//!
//!   * `EINTR` (and any wait error) RETRIES the wait instead of returning. The
//!     `io-uring` crate's `submit_and_wait` derives `to_submit` from the
//!     current SQ length, so once the SQE has been consumed by the kernel the
//!     retry degrades to a wait-only `io_uring_enter(0, 1, GETEVENTS)` — it
//!     does not double-submit.
//!   * Each submission carries a distinct, monotonically increasing
//!     `user_data`. The reap loop matches the CQE by `user_data`; a stale CQE
//!     left over from a prior interrupted submission can no longer be
//!     mis-attributed to this write — it is recognised and skipped.
//!   * Because the function only returns after the matching CQE is reaped, the
//!     caller's buffer provably outlives every kernel reference to it, closing
//!     the UAF window.
//!
//! Error classification (two further defects, fixed together):
//!
//!   * #2477 — retry safety. On failure [`write_all`] returns a [`WriteError`]
//!     that tells the caller whether a synchronous retry from offset 0 is safe.
//!     `NothingWritten` (submit-queue full, a kernel completion error, a
//!     zero-byte completion) put nothing on the fd → safe to sync-retry.
//!     `Transferred` (a packet-fd partial write, or an ambiguous submit/wait
//!     error where the SQE may be in flight) means bytes are — or may be —
//!     already on the device → the caller MUST drop, never re-send. The TUN slow
//!     path uses this so its io_uring→sync fallback cannot double-transmit a
//!     packet; the state writer (a true byte stream, no sync fallback) ignores
//!     it.
//!   * #2478 — permanent-error fast-fail. [`reap_matching`] no longer
//!     re-spins the submit/wait on a PERMANENT OS error (a bad/closed ring fd,
//!     EINVAL, EFAULT, …) — those return the same error forever and would burn a
//!     full core through the `MAX_WAIT_RETRIES` ceiling. [`is_permanent`]
//!     classifies the errno; permanent errors return immediately, transient ones
//!     (EINTR/EAGAIN) retry after a `yield_now`.

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
/// retry/drain logic is exercisable without a live io_uring.
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

    /// Submit any queued SQEs and wait for at least one completion. Mirrors
    /// `io_uring::IoUring::submit_and_wait(1)`: it may return
    /// `ErrorKind::Interrupted` (EINTR) with the SQE already in flight.
    fn submit_and_wait_one(&mut self) -> io::Result<()>;

    /// Pop the next ready completion, or `None` if the completion queue is
    /// currently empty.
    fn next_completion(&mut self) -> Option<Completion>;
}

/// Result of [`write_all`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteOutcome {
    /// All `data.len()` bytes were written.
    Done,
}

/// Failure of [`write_all`] / [`write_all_to_fd`], carrying enough state for the
/// caller to decide whether a synchronous retry is safe.
///
/// The distinction matters for a packet-oriented fd (the TUN slow path, #2477):
/// a synchronous fallback must NEVER re-send a packet whose bytes the io_uring
/// path already placed on the device, or the TUN sees a truncated frame followed
/// by a duplicate full frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WriteError {
    /// Nothing was transferred — the io_uring path failed before (or while)
    /// putting any bytes on the fd (submit-queue full, the kernel completion
    /// reported an error, or a zero-byte completion). A synchronous retry from
    /// offset 0 is safe: no bytes are on the device yet.
    NothingWritten(String),
    /// Bytes were (or may have been) transferred and a retry would corrupt the
    /// stream. Two cases:
    ///   * a packet-fd short write — `0 < n < len` bytes are already on the TUN
    ///     as a truncated frame; re-sending the whole packet would duplicate it;
    ///   * an ambiguous submit/wait error after the SQE was submitted — the
    ///     write may be in flight, so a retry could double-transmit.
    /// The caller MUST drop the packet, never fall back to a synchronous write.
    Transferred(String),
}

impl WriteError {
    /// True when a synchronous retry from offset 0 is safe (nothing is on the
    /// fd yet). Only [`WriteError::NothingWritten`] qualifies.
    pub(crate) fn safe_to_retry(&self) -> bool {
        matches!(self, WriteError::NothingWritten(_))
    }

    pub(crate) fn message(&self) -> &str {
        match self {
            WriteError::NothingWritten(m) | WriteError::Transferred(m) => m,
        }
    }
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
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
        // SAFETY: `buf` outlives the completion. `write_all` does not return
        // until the matching CQE is reaped (the #2297 invariant), so the kernel
        // holds no dangling reference once we return to the caller.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| "io_uring submit queue full".to_string())
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

/// Write all of `data` to `fd` through `ring`, with the #2297 EINTR-retry /
/// stale-CQE-drain / buffer-lifetime guarantees. `positioned` selects a
/// file-offset write (regular file) vs. a stream write (TUN device).
///
/// Returns once every byte is written AND every SQE this call submitted has
/// been reaped, so `data` may be dropped safely on return.
///
/// On failure the [`WriteError`] reports whether a synchronous retry is safe —
/// see [`WriteError::safe_to_retry`] / #2477. The state writer ignores this
/// (it has no sync fallback); the TUN slow path uses it to avoid double-sending
/// a packet whose bytes are already on the device.
pub(crate) fn write_all_to_fd(
    ring: &mut IoUring,
    fd: i32,
    data: &[u8],
    positioned: bool,
    label: &str,
) -> Result<(), WriteError> {
    let mut port = IoUringPort { ring, fd };
    write_all(&mut port, data, positioned, label).map(|_| ())
}

/// Drive `port` to write all of `data`, advancing `offset` only by bytes a
/// completion that MATCHES our own submission reports. `positioned` selects a
/// file-offset write (state writer) vs. a stream write (TUN slow path).
///
/// Invariants this upholds (the #2297 fix):
///   * does not return while an SQE we submitted is still in flight — on any
///     submit/wait error we keep waiting until the matching CQE is reaped. The
///     one exception is the `MAX_WAIT_RETRIES` ceiling in [`reap_matching`],
///     which returns `Err` after thousands of consecutive interrupted/failed
///     waits to avoid wedging a worker forever; in that (astronomically rare)
///     case the SQE may still be outstanding when the buffer is dropped — the
///     same residual UAF window the pre-#2297 code always had, now bounded to a
///     storm that should never occur in practice rather than every EINTR;
///   * advances `offset` only by a CQE whose `user_data` matches the current
///     submission, so a stale leftover CQE cannot corrupt the offset;
///   * the caller's `data` buffer therefore outlives every kernel reference
///     except in the bounded ceiling case above.
pub(crate) fn write_all(
    port: &mut dyn RingPort,
    data: &[u8],
    positioned: bool,
    label: &str,
) -> Result<WriteOutcome, WriteError> {
    let mut offset = 0usize;
    // Distinct tag per submission. Start at 1 so a zero `user_data` (the value
    // an uninitialised / pre-existing CQE would carry) is never a valid match.
    let mut tag: u64 = 1;

    while offset < data.len() {
        let chunk = &data[offset..];
        let file_offset = if positioned { Some(offset as u64) } else { None };
        // A push failure means the SQE was never submitted — nothing is on the
        // fd, so a synchronous retry from offset 0 is safe (#2477). For a packet
        // fd this is always the first (only) chunk, so `offset == 0` and a
        // retry-from-0 is sound.
        port.push_write(tag, chunk, file_offset)
            .map_err(WriteError::NothingWritten)?;

        // Submit + reap exactly the completion for THIS submission. The
        // closure below loops on the wait so an EINTR (or any wait error) does
        // not leave the SQE outstanding. A reap error is AMBIGUOUS: the SQE was
        // already submitted, so the write may be in flight and a retry could
        // double-transmit on a packet fd — classify it as `Transferred` (drop,
        // never sync-retry).
        let res = reap_matching(port, tag, label).map_err(WriteError::Transferred)?;

        if res < 0 {
            // The kernel completion reported a write error: nothing was placed
            // on the fd, so a synchronous retry from offset 0 is safe.
            return Err(WriteError::NothingWritten(format!(
                "{label} io_uring write failed: {}",
                io::Error::from_raw_os_error(-res)
            )));
        }
        if res == 0 {
            // Zero bytes transferred — safe to retry synchronously.
            return Err(WriteError::NothingWritten(format!(
                "{label} io_uring short write: 0"
            )));
        }
        let n = res as usize;
        // A non-positioned (stream-mode) write targets a packet-oriented fd:
        // the TUN slow path (#2407). One submission is one L3 packet. A short
        // CQE count must NOT resubmit the remainder — re-writing `data[n..]`
        // would inject the leftover bytes as a SECOND, malformed packet. Treat
        // a partial as an unsendable packet and drop it (Err) — and because
        // `0 < n < len` bytes are ALREADY on the TUN, classify it as
        // `Transferred` so the caller does NOT fall back to a synchronous write
        // (which would re-send the whole packet → truncated frame + duplicate,
        // #2477). Positioned writes (a regular file — the state writer) are a
        // true byte stream and DO resume from `offset + n`.
        if !positioned && n < data.len() {
            return Err(WriteError::Transferred(format!(
                "{label} io_uring short write on packet fd: wrote {n} of {} bytes (packet dropped)",
                data.len()
            )));
        }
        offset += n;
        // Advance the tag so the next submission's CQE cannot be confused with
        // this one's (and a leftover CQE from this one cannot be reused).
        tag = tag.wrapping_add(1);
        if tag == 0 {
            tag = 1;
        }
    }
    Ok(WriteOutcome::Done)
}

/// True when `err` is a PERMANENT OS failure that a retry cannot recover from
/// (a bad/closed ring fd, an invalid argument, a faulting buffer). Retrying
/// these would just re-spin at 100% CPU through the `MAX_WAIT_RETRIES` ceiling
/// (#2478), so [`reap_matching`] returns immediately on them. EINTR/EAGAIN (and
/// any unrecognised errno) are treated as TRANSIENT and retried.
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
/// retrying the wait on `EINTR`/error so the in-flight SQE is never abandoned.
/// Stale completions (a different `user_data`, e.g. a leftover from a prior
/// interrupted call) are drained and discarded rather than mis-attributed.
///
/// A PERMANENT submit/wait error (bad ring fd, EINVAL, EFAULT, …) returns
/// immediately instead of re-spinning through `MAX_WAIT_RETRIES` at 100% CPU
/// (#2478); a TRANSIENT error yields the core before retrying.
fn reap_matching(port: &mut dyn RingPort, want: u64, label: &str) -> Result<i32, String> {
    // First, drain any already-ready stale completions so a leftover CQE from a
    // previously interrupted submission can never be returned as ours. At this
    // point the SQE for `want` has been pushed but NOT yet submitted/waited on,
    // so nothing in the completion queue can carry `want` — everything ready is
    // necessarily a leftover and safe to discard.
    drain_stale(port);

    // Bound the wait retries so a pathological always-EINTR storm cannot wedge
    // the worker forever. EINTR under normal signal pressure resolves in one or
    // two retries; this ceiling is generous.
    const MAX_WAIT_RETRIES: u32 = 4096;
    let mut waits = 0u32;

    loop {
        match port.submit_and_wait_one() {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                // EINTR: the SQE is already submitted (the enter syscall
                // flushed the SQ before sleeping). Retry the WAIT — the io-uring
                // crate recomputes to_submit from the now-empty SQ, so this is
                // wait-only and does not double-submit.
                waits += 1;
                if waits >= MAX_WAIT_RETRIES {
                    return Err(format!(
                        "{label} io_uring wait interrupted repeatedly ({waits} EINTR)"
                    ));
                }
                continue;
            }
            Err(err) => {
                // A PERMANENT error (bad/closed ring fd, EINVAL, EFAULT, …)
                // returns the SAME error on every retry. Looping on it just
                // burns a full core through the MAX_WAIT_RETRIES ceiling without
                // making progress (#2478) — fail fast instead. The caller drops
                // the packet; leaving the ring "desynchronised" is moot when the
                // ring fd itself is dead.
                if is_permanent(&err) {
                    return Err(format!(
                        "{label} io_uring permanent submit/wait error: {err}"
                    ));
                }
                // A TRANSIENT wait error (e.g. EAGAIN): the SQE may still be in
                // flight. Keep waiting for it to drain rather than returning and
                // leaving the ring desynchronised for the next write — but yield
                // the core first so a burst of transient failures does not
                // tight-spin at 100% CPU before the ceiling.
                std::thread::yield_now();
                waits += 1;
                if waits >= MAX_WAIT_RETRIES {
                    return Err(format!("{label} io_uring submit/wait: {err}"));
                }
                continue;
            }
        }

        // Reap whatever is ready, matching by user_data.
        while let Some(cqe) = port.next_completion() {
            if cqe.user_data == want {
                return Ok(cqe.result);
            }
            // Stale CQE from a prior interrupted submission — discard it.
        }
        // submit_and_wait(1) returned Ok but our completion was not among the
        // ready ones (only stale ones were). Wait again for ours.
        waits += 1;
        if waits >= MAX_WAIT_RETRIES {
            return Err(format!("{label} io_uring completion never matched"));
        }
    }
}

/// Discard every completion currently ready. Called by [`reap_matching`] only
/// at the point right after the current SQE is pushed but BEFORE it is submitted
/// or waited on, so no completion for the current tag can exist yet — everything
/// ready is necessarily a leftover from a prior interrupted call and is dropped
/// unconditionally. This is a full drain, not a keep-one-matching drain: there
/// is nothing to keep, and [`reap_matching`] re-checks `user_data` on the real
/// reap anyway, so a wrap-around tag collision is still caught there.
fn drain_stale(port: &mut dyn RingPort) {
    while let Some(_cqe) = port.next_completion() {
        // Drop stale completion.
    }
}

#[cfg(test)]
#[path = "io_uring_write_tests.rs"]
mod tests;
