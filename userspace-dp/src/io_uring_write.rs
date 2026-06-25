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
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Scripted fake ring. Each `submit_and_wait_one` consumes one entry from
    /// `wait_script`; on `Ok` it materialises the pending SQE's completion (with
    /// the configured `res`) into the ready queue. On `Err(EINTR)` it leaves the
    /// SQE in flight WITHOUT producing a completion — modelling the real kernel
    /// behaviour where the enter syscall already submitted the SQE but the wait
    /// was interrupted, so the completion surfaces on a later (retried) wait.
    struct FakeRing {
        /// Per-wait outcome: Ok(()) or Err(errno). Consumed front-to-back.
        wait_script: VecDeque<io::Result<()>>,
        /// res to report for the i-th SUCCESSFUL completion, consumed in order.
        results: VecDeque<i32>,
        /// SQEs submitted but whose completion has not yet been materialised.
        in_flight: VecDeque<u64>,
        /// Completions ready to be reaped.
        ready: VecDeque<Completion>,
        /// Number of `push_write` calls — i.e. SQEs submitted.
        push_calls: usize,
        /// `user_data` tags this fake itself materialised from `in_flight`
        /// (i.e. completions for SQEs we really submitted). A pre-seeded stale
        /// completion's tag is NOT in here, so we can tell, at reap time,
        /// whether a popped completion is a real one of ours.
        real_tags: std::collections::HashSet<u64>,
        /// Running total of `res` for REAL completions that the consumer popped
        /// and consumed. `reap_matching` discards non-matching (stale) CQEs and
        /// only ever advances `offset` by a CQE whose `user_data` matches its
        /// current tag — which is always one of `real_tags`. So this sum equals
        /// the byte total `write_all` actually applied to its offset.
        accepted_bytes: i64,
        /// Stale completions to inject AHEAD of the real one on the i-th
        /// SUCCESSFUL wait. Unlike `with_stale` (which pre-seeds the ready queue
        /// so `drain_stale` evicts it before the reap loop runs), these surface
        /// during the wait, so the leftover sits in the completion queue
        /// alongside the real CQE and the REAP-LOOP user_data match is what must
        /// skip it. `None` for a given wait injects nothing.
        stale_on_wait: VecDeque<Option<Completion>>,
        /// Number of `submit_and_wait_one` calls — the spin counter for #2478.
        /// A permanent error must return after exactly ONE wait, not loop to the
        /// `MAX_WAIT_RETRIES` ceiling.
        wait_calls: usize,
        /// When set, every wait beyond the scripted `wait_script` returns this
        /// errno (instead of materialising a completion). Models a ring fd that
        /// keeps returning the SAME error — the #2478 tight-spin condition.
        repeat_err: Option<i32>,
    }

    impl FakeRing {
        fn new(wait_script: Vec<io::Result<()>>, results: Vec<i32>) -> Self {
            Self {
                wait_script: wait_script.into_iter().collect(),
                results: results.into_iter().collect(),
                in_flight: VecDeque::new(),
                ready: VecDeque::new(),
                push_calls: 0,
                real_tags: std::collections::HashSet::new(),
                accepted_bytes: 0,
                stale_on_wait: VecDeque::new(),
                wait_calls: 0,
                repeat_err: None,
            }
        }

        /// Make every wait past the script return `errno` forever (no
        /// completion). Used to drive the #2478 permanent/transient spin tests.
        fn with_repeat_err(mut self, errno: i32) -> Self {
            self.repeat_err = Some(errno);
            self
        }

        fn with_stale(mut self, stale: Vec<Completion>) -> Self {
            self.ready.extend(stale);
            self
        }

        /// Inject a stale completion ahead of the real one on each successful
        /// wait. Entry `i` (a `Some(_)`) is pushed to the FRONT of the ready
        /// queue just before the i-th successful wait materialises its real CQE,
        /// so the reap loop encounters `[stale, real]` and must match on
        /// `user_data` to skip the stale. `None` injects nothing for that wait.
        fn with_stale_on_wait(mut self, stale: Vec<Option<Completion>>) -> Self {
            self.stale_on_wait = stale.into_iter().collect();
            self
        }

        /// Byte total of REAL (matched) completions the consumer accepted. A
        /// stale-CQE misattribution would show here as a wrong sum (e.g. the
        /// stale 9999) because only matched CQEs are supposed to advance offset.
        fn accepted_bytes(&self) -> i64 {
            self.accepted_bytes
        }

        /// On a successful wait: inject this wait's scripted stale CQE (if any)
        /// at the FRONT of the ready queue, then materialise one in-flight SQE's
        /// real completion at the BACK. The result is `[stale, real]` so the
        /// reap loop must skip the stale by `user_data` to find the real one.
        fn materialise_on_successful_wait(&mut self) {
            if let Some(Some(stale)) = self.stale_on_wait.pop_front() {
                self.ready.push_front(stale);
            }
            if let Some(ud) = self.in_flight.pop_front() {
                let res = self.results.pop_front().unwrap_or(0);
                self.real_tags.insert(ud);
                self.ready.push_back(Completion {
                    user_data: ud,
                    result: res,
                });
            }
        }
    }

    impl RingPort for FakeRing {
        fn push_write(
            &mut self,
            user_data: u64,
            _buf: &[u8],
            _offset: Option<u64>,
        ) -> Result<(), String> {
            self.push_calls += 1;
            self.in_flight.push_back(user_data);
            Ok(())
        }

        fn submit_and_wait_one(&mut self) -> io::Result<()> {
            self.wait_calls += 1;
            match self.wait_script.pop_front() {
                Some(Ok(())) => {
                    self.materialise_on_successful_wait();
                    Ok(())
                }
                Some(Err(e)) => Err(e),
                None => {
                    // Script exhausted: if a repeating errno was configured, keep
                    // returning it (no completion) so the caller's retry loop is
                    // exercised (#2478). Otherwise behave as a successful wait
                    // that materialises an in-flight completion if any, else Ok.
                    if let Some(errno) = self.repeat_err {
                        return Err(io::Error::from_raw_os_error(errno));
                    }
                    self.materialise_on_successful_wait();
                    Ok(())
                }
            }
        }

        fn next_completion(&mut self) -> Option<Completion> {
            let cqe = self.ready.pop_front();
            // Account a REAL (matched) completion as accepted. `reap_matching`
            // only ever advances `offset` by a CQE whose `user_data` matches its
            // tag, and a matching tag is always one we materialised, so summing
            // popped real completions equals the byte total applied to `offset`.
            // Stale (pre-seeded) completions are not in `real_tags` and so do
            // not contribute — exactly the misattribution this test guards.
            if let Some(c) = cqe {
                if self.real_tags.contains(&c.user_data) {
                    self.accepted_bytes += i64::from(c.result);
                }
            }
            cqe
        }
    }

    fn eintr() -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EINTR))
    }

    #[test]
    fn single_write_completes() {
        let mut ring = FakeRing::new(vec![Ok(())], vec![4]);
        let out = write_all(&mut ring, &[0u8; 4], false, "test").unwrap();
        assert_eq!(out, WriteOutcome::Done);
        assert_eq!(ring.push_calls, 1);
    }

    /// Positioned (regular-file / state-writer) stream write: a short count
    /// legitimately resumes from `offset + n` because a file IS a byte stream.
    #[test]
    fn positioned_short_write_advances_and_resubmits() {
        // First completion reports 2 of 4 bytes; second reports the remaining 2.
        let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![2, 2]);
        let out = write_all(&mut ring, &[0u8; 4], true, "state").unwrap();
        assert_eq!(out, WriteOutcome::Done);
        assert_eq!(ring.push_calls, 2);
    }

    /// #2407 fail-on-revert: a non-positioned (TUN, packet-oriented) write that
    /// reports a SHORT count must NOT resubmit the remainder — doing so would
    /// inject `data[n..]` as a second corrupt packet. It must return Err after
    /// exactly ONE push, never a second `data[n..]` write.
    ///
    /// If the packet-fd guard is reverted (the loop resumes from `offset + n`
    /// for non-positioned writes), the fake materialises the SECOND CQE (4),
    /// `push_calls` becomes 2, and the call returns Ok — both asserts fail.
    #[test]
    fn packet_short_write_drops_no_remainder_resubmit() {
        // Script a second successful wait + a second result so a (buggy)
        // resubmit WOULD succeed and complete — proving the guard, not a lack of
        // script, is what stops the corrupting remainder write.
        let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![2, 2]);
        let err = write_all(&mut ring, &[0u8; 4], false, "slow-path").unwrap_err();
        assert!(
            err.message().contains("short write on packet fd"),
            "partial packet write must be a drop, got: {err}"
        );
        // #2477: a packet-fd partial write put bytes on the TUN, so it MUST
        // classify as `Transferred` (NOT safe to retry) — otherwise the
        // slow-path caller would sync-retry and re-send the whole packet.
        assert!(
            matches!(err, WriteError::Transferred(_)),
            "a packet-fd partial write must be Transferred, got: {err:?}"
        );
        assert!(
            !err.safe_to_retry(),
            "a packet-fd partial write must NOT be safe to sync-retry (#2477)"
        );
        assert_eq!(
            ring.push_calls, 1,
            "a packet-fd short write must NOT resubmit the remainder (corruption)"
        );
        // Only the first (partial) CQE may have been accepted; the corrupting
        // second chunk's bytes must never be applied.
        assert_eq!(
            ring.accepted_bytes(),
            2,
            "no remainder bytes may be written after a partial packet write"
        );
    }

    /// A non-positioned FULL write still succeeds in one push (no regression).
    #[test]
    fn packet_full_write_succeeds() {
        let mut ring = FakeRing::new(vec![Ok(())], vec![4]);
        let out = write_all(&mut ring, &[0u8; 4], false, "slow-path").unwrap();
        assert_eq!(out, WriteOutcome::Done);
        assert_eq!(ring.push_calls, 1);
    }

    /// #2407: EINTR on a packet write retries the WAIT (not a re-push) and then
    /// reaps the full count — the whole packet is written with one submission.
    #[test]
    fn packet_eintr_retries_whole_no_corruption() {
        let mut ring = FakeRing::new(vec![eintr(), Ok(())], vec![4]);
        let out = write_all(&mut ring, &[0u8; 4], false, "slow-path").unwrap();
        assert_eq!(out, WriteOutcome::Done);
        assert_eq!(
            ring.push_calls, 1,
            "EINTR retry must be wait-only, never a remainder re-push"
        );
        assert_eq!(ring.accepted_bytes(), 4);
    }

    /// The core #2297 regression: an EINTR on the wait must NOT abandon the SQE
    /// and must NOT cause a stale/short offset. The retried wait reaps the real
    /// completion and the full byte count is applied.
    #[test]
    fn eintr_retries_wait_and_writes_full_count() {
        // wait #1 -> EINTR (SQE still in flight, no completion yet),
        // wait #2 -> Ok (completion for the same SQE, res = 8).
        let mut ring = FakeRing::new(vec![eintr(), Ok(())], vec![8]);
        let out = write_all(&mut ring, &[0u8; 8], false, "test").unwrap();
        assert_eq!(out, WriteOutcome::Done);
        // Exactly one SQE was pushed: the EINTR retry must be wait-only, never
        // a re-push (re-pushing would double-submit / double-count).
        assert_eq!(ring.push_calls, 1, "EINTR retry must not re-submit the SQE");
    }

    /// Counter-factual: prove the pre-fix behaviour WOULD corrupt the offset and
    /// that BOTH stale defences in the fix — the `drain_stale` pre-drain AND the
    /// `user_data` match inside the reap loop — genuinely matter. The buffer is
    /// two chunks (8 bytes, real results 4 then 4), so a CORRECT run pushes a
    /// SECOND SQE and applies exactly 8 bytes; a stale-CQE misattribution
    /// finishes in one push with an overshot offset.
    ///
    /// Two stale CQEs (`user_data = 999`, `res = 9999`) are placed to exercise
    /// each defence:
    ///   * one PRE-SEEDED in the ready queue (`with_stale`) — defended by the
    ///     `drain_stale` call at the top of `reap_matching`;
    ///   * one INJECTED ahead of the first real CQE DURING the wait
    ///     (`with_stale_on_wait`) — surfaces after `drain_stale` has run, so the
    ///     reap loop sees `[stale, real]` and ONLY the `user_data == want` match
    ///     stops it from returning the stale 9999.
    ///
    /// Fail-on-revert (verified): reverting `reap_matching` to reap the head CQE
    /// unconditionally (dropping the `user_data` match) makes the reap loop
    /// return the injected stale's `res = 9999`; `offset` jumps past the buffer,
    /// the loop ends after a SINGLE push, the second chunk is never written, and
    /// the real completion is abandoned. So buggy code yields `push_calls == 1`
    /// (assert wants 2) and an accepted-byte total that is not 8 — both fail.
    ///
    /// The fake also sums the `res` of every ACCEPTED (matched) completion so the
    /// test asserts the exact applied byte total, not just the push count: a
    /// misattribution shows up as a wrong running total even if the push count
    /// happened to coincide.
    #[test]
    fn stale_cqe_is_not_misattributed() {
        let stale = || Completion {
            user_data: 999, // not a tag this call will ever use
            result: 9999,
        };
        // Two-chunk write: real results 4 then 4. Both staged stale CQEs must be
        // skipped for the second push to ever happen.
        let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![4, 4])
            // Defended by drain_stale (already ready before the first wait).
            .with_stale(vec![stale()])
            // Defended by the reap-loop user_data match (surfaces during the
            // first wait, ahead of the real CQE).
            .with_stale_on_wait(vec![Some(stale()), None]);
        // Positioned (file/state-writer) write: a short count legitimately
        // resumes from offset+n, so the two-chunk resume here exercises the
        // stale-CQE defences across both pushes. (A non-positioned/TUN partial
        // would drop at the first chunk — that's the #2407 packet semantics,
        // covered by `packet_short_write_drops_no_remainder_resubmit`.)
        let out = write_all(&mut ring, &[0u8; 8], true, "test").unwrap();
        assert_eq!(out, WriteOutcome::Done);
        // A misattributed stale CQE (res=9999) would overshoot offset and finish
        // in ONE push; the correct path needs TWO.
        assert_eq!(
            ring.push_calls, 2,
            "stale CQE must be skipped; second chunk must still be written"
        );
        // The accepted completions must sum to exactly the buffer length — never
        // the stale 9999 — proving only our own CQEs advanced the offset.
        assert_eq!(
            ring.accepted_bytes(),
            8,
            "only matched CQEs (4 + 4) may advance the offset; stale 9999 excluded"
        );
    }

    /// A write error (negative res) surfaces as Err, not a silent advance.
    #[test]
    fn negative_result_is_error() {
        let mut ring = FakeRing::new(vec![Ok(())], vec![-libc::EIO]);
        let err = write_all(&mut ring, &[0u8; 4], false, "test").unwrap_err();
        assert!(err.message().contains("io_uring write failed"), "got: {err}");
        // The kernel completion errored — nothing reached the fd, so a
        // synchronous retry from offset 0 is safe (#2477).
        assert!(
            err.safe_to_retry(),
            "a kernel completion error transferred nothing; sync-retry must be safe"
        );
    }

    /// res == 0 is a short write and must be an error, not an infinite loop.
    #[test]
    fn zero_result_is_short_write_error() {
        let mut ring = FakeRing::new(vec![Ok(())], vec![0]);
        let err = write_all(&mut ring, &[0u8; 4], false, "test").unwrap_err();
        assert!(err.message().contains("short write"), "got: {err}");
        // Zero bytes transferred — safe to retry synchronously (#2477).
        assert!(err.safe_to_retry(), "a zero-byte completion must be safe to retry");
    }

    /// Several EINTRs in a row still converge — the loop keeps waiting.
    #[test]
    fn repeated_eintr_eventually_completes() {
        let mut ring = FakeRing::new(vec![eintr(), eintr(), eintr(), Ok(())], vec![16]);
        let out = write_all(&mut ring, &[0u8; 16], false, "test").unwrap();
        assert_eq!(out, WriteOutcome::Done);
        assert_eq!(ring.push_calls, 1);
    }

    /// Positioned writes (state writer) advance the file offset across chunks.
    #[test]
    fn positioned_multi_chunk() {
        let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![3, 3]);
        let out = write_all(&mut ring, &[0u8; 6], true, "state").unwrap();
        assert_eq!(out, WriteOutcome::Done);
        assert_eq!(ring.push_calls, 2);
    }

    fn os_err(errno: i32) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(errno))
    }

    /// #2478 errno classification: the permanent set returns from the retry
    /// loop, the transient set keeps retrying.
    #[test]
    fn is_permanent_classifies_errnos() {
        for e in [
            libc::EBADF,
            libc::EINVAL,
            libc::EFAULT,
            libc::ENXIO,
            libc::EBADFD,
            libc::ENODEV,
            libc::EOPNOTSUPP,
            libc::EPERM,
        ] {
            assert!(
                is_permanent(&io::Error::from_raw_os_error(e)),
                "errno {e} must be permanent"
            );
        }
        for e in [libc::EINTR, libc::EAGAIN] {
            assert!(
                !is_permanent(&io::Error::from_raw_os_error(e)),
                "errno {e} must be transient"
            );
        }
        // A non-OS io::Error has no errno — treated as transient (bounded by the
        // retry ceiling) rather than misclassified as permanent.
        assert!(!is_permanent(&io::Error::new(io::ErrorKind::Other, "no errno")));
    }

    /// #2478 fail-on-revert: a PERMANENT submit/wait error (EBADF) must return
    /// after exactly ONE `submit_and_wait_one` call — never tight-spin up to the
    /// MAX_WAIT_RETRIES (4096) ceiling at 100% CPU.
    ///
    /// `repeat_err` makes every wait return EBADF forever. With the old
    /// unconditional-retry arm, `wait_calls` would reach 4096 before the ceiling
    /// gives up (the assert `== 1` fails). With the fix, `is_permanent(EBADF)`
    /// returns immediately on the first wait.
    #[test]
    fn permanent_error_returns_without_spinning() {
        let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EBADF);
        let err = write_all(&mut ring, &[0u8; 4], false, "slow-path").unwrap_err();
        assert!(
            err.message().contains("permanent submit/wait error"),
            "got: {err}"
        );
        // The single load-bearing assertion: ONE wait, not 4096.
        assert_eq!(
            ring.wait_calls, 1,
            "a permanent error must fail fast after one wait, not spin to the ceiling"
        );
        // A permanent submit/wait error is ambiguous about the SQE, so it is
        // `Transferred` (no sync-retry) — consistent with the #2477 contract.
        assert!(matches!(err, WriteError::Transferred(_)));
    }

    /// #2478 complement: a TRANSIENT error (EAGAIN) is NOT permanent, so the loop
    /// keeps retrying and DOES reach the MAX_WAIT_RETRIES ceiling rather than
    /// returning on the first wait. This proves the classification actually
    /// gates the behaviour (and that transient errors are not fast-failed).
    #[test]
    fn transient_error_retries_to_ceiling() {
        let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EAGAIN);
        let err = write_all(&mut ring, &[0u8; 4], false, "slow-path").unwrap_err();
        assert!(err.message().contains("submit/wait"), "got: {err}");
        // It looped to the ceiling (4096) rather than bailing on wait #1.
        assert!(
            ring.wait_calls >= 4096,
            "a transient error must keep retrying to the ceiling, got {} waits",
            ring.wait_calls
        );
    }

    /// A single EINTR followed by a permanent EBADF returns on the permanent
    /// error — EINTR retried (wait #1), EBADF fast-failed (wait #2). Confirms the
    /// permanent check sits on the catch-all arm, not the EINTR arm.
    #[test]
    fn eintr_then_permanent_returns_promptly() {
        let mut ring = FakeRing::new(vec![os_err(libc::EINTR)], vec![]).with_repeat_err(libc::EBADF);
        let err = write_all(&mut ring, &[0u8; 4], false, "slow-path").unwrap_err();
        assert!(err.message().contains("permanent submit/wait error"), "got: {err}");
        assert_eq!(
            ring.wait_calls, 2,
            "EINTR retries once, then the permanent EBADF fast-fails — two waits total"
        );
    }
}
