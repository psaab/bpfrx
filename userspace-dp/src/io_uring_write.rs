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
pub(crate) fn write_all_to_fd(
    ring: &mut IoUring,
    fd: i32,
    data: &[u8],
    positioned: bool,
    label: &str,
) -> Result<(), String> {
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
) -> Result<WriteOutcome, String> {
    let mut offset = 0usize;
    // Distinct tag per submission. Start at 1 so a zero `user_data` (the value
    // an uninitialised / pre-existing CQE would carry) is never a valid match.
    let mut tag: u64 = 1;

    while offset < data.len() {
        let chunk = &data[offset..];
        let file_offset = if positioned { Some(offset as u64) } else { None };
        port.push_write(tag, chunk, file_offset)?;

        // Submit + reap exactly the completion for THIS submission. The
        // closure below loops on the wait so an EINTR (or any wait error) does
        // not leave the SQE outstanding.
        let res = reap_matching(port, tag, label)?;

        if res < 0 {
            return Err(format!(
                "{label} io_uring write failed: {}",
                io::Error::from_raw_os_error(-res)
            ));
        }
        if res == 0 {
            return Err(format!("{label} io_uring short write: 0"));
        }
        offset += res as usize;
        // Advance the tag so the next submission's CQE cannot be confused with
        // this one's (and a leftover CQE from this one cannot be reused).
        tag = tag.wrapping_add(1);
        if tag == 0 {
            tag = 1;
        }
    }
    Ok(WriteOutcome::Done)
}

/// Submit the queued SQE and reap the completion whose `user_data == want`,
/// retrying the wait on `EINTR`/error so the in-flight SQE is never abandoned.
/// Stale completions (a different `user_data`, e.g. a leftover from a prior
/// interrupted call) are drained and discarded rather than mis-attributed.
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
                // Any other wait error: the SQE may still be in flight. Keep
                // waiting for it to drain rather than returning and leaving the
                // ring desynchronised for the next write.
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
            }
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
            match self.wait_script.pop_front() {
                Some(Ok(())) => {
                    self.materialise_on_successful_wait();
                    Ok(())
                }
                Some(Err(e)) => Err(e),
                None => {
                    // No more script: behave as a successful wait that
                    // materialises an in-flight completion if any, else Ok.
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

    #[test]
    fn short_write_advances_and_resubmits() {
        // First completion reports 2 of 4 bytes; second reports the remaining 2.
        let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![2, 2]);
        let out = write_all(&mut ring, &[0u8; 4], false, "test").unwrap();
        assert_eq!(out, WriteOutcome::Done);
        assert_eq!(ring.push_calls, 2);
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
        let out = write_all(&mut ring, &[0u8; 8], false, "test").unwrap();
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
        assert!(err.contains("io_uring write failed"), "got: {err}");
    }

    /// res == 0 is a short write and must be an error, not an infinite loop.
    #[test]
    fn zero_result_is_short_write_error() {
        let mut ring = FakeRing::new(vec![Ok(())], vec![0]);
        let err = write_all(&mut ring, &[0u8; 4], false, "test").unwrap_err();
        assert!(err.contains("short write"), "got: {err}");
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
}
