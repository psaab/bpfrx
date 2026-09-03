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
    /// Number of `push_write` calls — i.e. write SQEs submitted.
    push_calls: usize,
    /// Byte length handed to each `push_write`, in order. #7751 row 12: lets a
    /// test assert the per-SQE clamp actually SPLIT the buffer. `push_calls`
    /// alone cannot discriminate — the UNCLAMPED path also pushes twice,
    /// because its first completion is short and the loop pushes the remainder
    /// anyway. Only the recorded lengths differ.
    push_lens: Vec<usize>,
    /// Number of `push_cancel` calls.
    cancel_calls: usize,
    /// Recorded (cancel_id, target) pairs for every `push_cancel` — lets a test
    /// assert the drain cancelled the exact deferred write id (#5800).
    cancels: Vec<(u64, u64)>,
    /// When true (default), a `push_cancel` also materialises the TARGET write's
    /// terminal CQE (modelling the kernel completing a cancelled op) so the
    /// drain can release it. When false, only the cancel's OWN completion
    /// surfaces on `push_cancel` — the target write's terminal CQE must arrive
    /// separately (a later successful wait), modelling a cancellation RACE where
    /// the cancel completes before the write does.
    cancel_completes_target: bool,
    /// `user_data` tags this fake itself materialised (real completions for SQEs
    /// we really submitted). A pre-seeded stale completion's tag is NOT in here,
    /// so a reaped popped completion can be told apart from a stale.
    real_tags: std::collections::HashSet<u64>,
    /// Running total of `res` for REAL completions the consumer popped. Because
    /// `reap_matching` only advances `offset` by a CQE whose `user_data` matches
    /// its current tag (always one of `real_tags`), this equals the byte total
    /// `write_all` actually applied to its offset.
    accepted_bytes: i64,
    /// Stale completions to inject AHEAD of the real one on the i-th SUCCESSFUL
    /// wait (surfaces alongside the real CQE so the REAP-LOOP user_data match is
    /// what must skip it). `None` for a given wait injects nothing.
    stale_on_wait: VecDeque<Option<Completion>>,
    /// Number of `submit_and_wait_one` calls — the spin counter for #2478.
    wait_calls: usize,
    /// When set, every wait beyond the scripted `wait_script` returns this errno
    /// (instead of materialising a completion). Models a ring fd that keeps
    /// returning the SAME error — the #2478 tight-spin / #5800 stuck-ring case.
    repeat_err: Option<i32>,
    /// Completions QUEUED by `push_cancel` but not yet reapable: a cancel is only
    /// submitted (and its completion reaped) by a subsequent SUCCESSFUL
    /// `submit_and_wait_one`. They flush into `ready` on the next successful wait.
    /// A fatal ring (whose every wait returns a permanent error) therefore never
    /// surfaces them — so `drain_for_teardown` cannot "reap" a completion the real
    /// kernel could not, and the parked buffer is correctly retained.
    pending_cqes: VecDeque<Completion>,
}

impl FakeRing {
    fn new(wait_script: Vec<io::Result<()>>, results: Vec<i32>) -> Self {
        Self {
            wait_script: wait_script.into_iter().collect(),
            results: results.into_iter().collect(),
            in_flight: VecDeque::new(),
            ready: VecDeque::new(),
            push_calls: 0,
            push_lens: Vec::new(),
            cancel_calls: 0,
            cancels: Vec::new(),
            cancel_completes_target: true,
            real_tags: std::collections::HashSet::new(),
            accepted_bytes: 0,
            stale_on_wait: VecDeque::new(),
            wait_calls: 0,
            repeat_err: None,
            pending_cqes: VecDeque::new(),
        }
    }

    /// Make every wait past the script return `errno` forever (no completion).
    /// Drives the #2478 permanent/transient spin tests and the #5800 stuck-ring
    /// deferral tests.
    fn with_repeat_err(mut self, errno: i32) -> Self {
        self.repeat_err = Some(errno);
        self
    }

    fn with_stale(mut self, stale: Vec<Completion>) -> Self {
        self.ready.extend(stale);
        self
    }

    fn with_stale_on_wait(mut self, stale: Vec<Option<Completion>>) -> Self {
        self.stale_on_wait = stale.into_iter().collect();
        self
    }

    /// Cancellation-race mode: a `push_cancel` surfaces ONLY the cancel's own
    /// completion; the target write's terminal CQE must arrive on a later wait.
    fn cancel_leaves_target_inflight(mut self) -> Self {
        self.cancel_completes_target = false;
        self
    }

    fn accepted_bytes(&self) -> i64 {
        self.accepted_bytes
    }

    /// Materialise the terminal CQE for every still-in-flight SQE (result `res`),
    /// as a REAL completion. Test helper to drive a deferred write to a terminal
    /// state after `write_all` parked it — the completion the retried/stuck wait
    /// never surfaced now becomes reapable via `reap_ready`.
    fn complete_inflight_now(&mut self, res: i32) {
        while let Some(ud) = self.in_flight.pop_front() {
            self.real_tags.insert(ud);
            self.ready.push_back(Completion {
                user_data: ud,
                result: res,
            });
        }
    }

    /// On a successful wait: inject this wait's scripted stale CQE (if any) at
    /// the FRONT of the ready queue, then materialise one in-flight SQE's real
    /// completion at the BACK — `[stale, real]` so the reap loop must skip the
    /// stale by `user_data`.
    fn materialise_on_successful_wait(&mut self) {
        // A successful wait actually submits/reaps: flush any cancel/terminal
        // CQEs queued by `push_cancel` (their completions surface only now).
        while let Some(cqe) = self.pending_cqes.pop_front() {
            self.ready.push_back(cqe);
        }
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
        buf: &[u8],
        _offset: Option<u64>,
    ) -> Result<(), String> {
        self.push_calls += 1;
        self.push_lens.push(buf.len());
        self.in_flight.push_back(user_data);
        Ok(())
    }

    fn push_cancel(&mut self, user_data: u64, target: u64) -> Result<(), String> {
        self.cancel_calls += 1;
        self.cancels.push((user_data, target));
        // The cancel op is only SUBMITTED — and its completion only reapable — by
        // a later SUCCESSFUL wait. Queue it as pending rather than making it
        // immediately ready, so a fatal ring (every wait errors) never surfaces
        // it (the parked buffer is retained, not released).
        self.pending_cqes.push_back(Completion {
            user_data,
            result: 0,
        });
        if self.cancel_completes_target {
            // Model the kernel completing the cancelled write: pull the target
            // out of in_flight and QUEUE its terminal CQE (result -ECANCELED),
            // also surfaced only on the next successful wait.
            if let Some(pos) = self.in_flight.iter().position(|id| *id == target) {
                self.in_flight.remove(pos);
                self.real_tags.insert(target);
                self.pending_cqes.push_back(Completion {
                    user_data: target,
                    result: -libc::ECANCELED,
                });
            }
        }
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
        if let Some(c) = cqe {
            if self.real_tags.contains(&c.user_data) && c.result > 0 {
                self.accepted_bytes += i64::from(c.result);
            }
        }
        cqe
    }
}

fn eintr() -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::EINTR))
}

fn os_err(errno: i32) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(errno))
}

// ---------------------------------------------------------------------------
// Healthy-path / #2297 / #2407 / #2477 behaviour (adapted to WriteResult)
// ---------------------------------------------------------------------------

#[test]
fn single_write_completes() {
    let mut ring = FakeRing::new(vec![Ok(())], vec![4]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "test");
    assert!(matches!(out, WriteResult::Done(_)));
    assert_eq!(ring.push_calls, 1);
    assert_eq!(reg.inflight_len(), 0, "a completed write parks nothing");
}

/// Positioned (regular-file / state-writer) stream write: a short count
/// legitimately resumes from `offset + n` because a file IS a byte stream.
#[test]
fn positioned_short_write_advances_and_resubmits() {
    let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![2, 2]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], true, "state");
    assert!(matches!(out, WriteResult::Done(_)));
    assert_eq!(ring.push_calls, 2);
}

/// #2407 fail-on-revert: a non-positioned (TUN) write that reports a SHORT
/// count must NOT resubmit the remainder — it returns `Transferred` after
/// exactly ONE push.
#[test]
fn packet_short_write_drops_no_remainder_resubmit() {
    let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![2, 2]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    match &out {
        WriteResult::Transferred(_buf, msg) => {
            assert!(
                msg.contains("short write on packet fd"),
                "partial packet write must be a drop, got: {msg}"
            );
        }
        other => panic!("a packet-fd partial write must be Transferred, got: {other:?}"),
    }
    assert_eq!(
        ring.push_calls, 1,
        "a packet-fd short write must NOT resubmit the remainder (corruption)"
    );
    assert_eq!(
        ring.accepted_bytes(),
        2,
        "no remainder bytes may be written after a partial packet write"
    );
    assert_eq!(reg.inflight_len(), 0, "a reaped partial parks nothing");
}

/// A non-positioned FULL write still succeeds in one push (no regression).
#[test]
fn packet_full_write_succeeds() {
    let mut ring = FakeRing::new(vec![Ok(())], vec![4]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    assert!(matches!(out, WriteResult::Done(_)));
    assert_eq!(ring.push_calls, 1);
}

/// #2407: EINTR on a packet write retries the WAIT (not a re-push) and then
/// reaps the full count.
#[test]
fn packet_eintr_retries_whole_no_corruption() {
    let mut ring = FakeRing::new(vec![eintr(), Ok(())], vec![4]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    assert!(matches!(out, WriteResult::Done(_)));
    assert_eq!(
        ring.push_calls, 1,
        "EINTR retry must be wait-only, never a remainder re-push"
    );
    assert_eq!(ring.accepted_bytes(), 4);
    assert_eq!(reg.inflight_len(), 0);
}

/// The core #2297 regression: an EINTR on the wait must NOT abandon the SQE and
/// must NOT cause a stale/short offset.
#[test]
fn eintr_retries_wait_and_writes_full_count() {
    let mut ring = FakeRing::new(vec![eintr(), Ok(())], vec![8]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 8], false, "test");
    assert!(matches!(out, WriteResult::Done(_)));
    assert_eq!(ring.push_calls, 1, "EINTR retry must not re-submit the SQE");
}

/// Counter-factual: prove BOTH stale defences — the `reap_ready` pre-drain AND
/// the `user_data` match inside the reap loop — genuinely matter. Two stale
/// CQEs (`user_data = 999`, `res = 9999`) are placed to exercise each defence.
#[test]
fn stale_cqe_is_not_misattributed() {
    let stale = || Completion {
        user_data: 999,
        result: 9999,
    };
    let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![4, 4])
        // Defended by the `reap_ready` pre-drain (already ready before the write).
        .with_stale(vec![stale()])
        // Defended by the reap-loop user_data match (surfaces during the first
        // wait, ahead of the real CQE).
        .with_stale_on_wait(vec![Some(stale()), None]);
    let mut reg = InflightRegistry::new();
    // Positioned write: a short count legitimately resumes, so the two-chunk
    // resume exercises the stale-CQE defences across both pushes.
    let out = write_all(&mut ring, &mut reg, vec![0u8; 8], true, "test");
    assert!(matches!(out, WriteResult::Done(_)));
    assert_eq!(
        ring.push_calls, 2,
        "stale CQE must be skipped; second chunk must still be written"
    );
    assert_eq!(
        ring.accepted_bytes(),
        8,
        "only matched CQEs (4 + 4) may advance the offset; stale 9999 excluded"
    );
}

/// A write error (negative res) surfaces as NothingWritten (safe to sync-retry).
#[test]
fn negative_result_is_nothing_written() {
    let mut ring = FakeRing::new(vec![Ok(())], vec![-libc::EIO]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "test");
    match out {
        WriteResult::NothingWritten(_buf, msg) => {
            assert!(msg.contains("io_uring write failed"), "got: {msg}");
        }
        other => panic!("a kernel completion error must be NothingWritten, got: {other:?}"),
    }
    assert_eq!(reg.inflight_len(), 0);
}

/// res == 0 is a short write → NothingWritten, not an infinite loop.
#[test]
fn zero_result_is_nothing_written() {
    let mut ring = FakeRing::new(vec![Ok(())], vec![0]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "test");
    assert!(
        matches!(out, WriteResult::NothingWritten(_, ref m) if m.contains("short write")),
        "got: {out:?}"
    );
}

#[test]
fn repeated_eintr_eventually_completes() {
    let mut ring = FakeRing::new(vec![eintr(), eintr(), eintr(), Ok(())], vec![16]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 16], false, "test");
    assert!(matches!(out, WriteResult::Done(_)));
    assert_eq!(ring.push_calls, 1);
    assert_eq!(reg.inflight_len(), 0);
}

#[test]
fn positioned_multi_chunk() {
    let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![3, 3]);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 6], true, "state");
    assert!(matches!(out, WriteResult::Done(_)));
    assert_eq!(ring.push_calls, 2);
}

// ---------------------------------------------------------------------------
// #2478 errno classification (retained), now feeding the #5800 deferral
// ---------------------------------------------------------------------------

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
    assert!(!is_permanent(&io::Error::new(io::ErrorKind::Other, "no errno")));
}

// ---------------------------------------------------------------------------
// #5800 — retry exhaustion / fatal ring DEFER the owned buffer, never free it
// ---------------------------------------------------------------------------

/// #5800 fail-on-revert (the core regression): a repeated-EINTR storm that hits
/// the `MAX_WAIT_RETRIES` ceiling must NOT free the buffer. `write_all` returns
/// `Deferred` only after the owned buffer has moved into the registry, so the
/// buffer stays OWNED (inflight_len == 1) until a later terminal completion.
///
/// This binds `reg.defer(slot)` in `write_all`'s reap-error arm. Neutralising
/// that line (e.g. `drop(slot)` in place of `reg.defer(slot)`) frees the buffer
/// at exhaustion, so `inflight_len` is 0 and BOTH asserts below go RED as clean
/// assertion failures.
#[test]
fn eintr_ceiling_defers_buffer_not_freed() {
    let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EINTR);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    match &out {
        WriteResult::Deferred {
            fatal_ring,
            message,
            ..
        } => {
            assert!(!fatal_ring, "an EINTR storm is not a fatal ring");
            assert!(message.contains("interrupted"), "got: {message}");
        }
        other => panic!("retry-ceiling exhaustion must Defer the buffer, got: {other:?}"),
    }
    assert_eq!(
        reg.inflight_len(),
        1,
        "the owned buffer must remain in the registry after ceiling exhaustion (not freed)"
    );
    assert_eq!(
        ring.wait_calls,
        super::MAX_WAIT_RETRIES as usize,
        "the EINTR ceiling bounds the wait, exactly MAX_WAIT_RETRIES"
    );
}

/// #5800: after the buffer is deferred, a later terminal completion releases it
/// — the deferred buffer stays owned right up until its CQE is reaped. This is
/// the "held until terminal completion/teardown" half of the invariant.
#[test]
fn deferred_buffer_released_on_terminal_completion() {
    let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EINTR);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    assert!(matches!(out, WriteResult::Deferred { .. }));
    assert_eq!(reg.inflight_len(), 1, "buffer owned after exhaustion");

    // The write's terminal CQE finally surfaces (the storm cleared). A plain
    // reap_ready (no submit_and_wait) must release the buffer.
    ring.complete_inflight_now(4);
    reg.reap_ready(&mut ring);
    assert_eq!(
        reg.inflight_len(),
        0,
        "the deferred buffer must be released once its terminal CQE is reaped"
    );
}

/// #5800: repeated TRANSIENT errors (EAGAIN) also defer (never free). The ring
/// is not fatal, so `fatal_ring == false` and the wait loops to the ceiling.
#[test]
fn transient_error_ceiling_defers_buffer() {
    let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EAGAIN);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    match &out {
        WriteResult::Deferred { fatal_ring, .. } => assert!(!fatal_ring),
        other => panic!("a transient-error ceiling must Defer, got: {other:?}"),
    }
    assert_eq!(reg.inflight_len(), 1, "transient exhaustion must not free the buffer");
    assert!(
        ring.wait_calls >= super::MAX_WAIT_RETRIES as usize,
        "a transient error retries to the ceiling, got {} waits",
        ring.wait_calls
    );
}

/// #5800 + #2478: a PERMANENT submit/wait error (EBADF) fast-fails after exactly
/// ONE wait AND retains the buffer with `fatal_ring = true` (the caller tears
/// the ring down). The #2478 fast-fail must not free the buffer.
#[test]
fn permanent_error_defers_buffer_and_fast_fails() {
    let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EBADF);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    match &out {
        WriteResult::Deferred {
            fatal_ring,
            message,
            ..
        } => {
            assert!(fatal_ring, "a permanent ring error must mark fatal_ring");
            assert!(message.contains("permanent submit/wait error"), "got: {message}");
        }
        other => panic!("a permanent error must Defer with fatal_ring, got: {other:?}"),
    }
    assert_eq!(
        ring.wait_calls, 1,
        "a permanent error must fail fast after one wait, not spin to the ceiling (#2478)"
    );
    assert_eq!(
        reg.inflight_len(),
        1,
        "a permanent error must RETAIN the in-flight buffer pending teardown (#5800)"
    );
}

/// A single EINTR then a permanent EBADF: EINTR retried (wait #1), EBADF
/// fast-failed (wait #2). Confirms the permanent check sits on the catch-all
/// arm and still defers the buffer.
#[test]
fn eintr_then_permanent_defers_promptly() {
    let mut ring = FakeRing::new(vec![os_err(libc::EINTR)], vec![]).with_repeat_err(libc::EBADF);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    assert!(matches!(out, WriteResult::Deferred { fatal_ring: true, .. }));
    assert_eq!(ring.wait_calls, 2, "EINTR retries once, then EBADF fast-fails");
    assert_eq!(reg.inflight_len(), 1);
}

// ---------------------------------------------------------------------------
// #5800 — ring-global id uniqueness + fail-closed wrap (invariant 3)
// ---------------------------------------------------------------------------

/// #5800: `user_data` is ring-global and monotonic — it does NOT restart per
/// call, so a leftover CQE from an earlier call cannot alias a later call.
#[test]
fn user_data_is_ring_global_monotonic() {
    let mut reg = InflightRegistry::new();
    assert_eq!(reg.alloc_id(), Some(1));
    assert_eq!(reg.alloc_id(), Some(2));

    // Two successive single-byte writes on the SAME registry must draw DISTINCT
    // ids (3 then 4), not both restart at 1.
    let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![1, 1]);
    let _ = write_all(&mut ring, &mut reg, vec![0u8; 1], false, "a");
    let _ = write_all(&mut ring, &mut reg, vec![0u8; 1], false, "b");
    assert_eq!(reg.alloc_id(), Some(5), "ids must keep advancing across calls");
}

/// #5800 fail-on-revert (invariant 3): the id space is fail-closed at the wrap
/// boundary. `alloc_id` hands out u64::MAX, then refuses (None) rather than wrap
/// back through 0 and reuse a possibly-live id.
#[test]
fn alloc_id_fails_closed_on_wrap() {
    let mut reg = InflightRegistry::new();
    reg.next_id = u64::MAX;
    assert_eq!(reg.alloc_id(), Some(u64::MAX), "the last id is handed out");
    assert_eq!(reg.next_id, 0, "the counter wraps to the exhausted sentinel");
    assert_eq!(reg.alloc_id(), None, "exhausted: must fail closed, never reuse");
    assert_eq!(reg.alloc_id(), None, "stays exhausted");
}

/// #5800: when the id space is exhausted, `write_all` fails closed WITHOUT
/// submitting anything — nothing reaches the fd (NothingWritten, push_calls 0).
#[test]
fn write_all_fails_closed_when_id_space_exhausted() {
    let mut ring = FakeRing::new(vec![Ok(())], vec![4]);
    let mut reg = InflightRegistry::new();
    reg.next_id = 0; // pretend the space is already exhausted
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "test");
    assert!(
        matches!(out, WriteResult::NothingWritten(_, ref m) if m.contains("space exhausted")),
        "got: {out:?}"
    );
    assert_eq!(ring.push_calls, 0, "an exhausted id space must not submit an SQE");
}

// ---------------------------------------------------------------------------
// #5800 — teardown drain + cancellation (the synchronous proof path)
// ---------------------------------------------------------------------------

/// #5800: `drain_for_teardown` submits an AsyncCancel for each deferred write id
/// and releases its buffer once the target write's terminal CQE is reaped.
#[test]
fn drain_cancels_and_releases_deferred_buffer() {
    let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EINTR);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    let deferred_id = match out {
        WriteResult::Deferred { id, .. } => id,
        other => panic!("expected Deferred, got: {other:?}"),
    };
    assert_eq!(reg.inflight_len(), 1);

    // The EINTR storm cleared: give the teardown drain a successful wait so its
    // submitted cancel — and the target write's terminal CQE — can be reaped
    // (a real cancel completes only once a wait submits it).
    ring.repeat_err = None;

    let released = reg.drain_for_teardown(&mut ring);
    assert_eq!(released, 1, "drain must release the one deferred buffer");
    assert_eq!(reg.inflight_len(), 0, "no buffer may survive a completed drain");
    assert_eq!(ring.cancel_calls, 1, "drain must submit exactly one cancel");
    assert_eq!(
        ring.cancels[0].1, deferred_id,
        "the cancel must target the exact deferred write id"
    );
}

/// #5800 (cancellation race): observing the CANCEL's completion alone must NOT
/// release the buffer — only the TARGET write's terminal CQE does. With the
/// cancel completing first, the buffer stays owned until the write CQE arrives.
///
/// `release_matching` is the release predicate: it matches only WRITE ids, so a
/// cancel id leaves the entry owned; the write id releases it.
#[test]
fn cancel_completion_alone_does_not_release() {
    let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EINTR);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    let write_id = match out {
        WriteResult::Deferred { id, .. } => id,
        other => panic!("expected Deferred, got: {other:?}"),
    };
    // A cancel id (not a write id) must not release the entry.
    let cancel_id = 999_999u64;
    assert!(!reg.release_matching(cancel_id), "a cancel CQE matches no write id");
    assert_eq!(
        reg.inflight_len(),
        1,
        "the cancel's own completion must NOT release the buffer (invariant 2)"
    );
    // The target write's terminal CQE releases it.
    assert!(reg.release_matching(write_id), "the write's terminal CQE releases it");
    assert_eq!(reg.inflight_len(), 0);
}

/// #5800 (cancellation race via the real drain): even when the cancel CQE
/// surfaces BEFORE the target write's terminal CQE, the drain releases the
/// buffer only after the write CQE arrives (on a later wait), never on the
/// cancel alone.
#[test]
fn drain_waits_for_target_cqe_not_just_cancel() {
    let mut ring = FakeRing::new(vec![], vec![])
        // Storm to force the defer, and a race where the cancel completes first.
        .with_repeat_err(libc::EINTR)
        .cancel_leaves_target_inflight();
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    assert!(matches!(out, WriteResult::Deferred { .. }));

    // repeat_err(EINTR) would keep the drain waiting forever, so clear it: the
    // drain's first wait then materialises the still-in-flight target write's
    // terminal CQE, which is what actually releases the buffer.
    ring.repeat_err = None;
    ring.wait_script.push_back(Ok(()));

    let released = reg.drain_for_teardown(&mut ring);
    assert_eq!(released, 1, "the buffer is released on the target write's CQE");
    assert_eq!(reg.inflight_len(), 0);
    assert_eq!(ring.cancel_calls, 1, "the drain cancelled the deferred write");
}

/// #5800: a FATAL ring cannot be drained (every wait returns the permanent
/// error), so `drain_for_teardown` RETAINS the buffer — it is never freed early.
/// The straggler is freed only when the registry itself drops, which
/// `RingWriter`'s field order puts after the ring fd close (#6168: a best-effort
/// narrowing of the window, not a proof the kernel is done). What THIS test
/// binds is the retain: a fatal ring must never release a buffer it cannot
/// prove terminal.
#[test]
fn fatal_ring_drain_retains_buffer() {
    let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EBADF);
    let mut reg = InflightRegistry::new();
    let out = write_all(&mut ring, &mut reg, vec![0u8; 4], false, "slow-path");
    assert!(matches!(out, WriteResult::Deferred { fatal_ring: true, .. }));
    assert_eq!(reg.inflight_len(), 1);

    let released = reg.drain_for_teardown(&mut ring);
    assert_eq!(released, 0, "a fatal ring cannot prove release — retain the buffer");
    assert_eq!(
        reg.inflight_len(),
        1,
        "the buffer is retained until teardown/registry-drop, never freed early"
    );
}

/// A drain with nothing in flight is a no-op (no cancels, no waits).
#[test]
fn drain_empty_is_noop() {
    let mut ring = FakeRing::new(vec![], vec![]);
    let mut reg = InflightRegistry::new();
    assert_eq!(reg.drain_for_teardown(&mut ring), 0);
    assert_eq!(ring.cancel_calls, 0);
    assert_eq!(ring.wait_calls, 0);
}

// ---------------------------------------------------------------------------
// #7106 measurement: what does the ceiling-during-teardown residual actually
// cost, and what would the proposed `mem::forget` hardening leak?
// ---------------------------------------------------------------------------

/// #7106 MEASUREMENT (not an assertion): how many entries can be live in the
/// registry at teardown, and how many bytes would the proposed leak retain?
///
/// #7106 asks whether to give `InflightRegistry` a `Drop` that `mem::forget`s
/// any entry the teardown drain could not prove terminal, making the #5800
/// buffer-lifetime invariant hold unconditionally at the cost of a leak. The
/// issue's own framing says to weigh "how many entries can actually be live at
/// teardown (`reap_ready` runs at the top of every write, so the steady-state
/// answer is 0)".
///
/// That parenthetical is right about steady state and is not the question the
/// leak has to survive. `reap_ready` reclaims entries whose CQE has SURFACED;
/// during the storm that produces deferrals, none has. So this measures the
/// accumulation directly rather than reasoning about it.
#[test]
#[ignore = "MEASUREMENT: not an assertion; run with --ignored --nocapture"]
fn measure_teardown_residual_7106() {
    // Payload sizes of the two real ring users:
    //   slowpath.rs:590   ring.write(fd, bytes, false, "slow-path")  -- one packet
    //   state_writer.rs:436 ring.write(fd, data, true, "state")      -- a snapshot
    const SLOW_PATH_PKT: usize = 1500;
    const STATE_SNAPSHOT: usize = 256 * 1024;

    println!("\n#7106: registry accumulation under a sustained EINTR storm");
    println!("(every write defers: its CQE never surfaces, so reap_ready reclaims nothing)");
    println!(" writes   inflight_len   slow-path bytes   state bytes");
    let mut reg = InflightRegistry::new();
    let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EINTR);
    for n in 1..=64usize {
        let out = write_all(&mut ring, &mut reg, vec![0u8; 64], false, "slow-path");
        assert!(
            matches!(out, WriteResult::Deferred { .. }),
            "write {n} must defer for this measurement to mean anything"
        );
        if n == 1 || n == 8 || n == 16 || n == 32 || n == 64 {
            let len = reg.inflight_len();
            println!(
                "{n:7}   {len:12}   {:15}   {:11}",
                len * SLOW_PATH_PKT,
                len * STATE_SNAPSHOT
            );
        }
    }

    // Does the accumulation drain once the storm ends? This is what decides
    // whether it is a transient spike or a monotonic leak in normal operation.
    let before = reg.inflight_len();
    ring.complete_inflight_now(64);
    reg.reap_ready(&mut ring);
    println!(
        "\nafter the storm ends and completions surface: {before} -> {} live",
        reg.inflight_len()
    );

    // And the state-writer ring, whose SQ is only 8 entries deep (RingWriter::new(8))
    // versus the slow path's 256 (slowpath.rs:522) -- does the SQ depth bound
    // the registry?
    let mut reg2 = InflightRegistry::new();
    let mut ring2 = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EINTR);
    for _ in 0..32 {
        let _ = write_all(&mut ring2, &mut reg2, vec![0u8; 64], true, "state");
    }
    println!(
        "state-ring shape after 32 deferred writes: inflight_len={} (SQ depth is 8)",
        reg2.inflight_len()
    );
}

/// #7106 fail-on-revert (the hardening #6168 left on the board): a buffer the
/// teardown drain could not PROVE terminal must be retained, not returned to
/// the allocator, when the registry drops.
///
/// Before this, such a buffer was freed by `Vec`'s own `Drop`. `RingWriter`'s
/// field order closes the ring fd first, but `close()` does not wait —
/// `io_uring_release` only queues `io_ring_exit_work` — so a write still
/// executing in io-wq could be writing into that allocation as it returned to
/// the allocator. Field order narrows the window; it is not a barrier.
///
/// Observed through the production counters, which are also the operator signal
/// the condition otherwise has none of. They are process-global and cumulative,
/// #8291: this used to sample the PROCESS counters and assert a delta, with a
/// comment resting the exactness on the mandated `-- --test-threads=1`. That
/// was the flake: the accounting is written by `InflightRegistry::drop`, so
/// every test that drops a non-empty registry is a writer — 28 of this module's
/// tests construct one — and a non-atomic read-act-read delta over shared state
/// cannot survive twenty-eight concurrent writers. It is now a PRIVATE sink, so
/// the assertion is ABSOLUTE and depends on nothing any other test does.
///
/// FAIL-ON-REVERT: delete `impl Drop for InflightRegistry` and `Vec`'s Drop
/// frees the buffer again — both deltas are 0 and this goes RED.
#[test]
fn unproven_buffers_are_retained_not_freed_7106() {
    const PAYLOAD: usize = 4096;
    let retained = std::sync::Arc::new(super::RetainedCounters::new());
    assert_eq!(
        (retained.buffers(), retained.bytes()),
        (0, 0),
        "a fresh sink starts empty, or the absolute assertions below could pass \
         on state this test did not create"
    );
    {
        // A fatal ring: every wait returns the permanent error, so the drain
        // can prove nothing and retains the entry.
        let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EBADF);
        let mut reg = InflightRegistry::with_retained_for_test(std::sync::Arc::clone(&retained));
        let out = write_all(&mut ring, &mut reg, vec![0u8; PAYLOAD], false, "slow-path");
        assert!(
            matches!(out, WriteResult::Deferred { fatal_ring: true, .. }),
            "precondition: a fatal ring must defer the buffer"
        );
        assert_eq!(
            reg.drain_for_teardown(&mut ring),
            0,
            "precondition: a fatal ring cannot prove release, so the drain frees nothing"
        );
        assert_eq!(reg.inflight_len(), 1, "precondition: the entry is retained");
    } // the registry drops HERE — this is the subject.

    assert_eq!(
        retained.buffers(),
        1,
        "the unproven buffer must be RETAINED at registry drop, not freed. \
         Freeing it hands an allocation the kernel may still be writing into \
         back to the allocator (#7106)"
    );
    assert_eq!(
        retained.bytes(),
        PAYLOAD as u64,
        "the retained BYTES must be accounted too — the count alone does not \
         tell an operator how much memory a retiring ring abandoned"
    );
}

/// #7106: the leak is confined to unproven entries. A drain that PROVES every
/// entry terminal must free them normally and retain nothing.
///
/// Without this, `unproven_buffers_are_retained_not_freed_7106` is satisfied by
/// a `Drop` that leaks unconditionally — which would turn every ordinary ring
/// retirement into a leak, including the overwhelmingly common case where the
/// drain works.
#[test]
fn a_proven_drain_retains_nothing_7106() {
    // #8291: private sink, so "retains nothing" is an ABSOLUTE zero rather than
    // "unchanged since a moment ago" — the latter is satisfied by a sibling
    // test's drop landing between the two reads and this one leaking too.
    let retained = std::sync::Arc::new(super::RetainedCounters::new());
    {
        let mut ring = FakeRing::new(vec![], vec![]).with_repeat_err(libc::EINTR);
        let mut reg = InflightRegistry::with_retained_for_test(std::sync::Arc::clone(&retained));
        let out = write_all(&mut ring, &mut reg, vec![0u8; 64], false, "slow-path");
        assert!(matches!(out, WriteResult::Deferred { .. }));
        // The storm ends: the write's terminal CQE surfaces and is reaped.
        ring.complete_inflight_now(64);
        reg.reap_ready(&mut ring);
        assert_eq!(
            reg.inflight_len(),
            0,
            "precondition: a proven-terminal entry is released before drop"
        );
    }
    assert_eq!(
        retained.buffers(),
        0,
        "a registry that proved every entry terminal must leak NOTHING; a \
         Drop that forgets unconditionally would leak on every ordinary ring \
         retirement"
    );
}

/// #7106 (#6168 task 3): `RingWriter`'s field DECLARATION ORDER is load-bearing
/// and was guarded only by a comment.
///
/// Rust drops struct fields in declaration order, so `ring` before `inflight`
/// means the ring fd closes — starting the kernel's teardown — before the
/// registry drops. Swapping the two declarations compiles, passes every
/// behavioural test, and silently removes that ordering.
///
/// Source-text rather than behavioural because Rust cannot reflect declaration
/// order: there is no runtime observable to assert on. Same instrument as the
/// existing `*_doc_guard` tests. Comments are stripped first, because this
/// file and the struct's own comment both NAME the fields and an unstripped
/// scan would match the prose describing the invariant rather than the
/// invariant.
#[test]
fn ring_writer_drops_the_ring_before_the_registry_7106() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("io_uring_write.rs"),
    )
    .expect("io_uring_write.rs must be readable");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let start = code
        .find("pub(crate) struct RingWriter {")
        .expect(
            "struct RingWriter not found — either it was renamed, in which case \
             this guard is scanning for something that no longer exists, or the \
             drop-order invariant moved. Either way this is not evidence.",
        );
    let body_end = code[start..]
        .find('}')
        .expect("unterminated struct RingWriter");
    let body = &code[start..start + body_end];

    let ring_at = body
        .find("ring:")
        .expect("RingWriter has no `ring` field; the guard cannot speak for it");
    let inflight_at = body
        .find("inflight:")
        .expect("RingWriter has no `inflight` field; the guard cannot speak for it");

    assert!(
        ring_at < inflight_at,
        "`ring` must be DECLARED before `inflight`. Rust drops fields in \
         declaration order, so this ordering is what closes the ring fd — \
         starting the kernel's teardown — before the registry drops and \
         releases buffers. Swapping them compiles and passes every behavioural \
         test while silently widening the #6168 window (#7106)"
    );
}

// ---------------------------------------------------------------------------
// #7751 row 12 — SQE length narrowing
// ---------------------------------------------------------------------------

/// Arithmetic half: the cast the fix replaced narrows a 4 GiB remainder to
/// **zero** — a valid-looking "nothing writable" that stalls `write_all`
/// forever. The clamp must never return 0 for a non-zero remainder.
#[test]
fn sqe_write_len_never_narrows_a_nonzero_remainder_to_zero() {
    let pathological = 1usize << 32;
    // Control: this is what makes the cell meaningful rather than decorative —
    // it asserts the hazard is real on this target. On a 32-bit `usize` it
    // fails loudly instead of the cell passing vacuously.
    assert_eq!(
        pathological as u32, 0,
        "control: the raw `as u32` cast DOES narrow 2^32 to zero"
    );
    let n = super::sqe_write_len(pathological, super::MAX_SQE_WRITE_LEN);
    assert!(
        n > 0,
        "a non-zero remainder must always yield a non-zero SQE length"
    );
    assert_eq!(n, u32::MAX as usize);
}

/// Wiring half: with the cap injected small, an 8-byte buffer must be SPLIT
/// into two 4-byte SQEs. Reverting the clamp inside `write_all_capped` makes
/// the first push carry all 8 bytes, so the recorded LENGTHS go red while
/// `push_calls` stays 2 either way (verified: the mutant yields [8, 4]).
#[test]
fn write_all_clamps_every_sqe_to_the_len_cap() {
    let mut ring = FakeRing::new(vec![Ok(()), Ok(())], vec![4, 4]);
    let mut reg = InflightRegistry::new();
    let out = super::write_all_capped(&mut ring, &mut reg, vec![0u8; 8], true, "cap", 4);
    assert!(matches!(out, WriteResult::Done(_)), "got {out:?}");
    assert_eq!(
        ring.push_lens,
        vec![4, 4],
        "each SQE must be clamped to the 4-byte cap"
    );
}
