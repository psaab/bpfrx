// Sequence-number allocation, replay-buffer trim/eviction, telemetry
// queue-budget hold/release, and lossless-producer seq accounting tests.
// Split from event_stream/tests.rs (#4664).

use super::*;


#[test]
fn test_sequence_monotonicity() {
    let shared = Arc::new(EventStreamShared::new());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let s = shared.clone();
            std::thread::spawn(move || {
                let mut seqs = Vec::with_capacity(100);
                for _ in 0..100 {
                    let seq = s.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
                    seqs.push(seq);
                }
                seqs
            })
        })
        .collect();

    let mut all_seqs: Vec<u64> = Vec::new();
    for h in handles {
        all_seqs.extend(h.join().unwrap());
    }
    all_seqs.sort();
    all_seqs.dedup();
    // All 400 sequences should be unique
    assert_eq!(all_seqs.len(), 400);
    // Should be 1..=400
    assert_eq!(*all_seqs.first().unwrap(), 1);
    assert_eq!(*all_seqs.last().unwrap(), 400);
}


#[test]
fn test_replay_buffer_trim() {
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Add 10 frames with seq 1..=10
    for seq in 1..=10u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    assert_eq!(replay_buf.len(), 10);

    // Simulate Ack seq=5: trim frames <= 5
    let acked_seq = 5u64;
    while let Some(front) = replay_buf.front() {
        if front.seq <= acked_seq {
            replay_buf.pop_front();
        } else {
            break;
        }
    }
    assert_eq!(replay_buf.len(), 5);
    assert_eq!(replay_buf.front().unwrap().seq, 6);
}


#[test]
fn test_replay_gap_at_zero_ack_sends_full_resync() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Simulate a replay buffer overrun before the daemon ever ACKed anything:
    // seq 1 has been trimmed, so replaying seq 2.. would silently lose the
    // first audit/session event unless the helper requests FullResync.
    for seq in 2..=REPLAY_BUFFER_CAPACITY as u64 + 1 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }

    replay_buffered(&helper_side, &mut replay_buf, 0, &shared).expect("replay gap");

    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    daemon_side.read_exact(&mut hdr).expect("full resync frame");
    assert_eq!(hdr[4], MSG_FULL_RESYNC);
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 1);
    assert_eq!(
        replay_buf.front().map(|f| f.seq),
        Some(2),
        "full resync keeps stale replay window until the daemon ACKs"
    );
}


#[test]
fn dataplane_event_budget_stays_held_after_connected_loop_drains_channel() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    helper_side.set_nonblocking(true).unwrap();

    let capacity = 1;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(
        EventStreamShared::new_with_dataplane_event_rate_and_queue_capacity(
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
            capacity,
        ),
    );
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 1 }
    );

    let loop_shared = shared.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        let reconnect = run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            Duration::from_secs(10),
        );
        drain_remaining(&rx, &loop_shared);
        release_replay_dataplane_event_queue_budget(&loop_shared, &mut replay_buf);
        reconnect
    });

    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    daemon_side
        .read_exact(&mut hdr)
        .expect("dataplane frame header");
    let payload_len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; payload_len];
    daemon_side
        .read_exact(&mut payload)
        .expect("dataplane frame payload");

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Dropped {
            reason: DataplaneEventDropReason::QueueFull
        },
        "draining the mpsc channel into replay must not release telemetry budget"
    );

    daemon_side
        .write_all(&build_raw_ack_frame(1))
        .expect("send ACK");
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match handle
            .try_emit_dataplane_event_at(test_dataplane_event(DataplaneEventKind::PolicyDeny, 7), 0)
        {
            DataplaneEventEmitOutcome::Queued { seq: 2 } => break,
            DataplaneEventEmitOutcome::Dropped {
                reason: DataplaneEventDropReason::QueueFull,
            } if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            other => panic!("telemetry budget should release after ACK, got {other:?}"),
        }
    }

    shared.stop.store(true, Ordering::Release);
    assert!(
        !loop_join.join().expect("connected loop thread"),
        "test loop should stop without requesting reconnect"
    );
}


#[test]
fn dataplane_event_budget_releases_when_replay_eviction_drops_frame() {
    let capacity = 1;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(
        EventStreamShared::new_with_dataplane_event_rate_and_queue_capacity(
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
            capacity,
        ),
    );
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 1 }
    );
    let frame = rx.try_recv().expect("queued dataplane frame");
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
    push_replay_frame(&shared, &mut replay_buf, frame);

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Dropped {
            reason: DataplaneEventDropReason::QueueFull
        }
    );

    for seq in 2..=REPLAY_BUFFER_CAPACITY as u64 {
        push_replay_frame(
            &shared,
            &mut replay_buf,
            EventFrame::encode_drain_complete(seq),
        );
    }
    push_replay_frame(
        &shared,
        &mut replay_buf,
        EventFrame::encode_drain_complete(REPLAY_BUFFER_CAPACITY as u64 + 1),
    );

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 2 },
        "replay eviction is a definitive drop and must release telemetry budget"
    );

    drain_remaining(&rx, &shared);
    release_replay_dataplane_event_queue_budget(&shared, &mut replay_buf);
}


// #2382: replay-buffer eviction (buffer wrapped at capacity before ACK) is a
// real telemetry loss and must be counted; ACK-trim (acknowledged-frame
// removal) is NOT a loss and must NOT bump the eviction counter. These tests
// fail if the increment is removed or moved into the shared pop path.

#[test]
fn replay_buffer_eviction_counts_telemetry_loss_2382() {
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);

    // Fill the replay buffer exactly to capacity — no eviction yet.
    for seq in 1..=REPLAY_BUFFER_CAPACITY as u64 {
        push_replay_frame(&shared, &mut replay_buf, EventFrame::encode_drain_complete(seq));
    }
    assert_eq!(replay_buf.len(), REPLAY_BUFFER_CAPACITY);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        0,
        "filling to capacity must not evict anything"
    );

    // Push N more frames past capacity: each wraps the buffer and evicts the
    // oldest unACKed frame. The counter must go 0 -> N. This assertion FAILS
    // (stays 0) if the eviction increment in `evict_replay_frame` is removed.
    let overflow = 5u64;
    for seq in 0..overflow {
        push_replay_frame(
            &shared,
            &mut replay_buf,
            EventFrame::encode_drain_complete(REPLAY_BUFFER_CAPACITY as u64 + 1 + seq),
        );
    }
    assert_eq!(replay_buf.len(), REPLAY_BUFFER_CAPACITY);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        overflow,
        "each buffer-full wrap must count exactly one replay eviction"
    );
    // And the surviving window starts past the evicted prefix.
    assert_eq!(replay_buf.front().map(|f| f.seq), Some(overflow + 1));
}


#[test]
fn ack_trim_does_not_count_as_replay_eviction_2382() {
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Buffer well under capacity so no wrap occurs.
    for seq in 1..=10u64 {
        push_replay_frame(&shared, &mut replay_buf, EventFrame::encode_drain_complete(seq));
    }
    assert_eq!(shared.frames_replay_evicted.load(Ordering::Relaxed), 0);

    // Simulate the MSG_ACK trim path: acked_seq = 5 removes the first 5 frames
    // via `pop_replay_frame`. Those frames were DELIVERED (acknowledged), not
    // lost — the eviction counter must stay 0.
    let acked_seq = 5u64;
    while let Some(front) = replay_buf.front() {
        if front.seq <= acked_seq {
            pop_replay_frame(&shared, &mut replay_buf);
        } else {
            break;
        }
    }
    assert_eq!(replay_buf.len(), 5);
    assert_eq!(replay_buf.front().unwrap().seq, 6);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        0,
        "ACK-trim is acknowledged removal, not a telemetry loss — must not \
         bump the replay-eviction counter"
    );

    // Shutdown drain (release_replay_dataplane_event_queue_budget → pop) also
    // must not count as eviction.
    release_replay_dataplane_event_queue_budget(&shared, &mut replay_buf);
    assert_eq!(replay_buf.len(), 0);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        0,
        "shutdown drain must not bump the replay-eviction counter"
    );
}


#[test]
fn replay_evictions_surface_in_event_stream_stats_2382() {
    let sender = EventStreamSender {
        tx: mpsc::sync_channel(1).0,
        shared: Arc::new(EventStreamShared::new()),
        io_thread: None,
    };
    sender
        .shared
        .frames_replay_evicted
        .store(42, Ordering::Relaxed);
    assert_eq!(sender.stats().replay_evictions, 42);
}


// #2874: the HA session-sync delta must route through the LOSSLESS producer
// (which surfaces a queue failure) while RT_FLOW telemetry stays best-effort
// (silently drops on a full channel). This documents the lossless-vs-telemetry
// split that `flush_session_deltas` relies on.
#[test]
fn session_delta_lossless_surfaces_failure_while_telemetry_drops() {
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new()); // connected=false
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };
    let zone_map = FxHashMap::default();
    let open = test_close_delta(crate::session::SessionDeltaKind::Open);

    // Session-sync delta: lossless surfaces the failure (NOT silently dropped).
    let err = handle
        .push_delta_lossless(&open, &zone_map)
        .expect_err("session-sync delta must not be silently dropped");
    assert!(err.contains("not connected"), "unexpected error: {err}");

    // Telemetry stays best-effort: try_send fills then silently drops.
    assert!(
        handle.try_send(EventFrame::encode_drain_complete(1)),
        "first telemetry frame fills the channel"
    );
    assert!(
        !handle.try_send(EventFrame::encode_drain_complete(2)),
        "telemetry frame must silently drop on a full channel"
    );
    assert_eq!(
        shared.frames_dropped.load(Ordering::Relaxed),
        1,
        "the silently-dropped telemetry frame is counted in frames_dropped"
    );
}


#[test]
fn test_lossless_send_fails_when_not_connected() {
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle { tx, shared };

    let err = handle
        .send_frame_lossless(EventFrame::encode_drain_complete(1))
        .expect_err("lossless send should fail when disconnected");
    assert!(err.contains("not connected"));
}


// #3878 F-153: a full-channel drop of a lossy session delta must NOT burn a
// sequence number. The producer allocates the seq atomically with the enqueue
// and, on a `Full` `try_send`, rolls the seq back — so the next successfully
// sent frame stays contiguous and the Go reader never sees a spurious gap that
// would force a full owner-RG resync.
//
// RED-on-revert: without the rollback, the dropped frame's seq is burned;
// `next_seq` advances to 2 after the drop and the next frame lands on seq 3,
// leaving a hole at seq 2.
#[test]
fn push_delta_full_channel_drop_does_not_burn_seq_3878() {
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };
    let zone_map = FxHashMap::default();
    let delta = test_close_delta(crate::session::SessionDeltaKind::Open);

    // Frame 1 fills the capacity-1 channel (seq 1).
    handle.push_delta(&delta, &zone_map);
    assert_eq!(shared.next_seq.load(Ordering::Relaxed), 1);

    // Frame 2: the channel is full -> `try_send` returns Full. The seq must be
    // rolled back, not burned.
    handle.push_delta(&delta, &zone_map);
    assert_eq!(
        shared.next_seq.load(Ordering::Relaxed),
        1,
        "#3878 F-153: a full-channel drop must not burn a sequence number",
    );

    // Drain frame 1, then send frame 2 for real: it must be seq 2 (contiguous
    // with seq 1), never seq 3 (a reader-visible gap -> spurious resync).
    let f1 = rx.try_recv().expect("frame 1 queued");
    assert_eq!(f1.seq, 1);
    handle.push_delta(&delta, &zone_map);
    let f2 = rx.try_recv().expect("frame 2 queued");
    assert_eq!(
        f2.seq, 2,
        "seq after a full-channel drop must stay contiguous (no gap)"
    );
    assert!(rx.try_recv().is_err(), "no extra frame should be queued");
}


// #3878 F-152: seq allocation and channel enqueue are atomic under the producer
// lock, so the seq embedded in each frame is strictly monotonic in wire
// (channel-FIFO) order even when many workers push concurrently. Without the
// lock two workers can allocate N and N+1 but enqueue them inverted, so a lower
// seq lands after a higher one and the Go reader treats the inversion as a
// session-sync gap -> spurious full owner-RG resync + disconnect.
//
// RED-on-revert: this is a concurrency stress test. With the non-atomic
// allocate-then-enqueue restored, the wide window between `next_seq()` and
// `try_send` (a full session-open encode) lets two of the eight workers invert
// within the few thousand frames, and the monotonicity assertion fails.
#[test]
fn concurrent_push_delta_preserves_monotonic_wire_order_3878() {
    // 8-way contention over the wide next_seq()->try_send window reorders very
    // early on revert (observed at seq ~192); 500 per thread keeps a large
    // margin while bounding the CPU burst so this does not starve co-scheduled
    // timing-sensitive tests in a module-only test run.
    const THREADS: u64 = 8;
    const PER_THREAD: u64 = 500;
    let total = (THREADS * PER_THREAD) as usize;

    // Channel sized to hold every frame: the I/O thread is not draining in this
    // unit test, so a smaller channel would exercise drops, not ordering.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(total);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle { tx, shared };

    let mut joins = Vec::new();
    for _ in 0..THREADS {
        let worker = handle.clone();
        joins.push(std::thread::spawn(move || {
            let zone_map = FxHashMap::default();
            let delta = test_close_delta(crate::session::SessionDeltaKind::Open);
            for _ in 0..PER_THREAD {
                worker.push_delta(&delta, &zone_map);
            }
        }));
    }
    for join in joins {
        join.join().expect("worker thread");
    }

    // Drain the channel in FIFO (wire) order; the embedded seqs must be strictly
    // increasing and form a contiguous 1..=total run (no inversions, no burns).
    let mut prev = 0u64;
    let mut count = 0u64;
    while let Ok(frame) = rx.try_recv() {
        assert!(
            frame.seq > prev,
            "wire seq went backwards: {} after {} (non-atomic allocate+enqueue reordered a frame)",
            frame.seq,
            prev,
        );
        prev = frame.seq;
        count += 1;
    }
    assert_eq!(
        count,
        THREADS * PER_THREAD,
        "every delta must reach the channel"
    );
    assert_eq!(
        prev,
        THREADS * PER_THREAD,
        "seqs must be a contiguous 1..=N run with no gaps or burns",
    );
}


// #3878 F-153 (lossless path): concurrent lossless flushers that all hit a FULL
// channel must NOT strand a sequence number. Each failed attempt's rollback
// runs UNDER the producer lock, so allocations+rollbacks are strictly LIFO and
// every drop returns `next_seq` to where it started. Before the follow-up fix
// the rollback ran AFTER the lock was released, so two flushers could interleave
// alloc(6)/alloc(7)/rollback(6)-CAS-fails/rollback(7)-CAS-succeeds and leave
// `next_seq` at 6 with seq 6 stranded — a wire hole → spurious owner-RG resync
// (reachable because `flush_session_deltas` → `push_delta_lossless` runs
// per-worker, up to 6 concurrent flushers on the mlx5 VF).
//
// RED-on-revert: with the rollback moved back outside the guard, the non-LIFO
// CAS failures strand seqs and `next_seq` ends well above the base.
#[test]
fn concurrent_lossless_full_drops_do_not_strand_seq_3878() {
    const CAP: usize = 5;
    const THREADS: usize = 3;

    // rx is HELD (never dropped/drained) so every `try_send` returns Full, not
    // Disconnected — the flushers stay in the retry loop.
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(CAP);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };
    let zone_map = FxHashMap::default();
    let delta = test_close_delta(crate::session::SessionDeltaKind::Open);

    // Fill the channel so every lossless attempt hits Full; base next_seq = CAP.
    for _ in 0..CAP {
        handle.push_delta(&delta, &zone_map);
    }
    assert_eq!(shared.next_seq.load(Ordering::Relaxed), CAP as u64);

    // Mark connected so the flushers enter the retry loop rather than bailing at
    // the initial connected check.
    shared.connected.store(true, Ordering::Release);

    let mut joins = Vec::new();
    for _ in 0..THREADS {
        let worker = handle.clone();
        joins.push(std::thread::spawn(move || {
            let zm = FxHashMap::default();
            let d = test_close_delta(crate::session::SessionDeltaKind::Open);
            // Retries on Full; gives up (Err) once `connected` is cleared below.
            let _ = worker.push_delta_lossless(&d, &zm);
        }));
    }

    // Let the flushers churn concurrently on the Full channel (this is where the
    // non-LIFO rollback strands seqs on the buggy version), then make them give
    // up quickly instead of waiting out the 5s lossless timeout. The flushers
    // sleep LOSSLESS_QUEUE_RETRY_DELAY (50us) between attempts, so this window is
    // low-CPU (mostly sleeping) yet still runs hundreds of interleaved attempts.
    std::thread::sleep(std::time::Duration::from_millis(20));
    shared.connected.store(false, Ordering::Release);
    for join in joins {
        join.join().expect("lossless flusher");
    }

    // Every lossless attempt was dropped and rolled back UNDER the lock, so the
    // counter must be back at the base with no stranded hole.
    assert_eq!(
        shared.next_seq.load(Ordering::Relaxed),
        CAP as u64,
        "#3878: concurrent lossless Full-drops must not strand a sequence number",
    );
}
