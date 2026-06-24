// Tests for event_stream/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from mod.rs.

use super::codec::{DataplaneEventKind, DataplaneEventPayload, MSG_FULL_RESYNC};
use super::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};

fn build_raw_ack_frame(seq: u64) -> [u8; FRAME_HEADER_SIZE] {
    let mut buf = [0u8; FRAME_HEADER_SIZE];
    // payload_len = 0 (header-only)
    buf[0..4].copy_from_slice(&0u32.to_le_bytes());
    buf[4] = MSG_ACK;
    // reserved bytes 5..8 stay zero
    buf[8..16].copy_from_slice(&seq.to_le_bytes());
    buf
}

fn test_dataplane_event(kind: DataplaneEventKind, ingress_zone_id: u16) -> DataplaneEventPayload {
    DataplaneEventPayload {
        kind,
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        action: 0,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        src_port: 12345,
        dst_port: 443,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id: 9,
        ingress_ifindex: 42,
        policy_id: 101,
        rule_id: 202,
        term_id: 303,
        reason: 5,
        owner_rg_id: 1,
        application_id: 404,
        filter_id: 505,
        screen_id: 606,
        timestamp_ns: 123_456_789,
    }
}

// #2460: build a forward Close SessionDelta for the RT_FLOW close-emit
// pairing tests.
#[cfg(test)]
fn test_close_delta(kind: crate::session::SessionDeltaKind) -> crate::session::SessionDelta {
    use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
    use crate::nat::NatDecision;
    use crate::session::{
        SessionDecision, SessionDelta, SessionKey, SessionMetadata, SessionOrigin,
    };
    SessionDelta {
        kind,
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 2,
                egress_ifindex: 3,
                tx_ifindex: 3,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                rewrite_src_port: Some(40000),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
    }
}

#[test]
fn test_emit_session_close_rt_flow_pairs_with_ha_delta() {
    // #2460 no-double-emit contract: a single close emits exactly ONE type-2
    // HA session-sync close delta (push_delta, unchanged) AND exactly ONE
    // type-14 RT_FLOW SESSION_CLOSE frame (emit_session_close_rt_flow). The
    // two are a 1:1 pair — the RT_FLOW frame is additive, it does not
    // duplicate or replace the HA delta.
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let zone_map = FxHashMap::default();
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close);

    // Mirror flush_session_deltas: the HA delta then the RT_FLOW frame.
    handle.push_delta(&delta, &zone_map);
    handle.emit_session_close_rt_flow(&delta);

    let frames: Vec<EventFrame> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert_eq!(frames.len(), 2, "expected exactly one HA delta + one RT_FLOW frame");

    let ha = frames.iter().filter(|f| f.data[4] == codec::MSG_SESSION_CLOSE).count();
    let rt = frames
        .iter()
        .filter(|f| f.data[4] == codec::MSG_SESSION_CLOSE_RT_FLOW)
        .count();
    assert_eq!(ha, 1, "exactly one type-2 HA close delta");
    assert_eq!(rt, 1, "exactly one type-14 RT_FLOW close frame");

    // The RT_FLOW frame carries the SESSION_CLOSE event-type byte and tuple.
    let rt_frame = frames
        .iter()
        .find(|f| f.data[4] == codec::MSG_SESSION_CLOSE_RT_FLOW)
        .unwrap();
    let p = &rt_frame.data[FRAME_HEADER_SIZE..rt_frame.len as usize];
    assert_eq!(p[52], 2, "RT_FLOW event type must be SESSION_CLOSE (2)");
    assert_eq!(&p[8..12], &[10, 0, 1, 102]);
    assert_eq!(&p[24..28], &[172, 16, 80, 200]);
}

#[test]
fn test_emit_session_close_rt_flow_ignores_open_delta() {
    // #2460: the RT_FLOW close emit is gated on Close — calling it for an
    // Open delta is a no-op (guards against a future caller misusing it and
    // injecting a bogus SESSION_CLOSE for an opening session).
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Open);
    handle.emit_session_close_rt_flow(&delta);
    assert!(rx.try_recv().is_err(), "Open delta must emit no RT_FLOW close frame");
}

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
fn test_channel_backpressure() {
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(2);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    // Fill the channel (capacity 2)
    let frame = EventFrame::encode_drain_complete(1);
    assert!(handle.try_send(frame.clone()));
    assert!(handle.try_send(frame.clone()));

    // Third send should fail (channel full)
    assert!(!handle.try_send(frame));
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 2);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 1);
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
    let stop = Arc::new(AtomicBool::new(false));

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 1 }
    );

    let loop_shared = shared.clone();
    let loop_stop = stop.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        let reconnect = run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &loop_stop,
            &mut replay_buf,
            &mut ctrl_read_buf,
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

    stop.store(true, Ordering::Release);
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
        stop: Arc::new(AtomicBool::new(false)),
    };
    sender
        .shared
        .frames_replay_evicted
        .store(42, Ordering::Relaxed);
    assert_eq!(sender.stats().replay_evictions, 42);
}

// #2381: the write-backlog cap converts a wedged daemon reader from
// unbounded helper heap growth into bounded, counted telemetry loss at the
// already-bounded mpsc channel. These tests fail if the cap is removed or the
// stall is not counted.

#[test]
fn write_backlog_cap_halts_drain_and_counts_stall() {
    // Channel holds frames the I/O thread would normally migrate into the
    // pending write backlog. With the backlog already at the cap, the drain
    // must stop, count the stall, and LEAVE the frames in the channel.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(8);
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    for seq in 1..=4u64 {
        tx.send(EventFrame::encode_drain_complete(seq))
            .expect("seed channel");
    }

    // Simulate a wedged consumer: the backlog is already at the cap because
    // prior socket writes returned WouldBlock.
    let mut write_buf: Vec<u8> = vec![0u8; WRITE_BACKLOG_MAX_BYTES];

    let outcome = drain_channel_into_write_buf(&rx, &shared, &mut replay_buf, &mut write_buf, false);

    assert!(outcome.stalled, "drain must report the backlog stall");
    assert!(!outcome.disconnected);
    assert!(!outcome.drained_any, "no frame may move into a full backlog");
    assert_eq!(
        write_buf.len(),
        WRITE_BACKLOG_MAX_BYTES,
        "backlog must not grow past the cap"
    );
    assert_eq!(
        shared.frames_write_stalled.load(Ordering::Relaxed),
        1,
        "the stall must be counted"
    );
    // Frames stay in the channel (the real backpressure surface), not silently
    // relocated into one unbounded heap buffer.
    assert_eq!(rx.try_recv().map(|f| f.seq).ok(), Some(1));
}

#[test]
fn write_backlog_stall_makes_channel_the_backpressure_surface() {
    // Once the backlog is capped, the bounded channel fills and worker
    // try_send drops the NEWEST events with the existing frames_dropped
    // counter — bounded, counted loss instead of unbounded growth.
    let capacity = 4;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx: tx.clone(),
        shared: shared.clone(),
    };
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let mut write_buf: Vec<u8> = vec![0u8; WRITE_BACKLOG_MAX_BYTES];

    // Fill the channel to capacity.
    for seq in 1..=capacity as u64 {
        assert!(handle.try_send(EventFrame::encode_drain_complete(seq)));
    }

    // I/O thread cannot drain into the full backlog: channel stays full.
    let outcome = drain_channel_into_write_buf(&rx, &shared, &mut replay_buf, &mut write_buf, false);
    assert!(outcome.stalled);
    assert!(!outcome.drained_any);

    // Subsequent producer sends now drop (newest-first) and are counted.
    assert!(
        !handle.try_send(EventFrame::encode_drain_complete(99)),
        "producer must drop, never block, when the channel is full"
    );
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), capacity as u64);
    assert_eq!(
        shared.frames_dropped.load(Ordering::Relaxed),
        1,
        "the bounded channel drop must be counted"
    );
}

#[test]
fn paused_drain_ignores_backlog_cap_and_never_stalls() {
    // While paused, frames are consumed into the already-bounded replay
    // buffer only (never the write backlog), so the cap must not engage even
    // with a pre-filled write_buf.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(8);
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let mut write_buf: Vec<u8> = vec![0u8; WRITE_BACKLOG_MAX_BYTES];

    for seq in 1..=3u64 {
        tx.send(EventFrame::encode_drain_complete(seq))
            .expect("seed channel");
    }

    let outcome = drain_channel_into_write_buf(&rx, &shared, &mut replay_buf, &mut write_buf, true);
    assert!(!outcome.stalled, "paused drain must not stall on the cap");
    assert!(outcome.drained_any);
    assert_eq!(
        write_buf.len(),
        WRITE_BACKLOG_MAX_BYTES,
        "paused frames must not be added to the write backlog"
    );
    assert_eq!(replay_buf.len(), 3, "paused frames go to the replay buffer");
    assert_eq!(shared.frames_write_stalled.load(Ordering::Relaxed), 0);
}

#[test]
fn stalled_consumer_does_not_grow_backlog_unbounded_end_to_end() {
    // End-to-end: a daemon that connects but never reads (socket buffer fills
    // → write returns WouldBlock). Pump far more than the backlog cap worth of
    // frames through the channel and assert the loop SHEDS at the bounded
    // channel (frames_dropped grows, stalls counted) instead of migrating
    // every frame into an unbounded write_buf.
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    // Never read on the daemon side: let the socket buffer wedge.

    let capacity = 64;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());
    let stop = Arc::new(AtomicBool::new(false));
    let handle = EventStreamWorkerHandle {
        tx: tx.clone(),
        shared: shared.clone(),
    };

    let loop_shared = shared.clone();
    let loop_stop = stop.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &loop_stop,
            &mut replay_buf,
            &mut ctrl_read_buf,
        )
    });

    // Encode-only frame size; pump >> WRITE_BACKLOG_MAX_BYTES worth of frames.
    let frame_bytes = EventFrame::encode_drain_complete(1).as_bytes().len();
    let frames_to_pump = (WRITE_BACKLOG_MAX_BYTES / frame_bytes) * 3 + 4096;

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut sent_ok = 0u64;
    for seq in 0..frames_to_pump as u64 {
        // Non-blocking producer: retry on transient full but never block the
        // "worker" forever. A persistently full channel is the expected
        // backpressure once the backlog caps.
        loop {
            if handle.try_send(EventFrame::encode_drain_complete(seq + 1)) {
                sent_ok += 1;
                break;
            }
            // Channel full → backpressure engaged; that is the intended state.
            if shared.frames_dropped.load(Ordering::Relaxed) > 0 {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::yield_now();
        }
        if Instant::now() >= deadline {
            break;
        }
    }

    // The defining proof: with a wedged reader and a sustained source far
    // exceeding the cap, the loop must have stalled and shed at the channel.
    let deadline2 = Instant::now() + Duration::from_secs(5);
    while shared.frames_write_stalled.load(Ordering::Relaxed) == 0
        && Instant::now() < deadline2
    {
        let _ = handle.try_send(EventFrame::encode_drain_complete(0));
        thread::sleep(Duration::from_millis(1));
    }

    stop.store(true, Ordering::Release);
    let _ = loop_join.join();

    assert!(
        shared.frames_write_stalled.load(Ordering::Relaxed) > 0,
        "a wedged reader with a sustained source must trip the backlog cap"
    );
    assert!(
        shared.frames_dropped.load(Ordering::Relaxed) > 0,
        "shedding must happen at the bounded channel (counted), not via \
         unbounded write_buf growth"
    );
    // The channel is bounded, so accepted frames are bounded by capacity +
    // whatever the (capped) backlog/replay absorbed — never the full source.
    assert!(
        sent_ok < frames_to_pump as u64,
        "not every pumped frame can be accepted once backpressure engages"
    );
    drop(daemon_side);
}

#[test]
fn keeping_up_consumer_sees_full_fidelity_and_no_stalls() {
    // A daemon that drains the socket promptly must lose nothing: no stalls,
    // no drops, every byte delivered in order.
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let capacity = 16;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());
    let stop = Arc::new(AtomicBool::new(false));
    let handle = EventStreamWorkerHandle {
        tx: tx.clone(),
        shared: shared.clone(),
    };

    let total: u64 = 5000;
    let mut expected: Vec<u8> = Vec::new();
    for seq in 1..=total {
        expected.extend_from_slice(EventFrame::encode_drain_complete(seq).as_bytes());
    }

    let loop_shared = shared.clone();
    let loop_stop = stop.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &loop_stop,
            &mut replay_buf,
            &mut ctrl_read_buf,
        )
    });

    let frame_bytes = EventFrame::encode_drain_complete(1).as_bytes().len();
    let want = total as usize * frame_bytes;

    // Reader thread drains promptly so the helper never backs up.
    let mut reader = daemon_side;
    let read_join = thread::spawn(move || {
        let mut got: Vec<u8> = Vec::with_capacity(want);
        let mut chunk = [0u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(15);
        while got.len() < want && Instant::now() < deadline {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        got
    });

    for seq in 1..=total {
        // Lossless producer-side feed paced by the bounded channel; the prompt
        // reader keeps it draining so this never has to drop.
        let mut frame = EventFrame::encode_drain_complete(seq);
        loop {
            match tx.try_send(frame) {
                Ok(()) => {
                    shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(mpsc::TrySendError::Full(returned)) => {
                    frame = returned;
                    thread::yield_now();
                }
                Err(mpsc::TrySendError::Disconnected(_)) => panic!("channel closed"),
            }
        }
    }

    let got = read_join.join().expect("reader thread");
    stop.store(true, Ordering::Release);
    let _ = loop_join.join();

    assert_eq!(got.len(), want, "every frame byte must be delivered");
    assert_eq!(got, expected, "frames must arrive in order, unmodified");
    assert_eq!(
        shared.frames_write_stalled.load(Ordering::Relaxed),
        0,
        "a keeping-up consumer must never trip the backlog cap"
    );
    assert_eq!(
        shared.frames_dropped.load(Ordering::Relaxed),
        0,
        "a keeping-up consumer must see zero drops"
    );
}

#[test]
fn test_lossless_send_waits_for_capacity() {
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new());
    shared.connected.store(true, Ordering::Release);
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    assert!(handle.try_send(EventFrame::encode_drain_complete(1)));

    let (release_tx, release_rx) = mpsc::sync_channel::<()>(0);
    let (attempt_tx, attempt_rx) = mpsc::sync_channel::<()>(0);
    let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(0);
    let (hold_tx, hold_rx) = mpsc::sync_channel::<()>(0);

    let consumer_join = thread::spawn(move || {
        release_rx.recv().expect("release consumer");
        rx.recv().expect("drain queued frame");
        hold_rx
            .recv()
            .expect("hold consumer open until sender finishes");
    });

    let sender_handle = handle.clone();
    let sender_join = thread::spawn(move || {
        attempt_tx
            .send(())
            .expect("notify that lossless send is about to start");
        let result = sender_handle.send_frame_lossless(EventFrame::encode_drain_complete(2));
        done_tx.send(result).expect("send lossless result");
    });

    attempt_rx
        .recv()
        .expect("wait for sender thread to begin lossless send");

    assert!(
        done_rx.recv_timeout(Duration::from_millis(20)).is_err(),
        "lossless send should still be waiting while the channel remains full"
    );

    release_tx.send(()).expect("allow consumer to drain");

    done_rx
        .recv_timeout(Duration::from_millis(100))
        .expect("lossless send should finish once capacity is available")
        .expect("lossless send should wait for capacity");

    hold_tx.send(()).expect("release consumer thread");
    sender_join.join().expect("sender thread");
    consumer_join.join().expect("consumer thread");
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 2);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 0);
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

#[test]
fn test_partial_read_accumulation() {
    // Simulate a partial Unix stream read: first 8 bytes, then the
    // remaining 8 bytes of a 16-byte ACK frame.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    // Seed replay buffer so we can observe the trim from the ACK.
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }

    let raw = build_raw_ack_frame(3);
    let mut ctrl_buf: Vec<u8> = Vec::new();

    // We don't have a real stream for this unit test, so call
    // process_control_frames directly with partial data.

    // First "read": only the first 8 bytes arrive.
    ctrl_buf.extend_from_slice(&raw[..8]);
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, 0, "partial frame must not be consumed");
    // Replay buffer untouched -- no ACK processed yet
    assert_eq!(replay_buf.len(), 5);

    // Second "read": remaining 8 bytes arrive.
    ctrl_buf.extend_from_slice(&raw[8..]);
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    // ACK seq=3 should have trimmed frames 1,2,3
    assert_eq!(replay_buf.len(), 2);
    assert_eq!(replay_buf.front().unwrap().seq, 4);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 3);

    // Drain consumed bytes as the real loop would.
    ctrl_buf.drain(..consumed);
    assert!(ctrl_buf.is_empty());
}

#[test]
fn test_two_frames_in_one_read() {
    // Two complete ACK frames arrive in a single read.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=10u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }

    let ack5 = build_raw_ack_frame(5);
    let ack8 = build_raw_ack_frame(8);
    let mut ctrl_buf: Vec<u8> = Vec::new();
    ctrl_buf.extend_from_slice(&ack5);
    ctrl_buf.extend_from_slice(&ack8);

    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, 2 * FRAME_HEADER_SIZE);
    // ACK 5, then ACK 8 -- replay should have frames 9,10
    assert_eq!(replay_buf.len(), 2);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 8);
}

#[test]
fn test_one_and_half_frames() {
    // 1.5 frames: one complete ACK + first 4 bytes of next frame.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }

    let ack2 = build_raw_ack_frame(2);
    let ack4 = build_raw_ack_frame(4);
    let mut ctrl_buf: Vec<u8> = Vec::new();
    ctrl_buf.extend_from_slice(&ack2);
    ctrl_buf.extend_from_slice(&ack4[..4]); // partial second frame

    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE); // only first frame consumed
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 2);
    assert_eq!(replay_buf.len(), 3); // frames 3,4,5 remain

    // Drain consumed, then "read" remaining bytes of second frame.
    ctrl_buf.drain(..consumed);
    assert_eq!(ctrl_buf.len(), 4);
    ctrl_buf.extend_from_slice(&ack4[4..]);

    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 4);
    assert_eq!(replay_buf.len(), 1); // only frame 5 remains
}
