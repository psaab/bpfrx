//! Event stream producer for session sync.
//!
//! Replaces the polled `drain_session_deltas` RPC with a push-based binary
//! event stream over a dedicated Unix socket. The Go daemon creates a listener
//! at the event socket path; the helper connects and pushes binary-framed
//! session events (open/close/update) with monotonic sequence numbers.
//!
//! Wire format (per docs/session-sync-design.md):
//!   Frame header: [length:u32 LE][type:u8][reserved:3][seq:u64 LE]
//!   Payload: type-specific binary (see codec module)

pub(crate) mod codec;
mod producer;

pub(crate) use codec::{EventFrame, close_flags};
use codec::DataplaneEventKind;
#[allow(unused_imports)] // public API for later policy/screen/filter producer wiring
pub(crate) use producer::{
    DataplaneEventDropReason, DataplaneEventEmitOutcome, DataplaneEventRateLimitConfig,
    DataplaneEventStats,
};

use crate::session::{SessionDelta, SessionDeltaKind};
use codec::{FRAME_HEADER_SIZE, MSG_ACK, MSG_DRAIN_REQUEST, MSG_KEEPALIVE, MSG_PAUSE, MSG_RESUME};
use producer::{DataplaneEventCounters, DataplaneEventQueueBudget, DataplaneEventRateLimiter};
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const NS_PER_SEC: u64 = 1_000_000_000;

/// #2465: read CLOCK_MONOTONIC (ns) and the wall clock (ns since the Unix
/// epoch) in one pair so the two are anchored to the same instant. Used to
/// convert the session table's monotonic creation/last-seen instants into the
/// absolute wall-clock values the flow-export wire fields carry. On a clock
/// read failure both fall back to 0 (→ the Go-side packet-count fallback).
fn read_mono_and_wall_clocks() -> (u64, u64) {
    let mut mono = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut wall = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc_mono = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) };
    let rc_wall = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut wall) };
    if rc_mono != 0 || rc_wall != 0 || mono.tv_sec < 0 || wall.tv_sec < 0 {
        return (0, 0);
    }
    let mono_ns = (mono.tv_sec as u64)
        .saturating_mul(NS_PER_SEC)
        .saturating_add(mono.tv_nsec.max(0) as u64);
    let wall_ns = (wall.tv_sec as u64)
        .saturating_mul(NS_PER_SEC)
        .saturating_add(wall.tv_nsec.max(0) as u64);
    (mono_ns, wall_ns)
}

/// #2465: convert a monotonic instant (`mono_ns`) to an absolute wall-clock
/// nanosecond count, anchored against a (`now_mono_ns`, `now_unix_ns`) reading.
/// `mono_ns == 0` (unknown) maps to 0. The age is clamped at the present so a
/// monotonic value slightly ahead of `now_mono_ns` (a benign cross-CPU read
/// skew) cannot push the result into the future.
pub(crate) fn monotonic_ns_to_unix_ns(mono_ns: u64, now_mono_ns: u64, now_unix_ns: u64) -> u64 {
    if mono_ns == 0 || now_mono_ns == 0 || now_unix_ns == 0 {
        return 0;
    }
    let age_ns = now_mono_ns.saturating_sub(mono_ns);
    now_unix_ns.saturating_sub(age_ns)
}

/// #2465: convert a monotonic instant to absolute wall-clock Unix SECONDS for
/// the `created` wire field (offset 108, u32). Truncates toward the epoch;
/// 0/unknown stays 0; values beyond u32 (year 2106) saturate.
pub(crate) fn monotonic_ns_to_unix_secs(mono_ns: u64, now_mono_ns: u64, now_unix_ns: u64) -> u32 {
    monotonic_ns_to_unix_secs_subnanos(mono_ns, now_mono_ns, now_unix_ns).0
}

/// #2853: convert a monotonic instant to absolute wall-clock Unix SECONDS plus
/// the sub-second NANOSECOND remainder (0..=999_999_999). The integer seconds
/// ride the `created` wire field (offset 108, u32); the sub-second nanos ride
/// the SESSION_CLOSE-unused policy_id slot (offset 44, u32) so the Go flow
/// exporters can build a MILLISECOND-accurate flow StartTime instead of one
/// truncated to the whole second (the #2853 defect: short flows — DNS, single
/// HTTP requests — all collapsed onto the same integer-second start).
///
/// 0/unknown stays `(0, 0)`; a seconds value beyond u32 (year 2106) saturates
/// to `(u32::MAX, 0)` so the saturated record carries no misleading remainder.
pub(crate) fn monotonic_ns_to_unix_secs_subnanos(
    mono_ns: u64,
    now_mono_ns: u64,
    now_unix_ns: u64,
) -> (u32, u32) {
    let unix_ns = monotonic_ns_to_unix_ns(mono_ns, now_mono_ns, now_unix_ns);
    let secs = unix_ns / NS_PER_SEC;
    if secs > u32::MAX as u64 {
        return (u32::MAX, 0);
    }
    (secs as u32, (unix_ns % NS_PER_SEC) as u32)
}

/// #2470: convert a CLOCK_MONOTONIC instant (the `now_ns`/`now_secs`-derived
/// value the worker poll loop hands to the RT_FLOW deny/screen/filter-log
/// emitters) to an absolute wall-clock Unix nanosecond count, taking a fresh
/// anchored (`mono`, `wall`) reading here. This is the emission-time
/// conversion boundary: the deny/screen/filter-log events carry the dataplane
/// DECISION instant on the wire (offset 0, LE u64, absolute Unix ns — the same
/// `timestamp_ns` format the SESSION_CLOSE frame uses and the Go decoder
/// reads), so a queued/backlogged delivery on the Go side cannot skew the
/// logged event time to consumption time. A 0 `mono_ns` (unknown) or a clock
/// read failure maps to 0 → the Go side (`pkg/logging/ringbuf.go`) falls back
/// to receive time, preserving the old behavior only when no real instant is
/// available.
///
/// These events fire on drops / denies / log-matched packets (NOT per normal
/// packet), so one anchored clock read per emit is acceptable; correctness
/// (a real decision timestamp) is preferred over saving the read.
pub(crate) fn mono_ns_to_wall_clock_unix_ns(mono_ns: u64) -> u64 {
    let (now_mono_ns, now_unix_ns) = read_mono_and_wall_clocks();
    monotonic_ns_to_unix_ns(mono_ns, now_mono_ns, now_unix_ns)
}

/// Idle interval after which the connected loop enqueues a keepalive frame to
/// keep the Go listener from treating the stream as dead. The keepalive is
/// routed through the normal `write_buf` backpressure path (#2883), so this is
/// the cadence of enqueue, not of a guaranteed flush.
const KEEPALIVE_IDLE_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum event frames buffered in the mpsc channel (shared across workers).
const CHANNEL_CAPACITY: usize = 8192;

/// Maximum frames retained for replay after disconnect.
const REPLAY_BUFFER_CAPACITY: usize = 4096;

/// Hard cap on the I/O thread's pending socket-write backlog (`write_buf`).
///
/// The bounded mpsc channel (`CHANNEL_CAPACITY`) is the only intended
/// backpressure surface. Without this cap a wedged daemon (socket open but
/// not reading → `write_buf` writes return `WouldBlock`) lets the I/O thread
/// migrate the entire channel into the heap-backed `write_buf` every cycle;
/// the channel then refills from worker `try_send`, the I/O thread drains it
/// again, and `write_buf` grows without bound → helper OOM / allocator
/// pressure on the forwarding plane (#2381). Once the backlog reaches this
/// cap the I/O thread stops pulling frames out of the channel, so the bounded
/// channel becomes the real backpressure surface and `try_send` drops (with
/// the existing `frames_dropped` / per-kind `queue_full` counters) instead of
/// silently relocating bytes into one unbounded buffer.
///
/// `EventFrame::data` is a fixed `[u8; 256]` (see codec.rs), so a fully
/// drained `CHANNEL_CAPACITY` (8192) channel is at most 8192 × 256 ≈ 2 MiB of
/// bytes. 16 MiB is therefore ≈ 8× that worst-case channel drain — generous
/// headroom so transient bursts (plus any in-flight replay/partial-write
/// remainder) are absorbed losslessly, while a persistently stalled consumer
/// stays bounded.
///
/// The cap is checked at the top of the drain loop, before the in-flight frame
/// is appended, so `write_buf` can reach at most `WRITE_BACKLOG_MAX_BYTES` plus
/// one already-pulled max `EventFrame` (≤ 256 B) before the drain halts — i.e.
/// the bound is `cap + one frame`, not a strict 16 MiB. The overshoot is
/// bounded and accepted (simpler than a pre-reserve check); memory is bounded
/// either way.
const WRITE_BACKLOG_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Upper bound for explicit lossless queueing operations such as full
/// session export on connect. Normal packet-path delta export remains
/// non-blocking via `try_send`.
const LOSSLESS_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
const LOSSLESS_QUEUE_RETRY_DELAY: Duration = Duration::from_micros(50);

/// Bounded time the stop-aware replay/drain writer (`write_all_backpressured`)
/// will spend backpressured on a slow/stuck reader before giving up — i.e.
/// reconnecting (replay) or withholding DrainComplete (drain). This caps how
/// long a wedged daemon can hold the I/O thread in the replay/drain write even
/// if the stop flag is never raised (#2877). The replay/drain paths used to
/// flip the socket to BLOCKING and `write_all` with no deadline, so a daemon
/// that stopped reading wedged the I/O thread indefinitely — and because
/// `EventStreamSender::stop` joins that thread, stop/demotion hung.
const REPLAY_DRAIN_WRITE_DEADLINE: Duration = Duration::from_secs(5);
/// Sleep between `WouldBlock` retries in `write_all_backpressured`. Also the
/// worst-case latency for that writer to observe a raised stop flag, so
/// stop/demotion never waits more than one poll interval on a stuck reader.
const REPLAY_DRAIN_WRITE_POLL: Duration = Duration::from_millis(1);

// ---------------------------------------------------------------------------
// Shared state between I/O thread and workers
// ---------------------------------------------------------------------------

/// Statistics exposed to coordinator / status reporting.
pub(crate) struct EventStreamStats {
    pub(crate) connected: bool,
    pub(crate) seq: u64,
    pub(crate) acked_seq: u64,
    pub(crate) sent: u64,
    pub(crate) dropped: u64,
    /// Count of I/O cycles in which the pending socket-write backlog reached
    /// `WRITE_BACKLOG_MAX_BYTES` and the I/O thread therefore stopped pulling
    /// frames from the channel (a wedged/stalled daemon reader, #2381). A
    /// non-zero, growing value means telemetry is being shed at the bounded
    /// channel because the consumer is not draining the socket — the dataplane
    /// is unaffected.
    pub(crate) write_stalls: u64,
    /// Count of accepted frames evicted from the replay buffer on wrap before
    /// the daemon ACKed them (#2382). These were counted as `sent` but are
    /// permanently lost; a non-zero, growing value means RT_FLOW / dataplane
    /// telemetry was dropped via replay-buffer eviction (a daemon that
    /// disconnected or withheld ACKs long enough for the window to wrap).
    /// ACK-trim does NOT increment this — only the buffer-full eviction.
    pub(crate) replay_evictions: u64,
    /// Count of MSG_ACK control frames rejected because the daemon ACKed a
    /// sequence outside the valid `[acked_seq, next_seq]` window — either a
    /// backward ACK (`seq < acked_seq`) or a future ACK of a sequence the
    /// helper never allocated (`seq > next_seq`) (#2959). Such an ACK comes
    /// from a buggy, mixed-version, or corrupted daemon listener; the helper
    /// fails closed by ignoring it (watermark + replay buffer left intact). A
    /// non-zero, growing value means the peer's ACK view is corrupt.
    pub(crate) invalid_acks: u64,
    #[allow(dead_code)] // stats field for future reporting
    pub(crate) replayed: u64,
    #[allow(dead_code)] // producer-call-site wiring will surface these fields
    pub(crate) dataplane_events: DataplaneEventStats,
}

struct EventStreamShared {
    /// Workers fetch_add to get globally monotonic sequence numbers.
    next_seq: AtomicU64,
    /// Updated by I/O thread from Ack frames.
    acked_seq: AtomicU64,
    /// Set by Pause, cleared by Resume.
    paused: AtomicBool,
    /// #2875: poison flag for the paused demotion drain. Set when a SESSION-SYNC
    /// delta (`SessionOpen`/`SessionUpdate`/`SessionClose`) is evicted from the
    /// bounded replay buffer at `REPLAY_BUFFER_CAPACITY` WHILE PAUSED.
    ///
    /// A paused drain is meant to be a lossless, stable window the future owner
    /// reads before demotion completes (`docs/session-sync-design.md`). The
    /// replay buffer is bounded, so a long pause that overruns it evicts the
    /// oldest frames (bumping `frames_replay_evicted` only). If an evicted frame
    /// is a session mutation, that mutation never reaches the new owner — yet
    /// `handle_drain_request` would still report `DrainComplete` and demotion
    /// would finish with lost sessions on the peer.
    ///
    /// When set, `handle_drain_request` WITHHOLDS `DrainComplete` and emits a
    /// `FullResync` instead, forcing the daemon to re-export full session state
    /// (the same recovery path as #2874 / the replay-gap resync). Telemetry
    /// eviction does NOT set this — it must not trigger a spurious resync.
    ///
    /// Lifecycle: set on a session-frame eviction during pause
    /// (`evict_replay_frame`); cleared at pause-start (`MSG_PAUSE`) so each
    /// fresh pause window starts clean, and after a poisoned drain emits its
    /// `FullResync` (window consumed — a later eviction re-poisons). NOT a
    /// substitute for bounding the buffer: the fix is poison-on-loss, the buffer
    /// stays bounded (no unbounded growth / memory DoS).
    session_evicted_while_paused: AtomicBool,
    /// Raised once by `EventStreamSender::stop` (and `Drop`) to ask the I/O
    /// thread to exit. Lives in the shared state — rather than as a separately
    /// threaded `Arc<AtomicBool>` — so every I/O-thread function that already
    /// holds `shared` (connect, replay, drain, the connected loop) can observe
    /// it. This is what makes the bounded replay/drain writer
    /// (`write_all_backpressured`) stop-aware: a write that keeps hitting
    /// `WouldBlock` against a stuck reader bails out as soon as this is set, so
    /// the stop-join can never deadlock behind a wedged write (#2877).
    stop: AtomicBool,
    /// True when the event socket is connected.
    connected: AtomicBool,
    /// Counters.
    frames_sent: AtomicU64,
    frames_dropped: AtomicU64,
    /// I/O cycles in which `write_buf` hit `WRITE_BACKLOG_MAX_BYTES` and the
    /// channel drain was halted (stalled consumer signal, #2381).
    frames_write_stalled: AtomicU64,
    /// Accepted-and-enqueued frames evicted from the replay buffer when it
    /// wrapped at `REPLAY_BUFFER_CAPACITY` before the daemon ACKed them
    /// (#2382). These frames were counted in `frames_sent` at enqueue but are
    /// unrecoverable after reconnect — a real telemetry loss. Distinct from
    /// ACK-trim (frames removed because they were acknowledged, which is NOT a
    /// loss): only the buffer-full eviction path increments this.
    frames_replay_evicted: AtomicU64,
    /// MSG_ACK frames rejected because the daemon ACKed a sequence outside the
    /// valid `[acked_seq, next_seq]` window (#2959). See `invalid_acks` in
    /// `EventStreamStats`.
    frames_invalid_acks: AtomicU64,
    frames_replayed: AtomicU64,
    dataplane_event_counters: DataplaneEventCounters,
    #[allow(dead_code)] // consumed by producer call sites once they are wired
    dataplane_event_limiter: DataplaneEventRateLimiter,
    dataplane_event_queue: DataplaneEventQueueBudget,
}

impl EventStreamShared {
    fn new() -> Self {
        Self::new_with_dataplane_event_rate(DataplaneEventRateLimitConfig::default())
    }

    fn new_with_dataplane_event_rate(config: DataplaneEventRateLimitConfig) -> Self {
        Self::new_with_dataplane_event_rate_and_queue_capacity(config, CHANNEL_CAPACITY)
    }

    fn new_with_dataplane_event_rate_and_queue_capacity(
        config: DataplaneEventRateLimitConfig,
        channel_capacity: usize,
    ) -> Self {
        Self {
            next_seq: AtomicU64::new(0),
            acked_seq: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            session_evicted_while_paused: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            frames_sent: AtomicU64::new(0),
            frames_dropped: AtomicU64::new(0),
            frames_write_stalled: AtomicU64::new(0),
            frames_replay_evicted: AtomicU64::new(0),
            frames_invalid_acks: AtomicU64::new(0),
            frames_replayed: AtomicU64::new(0),
            dataplane_event_counters: DataplaneEventCounters::new(),
            dataplane_event_limiter: DataplaneEventRateLimiter::new(config),
            dataplane_event_queue: DataplaneEventQueueBudget::new(channel_capacity),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventStreamSendError {
    Full,
    Disconnected,
}

// ---------------------------------------------------------------------------
// EventStreamSender -- coordinator-level handle
// ---------------------------------------------------------------------------

/// Coordinator-level event stream handle. Owns the I/O thread.
pub(crate) struct EventStreamSender {
    tx: SyncSender<EventFrame>,
    shared: Arc<EventStreamShared>,
    io_thread: Option<JoinHandle<()>>,
}

impl EventStreamSender {
    /// Create a new event stream sender and spawn the I/O thread.
    /// The helper connects to the daemon listener at `socket_path`.
    pub(crate) fn new(socket_path: &str) -> Self {
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let shared = Arc::new(EventStreamShared::new());

        let shared_clone = shared.clone();
        let path = socket_path.to_string();

        let io_thread = thread::Builder::new()
            .name("xpf-event-stream".to_string())
            .spawn(move || {
                io_thread_main(rx, shared_clone, path);
            })
            .expect("spawn event stream I/O thread");

        Self {
            tx,
            shared,
            io_thread: Some(io_thread),
        }
    }

    /// Get a lightweight handle to pass to worker threads.
    pub(crate) fn worker_handle(&self) -> EventStreamWorkerHandle {
        EventStreamWorkerHandle {
            tx: self.tx.clone(),
            shared: self.shared.clone(),
        }
    }

    /// Current event stream statistics.
    pub(crate) fn stats(&self) -> EventStreamStats {
        EventStreamStats {
            connected: self.shared.connected.load(Ordering::Relaxed),
            seq: self.shared.next_seq.load(Ordering::Relaxed),
            acked_seq: self.shared.acked_seq.load(Ordering::Relaxed),
            sent: self.shared.frames_sent.load(Ordering::Relaxed),
            dropped: self.shared.frames_dropped.load(Ordering::Relaxed),
            write_stalls: self.shared.frames_write_stalled.load(Ordering::Relaxed),
            replay_evictions: self.shared.frames_replay_evicted.load(Ordering::Relaxed),
            invalid_acks: self.shared.frames_invalid_acks.load(Ordering::Relaxed),
            replayed: self.shared.frames_replayed.load(Ordering::Relaxed),
            dataplane_events: self.shared.dataplane_event_counters.snapshot(),
        }
    }

    /// #2880 test seam: build an `EventStreamSender` WITHOUT spawning the I/O
    /// thread, with the connected flag forced to `connected`. The returned
    /// `Receiver` must be kept alive by the test so the channel does not
    /// disconnect; `push_delta_lossless` then succeeds (connected + live rx)
    /// or fails immediately (`connected = false`) exactly like the production
    /// disconnected / connected paths, without a real socket.
    #[cfg(test)]
    pub(crate) fn test_sender(
        connected: bool,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<EventFrame>) {
        let (tx, rx) = mpsc::sync_channel(capacity);
        let shared = Arc::new(EventStreamShared::new());
        shared.connected.store(connected, Ordering::Release);
        (
            Self {
                tx,
                shared,
                io_thread: None,
            },
            rx,
        )
    }

    /// Signal the I/O thread to stop and wait for it to exit.
    ///
    /// The stop flag lives in `shared`, so a replay/drain write that is
    /// currently backpressured against a stuck reader observes it within one
    /// `REPLAY_DRAIN_WRITE_POLL` and bails out — the join below cannot deadlock
    /// behind a wedged blocking write (#2877).
    pub(crate) fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(join) = self.io_thread.take() {
            let _ = join.join();
        }
    }
}

impl Drop for EventStreamSender {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
pub(crate) fn test_worker_handle(
    capacity: usize,
    config: DataplaneEventRateLimitConfig,
) -> (EventStreamWorkerHandle, mpsc::Receiver<EventFrame>) {
    let (tx, rx) = mpsc::sync_channel(capacity);
    let shared = Arc::new(
        EventStreamShared::new_with_dataplane_event_rate_and_queue_capacity(config, capacity),
    );
    (EventStreamWorkerHandle { tx, shared }, rx)
}

// ---------------------------------------------------------------------------
// EventStreamWorkerHandle -- lightweight clone for worker threads
// ---------------------------------------------------------------------------

/// Worker-thread handle. Cheap to clone (Arc + SyncSender clone).
#[derive(Clone)]
pub(crate) struct EventStreamWorkerHandle {
    tx: SyncSender<EventFrame>,
    shared: Arc<EventStreamShared>,
}

impl EventStreamWorkerHandle {
    /// Allocate the next globally-monotonic sequence number.
    pub(crate) fn next_seq(&self) -> u64 {
        self.shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Non-blocking send. Returns false if the channel is full (event dropped).
    pub(crate) fn try_send(&self, frame: EventFrame) -> bool {
        self.try_send_frame(frame).is_ok()
    }

    /// #2880: record `n` deltas that could not be queued through the LOSSLESS
    /// producer (event stream disconnected / saturated). `send_frame_lossless`
    /// returns the failure as an `Err` rather than bumping `frames_dropped`
    /// (its caller decides whether the loss matters), so a caller that treats
    /// the drop as a tolerated cleanup miss — the tunnel-remap purge, #2880 —
    /// records it here so it surfaces in the same dropped-frames metric the
    /// lossy `try_send` path uses, instead of being silently swallowed.
    pub(crate) fn record_dropped_frames(&self, n: u64) {
        self.shared.frames_dropped.fetch_add(n, Ordering::Relaxed);
    }

    fn try_send_frame(&self, frame: EventFrame) -> Result<(), EventStreamSendError> {
        match self.tx.try_send(frame) {
            Ok(()) => {
                self.shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::TrySendError::Full(_)) => {
                self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                Err(EventStreamSendError::Full)
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                Err(EventStreamSendError::Disconnected)
            }
        }
    }

    fn send_frame_lossless(&self, mut frame: EventFrame) -> Result<(), String> {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err("event stream not connected".to_string());
        }
        let deadline = Instant::now() + LOSSLESS_QUEUE_TIMEOUT;
        loop {
            match self.tx.try_send(frame) {
                Ok(()) => {
                    self.shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(mpsc::TrySendError::Full(returned)) => {
                    frame = returned;
                    if !self.shared.connected.load(Ordering::Acquire) {
                        return Err(format!(
                            "event stream disconnected while queuing seq {}",
                            frame.seq
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "timed out queuing event stream frame seq {}",
                            frame.seq
                        ));
                    }
                    thread::sleep(LOSSLESS_QUEUE_RETRY_DELAY);
                }
                Err(mpsc::TrySendError::Disconnected(returned)) => {
                    return Err(format!(
                        "event stream channel disconnected while queuing seq {}",
                        returned.seq
                    ));
                }
            }
        }
    }

    fn encode_delta_frame(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) -> EventFrame {
        let seq = self.next_seq();
        match delta.kind {
            SessionDeltaKind::Open => EventFrame::encode_session_open(
                seq,
                &delta.key,
                &delta.decision,
                &delta.metadata,
                zone_name_to_id,
                delta.fabric_redirect_sync,
            ),
            SessionDeltaKind::Close => EventFrame::encode_session_close(
                seq,
                &delta.key,
                delta.metadata.owner_rg_id,
                close_flags(delta),
                delta.metadata.ingress_zone,
                delta.metadata.egress_zone,
            ),
        }
    }

    /// Encode and send a session delta as an event frame.
    pub(crate) fn push_delta(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) {
        let frame = self.encode_delta_frame(delta, zone_name_to_id);
        self.try_send(frame);
    }

    /// Lossless variant used for explicit bootstrap/replay exports. This path
    /// may wait briefly for queue capacity, but it never silently drops.
    pub(crate) fn push_delta_lossless(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) -> Result<(), String> {
        let frame = self.encode_delta_frame(delta, zone_name_to_id);
        self.send_frame_lossless(frame)
    }

    /// #2460: emit a SESSION_CLOSE RT_FLOW frame (type 14) for a Close delta
    /// on the raw dataplane-event channel.
    ///
    /// This is ADDITIVE to — and must be called ALONGSIDE, never instead of
    /// — `push_delta`, which carries the unchanged type-2 HA session-sync
    /// close delta. The RT_FLOW frame drives the Go NetFlow/IPFIX
    /// session-close exporters (`pkg/daemon/daemon_flowexport.go`), which
    /// only run on a `Type == "SESSION_CLOSE"` `logging.EventRecord` — a
    /// record userspace mode never produced before this. The caller
    /// (`flush_session_deltas`) gates on `delta.kind == Close`, but the
    /// guard is repeated here so a future caller cannot misuse it on an Open
    /// delta. Best-effort (`try_send`): a dropped close frame loses only one
    /// flow-export record, never the HA close delta (a separate frame).
    /// `app_id` is the application resolved for the closing session's 5-tuple
    /// by the caller (`flush_session_deltas`) via the same `app_catalog.lookup`
    /// the forwarding hot path runs — #2520. 0 means UNKNOWN (no catalog
    /// match), the unchanged behavior.
    /// `ingress_ifindex` is the closing binding's interface index (#2615); the
    /// Go side resolves it to the RT_FLOW `packet-incoming-interface`. 0 keeps
    /// the prior "N/A" rendering.
    pub(crate) fn emit_session_close_rt_flow(
        &self,
        delta: &SessionDelta,
        app_id: u16,
        ingress_ifindex: u32,
    ) {
        if delta.kind != SessionDeltaKind::Close {
            return;
        }
        let nat = &delta.decision.nat;
        // #2465: convert the monotonic creation / last-seen instants on the
        // close delta to absolute wall-clock values for the wire. The session
        // table uses CLOCK_MONOTONIC, but the flow record needs an absolute
        // StartTime (and the EndTime is a wall-clock instant on the Go side),
        // so we anchor monotonic deltas against a single (mono, wall) reading
        // taken here at emit time. A 0 created_ns stays 0 on the wire and
        // triggers the Go-side packet-count fallback.
        let (now_mono_ns, now_unix_ns) = read_mono_and_wall_clocks();
        // #2853: carry BOTH the integer Unix second (offset 108) and the
        // sub-second nanosecond remainder (offset 44, the close-unused policy_id
        // slot) so the Go exporters render a millisecond-accurate flow
        // StartTime. The pre-#2853 code stamped only the truncated second, so
        // every flow opened in the same second shared one start instant.
        let (created_unix_secs, created_subsec_nanos) =
            monotonic_ns_to_unix_secs_subnanos(delta.created_ns, now_mono_ns, now_unix_ns);
        let close_unix_ns =
            monotonic_ns_to_unix_ns(delta.last_seen_ns, now_mono_ns, now_unix_ns);
        // #2512: route through the per-kind rate limiter + queue budget +
        // sent/dropped counters instead of a bare `try_send`. The same mono
        // clock reading anchors the limiter so a dropped close is counted
        // under DataplaneEventKind::SessionClose. The frame is encoded only
        // after the budget passes (seq supplied by the budget path), so a
        // rate-limited / budget-exhausted close never burns a sequence
        // number. A dropped close loses only one flow-export record — the
        // separate type-2 HA close delta (`push_delta`) is untouched.
        self.try_emit_dataplane_frame(
            DataplaneEventKind::SessionClose,
            delta.metadata.ingress_zone,
            now_mono_ns,
            |seq| {
                EventFrame::encode_session_close_rt_flow(
                    seq,
                    delta.key.addr_family,
                    delta.key.protocol,
                    delta.key.src_ip,
                    delta.key.dst_ip,
                    delta.key.src_port,
                    delta.key.dst_port,
                    nat.rewrite_src,
                    nat.rewrite_dst,
                    nat.rewrite_src_port.unwrap_or(0),
                    nat.rewrite_dst_port.unwrap_or(0),
                    delta.metadata.ingress_zone,
                    delta.metadata.egress_zone,
                    // #3056: the admitting policy ID stamped on the session at
                    // install, so the SESSION_CLOSE RT_FLOW record (and the
                    // NetFlow/IPFIX close exporters) name the policy that
                    // admitted the flow instead of policy 0. Rides the trailing
                    // [136:140] slot because #2853 took [44:48] on a close.
                    delta.metadata.policy_id,
                    delta.metadata.owner_rg_id as i16,
                    // #2508: per-policy RT_FLOW SYSLOG gate byte. The frame is
                    // sent unconditionally (the Go NetFlow/IPFIX exporter
                    // accounts every close), but this bit tells the Go
                    // logEvent path whether to ALSO emit the per-policy
                    // RT_FLOW_SESSION_CLOSE syslog record.
                    delta.metadata.log_session_close,
                    created_unix_secs,
                    // #2853: sub-second nanosecond remainder of the creation
                    // instant, rides the [44:48] slot (unused on a close).
                    created_subsec_nanos,
                    close_unix_ns,
                    // #2520: carry the resolved AppID in the [132:134] wire
                    // slot so SESSION_CLOSE RT_FLOW records (and the
                    // NetFlow/IPFIX exporters) show the application.
                    app_id,
                    // #2615: carry the closing binding's ingress ifindex in
                    // the [128:132] wire slot so the record shows the
                    // admitting interface instead of "N/A".
                    ingress_ifindex,
                    // #2501: real per-session volume harvested off the
                    // expiring entry's counters, into the reserved
                    // [56:64]/[64:72] (forward) and [112:120]/[120:128]
                    // (reverse) slots.
                    delta.counters.fwd_packets,
                    delta.counters.fwd_bytes,
                    delta.counters.rev_packets,
                    delta.counters.rev_bytes,
                )
            },
        );
    }

    /// #2508: emit an RT_FLOW SESSION_CREATE frame (type 15) for a session
    /// admitted by a policy configured with `then log session-init`. There is
    /// NO flowexport consumer of session opens, so unlike the close frame this
    /// is gated entirely at the producer: the caller invokes it only when
    /// `delta.metadata.log_session_init` is set. The frame rides the same raw
    /// dataplane-event channel and is formatted as RT_FLOW_SESSION_CREATE by
    /// the Go logEvent path. Best-effort (`try_send`).
    /// #2615: `app_id` is the application resolved for the new session's
    /// 5-tuple (caller runs the same `app_catalog.lookup` the close path uses,
    /// mirroring #2520) and `ingress_ifindex` is the admitting binding's
    /// interface index. 0 in either keeps the prior UNKNOWN / N/A rendering.
    pub(crate) fn emit_session_create_rt_flow(
        &self,
        delta: &SessionDelta,
        app_id: u16,
        ingress_ifindex: u32,
    ) {
        if delta.kind != SessionDeltaKind::Open {
            return;
        }
        let nat = &delta.decision.nat;
        // #2512: same per-kind budget path as the close frame (see
        // emit_session_close_rt_flow). SESSION_CREATE is producer-gated by
        // the caller (only emitted for `log session-init` policies), but it
        // still rides the shared dataplane-event channel so it MUST honor the
        // same limiter / budget / counters under
        // DataplaneEventKind::SessionCreate rather than a bare `try_send`.
        let (now_mono_ns, _) = read_mono_and_wall_clocks();
        self.try_emit_dataplane_frame(
            DataplaneEventKind::SessionCreate,
            delta.metadata.ingress_zone,
            now_mono_ns,
            |seq| {
                EventFrame::encode_session_create_rt_flow(
                    seq,
                    delta.key.addr_family,
                    delta.key.protocol,
                    delta.key.src_ip,
                    delta.key.dst_ip,
                    delta.key.src_port,
                    delta.key.dst_port,
                    nat.rewrite_src,
                    nat.rewrite_dst,
                    nat.rewrite_src_port.unwrap_or(0),
                    nat.rewrite_dst_port.unwrap_or(0),
                    delta.metadata.ingress_zone,
                    delta.metadata.egress_zone,
                    // #3056: the admitting policy ID stamped on the session at
                    // install, so the SESSION_CREATE RT_FLOW record names the
                    // policy that admitted the flow instead of policy 0.
                    delta.metadata.policy_id,
                    // #2615: ingress ifindex ([128:132]) + resolved AppID
                    // ([132:134]) so the SESSION_CREATE RT_FLOW record shows
                    // the admitting interface and application instead of
                    // N/A / UNKNOWN.
                    ingress_ifindex,
                    app_id,
                )
            },
        );
    }
}

// ---------------------------------------------------------------------------
// I/O thread -- manages connection, writes events, reads control frames
// ---------------------------------------------------------------------------

fn io_thread_main(
    rx: mpsc::Receiver<EventFrame>,
    shared: Arc<EventStreamShared>,
    socket_path: String,
) {
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
    let mut ctrl_read_buf: Vec<u8> = Vec::with_capacity(128);

    while !shared.stop.load(Ordering::Acquire) {
        // ---- Connect phase ----
        let stream = match try_connect(&socket_path, &shared) {
            Some(s) => s,
            None => break, // stop requested during connect
        };
        stream.set_nonblocking(true).ok();
        shared.connected.store(true, Ordering::Release);
        eprintln!("xpf-event-stream: connected to {}", socket_path);

        // Replay buffered events from last acked seq
        let acked = shared.acked_seq.load(Ordering::Acquire);
        let replay_result = replay_buffered(&stream, &mut replay_buf, acked, &shared);
        if replay_result.is_err() {
            shared.connected.store(false, Ordering::Release);
            eprintln!("xpf-event-stream: replay failed, reconnecting");
            continue;
        }

        // ---- Steady-state loop ----
        ctrl_read_buf.clear(); // discard stale data from previous connection
        let disconnect = run_connected_loop(
            &rx,
            &stream,
            &shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            KEEPALIVE_IDLE_INTERVAL,
        );

        shared.connected.store(false, Ordering::Release);
        if disconnect {
            eprintln!("xpf-event-stream: disconnected, will reconnect");
        }
    }

    // Drain remaining events on shutdown
    drain_remaining(&rx, &shared);
    release_replay_dataplane_event_queue_budget(&shared, &mut replay_buf);
    shared.connected.store(false, Ordering::Release);
    eprintln!("xpf-event-stream: I/O thread exiting");
}

/// Try to connect to the daemon event socket, retrying every 100ms.
/// Returns None if stop is requested.
fn try_connect(path: &str, shared: &Arc<EventStreamShared>) -> Option<UnixStream> {
    loop {
        if shared.stop.load(Ordering::Acquire) {
            return None;
        }
        match UnixStream::connect(path) {
            Ok(stream) => return Some(stream),
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Replay buffered events that are newer than the last acked sequence.
/// If the replay buffer doesn't cover acked+1, send FullResync.
fn replay_buffered(
    stream: &UnixStream,
    replay_buf: &mut VecDeque<EventFrame>,
    acked_seq: u64,
    shared: &Arc<EventStreamShared>,
) -> io::Result<()> {
    // One shared deadline bounds the whole replay so a stuck reader cannot hold
    // the I/O thread for `frames * deadline` (#2877). `write_all_backpressured`
    // keeps the socket NONBLOCKING (the canonical data-frame mode) and polls
    // the stop flag each WouldBlock cycle; on stop/deadline/error it returns
    // Err and the caller reconnects.
    let deadline = Instant::now() + REPLAY_DRAIN_WRITE_DEADLINE;
    // Check if replay buffer covers what we need. On a true fresh start
    // (acked_seq == 0 and no buffered frames), start clean. Otherwise any gap
    // at acked+1 requires FullResync, including the acked_seq==0 case where an
    // overrun replay buffer has already trimmed seq 1.
    let oldest_buffered = replay_buf.front().map(|f| f.seq).unwrap_or(0);
    let has_gap = (replay_buf.is_empty() && acked_seq > 0) || oldest_buffered > acked_seq + 1;
    if has_gap {
        let seq = shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let frame = EventFrame::encode_full_resync(seq);
        write_all_backpressured(stream, frame.as_bytes(), shared, deadline)?;
        shared.frames_sent.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "xpf-event-stream: sent FullResync (buffer gap: acked={}, oldest_buffered={})",
            acked_seq, oldest_buffered
        );
        // Keep the stale replay window until the daemon ACKs the FullResync.
        // Clearing here can make an acked_seq=0 reconnect look like a clean
        // fresh start and permanently suppress the required bulk export.
        return Ok(());
    }

    // Replay frames newer than acked_seq
    let mut replayed = 0u64;
    for frame in replay_buf.iter() {
        if frame.seq > acked_seq {
            write_all_backpressured(stream, frame.as_bytes(), shared, deadline)?;
            replayed += 1;
        }
    }
    if replayed > 0 {
        shared
            .frames_replayed
            .fetch_add(replayed, Ordering::Relaxed);
        eprintln!("xpf-event-stream: replayed {replayed} events");
    }
    Ok(())
}

/// Write all of `bytes` to the NONBLOCKING `stream`, honoring backpressure
/// without ever wedging the I/O thread (#2877).
///
/// The replay (`replay_buffered`) and drain (`handle_drain_request`) paths must
/// push frames to a socket whose daemon reader may have stalled. The old
/// `write_frame_blocking` flipped the socket to BLOCKING and called `write_all`
/// with no deadline and no stop check, so a stuck reader held the I/O thread in
/// the blocking write forever — and since `EventStreamSender::stop` joins that
/// thread, a write-blocked thread could not observe the stop flag and
/// stop/demotion hung. That violates the slow-consumer invariant in
/// `docs/session-sync-design.md`: a slow telemetry/session consumer must never
/// stall the helper.
///
/// This writer keeps the socket nonblocking (the same mode the steady-state
/// data-frame writes use) and, on `WouldBlock`, sleeps `REPLAY_DRAIN_WRITE_POLL`
/// and retries — polling `shared.stop` every cycle and bailing at `deadline`.
/// It returns `Err` on stop (Interrupted), deadline (TimedOut), or a real
/// socket error so the caller reconnects / withholds DrainComplete rather than
/// blocking indefinitely. `deadline` is shared across all frames in one
/// replay/drain pass so total time is bounded even if stop is never raised.
fn write_all_backpressured(
    stream: &UnixStream,
    bytes: &[u8],
    shared: &Arc<EventStreamShared>,
    deadline: Instant,
) -> io::Result<()> {
    use std::io::Write;
    let mut written = 0usize;
    while written < bytes.len() {
        if shared.stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "event stream stop requested during replay/drain write",
            ));
        }
        match (&*stream).write(&bytes[written..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "event stream replay/drain write returned 0",
                ));
            }
            Ok(n) => written += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "event stream replay/drain write deadline exceeded",
                    ));
                }
                thread::sleep(REPLAY_DRAIN_WRITE_POLL);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Main connected loop. Returns true if we should reconnect, false if stopping.
fn run_connected_loop(
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
    ctrl_read_buf: &mut Vec<u8>,
    keepalive_interval: Duration,
) -> bool {
    use std::io::{Read, Write};

    let mut write_buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp_read = [0u8; 64];
    let mut idle_cycles = 0u32;
    let mut last_write = Instant::now();

    loop {
        if shared.stop.load(Ordering::Acquire) {
            return false;
        }

        let paused = shared.paused.load(Ordering::Acquire);

        let drain = drain_channel_into_write_buf(rx, shared, replay_buf, &mut write_buf, paused);
        if drain.disconnected {
            return false;
        }
        let drained_any = drain.drained_any;

        // Write buffered frames to socket
        if !write_buf.is_empty() {
            match (&*stream).write(&write_buf) {
                Ok(n) => {
                    if n < write_buf.len() {
                        // Partial write -- keep remainder
                        write_buf.drain(..n);
                    } else {
                        write_buf.clear();
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Socket buffer full, keep write_buf for next cycle
                }
                Err(_) => {
                    // Socket error -- disconnect
                    return true;
                }
            }
        }

        // Read control frames from daemon (non-blocking), accumulating
        // partial reads so that incomplete frames are not lost.
        match (&*stream).read(&mut tmp_read) {
            Ok(0) => {
                // EOF -- peer closed
                return true;
            }
            Ok(n) => {
                ctrl_read_buf.extend_from_slice(&tmp_read[..n]);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available -- normal
            }
            Err(_) => {
                return true;
            }
        }

        // Process complete control frames from accumulated buffer
        if !ctrl_read_buf.is_empty() {
            let (action, consumed) =
                process_control_frames(ctrl_read_buf, shared, rx, stream, replay_buf);
            if consumed > 0 {
                ctrl_read_buf.drain(..consumed);
            }
            if let Some(reconnect) = action {
                return reconnect;
            }
        }

        // Idle backoff + keepalive
        if drained_any {
            idle_cycles = 0;
            last_write = Instant::now();
        } else {
            idle_cycles = idle_cycles.saturating_add(1);
            if idle_cycles > 10 {
                // Enqueue a keepalive (prevents idle disconnect on the Go side)
                // through the SAME `write_buf` backpressure path data frames use
                // (#2883). The old code called `write_all` directly on the
                // nonblocking socket and returned true (immediate reconnect) on
                // ANY error — including `WouldBlock` when the kernel send buffer
                // is full under a slow reader — bypassing the partial-write /
                // WouldBlock backpressure and stall accounting and causing
                // reconnect churn -> replay storms. Routing the keepalive bytes
                // into `write_buf` makes WouldBlock ordinary backpressure: the
                // top-of-loop flush retains the remainder for the next cycle,
                // and a genuinely dead consumer is still detected by the normal
                // socket-error / EOF path rather than by a false reconnect on
                // transient fullness.
                if last_write.elapsed() >= keepalive_interval {
                    let mut ka = [0u8; FRAME_HEADER_SIZE];
                    ka[4] = MSG_KEEPALIVE;
                    write_buf.extend_from_slice(&ka);
                    last_write = Instant::now();
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// Process control frames received from the daemon.
/// Returns (action, bytes_consumed) where action is Some(true) to reconnect,
/// Some(false) to stop, or None to continue. Only complete frames are consumed;
/// any trailing partial frame is left for the next read cycle.
fn process_control_frames(
    data: &[u8],
    shared: &Arc<EventStreamShared>,
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    replay_buf: &mut VecDeque<EventFrame>,
) -> (Option<bool>, usize) {
    let mut offset = 0;
    while offset + FRAME_HEADER_SIZE <= data.len() {
        let payload_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let frame_len = FRAME_HEADER_SIZE + payload_len as usize;
        if offset + frame_len > data.len() {
            break; // incomplete frame -- wait for more data
        }
        let msg_type = data[offset + 4];
        let seq = u64::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        offset += frame_len;

        match msg_type {
            MSG_ACK => {
                // Validate the ACK watermark BEFORE mutating acked_seq or
                // trimming the replay buffer (#2959). A correct daemon ACKs
                // only frames it has applied, so the sequence must lie in the
                // window [acked_seq, next_seq]:
                //   - seq == acked_seq  -> duplicate ACK, benign no-op
                //   - seq == next_seq   -> ACK of the latest allocated frame
                //   - acked < seq < next -> normal forward ACK
                // A backward ACK (seq < acked_seq) or a future ACK of a
                // sequence the helper never allocated (seq > next_seq) means
                // the peer's view is corrupt (buggy / mixed-version /
                // corrupted listener). Trusting it would poison acked_seq and
                // trim or permanently suppress replay of frames the daemon has
                // not actually acknowledged. Fail closed: ignore the impossible
                // ACK, leave the watermark and replay buffer intact, and
                // surface it via the invalid_acks counter. Ignoring (rather
                // than disconnecting) preserves the live connection and avoids
                // a reconnect-thrash loop against a peer that keeps emitting
                // bad ACKs; valid ACKs interleaved with the bad ones still
                // advance the watermark normally.
                let acked = shared.acked_seq.load(Ordering::Acquire);
                let next = shared.next_seq.load(Ordering::Acquire);
                if seq < acked || seq > next {
                    shared.frames_invalid_acks.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "xpf-event-stream: ignoring out-of-range ACK seq={} \
                         (acked={}, next={})",
                        seq, acked, next
                    );
                } else {
                    shared.acked_seq.store(seq, Ordering::Release);
                    // Trim replay buffer: remove frames with seq <= acked
                    while let Some(front) = replay_buf.front() {
                        if front.seq <= seq {
                            pop_replay_frame(shared, replay_buf);
                        } else {
                            break;
                        }
                    }
                }
            }
            MSG_PAUSE => {
                // #2875: a fresh pause window starts lossless. Clear any poison
                // left from a previous drain so only an eviction WITHIN this
                // pause window can withhold the upcoming DrainComplete.
                shared
                    .session_evicted_while_paused
                    .store(false, Ordering::Release);
                shared.paused.store(true, Ordering::Release);
                eprintln!("xpf-event-stream: paused by daemon");
            }
            MSG_RESUME => {
                shared.paused.store(false, Ordering::Release);
                eprintln!("xpf-event-stream: resumed by daemon");
                // Flush any buffered-during-pause frames on next write cycle
            }
            MSG_DRAIN_REQUEST => {
                // Drain channel until we have all events up to target seq,
                // then send DrainComplete.
                let target_seq = seq;
                handle_drain_request(target_seq, rx, stream, shared, replay_buf);
            }
            _ => {
                eprintln!("xpf-event-stream: unknown control frame type {}", msg_type);
            }
        }
    }
    (None, offset)
}

/// Handle DrainRequest: drain channel, write all buffered events up to target
/// seq, then send DrainComplete.
fn handle_drain_request(
    target_seq: u64,
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) {
    let deadline = Instant::now() + Duration::from_millis(200);
    let was_paused = shared.paused.load(Ordering::Acquire);

    // Drain channel until we've seen target_seq or timeout. `reached_target`
    // records whether the fence was actually reached: a timeout below the fence
    // (#2876) must NOT be reported as a successful DrainComplete, because the
    // events after the fence have not been flushed to the daemon/peer.
    let mut reached_target = false;
    loop {
        match rx.try_recv() {
            Ok(frame) => {
                let frame_seq = frame.seq;
                push_replay_frame(shared, replay_buf, frame);
                if frame_seq >= target_seq {
                    reached_target = true;
                    break;
                }
            }
            Err(TryRecvError::Empty) => {
                // Check if we already have the target in replay buf
                if replay_buf
                    .back()
                    .map(|f| f.seq >= target_seq)
                    .unwrap_or(false)
                {
                    reached_target = true;
                    break;
                }
                if Instant::now() >= deadline {
                    eprintln!(
                        "xpf-event-stream: drain timeout below fence, highest_seq={} target={}",
                        replay_buf.back().map(|f| f.seq).unwrap_or(0),
                        target_seq
                    );
                    break;
                }
                thread::sleep(Duration::from_micros(100));
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }

    // Write replay-buffered frames to the socket using the canonical
    // nonblocking + stop-aware backpressure writer (#2877). The socket stays
    // nonblocking (the connected loop set it so); a stuck reader can no longer
    // wedge the I/O thread in a blocking write, and a raised stop flag is
    // observed within one poll interval. A shared deadline bounds the whole
    // drain write.
    let write_deadline = Instant::now() + REPLAY_DRAIN_WRITE_DEADLINE;
    let mut write_failed = false;
    // #2882: honor the fence — write only frames UP TO the requested target,
    // not the whole replay head. DrainRequest is contracted (see
    // docs/session-sync-design.md) as "flush all buffered events up to target
    // seq". Frames newer than the fence belong to a later drain/replay;
    // flushing (and reporting) them here changes the contract to "dump current
    // replay head", which masks holes and couples demotion correctness to
    // unrelated later-buffered frames. `drained_up_to` tracks the highest seq
    // <= target actually written (the replay buffer is seq-ordered).
    let mut drained_up_to = 0u64;
    for frame in replay_buf.iter() {
        if frame.seq > target_seq {
            continue; // beyond the fence — not part of this drain
        }
        if let Err(e) = write_all_backpressured(stream, frame.as_bytes(), shared, write_deadline) {
            eprintln!("xpf-event-stream: drain write error: {e}");
            write_failed = true;
            break;
        }
        drained_up_to = frame.seq;
    }

    // Send DrainComplete ONLY when the target fence was reached AND every frame
    // up to it was flushed. If the drain timed out below the fence, or a write
    // failed against a stuck/stopping reader, withhold DrainComplete: the
    // daemon's SendDrainRequest then times out (or rejects a below-target seq)
    // and refuses to proceed with demotion, rather than silently losing the
    // post-fence sessions on failover (#2876/#2877).
    //
    // #2882: report the fence the daemon requested, not replay_buf.back().seq
    // (which could exceed the target). Everything with seq <= target_seq is now
    // flushed, so report the highest such seq actually written; if the buffer
    // held nothing at/below the fence (all already ACK-trimmed), the fence is
    // still satisfied, so report target_seq.
    let drain_seq = if drained_up_to == 0 {
        target_seq
    } else {
        drained_up_to
    };

    // #2875: a SESSION-SYNC delta was evicted from the bounded replay buffer
    // while paused, so this drain window is missing mutations the new owner
    // needs. The drain is POISONED: it must NOT report DrainComplete (that
    // would complete demotion with lost sessions on the peer). Checked AFTER
    // the drain+write loops so an eviction during this drain's own
    // push_replay_frame calls is also caught.
    let session_evicted = shared
        .session_evicted_while_paused
        .load(Ordering::Acquire);

    if session_evicted {
        // Surface the poison the same way as #2874 / the replay-gap path: emit
        // a FullResync so the daemon re-exports full session state. The
        // daemon's SendDrainRequest receives no DrainComplete, times out, and
        // refuses to proceed with demotion until the resync re-establishes
        // state. Allocate a fresh seq (mirrors replay_buffered's resync).
        let resync_seq = shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let resync_frame = EventFrame::encode_full_resync(resync_seq);
        if let Err(e) =
            write_all_backpressured(stream, resync_frame.as_bytes(), shared, write_deadline)
        {
            eprintln!("xpf-event-stream: drain-poison FullResync write error: {e}");
        } else {
            shared.frames_sent.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "xpf-event-stream: drain POISONED -- session delta evicted while paused; \
                 sent FullResync seq {} instead of DrainComplete (demotion must full-resync)",
                resync_seq
            );
        }
        // Window consumed: clear so a later clean drain in this pause window can
        // complete (a fresh session-frame eviction re-poisons).
        shared
            .session_evicted_while_paused
            .store(false, Ordering::Release);
    } else if reached_target && !write_failed {
        let complete_frame = EventFrame::encode_drain_complete(drain_seq);
        if let Err(e) =
            write_all_backpressured(stream, complete_frame.as_bytes(), shared, write_deadline)
        {
            eprintln!("xpf-event-stream: drain complete write error: {e}");
        } else {
            shared.frames_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Restore pause state
    if was_paused {
        shared.paused.store(true, Ordering::Release);
    }

    if session_evicted {
        // Already logged above (poison + FullResync).
    } else if reached_target {
        eprintln!("xpf-event-stream: drain complete up to seq {}", drain_seq);
    } else {
        eprintln!(
            "xpf-event-stream: drain incomplete (below fence), highest_seq={} target={} -- DrainComplete withheld",
            drain_seq, target_seq
        );
    }
}

/// Drain remaining events from the channel on shutdown.
fn drain_remaining(rx: &mpsc::Receiver<EventFrame>, shared: &Arc<EventStreamShared>) {
    loop {
        match rx.try_recv() {
            Ok(frame) => release_dataplane_event_queue_budget(shared, &frame),
            Err(_) => break,
        }
    }
}

fn release_dataplane_event_queue_budget(shared: &Arc<EventStreamShared>, frame: &EventFrame) {
    if let Some(kind) = frame.dataplane_event_kind() {
        shared.dataplane_event_queue.release(kind);
    }
}

/// Outcome of one channel-drain pass in the connected loop.
struct DrainOutcome {
    /// At least one frame was pulled from the channel this pass.
    drained_any: bool,
    /// The channel sender side was dropped (helper shutting down).
    disconnected: bool,
    /// The write backlog hit `WRITE_BACKLOG_MAX_BYTES` and the drain was
    /// halted before emptying the channel (stalled-consumer signal). Exposed
    /// for tests; the loop relies on the side-effect counter.
    #[cfg_attr(not(test), allow(dead_code))]
    stalled: bool,
}

/// Drain the bounded channel into `replay_buf` and (when not paused) into the
/// pending socket-write backlog `write_buf`.
///
/// The drain halts once `write_buf` reaches `WRITE_BACKLOG_MAX_BYTES` (#2381).
/// Without that cap a wedged daemon (socket open but not reading → the socket
/// `write` returns `WouldBlock`) lets this loop migrate the entire bounded
/// channel into the heap-backed `write_buf` every cycle; the channel then
/// refills from worker `try_send`, the loop drains it again, and `write_buf`
/// grows without bound → helper OOM / allocator pressure on the forwarding
/// plane. Halting the drain leaves the frames in the bounded channel, which
/// becomes the real backpressure surface: worker `try_send` then fails and
/// increments the existing `frames_dropped` / per-kind `queue_full` counters
/// (oldest queued/replay frames are preserved; newest producer events are
/// shed — keeping RT_FLOW current). Each pass that hits the cap bumps
/// `frames_write_stalled` so a wedged consumer is observable rather than a
/// silent OOM.
///
/// The cap does not apply while paused: paused frames are consumed into the
/// already-bounded replay buffer only, never into `write_buf`, so they cannot
/// grow the backlog.
fn drain_channel_into_write_buf(
    rx: &mpsc::Receiver<EventFrame>,
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
    write_buf: &mut Vec<u8>,
    paused: bool,
) -> DrainOutcome {
    let mut drained_any = false;
    loop {
        if !paused && write_buf.len() >= WRITE_BACKLOG_MAX_BYTES {
            shared.frames_write_stalled.fetch_add(1, Ordering::Relaxed);
            return DrainOutcome {
                drained_any,
                disconnected: false,
                stalled: true,
            };
        }
        match rx.try_recv() {
            Ok(frame) => {
                drained_any = true;
                if !paused {
                    write_buf.extend_from_slice(frame.as_bytes());
                }
                push_replay_frame(shared, replay_buf, frame);
            }
            Err(TryRecvError::Empty) => {
                return DrainOutcome {
                    drained_any,
                    disconnected: false,
                    stalled: false,
                };
            }
            Err(TryRecvError::Disconnected) => {
                return DrainOutcome {
                    drained_any,
                    disconnected: true,
                    stalled: false,
                };
            }
        }
    }
}

fn push_replay_frame(
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
    frame: EventFrame,
) {
    if replay_buf.len() >= REPLAY_BUFFER_CAPACITY {
        // Buffer-full eviction: the oldest accepted-and-enqueued frame is
        // dropped before the daemon ACKed it. It was already counted in
        // `frames_sent`, so it must be counted as a telemetry loss here
        // (#2382). This is distinct from ACK-trim / shutdown drain, which
        // remove frames via `pop_replay_frame` WITHOUT bumping the eviction
        // counter (an ACKed frame is delivered, not lost).
        evict_replay_frame(shared, replay_buf);
    }
    replay_buf.push_back(frame);
}

/// Evict the oldest replay frame because the buffer wrapped at capacity. This
/// is the ONLY telemetry-loss removal path: it increments
/// `frames_replay_evicted` (#2382) in addition to releasing the queue budget.
fn evict_replay_frame(
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) -> Option<EventFrame> {
    let frame = pop_replay_frame(shared, replay_buf);
    if let Some(evicted) = frame.as_ref() {
        shared
            .frames_replay_evicted
            .fetch_add(1, Ordering::Relaxed);
        // #2875: evicting a SESSION-SYNC delta WHILE PAUSED loses a session
        // mutation the future owner needs to take over cleanly. Poison the
        // pending demotion drain so `handle_drain_request` withholds
        // DrainComplete and forces a FullResync instead of silently
        // completing demotion. Telemetry eviction is a tolerated loss and
        // must NOT poison (no spurious resync). Read `paused` here so the
        // poison fires for evictions both in the connected-loop paused drain
        // and in the drain-request drain loop (both run while paused).
        if evicted.is_session_sync() && shared.paused.load(Ordering::Acquire) {
            shared
                .session_evicted_while_paused
                .store(true, Ordering::Release);
        }
    }
    frame
}

/// Remove the oldest replay frame and release its queue budget WITHOUT
/// counting it as an eviction. Used by ACK-trim (the frame was acknowledged —
/// delivered, not lost) and shutdown drain. The buffer-full loss path is
/// `evict_replay_frame`.
fn pop_replay_frame(
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) -> Option<EventFrame> {
    let frame = replay_buf.pop_front();
    if let Some(frame) = frame.as_ref() {
        release_dataplane_event_queue_budget(shared, frame);
    }
    frame
}

fn release_replay_dataplane_event_queue_budget(
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) {
    while pop_replay_frame(shared, replay_buf).is_some() {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
