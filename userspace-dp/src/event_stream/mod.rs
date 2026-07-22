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

mod backlog;
mod budget;
pub(crate) mod codec;
mod clock;
mod control;
mod drain;
mod producer;
mod replay;

// #6235 split: re-export the moved intra-crate helpers back into the
// `event_stream` namespace so the sibling submodules (each `use super::*`) and
// the `#[cfg(test)] mod tests` tree resolve them unchanged. Several are consumed
// only by siblings/tests, not by mod.rs directly.
#[allow(unused_imports)]
use backlog::{WRITE_BACKLOG_MAX_BYTES, WriteBacklog};
#[allow(unused_imports)]
use budget::release_dataplane_event_queue_budget;
#[allow(unused_imports)]
use control::{handle_drain_request, process_control_frames};
#[allow(unused_imports)]
use drain::{DrainOutcome, drain_channel_into_write_buf, drain_remaining, flush_pending_resync};
#[allow(unused_imports)]
use replay::{pop_replay_frame, push_replay_frame, release_replay_dataplane_event_queue_budget};

#[allow(unused_imports)] // monotonic_ns_to_unix_secs is consumed only by the rt_flow tests
pub(crate) use clock::{
    mono_ns_to_wall_clock_unix_ns, monotonic_ns_to_unix_ns, monotonic_ns_to_unix_secs,
    monotonic_ns_to_unix_secs_subnanos,
};
use clock::read_mono_and_wall_clocks;
pub(crate) use codec::{EventFrame, close_flags};
use codec::DataplaneEventKind;
#[allow(unused_imports)] // public API for later policy/screen/filter producer wiring
pub(crate) use producer::{
    DataplaneEventDropReason, DataplaneEventEmitOutcome, DataplaneEventRateLimitConfig,
    DataplaneEventStats,
};

use crate::session::{SessionDelta, SessionDeltaKind};
// FRAME_HEADER_SIZE / MSG_* resolve for the connection + control submodules
// (each `use super::*`) and the test tree; several are not used by mod.rs itself.
#[allow(unused_imports)]
use codec::{FRAME_HEADER_SIZE, MSG_ACK, MSG_DRAIN_REQUEST, MSG_KEEPALIVE, MSG_PAUSE, MSG_RESUME};
use producer::{DataplaneEventCounters, DataplaneEventQueueBudget, DataplaneEventRateLimiter};
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Idle interval after which the connected loop enqueues a keepalive frame to
/// keep the Go listener from treating the stream as dead. The keepalive is
/// routed through the normal `write_buf` backpressure path (#2883), so this is
/// the cadence of enqueue, not of a guaranteed flush.
const KEEPALIVE_IDLE_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum event frames buffered in the mpsc channel (shared across workers).
const CHANNEL_CAPACITY: usize = 8192;

/// Maximum frames retained for replay after disconnect.
const REPLAY_BUFFER_CAPACITY: usize = 4096;

/// Hard ceiling on any single daemon->helper control-frame payload (#2879).
///
/// `process_control_frames` reads a 32-bit `payload_len` from the wire and waits
/// for `FRAME_HEADER_SIZE + payload_len` bytes before parsing. Every current
/// daemon->helper opcode (Ack / Pause / Resume / DrainRequest) is HEADER-ONLY --
/// zero payload -- so this is 0 today. Without a cap a buggy or compromised local
/// daemon sends a header with `payload_len = 1<<30` and trickles bytes; the
/// helper would keep extending `ctrl_read_buf` (consuming nothing, since the
/// frame never completes) and grow the heap without bound on the forwarding
/// plane. Any `payload_len` above this ceiling can never form a valid control
/// frame, so the helper disconnects (reconnect resets `ctrl_read_buf`) instead
/// of buffering. It is a NAMED constant so a future payload-carrying opcode
/// raises it deliberately, rather than the parser silently honoring an arbitrary
/// 32-bit length.
const MAX_CONTROL_PAYLOAD_LEN: usize = 0;

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
    /// Serializes seq allocation with channel enqueue across all producer
    /// threads (#3878). Held ONLY around `next_seq` allocation + the single
    /// `tx.try_send`, so the wire (channel-FIFO) order equals seq order and two
    /// workers cannot allocate N and N+1 but enqueue them inverted (F-152). The
    /// critical section is non-blocking (an atomic + a byte-copy encode + a
    /// non-blocking `try_send`); the lossless retry path releases it before any
    /// sleep so a backpressured export never stalls the other producers.
    ///
    /// #5267: the I/O thread's replay-gap FullResync now ALSO allocates its seq
    /// under this lock (`replay_buffered`). Holding the lock across just the
    /// `fetch_add` guarantees every delta already committed to the channel has a
    /// strictly LOWER seq (the channel commit is atomic under the same lock), so
    /// no producer-committed lower seq can be assigned between the barrier's
    /// allocation and those deltas. The FullResync is NOT written directly to
    /// the socket; it is parked in `pending_resync` and emitted by the connected
    /// loop's drain in seq order (`drain_channel_into_write_buf`), restoring the
    /// wire==seq invariant the Go reader (zero reorder tolerance) depends on. No
    /// socket write happens under the lock — the barrier is written later, on
    /// the I/O thread's own write path — so a wedged reader cannot stall the
    /// producers through this path. Only the DORMANT drain-poison resync
    /// (`handle_drain_request`, which has no live caller) still allocates
    /// outside this lock; the rollback CAS below tolerates that rare interleave.
    producer_seq_lock: Mutex<()>,
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
            producer_seq_lock: Mutex::new(()),
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

/// #5468 test seam: build a CONNECTED worker handle (connected flag forced
/// `true`) whose bounded mpsc channel has `capacity` slots. The returned
/// `Receiver` is never drained by the test, so filling the channel to capacity
/// models a connected-but-unread peer — exactly the state that drives the
/// bounded backpressure retry loop in `push_delta_lossless_within` (rather than
/// the immediate `!connected` early return that `test_worker_handle` exercises).
/// The `Receiver` must be kept alive so the channel stays connected.
#[cfg(test)]
pub(crate) fn test_worker_handle_connected(
    capacity: usize,
    config: DataplaneEventRateLimitConfig,
) -> (EventStreamWorkerHandle, mpsc::Receiver<EventFrame>) {
    let (handle, rx) = test_worker_handle(capacity, config);
    handle.shared.connected.store(true, Ordering::Release);
    (handle, rx)
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

    /// Roll back a sequence number allocated by `next_seq()` when the frame it
    /// was allocated for could NOT be committed to the channel (#3878 F-153).
    ///
    /// Called ONLY while `producer_seq_lock` is held, so no other producer
    /// thread can have allocated after us — `seq` is the highest
    /// producer-allocated value and rolling it back frees it for the next
    /// enqueue, keeping the wire seq contiguous. The compare-exchange guards
    /// the rare race with the I/O thread's own FullResync allocation (the
    /// DORMANT drain-poison path in `handle_drain_request`, which does not take
    /// this lock; #5267 moved `replay_buffered`'s FullResync allocation UNDER
    /// this lock, so it no longer races here): if it
    /// bumped `next_seq` past `seq`, the CAS fails and we leave the counter
    /// alone — that seq is burned, but a FullResync is already in flight so the
    /// reader resets and the hole is moot. The CAS can never create a duplicate
    /// wire seq.
    fn rollback_seq(&self, seq: u64) {
        let _ = self.shared.next_seq.compare_exchange(
            seq,
            seq - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Allocate the next wire sequence number and enqueue `encode(seq)` to the
    /// shared channel ATOMICALLY under `producer_seq_lock`, so seq order ==
    /// channel (wire) order across every producer thread (#3878 F-152). On a
    /// `Full` drop the seq is rolled back so a saturation drop never burns a
    /// sequence number and trips the reader's gap check (#3878 F-153). A
    /// `Disconnected` drop leaves the counter advanced: the stream tears down
    /// and the reader reconnects from `lastRecvSeq = 0`, so the burn is benign
    /// and rolling it back would only risk racing a fresh reconnect.
    fn send_sequenced<F>(&self, encode: F) -> Result<u64, EventStreamSendError>
    where
        F: FnOnce(u64) -> EventFrame,
    {
        let _guard = self
            .shared
            .producer_seq_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let seq = self.next_seq();
        let frame = encode(seq);
        match self.try_send_frame(frame) {
            Ok(()) => Ok(seq),
            Err(EventStreamSendError::Full) => {
                self.rollback_seq(seq);
                Err(EventStreamSendError::Full)
            }
            Err(EventStreamSendError::Disconnected) => Err(EventStreamSendError::Disconnected),
        }
    }

    /// Lossless retry core shared by `send_frame_lossless` (pre-built control
    /// frames) and `push_delta_lossless` (session deltas). On EACH attempt the
    /// `encode` closure runs and the frame is enqueued while
    /// `producer_seq_lock` is held, so a delta's seq is allocated in the same
    /// critical section as its enqueue (#3878) even across the retry loop and
    /// concurrent lossy producers. The lock is dropped before any sleep so a
    /// backpressured lossless export never stalls the other producers.
    ///
    /// `encode` returns `(frame, rollback_seq)`; `rollback_seq` is `Some(seq)`
    /// for frames whose seq came from `next_seq()` (roll it back on a drop,
    /// #3878 F-153) and `None` for control frames that carry a fixed, non-
    /// allocated seq (e.g. `DrainComplete`).
    ///
    /// `timeout` bounds the total backpressure wait before this gives up and
    /// returns `Err`. Off-worker-loop callers (bulk export on connect, the
    /// tunnel-remap purge) pass the full `LOSSLESS_QUEUE_TIMEOUT` (5 s). The
    /// packet-worker-loop caller (`flush_session_deltas` via
    /// `push_delta_lossless_within`) passes a SHORT budget well below
    /// `HEARTBEAT_STALE_AFTER` so a connected-but-unread peer cannot stall the
    /// worker past the heartbeat-stale threshold and self-inflict a spurious
    /// failover (#5468). Either way the give-up is a genuine `Err` the caller
    /// latches as loss-of-sync (forcing a full resync) — never a silent drop.
    fn send_lossless_encoded<F>(&self, timeout: Duration, mut encode: F) -> Result<(), String>
    where
        F: FnMut() -> (EventFrame, Option<u64>),
    {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err("event stream not connected".to_string());
        }
        let deadline = Instant::now() + timeout;
        loop {
            // Raw `tx.try_send` (NOT `try_send_frame`): a `Full` here is a
            // RETRY, not a drop, so it must not bump `frames_dropped` — the
            // lossless caller decides whether an eventual give-up counts as a
            // loss (#2880). Allocation, enqueue, AND the rollback-on-drop all
            // happen together under the producer lock (#3878): the rollback
            // MUST stay inside the guard so allocations+rollbacks are strictly
            // LIFO and `rollback_seq`'s CAS always targets the top of the
            // stack. Rolling back after the lock is released lets two
            // concurrent flushers interleave alloc(N)/alloc(N+1)/rollback(N)-
            // fails/rollback(N+1)-succeeds and STRAND seq N — the exact F-153
            // hole this fix targets (flush_session_deltas runs push_delta_
            // lossless per-worker, so >=2 concurrent flushers on a Full channel
            // is the normal recovery-churn regime).
            let outcome = {
                let _guard = self
                    .shared
                    .producer_seq_lock
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let (frame, rollback_seq) = encode();
                let reported_seq = frame.seq;
                match self.tx.try_send(frame) {
                    Ok(()) => Ok(()),
                    Err(mpsc::TrySendError::Full(_)) => {
                        // The next attempt re-allocates, so this attempt's seq
                        // must be freed for the next successful enqueue (and a
                        // give-up must leave no burned seq). Control frames
                        // carry a fixed seq (None).
                        if let Some(seq) = rollback_seq {
                            self.rollback_seq(seq);
                        }
                        Err((EventStreamSendError::Full, reported_seq))
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        if let Some(seq) = rollback_seq {
                            self.rollback_seq(seq);
                        }
                        Err((EventStreamSendError::Disconnected, reported_seq))
                    }
                }
            };
            match outcome {
                Ok(()) => {
                    self.shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err((EventStreamSendError::Full, reported_seq)) => {
                    if !self.shared.connected.load(Ordering::Acquire) {
                        return Err(format!(
                            "event stream disconnected while queuing seq {reported_seq}"
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "timed out queuing event stream frame seq {reported_seq}"
                        ));
                    }
                    thread::sleep(LOSSLESS_QUEUE_RETRY_DELAY);
                }
                Err((EventStreamSendError::Disconnected, reported_seq)) => {
                    return Err(format!(
                        "event stream channel disconnected while queuing seq {reported_seq}"
                    ));
                }
            }
        }
    }

    /// Lossless send of a caller-encoded frame that carries its own seq (a
    /// control frame such as `DrainComplete`). Retries on a full channel until
    /// capacity frees, the deadline expires, or the peer disconnects. Test-only
    /// after #3878 rerouted `push_delta_lossless` through the seq-allocating
    /// `send_lossless_encoded` closure.
    #[cfg_attr(not(test), allow(dead_code))]
    fn send_frame_lossless(&self, frame: EventFrame) -> Result<(), String> {
        self.send_lossless_encoded(LOSSLESS_QUEUE_TIMEOUT, move || (frame.clone(), None))
    }

    fn encode_delta_frame(
        seq: u64,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) -> EventFrame {
        match delta.kind {
            SessionDeltaKind::Open => EventFrame::encode_session_open(
                seq,
                &delta.key,
                &delta.decision,
                &delta.metadata,
                zone_name_to_id,
                delta.fabric_redirect_sync,
                // #5212: the delta's stable RT_FLOW session id, carried on the
                // HA session-sync open frame so the peer adopts it on import.
                delta.session_id,
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

    /// Encode and send a session delta as an event frame. The seq is allocated
    /// atomically with the channel enqueue (#3878) so a concurrent producer
    /// cannot invert wire order, and a full-channel drop rolls the seq back
    /// rather than burning it into a reader-visible gap.
    pub(crate) fn push_delta(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) {
        let _ = self.send_sequenced(|seq| Self::encode_delta_frame(seq, delta, zone_name_to_id));
    }

    /// Lossless variant used for explicit bootstrap/replay exports. This path
    /// may wait briefly for queue capacity, but it never silently drops. The
    /// seq is (re)allocated under the producer lock on each retry (#3878), so
    /// the delta's wire seq matches its enqueue order even under backpressure
    /// and concurrent lossy producers.
    pub(crate) fn push_delta_lossless(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) -> Result<(), String> {
        self.push_delta_lossless_within(delta, zone_name_to_id, LOSSLESS_QUEUE_TIMEOUT)
    }

    /// #5468: worker-loop variant of [`push_delta_lossless`] that bounds the
    /// backpressure wait to `budget` instead of the fixed 5 s
    /// `LOSSLESS_QUEUE_TIMEOUT`.
    ///
    /// `flush_session_deltas` runs on the packet worker loop, so a
    /// connected-but-unread peer (a slow/stalled reader whose channel is full)
    /// must NOT be able to block the loop for the full `LOSSLESS_QUEUE_TIMEOUT`
    /// — that exceeds `HEARTBEAT_STALE_AFTER`, so the peer marks this node stale
    /// and triggers a false failover. The caller passes a `budget` well below
    /// the heartbeat-stale threshold (`WORKER_LOSSLESS_QUEUE_BUDGET`); on
    /// timeout this returns `Err` exactly like the 5 s path and the caller
    /// latches loss-of-sync (a full owner-RG resync). Losslessness is preserved
    /// — the delta is either delivered or a resync is forced, never a silent
    /// drop (the #2874 contract).
    pub(crate) fn push_delta_lossless_within(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
        budget: Duration,
    ) -> Result<(), String> {
        self.send_lossless_encoded(budget, || {
            let seq = self.next_seq();
            (
                Self::encode_delta_frame(seq, delta, zone_name_to_id),
                Some(seq),
            )
        })
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
    ///
    /// #3395: `policy_id` is the RE-RESOLVED admitting policy id, computed by the
    /// caller (`flush_session_deltas`) from the session's bound rule handle
    /// against the CURRENT rule table — NOT `delta.metadata.policy_id` (which is
    /// frozen at install and goes stale after a live policy reorder). The caller
    /// owns re-resolution because only it holds the `ForwardingState`/`PolicyState`
    /// the lookup needs.
    pub(crate) fn emit_session_close_rt_flow(
        &self,
        delta: &SessionDelta,
        app_id: u16,
        ingress_ifindex: u32,
        policy_id: u32,
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
                    // #3056: the admitting policy ID, so the SESSION_CLOSE
                    // RT_FLOW record (and the NetFlow/IPFIX close exporters) name
                    // the policy that admitted the flow instead of policy 0.
                    // Rides the trailing [136:140] slot because #2853 took
                    // [44:48] on a close. #3395: this is the caller's RE-RESOLVED
                    // id (current positional id of the bound admitting rule),
                    // not the frozen `delta.metadata.policy_id`, so a live policy
                    // reorder before the close no longer mis-attributes the
                    // record.
                    policy_id,
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
                    // #2749: observed forward ToS + cumulative TCP control
                    // bits harvested off the closing entry, and the session's
                    // resolved egress (output) interface. These drive the
                    // re-introduced NetFlow v9 / IPFIX close-record fields
                    // (srcTos/ipClassOfService, tcpControlBits, egressInterface
                    // / OutputSNMP). A kernel ifindex is positive; a 0/unset or
                    // negative (no concrete egress, e.g. local delivery)
                    // resolution maps to 0 — the collector's "unknown
                    // interface" sentinel.
                    delta.observed_tos,
                    delta.observed_tcp_flags,
                    u32::try_from(delta.decision.resolution.egress_ifindex).unwrap_or(0),
                    // #4915: the stable session id harvested off the expiring
                    // entry (0 for a synthesized close with no live entry). Rides
                    // the additive [152:160] slot so the SESSION_CLOSE record
                    // carries the same id as this session's SESSION_CREATE.
                    delta.session_id,
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
                    // #4915: the stable session id assigned at install, carried
                    // in the additive [152:160] slot so this SESSION_CREATE
                    // record shares an id with its eventual SESSION_CLOSE.
                    delta.session_id,
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
        // #5267: `connected` stays set BEFORE `replay_buffered`. It gates only
        // the LOSSLESS producer path (`send_lossless_encoded` fails closed when
        // clear); deferring it past the non-gap replay window would make every
        // worker `push_delta_lossless` return "not connected" mid-reconnect,
        // which `flush_session_deltas` latches as loss-of-sync -> a spurious
        // full owner-RG resync on every CLEAN reconnect (the exact churn class
        // this fix removes). Wire ORDERING is instead guaranteed by allocating
        // the replay-gap FullResync's seq under `producer_seq_lock` and merging
        // it into the drain in seq order (below), so the `connected` timing is
        // orthogonal to ordering.
        shared.connected.store(true, Ordering::Release);
        eprintln!("xpf-event-stream: connected to {}", socket_path);

        // #5267: per-connection slot for a replay-gap FullResync barrier.
        // `replay_buffered` allocates the barrier's seq under `producer_seq_lock`
        // and PARKS the frame here instead of writing it out of order; the
        // connected loop's channel drain emits it in seq order relative to the
        // concurrently-committed deltas. Fresh per connection so a stale barrier
        // from a prior connection is never re-emitted.
        let mut pending_resync: Option<EventFrame> = None;

        // Replay buffered events from last acked seq. A replay-buffer gap parks
        // an ordered FullResync barrier in `pending_resync` rather than writing
        // it directly ahead of the still-queued lower-seq deltas.
        let acked = shared.acked_seq.load(Ordering::Acquire);
        let replay_result =
            replay_buffered(&stream, &mut replay_buf, acked, &shared, &mut pending_resync);
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
            &mut pending_resync,
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
    pending_resync: &mut Option<EventFrame>,
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
        // #5267: allocate the FullResync's seq UNDER `producer_seq_lock` and
        // PARK the frame in `pending_resync` instead of writing it directly to
        // the socket. Writing it here (outside the lock, ahead of the channel
        // drain) put a HIGHER seq on the wire before the lower-seq deltas still
        // queued in the channel: the Go reader (zero reorder tolerance) then
        // diagnosed a session-sync gap on the first post-barrier delta and
        // dropped the connection, churning resyncs on the very HA-recovery
        // barrier. Holding the lock for JUST the `fetch_add` guarantees every
        // delta already committed to the channel has a strictly LOWER seq (the
        // channel commit is atomic under the same lock, #3878) and every delta
        // committed afterward has a strictly higher seq; the connected loop's
        // drain then merges this barrier into the write stream in seq order
        // (`drain_channel_into_write_buf`). The lock is released immediately —
        // no socket write happens under it, so a wedged reader can never stall
        // the producers through this path, and there is no lock-ordering cycle
        // (the section is a single atomic).
        let seq = {
            let _guard = shared
                .producer_seq_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1
        };
        *pending_resync = Some(EventFrame::encode_full_resync(seq));
        eprintln!(
            "xpf-event-stream: queued ordered FullResync seq {} (buffer gap: acked={}, oldest_buffered={})",
            seq, acked_seq, oldest_buffered
        );
        // Keep the stale replay window until the daemon ACKs the FullResync.
        // Clearing here can make an acked_seq=0 reconnect look like a clean
        // fresh start and permanently suppress the required bulk export.
        // `frames_sent` is bumped when the ordered drain accepts the barrier,
        // matching producer-frame enqueue accounting. When the stream is
        // paused that means replay retention rather than a socket write; #5328
        // tracks the existing Resume path's missing replay-suffix scheduling.
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
    pending_resync: &mut Option<EventFrame>,
    keepalive_interval: Duration,
) -> bool {
    use std::io::{Read, Write};

    let mut write_buf = WriteBacklog::with_capacity(4096);
    let mut tmp_read = [0u8; 64];
    let mut idle_cycles = 0u32;
    let mut last_write = Instant::now();

    loop {
        if shared.stop.load(Ordering::Acquire) {
            return false;
        }

        let paused = shared.paused.load(Ordering::Acquire);

        let drain = drain_channel_into_write_buf(
            rx,
            shared,
            replay_buf,
            &mut write_buf,
            paused,
            pending_resync,
        );
        if drain.disconnected {
            return false;
        }
        let drained_any = drain.drained_any;

        // Write buffered frames to socket. On a partial (short) write we advance
        // the backlog cursor in O(1) instead of memmoving the whole remaining
        // suffix to offset 0 on every write (the #4974 O(n^2) drain).
        if !write_buf.is_empty() {
            match (&*stream).write(write_buf.pending()) {
                Ok(n) => {
                    write_buf.advance(n);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
