# userspace-dp/src/event_stream/

Push-based binary session-delta stream. Replaces the previous polled
`drain_session_deltas` RPC: the helper sends frames to a Go-side
listener as session events occur, with monotonic sequence numbers and a
periodic ACK from the daemon.

## Files

- `mod.rs` — `EventStreamSender` owns its own I/O thread, connects to
  the daemon's listener, sends frames, handles reconnect on EPIPE.
- `codec.rs` — frame layout: 16-byte header
  `[length:u32 LE][type:u8][reserved:3][seq:u64 LE]` followed by the
  payload. Message types: `MSG_SESSION_OPEN`, `MSG_SESSION_CLOSE`,
  `MSG_SESSION_UPDATE`, `MSG_ACK`, `MSG_PAUSE`, `MSG_RESUME`,
  `MSG_DRAIN_REQUEST`, `MSG_DRAIN_COMPLETE`, `MSG_FULL_RESYNC`,
  `MSG_KEEPALIVE` (1..10), plus RT_FLOW dataplane telemetry frames
  `MSG_POLICY_DENY`, `MSG_SCREEN_DROP`, and `MSG_FILTER_LOG` (11..13),
  and (#2460) `MSG_SESSION_CLOSE_RT_FLOW` (14).
  The telemetry frame payload is not a userspace-specific schema: it is
  the same 136-byte `dataplane.Event` layout consumed by the Go ringbuf
  logger, including AF values 2/10 and big-endian L4 ports. Userspace
  telemetry may also populate the non-session metadata slots used by
  the Go adapter for action, rule ID, term ID, reason, owner RG,
  ingress ifindex, and application ID.
  `MSG_SESSION_CLOSE_RT_FLOW` (14) carries that same 136-byte payload
  with the event-type byte set to RT_FLOW SESSION_CLOSE (2). It is
  emitted once per session close (via `emit_session_close_rt_flow`,
  paired 1:1 with — and ADDITIVE to — the unchanged minimal type-2
  `MSG_SESSION_CLOSE` HA session-sync delta), and is what drives the Go
  NetFlow v9 / IPFIX session-close exporters in userspace mode (they only
  fire on a `Type == "SESSION_CLOSE"` record; before #2460 none was
  produced). It carries the real 5-tuple, NAT tuple, zones, and protocol;
  the byte/packet counters and the session-creation stamp are 0 pending the
  per-session accounting follow-up #2501. The exporter-reported flow
  duration is derived from the packet count today
  (`estimateSessionDuration(SessionPkts)`), not the `created` stamp, so it
  is 0 while the counters are 0. Unlike the deny/
  screen/filter frames, the close frame is NOT rate-limited (a dropped
  close loses one flow-export record; it is bounded by session churn, not
  attacker-controlled), so it is sent with the lossy `try_send` path
  directly rather than through the `producer.rs` rate limiter.
  `MSG_FILTER_LOG` intentionally reuses the RT_FLOW `reason` byte as
  a filter-log source discriminator (`pbr`, `input`, `output`,
  `cached-output`, or `lo0`). Close events still interpret that byte as
  a close reason. The helper and daemon must therefore be upgraded
  lockstep for this event-stream semantic; it is not governed by the
  config snapshot protocol version.
- `producer.rs` — non-blocking helper-side producer API for RT_FLOW
  dataplane telemetry. It rate-limits each `(event type, ingress
  zone)` bucket, encodes fixed-size frames only after the limiter
  admits the event, and accounts sent/rate-limited/queue-full/
  disconnected outcomes per event type. Dataplane telemetry can occupy
  only a bounded share of the shared event-stream channel, and each
  event type has its own in-flight cap so one deny/drop/log storm cannot
  monopolize queue capacity.
- `codec_tests.rs`, `producer_tests.rs`, `tests.rs` — co-located.

## Why push

Polled deltas at 1 Hz were missing fast-cycling sessions (open + close
between ticks). The push stream sees every transition. The Go listener
feeds RT_FLOW dataplane events through the same `logging.EventReader`
path as ringbuf records, so EventBuffer, callbacks, local writers,
syslog, NetFlow/IPFIX consumers, and name resolution stay consistent
between eBPF and userspace transports. The listener is wired in both HA
cluster and standalone userspace modes; only session replication remains
cluster-scoped.

## Gotchas

- The sequence number is monotonic across reconnects; the daemon ACKs
  the highest seen so the helper can prune its retransmit buffer.
- The default `push_delta()` path is **non-blocking** (`try_send`) and
  **silently drops** when the channel is full. The internal counter
  is `EventStreamShared.frames_dropped` (`mod.rs`); the surface
  exported through the daemon status JSON is `event_stream_dropped`
  (see `protocol.rs`). Use `push_delta_lossless()` only when
  correctness requires every frame and the producer can tolerate
  back-pressure.
- **Write-backlog cap (#2381).** The bounded mpsc channel
  (`CHANNEL_CAPACITY`) is the ONLY intended backpressure surface. The
  I/O thread's pending socket-write backlog (`write_buf`) is capped at
  `WRITE_BACKLOG_MAX_BYTES` (16 MiB ≈ 8× a fully-drained 8192×256 B
  channel) in `drain_channel_into_write_buf()`. The cap is checked at the
  top of the drain loop, so the effective bound is `cap + one max
  EventFrame` (≤ 256 B) — the in-flight frame already pulled may carry
  `write_buf` just past 16 MiB before the drain halts. A wedged daemon
  (socket open but not
  reading → `write_buf` writes return `WouldBlock`) would otherwise let
  the I/O thread migrate the whole channel into the heap-backed
  `write_buf` every cycle; the channel refills from worker `try_send`,
  the thread drains it again, and `write_buf` grows without bound →
  helper OOM / allocator pressure on the **forwarding plane**. Once the
  backlog reaches the cap the drain STOPS pulling from the channel, the
  channel becomes the real backpressure surface (newest producer events
  shed via `try_send`, counted in `frames_dropped` / per-kind
  `queue_full`; oldest queued + replay frames are preserved so RT_FLOW
  stays current), and each capped pass bumps `frames_write_stalled`
  (wire key `event_stream_write_stalls`, Prometheus
  `xpf_userspace_event_stream_producer_frames_total{result="write_stalled"}`).
  The cap does not apply while paused — paused frames go only to the
  already-bounded replay buffer, never to `write_buf`. **Invariant: the
  data plane never stalls because a telemetry consumer is slow; a stuck
  consumer degrades telemetry (counted drops), nothing else.**
- RT_FLOW dataplane telemetry producers must use
  `try_emit_dataplane_event_at()`, not hand-rolled `try_send()`
  wrappers. The API applies the per-kind/per-ingress-zone limiter
  before sequence allocation, increments the generic producer drop
  counter for rate-limited events, and records per-event loss reason
  counters for later status surfacing. It also enforces the telemetry
  queue budget before sequence allocation or shared-channel enqueue;
  event budget drops are reported as queue-full drops. Accepted
  telemetry holds that budget while retained for replay, releasing it
  only when an ACK trims the frame or the helper definitively drops it
  during replay eviction, enqueue failure, or shutdown. Budget release
  saturates at zero; an underflow (accounting invariant broken) bumps a
  local-only diagnostic counter and logs one stderr line on first hit
  (#1826 — release builds compile out the debug_assert, the counter is
  intentionally not wire-plumbed).
- The Go daemon must know every helper→daemon frame type that carries a
  sequence number. For RT_FLOW-style dataplane telemetry, the daemon
  decodes valid frames through the same RT_FLOW adapter used for ringbuf
  records into `logging.EventRecord`; malformed or
  forward-version unknown frames are explicitly counted, dropped, and
  ACKed so the helper replay buffer cannot churn forever on an
  unconsumable event.
- Callback-dependent frames are ACKed only after the relevant daemon
  callback has consumed them. If the helper connects before session-sync
  or RT_FLOW callbacks are wired, the daemon queues a bounded prefix and
  withholds the cumulative ACK; overflow closes the stream so the helper
  replays instead of silently losing audit or HA session events. If the
  replay buffer no longer contains `acked_seq + 1`, the helper sends a
  FullResync request even when `acked_seq == 0`; this covers the
  boot-time queue-overflow case where seq 1 was trimmed before any ACK.
- Session callbacks and FullResync callbacks are ACK gates. A callback
  that returns false means the daemon is not ready or did not complete
  the side effect, so ACK remains withheld and the helper must replay.
- Daemon-side transport counters are exported as
  `xpf_userspace_event_stream_*` Prometheus metrics from
  `ProcessStatus.EventStream`. Helper-side send/drop counters remain in
  the helper status fields.
