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
  (#2460) `MSG_SESSION_CLOSE_RT_FLOW` (14), and (#2508)
  `MSG_SESSION_CREATE_RT_FLOW` (15).
  The telemetry frame payload is not a userspace-specific schema: it is
  the same `dataplane.Event` layout consumed by the Go ringbuf logger,
  including AF values 2/10 and big-endian L4 ports. The payload is 144
  bytes (#3056 grew it from 136): the trailing [136:140] u32 carries the
  admitting policy ID on the SESSION_CLOSE frame, whose [44:48] policy_id
  slot is occupied by the #2853 created-subsec-nanos and so cannot hold
  the policy ID the way every other frame does; [140:144] is reserved
  padding (keeps the Go mirror 8-byte aligned). Userspace telemetry may
  also populate the non-session metadata slots used by the Go adapter for
  action, rule ID, term ID, reason, owner RG, ingress ifindex, and
  application ID.
  (#2470) the `MSG_POLICY_DENY` / `MSG_SCREEN_DROP` (incl. the #2234
  scan-table-pressure ALARM) / `MSG_FILTER_LOG` emitters
  (`afxdp/event_emit.rs`) stamp `timestamp_ns` (offset 0, absolute Unix
  nanoseconds, little-endian u64 — same field/format as the close frame)
  with the dataplane DECISION instant, converting the poll loop's
  `CLOCK_MONOTONIC` `now_ns`/`now_secs` to wall-clock via
  `mono_ns_to_wall_clock_unix_ns` (one anchored `(monotonic, wall)` read
  per emit, reusing #2465's `read_mono_and_wall_clocks` +
  `monotonic_ns_to_unix_ns`). These fire on drops/denies/log-matched
  packets (not per normal packet), so a clock read per emit is cheap.
  Before #2470 all three wrote 0 → the Go decoder fell back to RECEIVE
  time, skewing the logged event time to consumption time under helper
  backlog / reconnect / CPU contention. A 0 (clock-read failure) still
  falls back to receive time on the Go side.
  (#2520) the cold-path RT_FLOW emitters also populate the `application id`
  slot (offset 132, little-endian u16) instead of hardcoding 0. The
  `emit_policy_deny_event` / `emit_filter_log_event` call sites and the
  `emit_session_close_rt_flow` (#2520) AND `emit_session_create_rt_flow`
  (#2615) callers resolve the AppID with the SAME
  `app_catalog.lookup(protocol, src_port, dst_port)` the forwarding hot
  path runs when it stamps the conntrack entry on session create (see
  `afxdp::event_emit::resolve_flow_app_id`), so a policy-deny / filter-log /
  session-create / session-close record shows `application=<name>` for a
  resolvable 5-tuple instead of `application="UNKNOWN"`.
  (#3058) a DNAT / static-NAT / inbound-NPTv6 policy-DENY record now reflects
  what the policy was actually evaluated against (the #2345 post-translation
  tuple), mirroring the permit / SESSION_CLOSE convention exactly: the
  RT_FLOW 5-tuple carries the ORIGINAL (received) addresses/ports and the
  `nat src/dst` slots (offsets 72/88 ip, 104/106 port) carry the TRANSLATED
  values — populated from the deny site's `decision.nat`
  (`rewrite_src/rewrite_dst/rewrite_*_port`) instead of the old hardcoded
  None/0. The deny AppID is resolved from the POST-translation destination
  port (`resolve_policy_deny_app_id` against `policy_dst_port`), so a public
  `:2222` DNAT'd to inside `:22` logs the inside `nat dst 10.0.0.10:22` +
  `application=junos-ssh` instead of an empty NAT dst + `UNKNOWN(2222)`. A
  deny with NO translation passes a default `NatDecision` (all-None) and a
  `policy_dst_port` equal to the original dst port, so its record stays
  byte-identical to the pre-#3058 wire — only NAT'd denies change.
  (#2615) the SESSION_CREATE and SESSION_CLOSE frames ALSO populate the
  ingress ifindex slot (offset 128, little-endian u32) from the admitting
  binding's `ident.ifindex`, so the Go decoder resolves
  `packet-incoming-interface=<name>` instead of `"N/A"`. A kernel ifindex
  is always positive, so the i32 -> u32 cast is loss-free, and this is a
  full-width u32 slot distinct from the i16 egress/TX ifindex width bug
  (#2467). 0 stays the UNKNOWN sentinel when the
  catalog has no match. The screen emitters (`emit_screen_drop_event` /
  `emit_screen_alarm_event`) deliberately keep 0: the screen parse-error
  fail-closed path (#2146) and the L4-less screen drops legitimately lack a
  resolvable 5-tuple, so fabricating an AppID there would be wrong.
  `MSG_SESSION_CLOSE_RT_FLOW` (14) carries that same 144-byte payload
  with the event-type byte set to RT_FLOW SESSION_CLOSE (2), plus the
  #3056 admitting policy ID in the trailing [136:140] slot. It is
  emitted once per session close (via `emit_session_close_rt_flow`,
  paired 1:1 with — and ADDITIVE to — the unchanged minimal type-2
  `MSG_SESSION_CLOSE` HA session-sync delta), and is what drives the Go
  NetFlow v9 / IPFIX session-close exporters in userspace mode (they only
  fire on a `Type == "SESSION_CLOSE"` record; before #2460 none was
  produced). It carries the real 5-tuple, NAT tuple, zones, and protocol
  (and, #2520, the resolved application id at offset 132).
  (#2465) it ALSO carries the real session timestamps: the
  session-creation instant in the `created` field (offset 108, absolute
  Unix **seconds**, little-endian u32) and the close instant in
  `timestamp_ns` (offset 0, absolute Unix **nanoseconds**, little-endian
  u64). The session table tracks these as `CLOCK_MONOTONIC` instants
  (`SessionEntry.created_ns`, write-once at install, +
  `last_seen_ns`); the close `SessionDelta` carries them, and
  `emit_session_close_rt_flow` converts them to wall-clock at emit time
  (one anchored `(monotonic, wall)` reading — see `monotonic_ns_to_unix_*`
  in `mod.rs`). The Go exporters use `created` as the flow StartTime
  directly, falling back to the packet-count
  `estimateSessionDuration(SessionPkts)` heuristic only when it is 0 (an
  explicit-delete / HA-purge close that carried no creation instant).
  (#2853) the `created` second is too coarse on its own — every flow
  opened in the same second exported the same StartTime, flattening IPFIX
  `flowStartMilliseconds` for short flows. The close frame now ALSO carries
  the creation instant's sub-second **nanosecond** remainder
  (0..=999,999,999) in the close-unused `policy_id` slot (offset 44,
  little-endian u32), produced by `monotonic_ns_to_unix_secs_subnanos`. The
  Go decoder reads it as `EventRecord.CreatedNanos` (and zeroes `PolicyID`,
  which a close never carried) so `flowStartTime` builds a
  millisecond-accurate `time.Unix(Created, CreatedNanos)`. The
  byte/packet **volume** counters remain 0 pending the per-session
  accounting follow-up #2501 — only the timing is real. (#2512) the close
  frame now rides the SAME per-kind rate limiter + queue budget +
  sent/dropped counters as the deny/screen/filter frames, under
  `DataplaneEventKind::SessionClose`, via
  `EventStreamWorkerHandle::try_emit_dataplane_frame` — NOT a bare
  unaccounted `try_send`. It stays telemetry-lossy by design: a dropped
  close loses exactly one flow-export/syslog record. That is safe because
  the type-2 `MSG_SESSION_CLOSE` HA session-sync delta is a SEPARATE frame
  (`push_delta`) that is never rate-limited, so consumer session state
  self-heals through the daemon's 1s session sweep; the lossy budget bounds
  a GC-time close storm instead of letting it consume channel / replay
  capacity outside the producer's backpressure model. A shed close is
  counted under the SessionClose `sent`/`dropped` counters surfaced in
  `ProcessStatus.event_stream_session_close_{sent,dropped}` (and the
  `xpf_userspace_event_stream_producer_frames_total{outcome="session_close_*"}`
  Prometheus series).
  (#2508) per-policy RT_FLOW SYSLOG logging: the admitting policy's
  `then log session-init` / `session-close` selection is stamped onto the
  session metadata at install. A close ALWAYS emits the type-14 frame
  (flowexport needs every close), but its final payload byte (offset 135)
  carries a per-policy SYSLOG gate — the Go `logEvent` path emits the
  RT_FLOW_SESSION_CLOSE SYSLOG record only when the bit is set, while the
  registered callbacks (NetFlow/IPFIX, #2460) always run. There is NO
  flowexport consumer of session opens, so `MSG_SESSION_CREATE_RT_FLOW`
  (15) is producer-gated: it is emitted (via `emit_session_create_rt_flow`)
  ONLY when the admitting policy requested `then log session-init`, carries
  the same 144-byte payload with the event-type byte set to SESSION_OPEN
  (1, rendered as RT_FLOW_SESSION_CREATE on the Go side). The SESSION_CREATE
  frame carries the #3056 admitting policy ID in the usual [44:48] slot (it
  has no created-subsec-nanos), and always sets
  the gate byte. (#2615) the create frame now also threads the resolved
  application id (offset 132) and the admitting binding's ingress ifindex
  (offset 128), mirroring the close-side #2520/#2615 fix — so a logged
  session-create no longer logs `application="UNKNOWN"` /
  `packet-incoming-interface="N/A"` for a resolvable session. The volume
  counters stay 0 (a create has no volume yet). (#2512) like the close
  frame, the create frame rides the
  per-kind budget path under `DataplaneEventKind::SessionCreate` (counters
  `event_stream_session_create_{sent,dropped}`), not a bare `try_send`.
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
  monopolize queue capacity. (#2512) the kind set is `PolicyDeny`,
  `ScreenDrop`, `FilterLog`, `SessionClose`, `SessionCreate` (5). The two
  RT_FLOW session frames (types 14/15) carry their own payload layout, so
  they enter the budget via `try_emit_dataplane_frame(kind, zone, now,
  encode)` (a generalization of `try_emit_dataplane_event_at` that accepts
  a caller-supplied frame encoder); the I/O-thread budget release keys each
  frame by its `msg_type` byte through `DataplaneEventKind::from_msg_type`,
  so all five kinds balance their per-kind reservation.
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
- **MSG_ACK watermark is validated before it is trusted (#2959).** The
  `MSG_ACK` arm in `process_control_frames` rejects any ACK whose sequence
  falls outside the valid `[acked_seq, next_seq]` window BEFORE mutating
  `acked_seq` or trimming the replay buffer. The contract is:
  `seq == acked_seq` is a benign duplicate (no-op); `seq == next_seq` is an
  ACK of the latest allocated frame (valid); `acked_seq < seq < next_seq`
  is a normal forward ACK (trims). A **backward** ACK (`seq < acked_seq`) or
  a **future** ACK of a sequence the helper never allocated
  (`seq > next_seq`) comes from a buggy, mixed-version, or corrupted daemon
  listener — trusting it would poison `acked_seq` and trim or permanently
  suppress replay of frames the daemon never actually acknowledged. The
  helper **fails closed**: it ignores the impossible ACK, leaves the
  watermark and replay buffer intact, and increments `frames_invalid_acks`
  (surfaced as `event_stream_invalid_acks` in the daemon status JSON). It
  does NOT disconnect: ignoring keeps the live connection and avoids a
  reconnect-thrash loop against a peer that keeps emitting bad ACKs, while
  valid ACKs interleaved with the bad ones still advance the watermark
  normally. (A disconnect+FullResync response is a possible future
  hardening if a corrupt peer ever needs to be actively reset, but it is
  more disruptive than the value gained here.)
- The default `push_delta()` path is **non-blocking** (`try_send`) and
  **silently drops** when the channel is full. The internal counter
  is `EventStreamShared.frames_dropped` (`mod.rs`); the surface
  exported through the daemon status JSON is `event_stream_dropped`
  (see `protocol.rs`). Use `push_delta_lossless()` only when
  correctness requires every frame and the producer can tolerate
  back-pressure.
- **HA session open/close deltas are correctness-critical and use the
  LOSSLESS path (#2874).** `flush_session_deltas` (`afxdp/session_delta.rs`)
  routes the type-2 session-sync open/close delta through
  `push_delta_lossless`, NOT `push_delta`. The lossy `push_delta` burns a
  sequence number in `encode_delta_frame` and then drops the frame on a full
  channel, leaving a hole the Go consumer cumulatively ACKs past — which
  trims the helper replay window over the missing open/close, so the standby
  permanently misses a session until an unrelated full-sync runs. When the
  lossless push cannot enqueue (peer disconnected / queue timeout — a
  genuinely wedged consumer), `flush_session_deltas` returns `true` and the
  worker loop latches loss-of-sync via `SessionTable::set_delta_loss`, which
  drives the existing #2442 `take_delta_loss` resync (a full owner-RG
  snapshot re-export). It stops attempting further lossless pushes for the
  rest of that drain batch, so the worst-case backpressure is one lossless
  wait (`LOSSLESS_QUEUE_TIMEOUT`) per drain cycle even on a wedged consumer —
  the snapshot supersedes the remaining incremental deltas. The RT_FLOW
  SESSION_CLOSE/SESSION_CREATE telemetry frames (types 14/15) stay
  best-effort (`try_send` via the per-kind budget) — a dropped flow-export
  record is not a correctness loss and MUST NOT force a resync.
- **Go consumer: a sequence gap on a session-sync frame is a HARD sync
  break (#2874).** `pkg/dataplane/userspace/eventstream.go` treats a gap on a
  correctness-critical session-sync frame (`EventTypeSessionOpen` / `Update`
  / `Close`) as a desync: it triggers `onFullResync`
  (`handleEventStreamFullResync` → bulk owner-RG export, the only path that
  recovers a producer-dropped delta) and returns from the read loop WITHOUT
  advancing `lastAppliedSeq` past the hole, so the cumulative ACK never moves
  past the missing sequence and the reconnect replays from the last
  contiguous ack. A gap on a TELEMETRY frame (`EventFrameType*`, types 11-15)
  is merely counted in `SeqGaps` and the frame is still dispatched — telemetry
  is lossy by design and a gap there must NOT force a resync (no
  thundering-resync regression). Session-sync resyncs are counted separately
  in `EventStreamStatus.session_sync_resyncs`.
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
  `try_emit_dataplane_event_at()` (or, for a producer that builds its own
  frame layout such as the session-close/create frames,
  `try_emit_dataplane_frame()`), not hand-rolled `try_send()`
  wrappers (#2512 removed the last two bare-`try_send` producers). The API
  applies the per-kind/per-ingress-zone limiter
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
