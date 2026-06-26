# pkg/logging

Multi-backend structured logging. Wraps `slog.Handler` with syslog
routing, a ring-buffer event subscription stream (consumed by the SSE
endpoint and the CLI's `monitor` commands), local file streaming with
facility/severity filtering, and a per-IP session aggregator for top-N
reports.

## Entry points

- `SyslogSlogHandler` — `slog_handler.go`. Slog handler that
  fans events out to configured syslog clients.
- `EventBuffer` — `eventbuf.go`. `NewEventBuffer(size int)` — the
  caller picks the size; `pkg/daemon/daemon_run.go` constructs it
  with 1000. Bounded ring; full → drops the oldest entry.
- `Subscription` — `eventbuf.go`. A consumer of the event ring.
- `LocalLogWriter` — `locallog.go`. File-based writer with
  facility/severity filters.
- `SessionAggregator` — `aggregator.go`. Top-N per-IP rollups,
  cardinality-capped (see "Aggregator cardinality cap" below).

## Callers

`pkg/daemon`, `pkg/api`, `pkg/grpcapi`, `pkg/flowexport`, `pkg/cli`.

## Dependencies

`pkg/config`, `pkg/dataplane`.

## Logging rules (CLAUDE.md authoritative)

- Use `slog.Debug` for high-frequency or per-packet diagnostics. Use
  `slog.Info` only for state transitions and one-time events.
- The HA watchdog sync was previously logging at `slog.Info` 15 times per
  second, drowning out real diagnostics. Don't reintroduce that pattern.
- Never put `slog.Info` inside per-session, per-packet, or per-poll-tick
  loops.

## Syslog stream-transport resilience (#2283)

`SyslogClient.Send` / `SendBinary` are reached on the SHARED dataplane
event hot-path (EventStream reader → `EventReader.ProcessRawEvent` →
`logEvent` → `SyslogClient.Send`). The event reader runs that path
inline, so a syslog client must never block or thrash on a bad target.
Two bounds enforce that for the stream transports (TCP/TLS); UDP is
connectionless and exempt:

- **Per-write deadline.** Every TCP/TLS `conn.Write` is preceded by
  `SetWriteDeadline(now + writeTimeout)` (default
  `defaultWriteTimeout`, 4s). A slow/hung/congested server surfaces as
  `os.ErrDeadlineExceeded`; the message is dropped (counted, not
  retried-in-place) and the reader continues. Without this a hung
  server stalls the entire event reader indefinitely.
- **Timeout drops without retry (#2287).** A write that fails with a
  *timeout* (the deadline expired — `net.Error.Timeout()==true`) is
  dropped and returned immediately. It is NOT reconnect+retried: the
  deadline already bounded the attempt, and reconnecting would re-arm
  another full `writeTimeout`, doubling the worst-case stall on the
  event reader (~2× plus a dial). Only a *genuine connection error*
  (broken pipe / ECONNRESET, non-timeout) triggers the reconnect+retry
  path below.
- **Reconnect cooldown.** A non-timeout write failure on a stream
  transport attempts one reconnect, gated by `reconnectCooldown`
  (default `defaultReconnectCooldown`, 1s). If the previous reconnect
  cycle failed inside the window, the reconnect is skipped and the send
  fails fast (drop) — so a down server cannot drive a fresh 5s-timeout
  dial on every event (thundering herd). The cooldown clock
  (`lastReconnectFailure`) is armed by BOTH failure modes (#2302): a
  failed **dial**, AND a dial that succeeds but whose subsequent
  retry-**write** fails (accept-then-reset collector, half-open server,
  TLS app-layer drop). Gating only on a failed dial left an
  accept-then-reset target permanently un-throttled — the dial succeeded
  every time, so every log message drove a fresh TCP connect + teardown
  (a dial storm: ephemeral port exhaustion + SYN pressure on the
  collector). The clock is cleared only on a FULLY successful reconnect
  (dial AND the retry-write both land), so the legitimate
  single-broken-pipe recovery path is unaffected.
- **Drop warning emitted AFTER the lock is released (#2287).**
  `SyslogClient.Send`/`SendBinary` hold `s.mu` for the whole write +
  reconnect sequence. The rate-limited drop warning (`slog.Warn`) must
  NOT be emitted while `s.mu` is held: `slog.Default()` is the
  `SyslogSlogHandler`, whose `Handle` synchronously calls back into
  this same client's `Send`, which re-locks `s.mu` (`sync.Mutex` is
  non-reentrant) → self-deadlock on the dataplane event-reader
  goroutine. `noteDrop` therefore only *captures* the warning snapshot
  under the lock; the caller emits it via a `defer` ordered to run
  after the `Unlock`. The ≤1/s gate is preserved.
- **Handler re-entrancy guard (#2287).** As defense-in-depth,
  `SyslogSlogHandler.Handle` tracks the set of goroutine IDs currently
  inside its syslog-forwarding section. If a client `Send` emits any
  slog record (drop warning or otherwise) that routes back through the
  handler on the SAME goroutine, the nested record is NOT re-forwarded
  to syslog — so no present or future under-lock/transitive slog call
  from the send path can wedge the daemon by recursing into a client's
  `Send`. The guard is per-goroutine (not a per-handler flag), so
  concurrent `Handle` calls on different goroutines are never falsely
  skipped. Forwarding to the base handler (stderr) stays unconditional,
  even on a re-entrant call, so records are never lost from local logs.
  `Handle` snapshots the client set FIRST and returns before the guard
  when there are no clients (the default until syslog config applies), so
  the guard's `goID()` (`runtime.Stack` + `ParseUint`) never runs on the
  common no-client path (#2295) — only when a record is actually being
  forwarded to at least one client.

Drops are observable via `DroppedWrites()` (write timeout or write
error), `DroppedDials()` (post-write-failure reconnect dial failed),
and `DroppedCooldown()` (reconnect suppressed by cooldown); the drop
warning is rate-limited to ≤1/s so a flapping target cannot spam the
log from the hot-path (CLAUDE.md logging rules). The warning's `reason`
attribute is one of `write` / `dial` / `cooldown`.

Tests (`syslog_resilience_test.go`, `syslog_reentrancy_test.go`) use
deterministic fakes — a deadline-honouring conn, an always-fail conn, a
timeout conn, a recording conn, a controllable clock, and a dial seam
(`dialFn`/`nowFn`) — plus a `goIDFn` seam — with no sleeps. The hang
test fails if the write deadline is removed; the cooldown test fails if
the cooldown gate is removed; the accept-then-reset test (#2302) fails
(sees a 50-dial storm) if the cooldown is not armed on a
dial-success-then-write-failure; the re-entrancy test deadlocks (and
times out) if the drop warning is moved back under `s.mu` or the handler
guard is removed; the timeout-drop test fails (sees a dial) if a write
timeout reconnects; the no-client test (#2295) fails (sees `goID` calls)
if `Handle` runs the re-entrancy guard before the client check.

## Gotchas

- The binary RT_FLOW format used by Junos session logging is custom; it
  is not human-readable without a parser. Use the local-log facility for
  human-readable session events.
- Userspace event-stream telemetry enters through
  `EventReader.ProcessRawEvent`, not by direct `EventBuffer.Add`, so it
  gets the same name resolution, callback fanout, local writers, and
  syslog delivery as the legacy eBPF ring-buffer events do.
  `DecodeRawEventRecord` is decode-only and must not be used as a
  replacement for the full reader path when audit delivery matters.
- **Protocol names come from the `appid.ProtocolName` SSOT (#3040).** The
  event-log `protoName` helper (`ringbuf.go`) renders an IP protocol number
  through the shared `appid.ProtocolName` table that REST (`pkg/api`,
  #2949) and gRPC (`pkg/grpcapi`, #3037) already use, so GRE(47)/ESP(50)/
  IPIP(4)/IPv6(41) sessions display named (GRE/ESP/IPIP/IPV6) instead of
  numeric — matching the other operator surfaces. Before #3040 this helper
  carried its own tcp/udp/icmp/icmpv6 map and rendered every other protocol
  as a bare number. Casing is an event-log-local concern (this surface
  upper-cases, keeping ICMPv6 mixed-case for the trace-filter contract);
  unknown protocols still fall back to the numeric form. Pin:
  `protoname_test.go`.
- **Event time is DECISION time, not receive time (#2465/#2470/#2511).**
  The on-wire RT_FLOW frame carries an absolute Unix-nanosecond timestamp
  in its first 8 bytes (LE u64), stamped by the userspace-dp producer at
  the instant the forwarding decision was made. Both the live reader path
  (`ProcessRawEvent` → `logEvent`) and the decode-only
  `DecodeRawEventRecord` set `EventRecord.Time` from that wire value via
  the shared `eventTimeFromWire` guard: a nonzero timestamp that fits an
  `int64` wins; a zero/absent stamp (old-format frame or synthesized
  event) or one that would overflow `int64` falls back to `time.Now()`
  (daemon receive time). Before #2511 `logEvent` always used `time.Now()`,
  so the production logging path recorded receive time even though
  `DecodeRawEventRecord` already honored the wire stamp — under helper
  backlog or reconnect that drifted from the decision instant. Keep the two
  paths on the single `eventTimeFromWire` SSOT.
- **SESSION_CLOSE log lines carry no `action` (#2513).** A session close
  is a termination event, not a forwarding decision, so it has no
  permit/deny/reject action — the userspace-dp producer writes the wire
  action byte as 0 for a close
  (`encode_session_close_rt_flow`). Byte 0 maps to "deny" via
  `actionName`, so the standard (plain) formatter used to render
  `RT_FLOW SESSION_CLOSE ... action=deny ...`, which misread as a drop.
  Both close renderers now omit action: the standard line
  (`formatSyslogMsg`, keyed on `Type == "SESSION_CLOSE"`) drops the
  `action=` field and keeps `proto/policy/zone/pkts/bytes`; the structured
  line (`formatStructuredMsg` `RT_FLOW_SESSION_CLOSE`) never carried one and
  reports a close `reason="..."` (e.g. "TCP FIN", "idle Timeout") matching
  Junos. The omission is scoped to the close event type only — POLICY_DENY,
  SCREEN_DROP, and FILTER_LOG (the genuine deny/reject paths) still render
  `action`. Golden coverage: `session_close_format_test.go`.
- **SESSION_OPEN log lines carry no `action` (#2593).** Sibling of #2513
  on the adjacent event: a session open (`RT_FLOW_SESSION_CREATE`) is a
  permit-and-create event, not a forwarding decision, so it has no
  permit/deny/reject action — the userspace-dp producer writes the wire
  action byte as 0 for a create
  (`encode_session_create_rt_flow`), identical to the close path. Byte 0
  maps to "deny" via `actionName`, so the standard (plain) formatter used
  to render `RT_FLOW SESSION_OPEN ... action=deny ...`, which misread a
  successful permit-and-open as a drop. Both create renderers now omit
  action: the standard line (`formatSyslogMsg`, keyed on
  `Type == "SESSION_OPEN"` — `eventTypeName(eventTypeSessionOpen)`) drops
  the `action=` field and keeps `proto/policy/zone`; the structured line
  (`formatStructuredMsg` `RT_FLOW_SESSION_CREATE`) never carried one. The
  omission is scoped to the open event type only — POLICY_DENY,
  SCREEN_DROP, and FILTER_LOG (the genuine deny/reject paths) still render
  `action`. Golden coverage: `session_create_format_test.go`.
- `pkg/dataplane/userspace/eventstream_test.go` owns the deterministic
  local syslog harness for userspace RT_FLOW policy-deny, screen-drop, and
  filter-log frames. It sends raw event-stream frames through
  `EventReader.ProcessRawEvent` and a UDP syslog listener, so changes to
  userspace decode or fanout should extend that harness rather than bypass it.
- The event buffer is bounded. If a subscriber stops draining, new events
  drop silently — by design. Don't wire a slow consumer to it.
- The session aggregator flushes on a 5-minute timer. The flushed
  snapshot is the basis for `show security session aggregate`.

### Aggregator cardinality cap (#2936)

`SessionAggregator` keyed its source/destination maps by every distinct
IP seen in `SESSION_CLOSE` events with no bound. Under high-cardinality
traffic (spoofed-source or scan traffic — exactly what a security
appliance sees during an incident) the two maps grew for the full flush
window, and `topEntries` then allocated and `sort.Slice`-sorted O(N) over
the entire cardinality twice per flush. The observability feature became
a control-plane resource-exhaustion amplifier — it degraded under the
very traffic it is meant to report on.

The interim fix bounds memory **by configuration, not by traffic
cardinality**: each map admits at most `defaultMaxAggKeys` (10000)
distinct keys per flush window. Once a map is at the cap, a NEW key is
dropped and counted in `droppedSrc`/`droppedDst`; keys already admitted
keep aggregating, so the top-N over the admitted set stays accurate. The
per-flush allocate+sort cost is therefore bounded by the cap.

When the cap is hit, `flushAndLog` emits a warning-severity
`RT_FLOW_SESSION_AGGREGATE dropped-keys source=N destination=M cap=K`
line in addition to the top-N report. A non-zero `dropped-keys` count is
itself an incident indicator (cardinality exceeded the cap this window).
Below-cap traffic produces identical top-N output with no dropped line —
the common case is behavior-preserving. Coverage:
`TestSessionAggregator_CardinalityCap` (fail-on-revert) and
`TestSessionAggregator_BelowCapUnchanged`.

This is a deliberate interim. Capped maps keep the top-N exact only for
the keys admitted *before* the cap was reached; a heavy hitter whose
first packet of the window arrives after the cap fills is missed.
Bounded heavy-hitter accounting (Space-Saving / Misra-Gries top-K with an
overflow bucket) would make the top-K accurate independent of arrival
order under adversarial cardinality. That accuracy refinement is tracked
as a follow-up and is not required to close the DoS.
