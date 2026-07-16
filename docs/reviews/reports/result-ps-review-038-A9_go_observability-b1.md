# Triage Result — ps-review-038-A9_go_observability (batch 1/1)

**Subsystem:** A9_go_observability (pkg/flowexport, pkg/snmp, pkg/eventengine,
pkg/ipmon, pkg/feeds, pkg/logging, pkg/rpm)
**Review base:** `d4506d4450` (stale)
**Verified against:** current `origin/master` = `57d24d9aed4b64680831a1765a128921e79c00f7`
**Source authenticity:** REAL bpfrx — every cited symbol resolves on master
(line numbers drift from the stale base, but all functions/consts exist). No
confabulation. No avacado tells.

## Outcome counts (15 findings)
- GENUINE-RESIDUAL: **0**
- NOT-MATERIAL: 7 (F-01, F-02, F-03, F-04, F-10, F-14, and F-05 which is also DELIBERATE)
- DELIBERATE: 1 (F-05, documented best-effort concurrent-producer design)
- NEGATIVE (reviewer self-refuted, re-verified sound): 7 (F-06..F-09, F-11, F-12, F-13, F-15)
- CONFABULATED: 0
- DUP: 0

The review self-classifies 9 of 15 as NEGATIVE/hardening. Only F-01 (High),
F-03 (Medium) and a handful of Low items carry an actionable claim. All are
refuted or immaterial on current master.

---

## Per-finding disposition

### F-01 (claimed High) — SNMPv3 encryptDES/encryptAES128 ignore `rand.Read` error → predictable IV
**Disposition: NOT-MATERIAL (refuted by stdlib guarantee — the A2 pattern).**

Symbol confirmed: `pkg/snmp/v3.go:772` (`encryptDES`) and `:796`
(`encryptAES128`) both call `rand.Read(privParams)` with the `(int,error)`
return discarded, using `crypto/rand` (import confirmed at v3.go:9).

The finding's HIGH rating rests entirely on the premise that `rand.Read` can
return an error and leave `privParams` zero/partial → predictable IV →
CBC/CFB chosen-plaintext. That premise is **false on this codebase**:

- `go.mod` pins `go 1.24.9`. As of Go 1.24, `crypto/rand.Read` is guaranteed
  never to return an error and always fully fills the buffer. If the OS
  randomness source fails, the runtime **irrecoverably crashes the program**
  (fatal), it does NOT return a recoverable error with a zeroed buffer. So the
  "entropy starvation → all-zero privParams → predictable IV" scenario cannot
  occur: there is no code path in which `privParams` is left zero/partial while
  execution continues.
- Even pre-1.24 on Linux, `getrandom(2)`-backed `crypto/rand` blocks until the
  pool is seeded and never partially fills — the described silent-zero outcome
  is not a real failure mode.

Therefore the unchecked error is a cosmetic errcheck-style lint (the returned
error is statically always nil under the pinned toolchain), carrying zero
security weight. A defensive `io.ReadFull(rand.Reader, privParams)` would be a
harmless style change but fixes no reachable defect. Not a genuine residual;
not worth a lane. Severity floor: this is the classic "claimed HIGH refuted by
an upstream guarantee" pattern the triage brief flags.

### F-02 (Low) — IPFIX/NetFlow template FlowSet length uint16 truncation
**Disposition: NOT-MATERIAL (no current defect).**

`encodeTemplateFlowSet` confirmed at `pkg/flowexport/netflow.go:223`;
`encodeIPFIXOptionsSamplerDataSet` present in ipfix.go. The finding itself
states `totalLen` = 18 for the sampler set and the template set is bounded far
below 65535 by the fixed field lists — "This is not a truncation bug
currently." It is a speculative guard against a hypothetical future that adds
100+ IEs. No reachable input truncates today. Pure hardening idea, no residual.

### F-03 (Medium) — SSRF via operator-configured feed URL
**Disposition: NOT-MATERIAL (no privilege boundary crossed; intended behavior).**

Code confirmed: `resolveBaseURL` (`pkg/feeds/feeds.go:85`) returns the
operator-supplied URL verbatim; `readFeed` (`:365`) issues
`http.NewRequestWithContext(ctx,"GET",fs.url,nil)` then `m.client.Do(req)` on a
default-transport client (`New`, `:72`) with only a 30s timeout — no
private/loopback/metadata DialContext guard.

The feed-server URL is set exclusively via committed Junos config
(`set security dynamic-address feed-server ... url ...`), which requires
commit privilege = root-equivalent in xpf's model. Fetching an
operator-authored feed URL from wherever the operator points it is the
*intended* function of a security-intelligence feed (matches Junos SRX
security-intelligence, which likewise fetches operator-configured URLs). The
review's own refutation concedes "operator already has full config access
(equivalent to root)." The only elevated angle it posits — config-sync from an
HA peer — does not cross a boundary either: cluster peers share one admin
domain and are mutually root-trusted. No lower-privilege injection vector is
identified. This is a defense-in-depth wishlist item, not a novel reachable
privilege-crossing residual. Not filed as genuine.

### F-04 (Low) — binary log totalLen uint16 truncation
**Disposition: NOT-MATERIAL (safe by cap; self-admitted).**

`formatBinaryRecord` / `binaryLogHeaderSize` confirmed in pkg/logging (binary.go
+ tests). The finding computes the worst case at ~1423 bytes (each variable
string capped at 255 by `truncStr`) — "Not actually exploitable at current
caps." Same hypothetical-future class as F-02. No current defect.

### F-05 (Low) — eventengine `supersede` drain-then-refill not atomic under concurrency
**Disposition: DELIBERATE / NOT-MATERIAL.**

`enqueue`/`supersede` confirmed at `pkg/eventengine/engine.go:391`/`:414`
(review's 584-637 line refs are stale but the functions match). The channel
operations are intentionally lock-free and best-effort by design: engine.go:336
documents "probe goroutines may call HandleEvent concurrently without racing on
the [queue]", and supersede's own comments name the concurrent-producer case
("It drains at most the current buffered entries to avoid an unbounded loop
under concurrent producers" / "Still no room (lost the race to another
producer)"). Correctness is preserved: each action object exists in the channel
at most once, `queueDepth` is an atomic that is +1 on every successful send and
-1 on every receive so it stays net-accurate even when a refill send fails
(item dropped + `droppedQueueFull++`). Worst observable effect is a transient
redundant same-policy remediation, which the worker's cooldown gating absorbs.
The review's own refutation agrees: "No data corruption or policy bypass."
Deliberate best-effort design, no residual.

### F-06 — ipmon Engine Start/Stop race
**Disposition: NEGATIVE (self-refuted, re-verified).** Reviewer's own trace
concludes `e.mu` guards `started`/`stopped` in both methods; `done`/`stop`
closed exactly once; cancel idempotent. Sound.

### F-07 — rpm Apply goroutine leak
**Disposition: NEGATIVE (self-refuted).** `probeCtx` derives from apply ctx;
`runProbeLoop` honors `ctx.Done()`; daemon serializes Apply via semaphore.
Bounded by context + WaitGroup. Sound.

### F-08 — routeMaskCache.populate fire-and-forget goroutine
**Disposition: NEGATIVE/INFO (self-refuted).** Bounded by `maxInflight` (32),
each goroutine does one netlink lookup and exits. Self-terminating; not a leak.

### F-09 — trace/locallog rotation ENOENT false-positive metric
**Disposition: NEGATIVE (self-refuted).** Rotation loop correctly skips
`os.IsNotExist(err)` before incrementing `failedRotations`. Metric accurate.

### F-10 (Low) — feeds response-header DoS
**Disposition: NOT-MATERIAL.** Bounded by Go's built-in response-header limit
(the finding itself measures the worst case at ≤10MB) and the client's 30s
timeout. Body cap already at 32MiB. No unbounded amplification. Hardening nit.

### F-11 — SNMP trap queue depth 256 / single worker drops under burst
**Disposition: NEGATIVE / DELIBERATE (self-refuted).** Bounded drop-on-full
queue is intentional (`trapsDropped` counter + Warn log) to avoid blocking the
link-monitor goroutine. Documented trade-off, not a defect.

### F-12 — `eventTimeFromWire` int64-ns cap at ~2262
**Disposition: NEGATIVE (self-refuted).** Confirmed at `pkg/logging/ringbuf.go:395`
with the `<= uint64(1<<63-1)` guard — this is the documented #2511 SSOT guard
(see pkg/logging/README.md). The ~2262 ceiling is an inherent Go `time` int64-ns
limitation, not a code bug.

### F-13 — rpm HoldPinsForReprogram map-replace consistency
**Disposition: NEGATIVE (self-refuted).** Map replace is atomic under `m.mu`;
the daemon call sequence keeps probes running when it fires (before Apply's
StopAll). No race.

### F-14 (Low) — snmp-engineboots file mode 0o644
**Disposition: NOT-MATERIAL (no secret exposed).** Confirmed at
`pkg/snmp/agent.go:304` (`WriteFileDurable(..., 0o644)`; dir created 0o755 at
:301). The engineBoots counter is NOT sensitive — it is transmitted in
cleartext in every authenticated SNMPv3 message per RFC 3414. The review itself
concedes "not directly sensitive." 0644-vs-0600 is a cosmetic consistency nit
that leaks nothing. No residual.

### F-15 — flowexport stableExporterID default value
**Disposition: NEGATIVE (self-refuted).** `stableExporterID` maps to
[1, 0xFFFFFFFF], never 0 — correctly avoids the ODID-0 special case. Sound.

---

## Summary
Zero genuine residuals. The one High (F-01) is refuted by the Go 1.24.9
`crypto/rand` infallibility/crash-on-failure guarantee (the exploit's zeroed-IV
premise is impossible on this toolchain). The one Medium (F-03) is intended
operator-authored-URL fetch behavior with no privilege boundary crossed. The
remaining Lows are self-admitted no-current-defect hardening notes or
deliberate designs; 7 were already NEGATIVE by the reviewer's own analysis and
re-verified sound. Nothing dedups to the #4517-#4581 backlog because nothing
here is a real defect to track.
