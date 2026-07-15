# Paladin Review — A9_go_observability (batch 1/1)

**Base commit:** `d4506d4450e23f9a3fc572206b3c82f6b6c99029`
**Area:** A9_go_observability — batch 1/1 (111 files)
**Reviewer:** paladin-038 prompt-018

---

## Module-by-Module Log

### pkg/flowexport (32 files: ipfix.go, netflow.go, manager.go, transport.go, exporter_id, routemask, addr_format, collector_health, collector_stall, cos_fields, dropped_fields, exporter, flowbatch_bounded, flowdir, flowstart, ingress_interface, instance_isolation, ipfix_biflow, ipfix_sampler, ipfix_seqnum, per_collector_source, postnat, protocol_num, routemask_vrf, srcmask_dstmask, template_group, version_binding, transport_test, feeds_sizecap, etc.)

Checked: NetFlow v9 / IPFIX wire encoding, length fields, uint16 truncation, sysUptime wrapping, sampling counters, template field alignment, post-NAT correctness, flow direction derivation, route-mask background-goroutine bounding, collector health write-deadline / probe-backoff gating, flowBatch cap.

### pkg/snmp (13 files: agent.go, v3.go, traps.go, agent_clients, agent_secret_log, agent_set, getbulk_size, traps_async, traps_community, traps_version, v3_auth, v3_context, v3_priv_iv, v3_seclevel, v3_set, v3_timeliness)

Checked: SNMPv3 IV/salt derivation, RNG-error handling on encrypt paths, auth MAC placement, priv-only rejection, timeliness / engineBoots persistence, BER encode/decode integer overflow, GETBULK trimToFit, trap queue bounding, community source-IP gating.

### pkg/eventengine (8 files: engine.go + 7 tests)

Checked: Worker goroutine lifecycle, bounded queue, cooldown revalidation, stale-action detection, timer leak on worker stop, retry backoff overflow, regex cache / event index consistency.

### pkg/ipmon (3 files: ipmon.go, display.go, nexthop_test + ipmon_test)

Checked: Engine goroutine lifecycle (start/stop idempotency), dirty-bit / debounce / throttle, actuateCtx cancellation, overlay computation, interface-typed next-hop resolution, SSRF/none.

### pkg/feeds (4 files: feeds.go + 3 tests)

Checked: Fetch SSRF surface, size/prefix-count caps, scanner overlong-line handling, stale-snapshot retain vs drop, HTTP client timeout.

### pkg/logging (26 files across aggregator, binary, eventbuf, trace, ringbuf, event_filter_args, goid, slog_handler, syslog, locallog, event_time, default_policy_sentinel, host_inbound_deny, per_policy_log, protocol_num_builder, protoname, event_severity, session_close_format, session_create_format, locallog_format, syslog_lazy_connect, syslog_partial_frame, syslog_reentrancy, syslog_replace_close, syslog_resilience, trace_filter, trace_size)

Checked: Binary log format length field truncation (uint16 on totalLen), ringbuf / eventbuf negative-size panic, trace writer rotation resource safety, syslog reconnect re-entrancy deadlock, aggregator overflow accounting, event filter parsing.

### pkg/rpm (10 files: rpm.go, icmp.go, display.go, event_buffer, http_scheme, icmp_ctx, icmp_linklocal, icmp_test, pin_hold, probe_dialer, scoped_hostname, transition_cycle)

Checked: Probe goroutine lifecycle, context-cancellation propagation for DNS, VRF-bound resolver, link-local zone handling, probe type dispatch, transition coalescing, goroutine/resource leaks.

---

## Findings

---

### F-01: SNMPv3 encryptDES / encryptAES128 ignore crypto/rand.Read error — trap PRIV params may be zero/partial

**Severity:** High
**Confidence:** High

**Evidence:**
- `pkg/snmp/v3.go:777-779`:
  ```go
  privParams := make([]byte, 8)
  rand.Read(privParams)
  iv := make([]byte, 8)
  ```
  And at line 801-802:
  ```go
  privParams := make([]byte, 8)
  rand.Read(privParams)
  iv := make([]byte, 16)
  ```
  In both `encryptDES` and `encryptAES128`, `crypto/rand.Read` returns `(int, error)` but only the first return is checked — actually neither is checked. The error is silently discarded. On a system where `/dev/urandom` is exhausted (embedded, early boot), `rand.Read` may return an error and leave `privParams` partially or fully zero, producing a predictable IV.

**Trace:**
1. SNMPv3 PRIV request arrives (authPriv).
2. Agent calls `encryptPDU` → `encryptAES128` (or `encryptDES`).
3. `rand.Read(privParams)` fails (RNG unavailable), `privParams` is all-zero.
4. IV is derived as `boots|time|00000000…` (predictable portion).
5. For DES in CBC mode, predictable `privParams` XOR'd with `preIV` makes the IV predictable, enabling chosen-plaintext attacks against CBC.

**Refutation attempt:** Checked whether Go's `crypto/rand.Read` can fail on Linux — yes, on early boot or when `getrandom(2)` blocks and `/dev/urandom` is not yet seeded, it can return an error. The Go docs explicitly state callers must check the error. No wrapper retries. The function does not panic on failure. This is a real (though low-probability on production systems) bug.

**Why it matters:** Predictable IV in DES-CBC (even if AES-CFB is less affected by IV predictability) violates RFC 3414 §8.1.1.1 / RFC 3826 §3.1.2.2. On a system experiencing entropy starvation, SNMPv3 PRIV provides no confidentiality.

**Fix direction:** Check `rand.Read` error:
```go
if _, err := io.ReadFull(rand.Reader, privParams); err != nil {
    return nil, nil
}
```
Falling back to "drop the response" (return nil, nil) is safe — manager will retry.

**Labels:** `crypto`, `snmp`

**Dedup note:** Checked dedup index — open issues #4549 (cluster/vrrp/ipsec LOW hardening) mentions PSK zeroize and unrelated crypto items, but does not mention SNMPv3 `rand.Read` error ignoring. No match.

---

### F-02: flowexport: NetFlow/IPFIX `encodeIPFIXOptionsSamplerDataSet` total length field truncates on large ODID but within normal range

**Severity:** Low
**Confidence:** Medium

**Evidence:**
- `pkg/flowexport/ipfix.go:491-514`:
  ```go
  func encodeIPFIXOptionsSamplerDataSet(odid uint32, samplingRate int) []byte {
      var space uint32
      if samplingRate > 1 {
          space = uint32(samplingRate - 1)
      }
      totalLen := 4 + ipfixOptionsSamplerRecordSize
      b := make([]byte, totalLen)
      off := 0
      binary.BigEndian.PutUint16(b[off:off+2], ipfixOptionsTemplateIDSampler)
      binary.BigEndian.PutUint16(b[off+2:off+4], uint16(totalLen))
  ```
  `totalLen` = 18, well within uint16. This is not a truncation bug currently.

- However, `pkg/flowexport/netflow.go:739-750`:
  ```go
  totalLen := 4 + (4 + len(v4fields)*4) + (4 + len(v6fields)*4)
  ```
  If a future change adds many optional template fields, `totalLen` could exceed 65535 and the `uint16(totalLen)` cast at line 278 silently truncates.

**Trace:** Future addition of 100+ template fields (enterprise fields, new IEs) could push totalLen past 65535, causing the FlowSet length field to wrap, making collectors parse the packet incorrectly.

**Why it matters:** Template-set length corruption causes all subsequent flow sets in the same packet to be misparsed by the collector — silent data loss or collector crash.

**Fix direction:** Add a `const` assertion or runtime check: `if totalLen > 65535 { panic(...) }` in `encodeTemplateFlowSet` and similar template builders.

**Labels:** `wire-format`, `hardening`

**Dedup note:** Dedup index has no mention of NetFlow/IPFIX template length field truncation. Not a duplicate.

---

### F-03: pkg/feeds — SSRF via feed URL pointing to localhost/metadata/private IPs

**Severity:** Medium
**Confidence:** Medium

**Evidence:**
- `pkg/feeds/feeds.go:126-134` (`resolveBaseURL`):
  ```go
  func resolveBaseURL(fsCfg *config.FeedServer) string {
      if fsCfg.URL != "" {
          return strings.TrimRight(fsCfg.URL, "/")
      }
      if fsCfg.Hostname != "" {
          return "https://" + strings.TrimRight(fsCfg.Hostname, "/")
      }
      return ""
  }
  ```
  No validation of the resulting URL. Any `http://` or `https://` URL is accepted, including `http://127.0.0.1/`, `http://169.254.169.254/` (cloud metadata), `http://10.0.0.1/` (internal management), `http://[::ffff:127.0.0.1]/`.

- `pkg/feeds/feeds.go:440-457` (`readFeed`):
  ```go
  req, err := http.NewRequestWithContext(ctx, "GET", fs.url, nil)
  ...
  resp, err := m.client.Do(req)
  ```
  Direct HTTP GET to the operator-supplied URL with no SSRF checks. The `http.Client` uses default transport (no custom Dialer that blocks private IPs).

**Trace:**
1. Operator (or compromised config) sets `feed-server URL http://169.254.169.254/latest/meta-data/`.
2. Daemon fetches it, parses response as CIDR feed (may fail parse, but the HTTP request already reached the metadata service).
3. On cloud platforms, this could leak metadata-credentials if Junos-style config comments accidentally include them.

**Refutation attempt:** Operator already has full config access (equivalent to root), so SSRF in this context requires the operator to attack themselves. However, per defense-in-depth and CPLN (cloud-provider) threat models, a feed URL arriving via config-sync from HA peer (which may have different network access) could reach internal endpoints. The commit-time validator (`config.ValidateFeedServer`) should block private/reserved IP feed URLs, or the HTTP transport should use a dial hook that rejects loopback/link-local/metadata IPs.

**Why it matters:** Cloud deployments where xpf runs on VMs (common — this project's test env is Incus VMs) would be vulnerable to metadata-service SSRF if a feed URL is attacker-controlled via config injection.

**Fix direction:** Add a `feedURLAllowed` check at commit validation (`config.ValidateFeedServer`) that rejects URLs resolving to loopback, link-local, or `169.254.169.254`. Alternatively, add a custom `http.Transport.DialContext` that rejects private IP destinations for feed fetches.

**Labels:** `ssrf`, `feeds`, `defense-in-depth`

**Dedup note:** Dedup index entries for feeds: none mention SSRF. Issue #4555 mentions `MAX_EXT_HDRS` vs `MAX_IPV6_EXT_HEADERS` (IPv6 EH mismatch). No SSRF dedup.

---

### F-04: pkg/logging: binary log total length field truncates at uint16 boundary for large variable sections

**Severity:** Low
**Confidence:** High

**Evidence:**
- `pkg/logging/ringbuf.go` (actually `pkg/logging/` — need correct file), `formatBinaryRecord`:
  ```go
  varLen := 5 + len(inZone) + len(outZone) + len(policyName) + len(appName) + len(iface)
  totalLen := binaryLogHeaderSize + varLen
  buf := make([]byte, totalLen)
  ...
  binary.BigEndian.PutUint16(buf[3:5], uint16(totalLen))
  ```
  `totalLen` is `int` but cast to `uint16` for the length field (bytes [3:5]). Each variable string is capped at 255 bytes (by `truncStr`), so max varLen = 5 + 255*5 = 1280, max totalLen = 143 + 1280 = 1423 bytes. Fits in uint16 (max 65535). Not actually exploitable at current caps.

**Trace:** Even if future changes remove `truncStr` caps or add more variable fields, `totalLen` could exceed 65535 and the uint16 cast would truncate, causing the collector/parser to read a shorter record length and misframe the stream.

**Why it matters:** Length-field truncation in self-framing binary protocol causes stream desync — exactly the same class of bug as #3874 (octet-counting partial-frame corruption).

**Fix direction:** Add compile-time or runtime assertion: `if totalLen > 65535 { panic(...) }` or use `uint32` if protocol allows. Or document the invariant: max totalLen = 1423 < 65535.

**Labels:** `wire-format`, `hardening`

**Dedup note:** Dedup index issue #4555 mentions IPv6 EH mismatch, not binary log length. No duplicate.

---

### F-05: pkg/eventengine — `supersede` double-counts or loses `droppedQueueFull` on concurrent producers (minor)

**Severity:** Low
**Confidence:** Medium

**Evidence:**
- `pkg/eventengine/engine.go:584-637` (`supersede`):
  ```go
  func (e *Engine) supersede(a plannedAction) bool {
      drained := make([]plannedAction, 0, actionQueueDepth)
      replaced := false
      for {
          select {
          case old := <-e.actions:
              e.counters.queueDepth.Add(-1)
              if old.policyName == a.policyName {
                  e.counters.droppedQueueFull.Add(1)
                  continue
              }
              drained = append(drained, old)
          default:
              goto refill
          }
      }
  refill:
      all := append(drained, a)
      for _, item := range all {
          select {
          case e.actions <- item:
              e.counters.queueDepth.Add(1)
              if item.policyName == a.policyName {
                  replaced = true
              }
          default:
              if item.policyName != a.policyName {
                  e.counters.droppedQueueFull.Add(1)
              }
          }
      }
      return replaced
  }
  ```
  Between `supersede` draining and refilling, another goroutine calling `enqueue` or another `supersede` could concurrently modify `e.actions`. The channel operations are thread-safe but the drain-then-refill is not atomic — concurrent `enqueue` could insert items between drain and refill, or concurrent `supersede` from another `HandleEvent` caller could interleave.

**Trace:**
1. Goroutine A: `supersede` drains channel, gets 3 items.
2. Goroutine B: `HandleEvent` → `enqueue` → non-blocking send succeeds (space freed by A's drain).
3. Goroutine A: refill puts back `drained + new`, including items B already re-added → channel may have duplicates or be over-reported in `queueDepth`.

**Refutation attempt:** `HandleEvent` is called from RPM probe goroutines concurrently. The `actions` channel is the shared point of contention. The drain-then-refill in `supersede` is not guarded by a mutex — `e.mu` is not held in `enqueue`/`supersede`. However, `supersede` is called only from `enqueue` which is called only from `HandleEvent`, which does not hold `e.mu` either. So concurrent calls to `supersede` are possible. The impact is low: double-counted counters, or temporarily slightly reordering queue entries. No data corruption or policy bypass.

**Why it matters:** Metric inaccuracy under sustained event flapping. Queue depth counter could drift from actual channel length.

**Fix direction:** Guard `enqueue`/`supersede` with a small mutex, or use a separate `sync.Mutex` for the channel operations, or restructure to avoid drain-then-refill entirely (use a map-based dedup queue).

**Labels:** `concurrency`, `metrics-accuracy`

**Dedup note:** Dedup index has no entry about eventengine queue supersede concurrency. Not a duplicate.

---

### F-06: pkg/ipmon — `Engine.Stop()` races with concurrent `Start()` on `started`/`stopped` flags (low contention)

**Severity:** Low
**Confidence:** Medium

**Evidence:**
- `pkg/ipmon/ipmon.go:331-367`:
  ```go
  func (e *Engine) Start() {
      e.mu.Lock()
      if e.started || e.stopped {
          e.mu.Unlock()
          return
      }
      e.started = true
      e.mu.Unlock()
      go e.run()
  }

  func (e *Engine) Stop() {
      e.mu.Lock()
      if e.stopped {
          e.mu.Unlock()
          return
      }
      e.stopped = true
      started := e.started
      e.actuateCancel()
      e.mu.Unlock()
      close(e.stop)
      if started {
          <-e.done
      }
  }
  ```
  `Start` and `Stop` both read/write `e.started` and `e.stopped` under `e.mu`, so they are race-free with respect to each other. However, `Stop` calls `actuateCancel()` under lock then releases lock and closes `e.stop`. If `Start` is called concurrently with `Stop`, the lock ordering ensures only one wins for `started`. This looks correct.

**Trace:** Re-analyzed — `e.mu` guards `started`/`stopped` reads/writes in both `Start` and `Stop`. No race. `done` is closed exactly once (by `run()` defer). `stop` is closed exactly once (by `Stop` guarded by `e.stopped`). `actuateCtx` is cancelled at most once (idempotent `context.CancelFunc`).

**Refutation result:** No bug found in this module after thorough analysis.

**Verdict:** NEGATIVE — ipmon engine lifecycle (start/stop idempotency, double-close prevention, actuate context cancellation) is sound.

---

### F-07: pkg/ipmon — `Manager.Apply` spawns probe goroutines that may leak if `ctx` is cancelled before ticker fires

**Severity:** Low
**Confidence:** Low

**Evidence:**
- `pkg/rpm/rpm.go:370-416` (`Apply`):
  ```go
  func (m *Manager) Apply(ctx context.Context, cfg *config.RPMConfig) {
      m.StopAll()
      ...
      probeCtx, cancel := context.WithCancel(ctx)
      m.cancel = cancel
      for _, probe := range cfg.Probes {
          for _, test := range probe.Tests {
              m.wg.Add(1)
              go func(p *config.RPMProbe, t *config.RPMTest, k string) {
                  defer m.wg.Done()
                  m.runProbeLoop(probeCtx, p, t, k)
              }(probe, test, key)
          }
      }
  }
  ```
  `probeCtx` is derived from `ctx` (the daemon's apply context). If `ctx` is cancelled (e.g., daemon shutdown during apply), `probeCtx` is also cancelled. `runProbeLoop` checks `ctx.Done()` in its select. This should be correct — probes exit when context is cancelled.

- `StopAll`:
  ```go
  func (m *Manager) StopAll() {
      if m.cancel != nil {
          m.cancel()
          m.wg.Wait()
          m.cancel = nil
      }
      m.mu.Lock()
      m.results = make(map[string]*ProbeResult)
      m.mu.Unlock()
  }
  ```

**Trace:** If `Apply` is called twice concurrently (e.g., daemon reconcile race), first `Apply` calls `StopAll()` which cancels previous probes, then second `Apply` also calls `StopAll()` which may cancel the first `Apply`'s new probes (because `m.cancel` was overwritten). However, the daemon apply path holds a semaphore, preventing concurrent `Apply` calls. Checked via grep — `pkg/daemon` serializes applies.

**Verdict:** NEGATIVE — RPM manager goroutine lifecycle is bounded by context cancellation and WaitGroup; no leak under normal daemon operation.

---

### F-08: pkg/flowexport — `routeMaskCache.populate` fire-and-forget goroutine may outlive exporter (bounded, low risk)

**Severity:** Low
**Confidence:** Medium

**Evidence:**
- `pkg/flowexport/routemask.go:164-206`:
  ```go
  func (c *routeMaskCache) scheduleLookupLocked(key routeMaskKey, ip16 net.IP, ifindex int) {
      ...
      c.pending[key] = struct{}{}
      c.inflight++
      ipCopy := append(net.IP(nil), ip16...)
      go c.populate(key, ipCopy, ifindex)
  }

  func (c *routeMaskCache) populate(key routeMaskKey, ip net.IP, ifindex int) {
      mask, ok := c.lookup(ip, ifindex)
      now := time.Now()
      c.mu.Lock()
      c.storeLocked(key, mask, ok, now)
      delete(c.pending, key)
      if c.inflight > 0 {
          c.inflight--
      }
      after := c.afterPopulate
      c.mu.Unlock()
      if after != nil {
          after()
      }
  }
  ```
  `populate` holds a reference to `c` via closure. If `NewRouteMaskResolver` is called again (config change creates new exporter with new cache), old cache's in-flight `populate` goroutines still run. They complete one netlink lookup and exit. Count is bounded by `maxInflight` (32). No persistent leak.

**Why it matters:** Under very high churn (rapid config changes that recreate exporters), old `populate` goroutines accumulate briefly (up to 32 per old cache), each holding a netlink socket briefly. Not a persistent leak but could cause transient resource pressure.

**Fix direction:** No fix needed — bounded and self-terminating. Document the bound.

**Verdict:** NEGATIVE (informational) — bounded, self-terminating goroutines. Not a resource-exhaustion bug.

---

### F-09: pkg/logging — `TraceWriter` and `LocalLogWriter` rotation: `os.Rename` failure on non-existent file counted as failedRotation (false positive metric)

**Severity:** Low
**Confidence:** Medium

**Evidence:**
- `pkg/logging/trace.go:510-521`:
  ```go
  for i := tw.maxFiles - 1; i > 0; i-- {
      old := fmt.Sprintf("%s.%d", tw.path, i)
      next := fmt.Sprintf("%s.%d", tw.path, i+1)
      if err := os.Rename(old, next); err != nil && !os.IsNotExist(err) {
          slog.Debug("trace rotate generation shift failed", "from", old, "to", next, "err", err)
          tw.failedRotations.Add(1)
          ...
      }
  }
  ```
  This correctly skips `ENOENT` (normal — missing generations). Similarly in `pkg/logging/locallog.go:247-257`. Both correctly filter `os.IsNotExist`.

**Verdict:** NEGATIVE — rotation error handling correctly distinguishes ENOENT from real failures. Metrics accurately reflect rotation problems.

---

### F-10: pkg/feeds — `http.Client` default Transport does not limit response header size (DoS vector with large headers)

**Severity:** Low
**Confidence:** Medium

**Evidence:**
- `pkg/feeds/feeds.go:113-121`:
  ```go
  func New(onUpdate func()) *Manager {
      return &Manager{
          feeds: make(map[string]*feedState),
          client: &http.Client{
              Timeout: httpClientTimeout,
          },
          ...
      }
  }
  ```
  The `http.Client` uses default transport with `MaxHeaderBytes` = 0 (unlimited by default in Go's `http.Transport`, actually defaults to 1MB in `net/http` server but not enforced on client side). A malicious feed server could send extremely large headers (hundreds of KB) before the `maxFeedBodyBytes` body cap applies. The body cap (`32 << 20`) protects against large bodies but not header bloat.

**Trace:**
1. Attacker (or compromised feed server) responds with 100KB of `Set-Cookie` headers.
2. `parseFeed` never runs because headers are consumed before body.
3. Each refresh interval, the feed fetcher allocates 100KB of header memory per fetch.
4. With many feeds, this multiplies.

**Why it matters:** Bounded DoS amplification — headers are not counted toward `maxFeedBodyBytes`. Go's default client `MaxHeaderBytes` on the server side is 1MB, but client side `http.Transport` has no equivalent limit by default. In practice, Go's `net/http` client does enforce a max response header size of 10MB (hardcoded in `http.readResponse`), so this is bounded to 10MB worst case.

**Fix direction:** Configure `http.Transport` with `MaxHeaderBytes` or use a custom transport that limits header exposure:
```go
transport := &http.Transport{
    MaxIdleConns: 10,
}
client := &http.Client{
    Timeout:   httpClientTimeout,
    Transport: transport,
}
```
Or simply document that the 10MB Go default header limit is acceptable for this use case.

**Labels:** `dos`, `feeds`

**Dedup note:** Dedup index entry #3934 mentions feed size/body caps (`maxFeedBodyBytes`, `maxFeedPrefixes`). Does not mention header-size DoS. Not a duplicate.

---

### F-11: pkg/snmp — `trapQueueDepth = 256` with single worker: burst of link flaps + slow targets can drop traps silently

**Severity:** Low
**Confidence:** Medium (known design, but worth noting)

**Evidence:**
- `pkg/snmp/traps.go:222`:
  ```go
  const trapQueueDepth = 256
  ```
- `pkg/snmp/traps.go:329-348` (`enqueueTrap`):
  ```go
  func (a *Agent) enqueueTrap(job trapJob) {
      a.trapWorkerOnce.Do(func() {
          a.trapQueue = make(chan trapJob, trapQueueDepth)
          go a.trapWorker()
      })
      select {
      case a.trapQueue <- job:
      default:
          dropped := a.trapsDropped.Add(1)
          slog.Warn("SNMP trap queue full, dropping trap", ...)
      }
  }
  ```
  Single worker, 256-depth queue. If N trap targets each have 2s dial timeout (#4744 style), and a link flap generates N trap group × M targets × 2 trap types (linkDown/linkUp) jobs, the queue can fill.

**Trace:**
1. Link flap on a highly-connected firewall (50 interfaces with many trap groups).
2. Each flap generates 50 interfaces × 3 trap groups × 2 trap versions (if "all") × 2 directions = 600 trap jobs.
3. Queue depth 256, single worker doing 2s UDP dial attempts for slow/dead targets.
4. 600 - 256 = 344 traps dropped silently (Warn logged but counter is the only metric).

**Why it matters:** Operator loses link-down/up trap notifications — the exact scenario SNMP traps are designed for (link-state alerting). Dropped traps during a flapping storm are the worst time to lose visibility. Though the design choice (bounded queue, drop-on-full) is documented and intentional to avoid blocking the link monitor.

**Verdict:** NEGATIVE (design trade-off, documented) — the bounded queue with drop is intentional (#2991) to prevent blocking the link-monitor goroutine. The `trapsDropped` metric and Warn log provide observability. A larger queue or multiple workers would increase goroutine count and memory. Current design is reasonable.

---

### F-12: pkg/logging — `eventTimeFromWire` overflow check uses `uint64(1<<63-1)` which is `9223372036854775807` — excludes valid timestamps after ~2262

**Severity:** Low
**Confidence:** Medium

**Evidence:**
- `pkg/logging/ringbuf.go` (actually event decode file):
  ```go
  func eventTimeFromWire(wireTS uint64) time.Time {
      if wireTS > 0 && wireTS <= uint64(1<<63-1) {
          return time.Unix(0, int64(wireTS))
      }
      return time.Now()
  }
  ```
  `wireTS` is nanoseconds since Unix epoch. `1<<63-1` ns = ~292 years = year 2262. After that, valid timestamps would be rejected and `time.Now()` would be used instead. The `int64` truncation is inherent to Go's `time.Unix(0, int64)`.

**Trace:** Only relevant after year 2262. Not actionable.

**Verdict:** NEGATIVE — `int64`-nanosecond Unix time inherently caps at ~2262. This is a known Go `time` package limitation, not a bug in this code.

---

### F-13: pkg/rpm — `Manager.HoldPinsForReprogram` replaces `pinFailed` map without holding `Results` consistent

**Severity:** Low
**Confidence:** Low

**Evidence:**
- `pkg/rpm/rpm.go:297-308`:
  ```go
  func (m *Manager) HoldPinsForReprogram(newPinKeys []string, cause error) {
      m.mu.Lock()
      defer m.mu.Unlock()
      held := make(map[string]error, len(m.marks)+len(newPinKeys))
      for k := range m.marks {
          held[k] = cause
      }
      for _, k := range newPinKeys {
          held[k] = cause
      }
      m.pinFailed = held
  }
  ```
  This holds all current pins and new pin keys as failed. But `m.marks` is also updated only in `Apply` (which calls `StopAll` first, clearing `m.marks`, then rebuilds). If `HoldPinsForReprogram` is called between `StopAll` clearing `m.marks` and the rebuild, `m.marks` is nil/empty and `held` will only contain `newPinKeys`. However, the docstring says "live probe goroutines — including ones whose keys are absent from the new pin set" must be held. If `HoldPinsForReprogram` runs after `StopAll`, no goroutines exist anyway (they were stopped).

**Verdict:** NEGATIVE — the calling sequence in the daemon (HoldPinsForReprogram → clear+reprogram → Apply) ensures probes are still running when HoldPinsForReprogram is called (before StopAll in Apply). The map replacement is atomic under `m.mu`. No race.

---

### F-14: pkg/snmp — `engineBootsPath` default `/var/lib/xpf/snmp-engineboots` — world-readable file (0644) leaks boots counter

**Severity:** Low
**Confidence:** Medium

**Evidence:**
- `pkg/snmp/agent.go:355-362`:
  ```go
  if err := fsatomic.WriteFileDurable(a.engineBootsPath, []byte(strconv.Itoa(boots)+"\n"), 0o644); err != nil {
  ```
  Mode `0o644` on a file that reveals the SNMPv3 engine Boots/Time. While not directly sensitive (boots counter is sent in cleartext in every authenticated SNMPv3 message per RFC 3414), the contrast with `#3477` hardening (other audit logs use `0o600`) is noted.

**Fix direction:** Use `0o600` for consistency with the hardening standard applied to other xpf runtime state files.

**Labels:** `hardening`

**Dedup note:** No dedup entry mentions SNMP engine boots file permissions.

---

### F-15: pkg/flowexport — `stableExporterID` returns 1 for unnamed default exporter — collides with IPFIX spec ODID 0 recommendation

**Severity:** Low
**Confidence:** Low

**Evidence:**
- `pkg/flowexport/exporterid.go:44-57`:
  ```go
  func stableExporterID(protocol, instance, template string) uint32 {
      if instance == "" && template == "" {
          return 1
      }
      ...
      return folded%0xFFFFFFFF + 1
  }
  ```
  When `instance == "" && template == ""`, returns 1. The comment says "some collectors treat ODID 0 specially". Returning 1 for the default is correct. The `folded%0xFFFFFFFF + 1` maps to [1, 0xFFFFFFFF], never 0. Correct.

**Verdict:** NEGATIVE — `stableExporterID` correctly avoids ODID 0 and provides stable per-group IDs. Implementation is sound.

---

## Summary

| # | Severity | Area | Title | Status |
|---|----------|------|-------|--------|
| F-01 | High | SNMPv3 crypto | `rand.Read` error ignored in DES/AES-128 PRIV encrypt | **BUG** — fix required |
| F-02 | Low | NetFlow/IPFIX | Template FlowSet length field could truncate with many fields | Hardening |
| F-03 | Medium | Feeds | SSRF via feed URL pointing to internal infrastructure | **BUG** — defense-in-depth |
| F-04 | Low | Binary log | Total length uint16 truncation for large variable sections | Hardening (currently safe by cap) |
| F-05 | Low | EventEngine | `supersede` drain-then-refill not atomic under concurrency | Minor metrics |
| F-06 | — | ipmon | Goroutine lifecycle | **NEGATIVE** — sound |
| F-07 | — | rpm manager | Goroutine leak | **NEGATIVE** — bounded by context/cancel |
| F-08 | — | routemask cache | Fire-and-forget populate goroutines | **NEGATIVE** — bounded, self-terminating |
| F-09 | — | logging rotation | ENOENT handling | **NEGATIVE** — correct |
| F-10 | Low | Feeds | Response header DoS (large headers bypass body cap) | Hardening |
| F-11 | — | SNMP traps | Queue depth / dropped traps under burst | **NEGATIVE** — intentional bounded design |
| F-12 | — | eventTimeFromWire | int64-ns overflow at year 2262 | **NEGATIVE** — Go time limitation |
| F-13 | — | rpm pin-hold | HoldPinsForReprogram consistency | **NEGATIVE** — correct call ordering |
| F-14 | Low | SNMP boots file | File permissions 0644 vs expected 0600 | Hardening |
| F-15 | — | flowexport ID | stableExporterID correctness | **NEGATIVE** — correct |

### Key Action Items

1. **F-01 (High):** Fix `encryptDES` / `encryptAES128` in `pkg/snmp/v3.go` to check `rand.Read` error — use `io.ReadFull(rand.Reader, ...)` and fail the encryption if it errors.

2. **F-03 (Medium):** Add SSRF protection for dynamic-address feed fetcher — validate feed URLs at commit time (reject loopback / private / metadata-service IPs) or add a custom Dialer that blocks private destinations.

3. **F-10 (Low):** Consider adding explicit header-size limits to feed HTTP client transport to complement existing body/entry-count caps.

4. **F-14 (Low):** Change `snmp-engineboots` file permissions from `0o644` to `0o600` for consistency with other xpf runtime-state hardening.

---

*Review generated by paladin-038 prompt-018, base commit d4506d4, batch 19 (A9_go_observability).*
