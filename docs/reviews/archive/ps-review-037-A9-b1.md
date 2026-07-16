# A9: Observability & Telemetry Review — SNMP, NetFlow/IPFIX, Logging, RPM, Feeds, Event Engine

Base: d4506d4450e2
Reviewer: A9 (telemetry — wire encoders, SNMPv3 crypto, goroutine/fd leaks, log correctness, backoff/retry)
Paths: pkg/flowexport/*.go, pkg/snmp/*.go, pkg/logging/*.go, pkg/rpm/*.go, pkg/feeds/*.go, pkg/eventengine/*.go

## Summary

Full review of every telemetry and observability module. No new High/Confident security issues found. NetFlow v9 / IPFIX wire encoding is correctly length-fielded with build-time size pins. SNMPv3 timeliness, HMAC verification, and priv IV construction are correct. Syslog TCP/TLS backoff and partial-write teardown (streamWrite) are correctly implemented. RPM probe loop correctly holds state on ErrProbeSetup. Feeds fetch is correctly bounded on bytes + entries with proper stale/retain logic. Event engine correctly reconciles runtime state across Apply (no cooldown wipe), uses deterministic semantic revision hashing. Several low-severity hardening observations noted.

---

## Finding A9-01: SNMPv3 privParams (AES/DES salt) generated with crypto/rand.Read but return value unchecked

- Title: SNMPv3 AES-128 / DES privParams RNG error silently ignored — salt reused on RNG failure
- Severity: MEDIUM
- Confidence: High
- Evidence:
  - `pkg/snmp/v3.go:778` — `encryptDES`:
    ```go
    privParams := make([]byte, 8)
    rand.Read(privParams)  // return (n, err) discarded
    ```
  - `pkg/snmp/v3.go:802` — `encryptAES128`:
    ```go
    privParams := make([]byte, 8)
    rand.Read(privParams)  // return (n, err) discarded
    ```
  - Both pass `privParams` (now zeroed on RNG failure) into IV construction without detecting the failure
  - Contrast with every other `crypto/rand.Read` site in the codebase that checks the error:
    - `pkg/wgkey/wgkey.go:101` — `if _, err := rand.Read(raw); err != nil {`
    - `pkg/configstore/crypto.go:95` — `if _, err := rand.Read(nonce); err != nil {`
    - `pkg/api/server.go:634` — `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)` (wraps rand.Reader internally)
  - Go `crypto/rand.Read` docs: "Read is a helper function that calls Reader.Read using io.ReadFull. On return, n == len(b) if and only if err == nil." — it CAN return n < len(b) with err != nil. Discarding both means a partially-filled or zero-filled privParams is used as the salt.
- Trace:
  - `encryptAES128` — AES-128-CFB IV = `boots(4) || time(4) || privParams(8)` (RFC 3826 §3.1.2.1). If `rand.Read(privParams)` fails and returns 0 bytes filled, IV = `boots||time||0000000000000000`. The IV is partially predictable (boots+time are semi-public, privParams should provide 64 bits of entropy). A zero salt means the IV is deterministic for a given (boots, time) pair.
  - `encryptDES` — DES-CBC IV = `preIV ^ privParams`. Zero privParams → IV = preIV (the first 8 bytes of privKey), which is derived from the user's passphrase deterministically. No randomness in the IV at all.
  - Impact of deterministic IV in SNMPv3:
    - For AES-128-CFB (RFC 3826): The IV for two messages with same boots+time would be identical. With CFB mode, same IV + same plaintext prefix → same ciphertext prefix (keystream reuse). This leaks whether two responses share a plaintext prefix. However, SNMP responses for the same OID at the same second are typically identical anyway.
    - For DES-CBC: Same IV for same plaintext → same ciphertext (full leak of equality). DES is already deprecated/marginal in SNMPv3 practice.
    - RNG failure in `crypto/rand` on Linux means `/dev/urandom` is unavailable — this is an extremely rare / pathological condition (device file missing, namespace isolation). When it happens, the process likely has bigger problems.
- Refutation attempt:
  - `crypto/rand.Read` on Linux reads from `getrandom(2)` syscall, which blocks until the CRNG is initialized (5.6+) or reads from `/dev/urandom` which never fails on a healthy system. Failure requires the kernel to have no entropy source at all, or `/dev/urandom` to be absent (container seccomp / chroot misconfiguration). This is extremely unlikely in production.
  - Even with deterministic IV, the SNMPv3 response is authenticated (HMAC-SHA-*/MD5 via `computeAuth` → `insertAuthMAC`), so a passive observer cannot modify it. Confidentiality degradation is limited to equality detection, not plaintext recovery (CFB is not CBC — identical IV with different plaintext does not directly leak plaintext, only keystream, and the keystream changes per key).
  - The fix is trivial and the pattern is inconsistent with every other `rand.Read` in the codebase — but the practical risk is very low.
- HPC check: N/A — SNMP runs in its own goroutine, blocking on UDP recv
- Why it matters: Deterministic privacy salt degrades the confidentiality guarantee of SNMPv3 USM encryption. While RNG failure is extremely rare on Linux, the correct pattern (check err, fail the encrypt) is one line and is already used everywhere else. A zero-salt AES IV with `boots||time||0000...` is also distinguishable from a proper random salt, which could fingerprint the agent to a passive observer.
- Fix direction: Check `rand.Read` return in both `encryptDES` and `encryptAES128`:
  ```go
  if _, err := io.ReadFull(rand.Reader, privParams); err != nil {
      return nil, nil  // fail the encrypt, caller drops priv and falls back to authNoPriv
  }
  ```
  Or: `if _, err := rand.Read(privParams); err != nil { return nil, nil }`. Note `io.ReadFull` pattern used in `configstore/crypto.go:95`.
- Labels: [medium, snmp, crypto, iv, rng, defense-in-depth]
- Dedup note: No prior issue tracks SNMPv3 privParams RNG error handling. #4549 LOW batch does not cover SNMP. #4555 XDP EH is unrelated.

---

## Finding A9-02: IPFIX exporter ODID collision — two instances with same (instance, template) but different sampling rates get same ODID

- Title: IPFIX stableExporterID uses only (protocol, instance, template) — two instances with same instance name but different config could collide
- Severity: INFO (correctness)
- Confidence: Low
- Evidence:
  - `pkg/flowexport/netflow.go:566-578` — `NewExporter` derives `sourceID := stableExporterID("netflow9", cfg.InstanceName, cfg.TemplateName)`
  - `pkg/flowexport/ipfix.go:772-785` — `NewIPFIXExporter` derives `sourceID := stableExporterID("ipfix", cfg.InstanceName, cfg.TemplateName)`
  - `pkg/flowexport/exporterid.go` — `stableExporterID` hashes the inputs deterministically
  - `pkg/flowexport/manager.go:395-462` — `ResolveV9TemplateGroups` / `ResolveIPFIXTemplateGroups` produces one `ExportConfig` per (instance, template) group
  - In practice, instance names are unique within `fo.Sampling.Instances` (map keys), so two configs with same InstanceName are the same instance. The ODID collision would only occur if an operator configured two sampling instances with the same name but in different address families — but `Sampling.Instances` is a flat map by name, so this cannot happen.
- Trace: Not exploitable in current config model — each instance name maps to one `SamplingInstance`, and each instance's collectors are partitioned by template. No collision path exists.
- Refutation attempt: Confirmed — instance names are unique map keys in `Sampling.Instances`. Two `ExportConfig` values with same (instance, template) are the same config (same collectors, same rate). Not a bug.
- HPC check: N/A
- Why it matters: N/A — no finding
- Fix direction: N/A
- Labels: [info, false-positive, negative-finding]
- Dedup note: N/A — negative finding, not filed.

---

## Finding A9-03: RPM ICMP probe — echoID derived from PID XOR atomic counter — predictable, no security impact

- Title: ICMP echo ID predictable from PID (information leak, no security impact)
- Severity: INFO
- Confidence: High
- Evidence:
  - `pkg/rpm/icmp.go:193` — `id := int(uint16(os.Getpid()) ^ uint16(echoIDCounter.Add(1)))`
  - PID is semi-public (visible in `/proc`), counter starts at 0 and increments monotonically
  - The ID is used to match ICMP echo replies (line 240: `echo.ID != id`)
- Trace: An on-path attacker who can inject ICMP echo replies could forge a reply with the correct ID/seq to make a failed path appear healthy. Predictability of the ID makes this marginally easier (need to guess one of ~64 concurrent in-flight IDs rather than brute-force 16 bits). However:
  - ICMP echo replies are authenticated only by ID/seq match on a raw socket that receives ALL ICMP on the host — this is the standard ICMP echo matching mechanism, same as `ping(8)`
  - An on-path attacker who can inject ICMP can already inject arbitrary packets — forging one echo reply is not the limiting factor
  - The probe measures path health, not security — a false PASS from a forged reply delays failover by one probe interval (seconds), then the next probe fails again
- Refutation attempt: Not a security issue — RPM probe ID predictability is by design (same as every ping implementation). No fix needed.
- HPC check: N/A
- Why it matters: N/A — no finding
- Fix direction: N/A
- Labels: [info, negative-finding]
- Dedup note: N/A

---

## Finding A9-04: Event engine — within clause zero-Seconds typo detection relies on config-layer validation, runtime belt is fail-closed

- Title: (Negative) Event engine withinMatches correctly fails closed on Seconds==0
- Severity: N/A (negative)
- Confidence: High
- Evidence:
  - `pkg/eventengine/engine.go:1163-1165` — `if wc.Seconds <= 0 || (wc.TriggerOn <= 0 && wc.TriggerUntil <= 0) { return false }` — zero Seconds fails closed (policy does not fire)
  - `pkg/config/compiler_eventoptions.go:validateEventOptionsWithinAST` — commit-time validator rejects zero Seconds
  - `pkg/eventengine/engine_4423_test.go` — tests verify fail-closed on zero Seconds / zero threshold
  - `pkg/eventengine/engine_within_failclosed_3751_test.go` — tests verify fail-closed on typo'd within
- Trace: A `within 0 { trigger on 3; }` clause (typo, should be `within 30`) would make `Seconds==0`. On strict commit path: rejected at commit. On lenient-load / HA-sync path (older binary silently coerced typo to 0): `withinMatches` returns false (fail-closed, remediation does not fire) rather than treating 0 as "always match" (fail-open, always-fires). Correct.

---

## Finding A9-05: RPM manager — event buffer replay on SetEventCallback: events replayed outside lock but callback could race with concurrent HandleEvent

- Title: RPM buffered event replay races with concurrent probe loop HandleEvent
- Severity: LOW
- Confidence: Medium
- Evidence:
  - `pkg/rpm/rpm.go:226-239` — `SetEventCallback`:
    ```go
    m.mu.Lock()
    m.onEvent = fn
    var replay []Event
    if fn != nil && len(m.bufferedEvents) > 0 {
        replay = m.bufferedEvents
        m.bufferedEvents = nil
    }
    m.mu.Unlock()
    for _, ev := range replay {
        fn(ev)  // called OUTSIDE m.mu — correct for deadlock avoidance
    }
    ```
  - After `m.mu.Unlock()` but before/during replay loop, a concurrent `runSingleTest` goroutine calls `fireEvent` → reads `m.onEvent` (now non-nil) → calls `fn(ev)` directly (no buffering). So the concurrent event fires during the replay loop.
  - `fn` is `eventengine.Engine.HandleEvent` — `HandleEvent` takes `e.mu`, evaluates policies, and enqueues via `e.enqueue`.
  - The replay and the concurrent event both call `HandleEvent` concurrently — but `HandleEvent` is documented safe for concurrent calls (it takes `e.mu` for evaluate, and `enqueue` is lock-free channel send). No data race despite logical interleaving.
  - Ordering: replay events (older, from boot-time first cycle) could interleave with live events (newer probe cycles) calling HandleEvent. The event engine's `withinMatches` uses window timestamps (`e.now()`), not event ordering, so interleaving doesn't affect correctness — each event's window is anchored to wall time.
- Refutation attempt: `eventengine.Engine.HandleEvent` is safe for concurrent calls — `evaluateEvent` takes `e.mu`, `enqueue` uses channel send. The replay loop and concurrent `fireEvent` both eventually call `HandleEvent`, which serializes via `e.mu`. No double-free, no lost event (each event delivered exactly once — either via replay or via direct `fireEvent`). Window computation uses wall-clock timestamps, not sequence order. Correct.
- HPC check: Probe loops run concurrently (one goroutine per test), so `fireEvent` can race with `SetEventCallback` replay. But the mutex protocol is correct.
- Why it matters: No issue — the code is correct. Noted as negative finding because the pattern (unlock-then-iterate with concurrent writers) looks racy at first glance.

---

## Finding A9-06: NetFlow / IPFIX batch — maxDepth uses non-atomic load-then-store under mu but readers Load without mu

- Title: (Negative) flowBatch.maxDepth load-then-store race is safe — serialized by mu on writer side
- Severity: N/A (negative)
- Confidence: High
- Evidence:
  - `pkg/flowexport/transport.go:403-422` — `add()` holds `b.mu`, computes `depth`, then non-atomically loads `maxDepth` and conditionally stores. Comment: "maxDepth is written only here; adds are serialized by mu, so the load-then-store cannot race another writer (readers only Load())."
  - `BatchMaxDepth()` / `MaxDepth()` use `Load()` without `mu` — readers are lock-free.
  - This is safe: all writers are serialized by `mu`, readers use atomic `Load()` which is linearizable with the `Store()`. The load-then-store is not a CAS (a concurrent add could increase depth between our Load and Store, causing us to miss a HWM update), but the missed HWM would be at most one add behind — and the next add from the same goroutine or another would catch up. Worst case: HWM slightly under-reports by one concurrent-add worth of depth for one add cycle. Not observable (HWM is a monotonic diagnostic, not used for flow control).
- Refutation attempt: The 1-behind HWM rare race is negligible — HWM would self-correct on the next add. Not a correctness issue.

---

## Finding A9-07: Syslog client — TLS with nil *tls.Config uses system roots (no client cert, no custom CA)

- Title: (Known) security log TLS stream with named tls-profile silently uses system CA roots
- Severity: N/A (known, tracked)
- Confidence: High
- Evidence:
  - `pkg/daemon/daemon_system.go:116-124` — comment acknowledges: "The final *tls.Config is nil — a TLS stream trusts the system CA roots. A named `transport tls-profile` is NOT honored here; it is rejected at commit by validateSecurityLogStreamTLSProfileAST"
  - `pkg/logging/syslog.go:263-276` — `dialTLS` with nil config uses `tls.Dialer{Config: nil}` which defaults to system roots
  - `pkg/config/compiler_security_log.go:196` — "rejects any named TLS profile at commit"
  - This is tracked as #3350 area per A8 review's N-11 — the commit-time validator rejects tls-profile, so the silent downgrade cannot be configured
- Dedup note: #3350 / A8-N-11 — not re-reporting.

---

## Finding A9-08: RPM — HTTP probe does not verify TLS certificate by default (InsecureSkipVerify not set, but no CA pinning)

- Title: RPM http-get probe against https:// target uses default TLS verification (system roots, no pinning) — could be MITM'd on fabric
- Severity: INFO
- Confidence: Medium
- Evidence:
  - `pkg/rpm/rpm.go:741-771` — `probeHTTP` → `canonicalizeHTTPTarget` → `http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}`
  - No `TLSClientConfig` set on the transport — Go's default is to verify against system CA roots
  - A `http-get https://target` probe where `target` is inside a VRF (resolved via VRF-bound resolver) could be MITM'd if the VRF's DNS is poisoned or the target's cert is not in system roots (self-signed internal service)
  - This is an availability probe, not a security check — a MITM that makes the probe PASS when it should FAIL delays failover (same as the ICMP forge analysis). A MITM that makes it FAIL when it should PASS triggers spurious failover.
  - The probe's purpose is path liveness, not endpoint authenticity — using system roots is the standard Go posture. Pinning/mTLS for probes is not configured anywhere.
- Refutation attempt: RPM http-get is a liveness probe (is the target reachable?), not an authentication check. System-root verification is correct for the threat model — it prevents a random on-path attacker from spoofing a random public HTTPS endpoint, while allowing operator-controlled internal HTTPS targets with proper PKI. Self-signed targets would need explicit handling but are unlikely for uplinks. Not a bug.
- Labels: [info, rpm, tls]
- Dedup note: No prior RPM TLS issue.

---

## Finding A9-09: Feeds — http.Client.Timeout includes DNS + connect + TLS + body read (30s total) — no per-attempt retry

- Title: (Negative) Feed fetcher correctly bounds fetch with 30s total timeout, retries on next tick
- Severity: N/A (negative)
- Confidence: High
- Evidence:
  - `pkg/feeds/feeds.go:65` — `httpClientTimeout = 30 * time.Second`
  - `pkg/feeds/feeds.go:114-121` — `http.Client{Timeout: httpClientTimeout}` — bounds connect + headers + body read (slow-loris protection)
  - `pkg/feeds/feeds.go:34` — `maxLineBytes = 1 << 20` — per-line cap
  - `pkg/feeds/feeds.go:51` — `maxFeedBodyBytes = 32 << 20` — total body cap with over-size detection via `countingReader` + `io.LimitReader(r, maxFeedBodyBytes+1)`
  - `pkg/feeds/feeds.go:60` — `maxFeedPrefixes = 1 << 20` — entry count cap
  - `pkg/feeds/feeds.go:2050` — retainForever default (fail-safe: stale denylist beats fail-open empty)
  - Single GET per fetch, no retry within a tick — next tick retries. Correct: retrying within a tick would amplify a down feed server with N× requests.
- Dedup note: #3934 tracked the feed size/line/timeout hardening — verified correct, not re-reporting.

---

## Finding A9-10: Logging ringbuf — 144-byte rawEvent wire size, additive [144:152] extension handled correctly

- Title: (Negative) Event wire format correctly handles legacy 144-byte and extended 152-byte frames
- Severity: N/A (negative)
- Confidence: High
- Evidence:
  - `pkg/logging/ringbuf.go:77-104` — `rawEventWireSize = 144`, `rawEventExtSize = 152`, `rawEventStructSize` compile-time assert `var _ [rawEventWireSize]struct{} = [rawEventStructSize]struct{}{}`
  - `pkg/logging/ringbuf.go:98-104` — comment: "The growth is ADDITIVE: the minimum-frame acceptance stays at rawEventWireSize (144) so a new daemon still accepts an old helper's 144-byte frames"
  - Rolling upgrade: new daemon accepts 144-byte frames (reads only what exists), old daemon ignores trailing 8 bytes (reads 144, skips remaining buffer). Both directions safe.
  - `pkg/logging/ringbuf.go:380-410` — field parsing checks `len(data) >= rawEventWireSize` before reading extended fields
- Dedup note: Verified correct, not re-reporting. No integer truncation in the wire format (all offsets are compile-time constants, all reads bounds-checked).

---

## Summary of actionable findings

| # | Severity | Title | Fix complexity |
|---|----------|-------|----------------|
| A9-01 | MEDIUM | SNMPv3 privParams RNG error unchecked | 2 lines (add err check in both encrypt funcs) |

All other modules reviewed with no new actionable findings. Areas with notable defense-in-depth already in place:

- **Flow export** (#3934 size caps, #3747 batch bounding, #2464 collector health, #4423 M10 zero-refresh-rate panic fix, #3748 PSAMP OPTIONS template, #3746 biflow reverse counters with enterprise bit handling) — all verified correct.
- **SNMP** (engineBoots persistence with durable write, timeliness window ±150s, HMAC constant-time compare via `hmac.Equal`, VRF-aware trap dispatch, link-state async worker with bounded queue, context gating for non-default context) — all verified correct except A9-01.
- **Logging** (syslog TCP/TLS cooldown-gated reconnect with `streamWrite` partial-frame teardown, eventbuf subscription close-then-delete ordering, trace file sanitization + clamping (#3420/#3424), locallog rotation with hardened open) — all verified correct.
- **RPM** (ErrProbeSetup hold-state doctrine, icmp link-local zone scoping (#2494), VRF-bound DNS (#2614), probeDialer source-address validation (#2492), http-get scheme canonicalization (#2495), pin install gating (#1895)) — all verified correct.
- **Feeds** (byte + entry count caps, line length cap, slow-loris timeout, countingReader over-size detection, retainForever default, staleSince tracking, degraded install warning) — all verified correct.
- **Event engine** (#2139 transactional batch, #2140 cooldown survives reload via semRev reconciliation, #2141 fail-closed matcher, #2157 fail-safe queue with backoff, #3750 revalidate-before-commit, #3751 within-clause fail-closed, #3756 M1 edge-triggered `trigger on`) — all verified correct.
