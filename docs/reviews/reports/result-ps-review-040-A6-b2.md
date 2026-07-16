# Triage Result: ps-review-040-A6-b2

- **Subsystem**: A6 batch 2 — `pkg/dataplane/userspace` NAT compilation, HA
  coordination, proactive neighbor resolution (userspace-dp Go manager).
- **Base == current master?**: Yes. Triaged against `origin/master`
  @ `95b33d49634d56086269a62a92e213dae7926f88` (fetched at triage time).
- **Repo**: real `bpfrx` (all cited paths are `pkg/dataplane/userspace/*.go`,
  not the `/home/ps/git/avacado-xpf` fork). NOTE: every file:line citation in
  this review is STALE — it was authored against a PRE-refactor-split tree
  (`process.go`, monolithic `nat.go`). On current master the code has been
  split into `process_napi.go` and `nat_destination.go` / `nat_source.go` /
  `nat_static.go` (the #4517-#4685-era cold-path Go refactor splits). Symbols
  exist but at different files/lines.
- **Outcome counts**: 3 findings → **0 GENUINE-RESIDUAL**, 1 ALREADY-FIXED,
  1 DELIBERATE, 1 NOT-MATERIAL. (0 residuals — expected for this hardened
  scope.)

---

## Finding 1 — Unbounded goroutine/raw-socket fan-out in proactive neighbor resolve
**Severity claimed: High → Disposition: NOT-MATERIAL (severity overstated)**

- **Symbol exists?** Yes, but MOVED. The review cites `process.go:1024-1032`
  and `process.go:869-876`. On master the target loop is
  `pkg/dataplane/userspace/process_napi.go:361-370` (inside
  `proactiveNeighborResolveAsync`) and the raw-socket sender is
  `sendICMPProbeWithID` at `process_napi.go:207-243`. The status-loop driver is
  `process_status.go:207-213`. The logic is byte-similar to what the review
  quotes, so this is a stale citation, not confabulation.

- **Already fixed?** No — the final `for _, t := range targets { go func(...) }`
  loop still spawns one goroutine per target with no explicit worker-pool cap.

- **Why NOT-MATERIAL (the claimed High "crash/freeze the daemon" does not hold):**
  1. **FD lifetime is microseconds.** `sendICMPProbeWithID` does
     `Socket()` → `SetsockoptString(SO_BINDTODEVICE)` → checksum compute →
     `Sendto(..., MSG_DONTWAIT, ...)` → `defer unix.Close(fd)`. Every syscall is
     non-blocking; the fd is held for a handful of fast syscalls, then closed
     immediately. The steady-state count of fds open *simultaneously* is bounded
     by how many probe goroutines are between `Socket()` and `Close()` at one
     instant, not by `len(targets)`.
  2. **The neighbor table is kernel-capped.** `targets` is drawn only from
     STALE/FAILED entries in the kernel neighbor table (+ unresolved route
     gateways), deduplicated via `targetSet`. The kernel caps the ARP/ND cache
     at `gc_thresh3` (default 1024), so `targets` is bounded to ~1024 worst-case,
     not "hundreds/thousands unbounded" as claimed.
  3. **EMFILE is handled gracefully, not fatally.** If `linuxsock.Socket`
     returns an error the goroutine does `return` — it silently skips that one
     probe. There is no panic, no fd leak, no cascading failure. The review's
     asserted impact ("crash or freeze the control plane daemon, preventing
     config updates / CLI / telemetry / HA failovers") is unsupported: transient
     fd pressure lasting microseconds would only affect another `socket()` caller
     that happened to race the exact window, and that caller would itself just
     get a retryable EMFILE.
  4. **Cadence bounds it further.** The driver fires
     `proactiveNeighborResolveAsyncLocked()` at most 1/s for the first 60s
     (`process_status.go:207`), then only on the throttled standby-prewarm path.
     Each burst drains in milliseconds, well before the next tick — no
     accumulation across ticks.

- **Residual value:** A worker-pool / semaphore bound would be tidier defensive
  hygiene, but it is a LOW-value nit, not a reachable High crash. Not filed as a
  genuine residual: no attacker-controlled reachable path to daemon crash on
  current master.

---

## Finding 2 — DNAT port-coalesce fail-open on out-of-range dest port
**Severity claimed: High → Disposition: ALREADY-FIXED**

- **Symbol / trace basis is STALE.** The review's mechanism depends on
  `coalescePortRanges` calling `clampPort(start)`/`clampPort(prev)` (cited at
  `nat.go:427-430`) so that `70000` → `[{Low:0,High:0}]`, which then slips past
  the `len(portRanges)==0` guard and emits a `DestinationPort:0` wildcard.

- **On current master this cannot happen.** `coalescePortRanges` is at
  `pkg/dataplane/userspace/nat.go:150-185` and does NOT use `clampPort` at all.
  It filters out-of-range ports at the TOP of the dedup loop:
  ```go
  for _, p := range ports {
      if p < 1 || p > 65535 { continue }   // nat.go:167-169
      ...
  }
  if len(uniq) == 0 { return nil }         // nat.go:174-176
  ```
  A configured `70000` is dropped; if it was the only port, `coalescePortRanges`
  returns `nil` (empty), NOT `[{0,0}]`.

- **The DNAT builder then fails CLOSED.** In `nat_destination.go:388-421`:
  `termPorts` still contains the raw `70000`, so `portConfigured :=
  len(termPorts) > 0 || termDstPortConfigured` is **true**. With
  `portRanges` empty, `if len(portRanges) == 0` → `case portConfigured:
  continue` — the term emits NO snapshot (matches nothing). Only the genuine
  no-port-configured `default:` branch produces the `[{0,0}]` wildcard. This is
  exactly the review's own recommended fix, already implemented via
  #3429 / #3726 / #3857 (the doc comment at `nat.go:137-149` and the
  `#3857` comment block at `nat_destination.go:397-406` describe it verbatim:
  "an all-invalid configured port therefore coalesces to nothing and is failed
  CLOSED below").

- **Verdict:** The fail-open path the review describes was already closed. The
  review triaged a pre-#3429 snapshot where coalesce used `clampPort`.

---

## Finding 3 — Static NAT clampPort widens port-restricted rule to whole-address
**Severity claimed: Medium → Disposition: DELIBERATE (NOT-MATERIAL)**

- **Symbol exists and IS current code.** `clampPort` lives at
  `pkg/dataplane/userspace/nat_static.go:13-18`; used in
  `buildStaticNATSnapshots` at `nat_static.go:49-50` for `MatchDestinationPort`
  and `MappedPort`. `clampPort(70000)` → 0, as the review states.

- **This is a deliberate, documented, test-locked decision (#2491).** The
  function doc explicitly states the intent: an out-of-range port "is rejected
  at strict commit-check (`compiler_nat.go validateNATHostMaskStrict`), but the
  lenient load/peer-sync path can still carry one; clamp it to 0 ('no port
  translation') so a bad value fails CLOSED on the wire instead of wrapping to a
  wrong u16. #2491." There is a fail-on-revert test
  `static_nat_mapped_port_2491_test.go::TestBuildStaticNATSnapshotClampsBadPort`
  that ASSERTS clamp-to-0 for `MatchDestinationPort:70000, MappedPort:-1`.

- **The review's framing is only half-right and the impact is negligible:**
  - For `MappedPort` → 0 = "no port rewrite" — unambiguously the safe/no-op
    direction (matches the #2491 "fail closed" claim).
  - For `MatchDestinationPort` → 0 = "match any port" — technically a WIDENING
    of the match scope, so the review's fail-open framing has a kernel of truth
    for that ONE field. BUT: (a) the alternative it never matched anything
    anyway (no real packet carries port 70000), (b) the rule stays scoped to a
    specific `ExternalIP/32` translating to one `InternalIP/32` — this is a
    NAT-scope widening on a single host, NOT an access-control decision;
    the security policy still governs whether that traffic is admitted, (c) it
    is reachable ONLY via the lenient/tolerant-load / mixed-version HA peer-sync
    backstop — strict commit rejects it, and a peer only syncs config that
    already passed strict validation on the sender, so the value could only
    originate on an OLD build lacking the check.

- **Verdict:** Reachability is narrow and non-attacker-controlled; blast radius
  is a single-host 1:1 NAT-scope widening gated by firewall policy; and the
  behavior is an explicitly reviewed, commented (#2491), and test-locked
  tradeoff. Re-classifying it to "skip the rule" would break the fail-on-revert
  test and re-litigate a settled design. Not a genuine residual.

---

## Negative-results section (report §2)
25+ modules listed as clean with per-module invariants. No findings asserted
there — nothing to triage. Spot-checks (coalesce fail-closed, static-NAT #2491,
DNAT #3857) corroborate the "well-hardened" characterization of this scope.
