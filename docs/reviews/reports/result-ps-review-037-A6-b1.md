# Triage result — ps-review-037-A6-b1

- **Subsystem / cohort:** A6 — Dataplane Go manager & control-plane→dataplane
  compilation (`pkg/dataplane/userspace/*`, plus DDNS Surface-A observer glue).
  Codex per-subsystem audit; persona = control-plane (typed config →
  dataplane control messages / BPF map writes, pool/binding index math &
  caps, eventstream framing, HA glue, partial-apply safety, integer
  truncation).
- **Base commit:** d4506d4450e2 == **current `origin/master`** (verified —
  `git rev-parse origin/master` == `git rev-parse d4506d445` ==
  d4506d4450e23f9a3fc572206b3c82f6b6c99029). No stale-base drift.
- **Findings in file:** 8 (F-A6-001..008). Only 2 are substantive
  (F-A6-001, F-A6-002); F-A6-003..008 are explicit NEGATIVE/INFO
  self-confirmations.

## Outcome counts

| Disposition | Count | Findings |
|---|---|---|
| GENUINE-RESIDUAL (novel) | 1 | F-A6-001 (LOW) |
| NOT-MATERIAL | 1 | F-A6-002 |
| NEGATIVE (author-confirmed, symbols verified) | 6 | F-A6-003..008 |
| CONFABULATED | 0 | — |
| DUP | 0 | — |
| ALREADY-FIXED | 0 | — |

**All cited symbols exist on current master.** No confabulation. The review
is accurate: every negative-finding symbol (`surfaceAObserver`,
`clampPort`, `sourceNATPoolPortRange`, binding-index guard,
`pendingCallbackFramesLimit`, zone-ID u16, FIB-gen u32) was confirmed
present and matching the described behavior.

---

## Per-finding disposition

### F-A6-001 — GENUINE-RESIDUAL (LOW, novel)
**Heartbeat map zero-init loop bound uses raw `cfg.Workers` (unclamped) →
negative Workers wraps `uint32` to ~4.29 B iterations → control-plane apply
hang (DoS).**

- **file:line:** `pkg/dataplane/userspace/maps_sync.go:179`
  ```go
  for slot := uint32(0); slot < uint32(cfg.Workers)*2*16; slot++ {
      _ = heartbeatMap.Update(slot, zeroHB, ebpf.UpdateAny)
  }
  ```
- **Verified reachability trace (real, no preceding guard):**
  1. `UserspaceConfig.Workers` is `int` (`pkg/config/types_system.go:68`).
  2. Compile path swallows the Atoi error:
     `pkg/config/compiler_system.go:738` — `cfg.Workers, _ = strconv.Atoi(v)`.
     Input `"-1"` parses cleanly to `-1` (no error), so a negative value
     survives compilation.
  3. STRICT commit rejects it via `ValidateIntegerMin(1)`
     (`pkg/config/schema_system.go:258`) — but the **lenient** ingress
     (`Store.Load` / `Store.SyncApply`) downgrades the schema violation to a
     *warning* and continues: `compileTreeLenient` /
     `schemaValidateExpandedTree` → `slog.Warn(... "#1319")`
     (`pkg/configstore/store.go:398-414`). So a persisted config from an
     older/pre-validation binary, a hand-edited config DB, or an
     un-upgraded HA peer pushing `workers -1` over config-sync reaches the
     manager with `cfg.Workers = -1`.
  4. `programBootstrapMapsLocked(snapshot, cfg)` runs on that apply and hits
     line 179 with the **raw** value: `uint32(-1) = 4294967295`;
     `4294967295 * 32 mod 2^32 = 4294967264` (arithmetic confirmed) →
     ~4.29 billion `heartbeatMap.Update` syscalls → apply blocks for
     hours; commit/sync never completes.
- **Why the guard is genuinely absent here (the precise inconsistency):**
  The *same function*, one line above, DOES clamp — `QueueCount:
  uint32(maxInt(cfg.Workers, 1))` (`maps_sync.go:155`), and a sibling site
  uses `maxInt(status.Workers, 1)` (`maps_sync.go:356`). But `Workers:
  uint32(cfg.Workers)` (line 154) and the loop bound (line 179) both use the
  **raw** value. The clamp pattern exists and was simply not applied to the
  loop bound — a real, self-consistent omission, not a hypothetical.
- **Severity reasoning — LOW (agree with review):**
  - It is a **DoS (control-plane apply hang), not fail-open** — no packet
    forwarding bypass; the dataplane never advances to a fail-open state,
    it just stalls the apply. Confirmed via HPC check: does not bypass
    firewall policy.
  - Reachability requires an **authenticated/trusted config source** already
    carrying a negative integer (operator commit history on a pre-gate
    binary, DB tamper, or a broken/old HA peer). Not attacker-injectable
    from the packet path or an unauthenticated channel.
  - It nonetheless **violates the stated lenient-path doctrine** ("WARN,
    don't blackout/hang" — the #1319/#1798/#1960 contract in the
    `compileTreeLenient` comment). A multi-hour BPF-update loop on the
    standby during config-sync apply is exactly the alarm-loop/hang the
    lenient path exists to prevent. That, plus the trivially-fixable
    clamp inconsistency, is why LOW (not INFO/dismiss) is the right rating.
  - Not higher than LOW because it needs a pre-existing malformed trusted
    config and produces a stall (recoverable by fixing the config /
    rolling the peer), not a security-relevant fail-open or memory
    corruption.
- **Fix (as review states, correct):** clamp before the loop, mirroring
  line 155 — `w := maxInt(cfg.Workers, 1)` (optionally cap to a sane
  ceiling) and use `uint32(w)*2*16` at line 179 (and ideally `Workers:
  uint32(w)` at line 154 so the ctrl map never advertises 0/negative
  workers on the lenient path).
- **Dedup:** NOVEL. `gh issue list` search for "workers"/"heartbeat map"
  returns worker-*semantics* issues (#1466, #1733, #2186, #2905, #4002,
  #4265 …) but **none** for this integer-overflow loop / heartbeat
  zero-init DoS. Sibling integer-overflow issues in the review's own dedup
  table (#4526 DHCP renewalTimers, #4525 RA randomAdvInterval) are
  different fields/subsystems. Not covered by any ps-037 A-series or the
  #4517–#4571 merged backlog.

### F-A6-002 — NOT-MATERIAL (unreachable / bounded)
**`TunnelEndpointID uint16` (max 65535) has no explicit cap → >65535 tunnel
endpoints would wrap the ID to 0 ("no tunnel").**

- Symbols verified: `sessionSyncTunnelEndpointIDLocked`
  (`manager_ha.go:1141`), `TunnelEndpointSnapshot` (`protocol.go:434`),
  `TunnelEndpointID uint16` (`protocol.go:1678` etc.),
  `buildTunnelEndpointSnapshots` (`tunnels.go:13`). All present.
- **Disproving bound:** tunnel endpoints are derived from interfaces, which
  are hard-capped at `MaxInterfaces = 256` (`pkg/dataplane/constants.go`,
  mirrors `MAX_INTERFACES`). Max realistic tunnel-endpoint count ≈ 256 —
  **two orders of magnitude below** the u16 ceiling. There is no config
  path that produces 65 536 tunnel endpoints. The review **itself
  concedes** "not reachable in production. No fix required for
  correctness." This is a defense-in-depth observation on an unreachable
  path, not a residual bug. Classified NOT-MATERIAL rather than genuine.
- Note: `protocol.go:1631` documents that tunnel selection on the wire is
  keyed by tunnel **name**, with `TunnelEndpointID` "informational only" for
  the relevant path — further reducing any real blast radius.

### F-A6-003 — NEGATIVE (verified correct)
`defer cancel()` inside the returned `AddressObserver` closure
(`pkg/daemon/daemon_ddns_surface_a.go:337`) is scoped to the closure
invocation, not to `surfaceAObserver` (`:296`). Both cited lines exist
(`:111` and `:337` carry `defer cancel()`). No context/timer accumulation.
Author's negative confirmation is correct.

### F-A6-004 — NEGATIVE (verified correct)
Binding index `uint32(binding.Ifindex)*16 + QueueID` is guarded: `if
binding.Ifindex <= 0 { continue }` (`maps_sync.go:664`) prevents the
negative→u32 wrap, and `idx >= BindingArrayMaxEntries` →
`failClosedUserspaceCtrlLocked` (`maps_sync.go:685-688`, also the
VLAN-alias child path at `:717`). Fail-closed. Confirmed correct.

### F-A6-005 — NEGATIVE (verified correct)
`clampPort` (`nat_static.go:13`) returns 0 (fail-closed "no translation")
for out-of-range; `sourceNATPoolPortRange` (`nat_source.go:406`) validates
`1..65535` and `low<=high` before the `uint16` cast;
`natNeverMatchPortRange{Low:1,High:0}` sentinel preserved. No pre-validation
truncation. Confirmed correct.

### F-A6-006 — NEGATIVE (verified correct)
Event stream bounded: `pendingCallbackFramesLimit = 4096`
(`eventstream.go:19`), enforced at `:638` (drops connection when full);
1024-byte frame cap; atomic u64 counters. No unbounded growth / goroutine
leak. Confirmed correct.

### F-A6-007 — NEGATIVE (verified correct)
Zone IDs widened u8→u16 (#3075) across event-stream wire, `SessionDeltaInfo`,
and `zoneNameByID(zoneID uint16)`. No truncation. Confirmed correct.

### F-A6-008 — NEGATIVE (verified correct)
`FIBGeneration uint32` wraps at 2^32 → cache-miss + re-resolve, no bypass;
`Generation uint64` effectively never wraps. Confirmed correct.

---

## Bottom line
A6 (dataplane Go manager / compilation) has **one novel LOW residual**
(F-A6-001, heartbeat-loop integer-overflow DoS on the lenient/HA-sync path,
genuinely reachable with a real absent-clamp inconsistency) and **one
non-material theoretical note** (F-A6-002, tunnel-ID u16, unreachable under
MaxInterfaces=256). Everything else is an author-confirmed NEGATIVE with the
cited symbols verified present on current master. No confabulation, no dups,
no already-fixed re-reports. Consistent with the A-series pattern (Codex
accurate but low novel yield after the #4517–#4571 backlog).
