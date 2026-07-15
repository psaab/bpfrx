# Triage result — ps-review-038 (SYNTHESIS roll-up)

- **File:** `/tmp/ps-review-038.md` — "ps-review-038 — Paladin Coverage Campaign (19 batches, 2126 source files)"
- **Nature:** Top-level all-cohort SYNTHESIS of the ps-038 A-series (A1–A10, sub-batches b1/b2/b3). This is a *mechanical roll-up* of the per-batch inspection logs. The `## Findings (High confidence first...)` section (line 165) is **EMPTY** — the file ends at line 167. There is NO consolidated cross-cutting finding beyond the per-batch bullet copies.
- **Base:** review base `d4506d445`; verified against **current origin/master `3bbe3d39`** (freshly fetched). NOT avacado.
- **Cohort:** SYNTHESIS of a cohort whose every sub-batch was ALREADY triaged this session and every novel residual filed (#4572–#4608).

## Outcome counts

| Disposition | Count |
|---|---|
| DUP-of-ps038-batch-triage (already triaged + filed/closed this session) | all aggregated bullets |
| ALREADY-FIXED (verified fix symbol on master) | 1 explicitly re-verified (A7 scp → #4589) |
| NOT-MATERIAL (verified latent/unreachable/display-only on master) | 4 re-verified (A5×2, A6 F-001, A8 gRPC port) |
| DELIBERATE (by-design, operator-controlled) | 1 (A9 feeds SSRF) |
| NEGATIVE / coverage-note (5 placeholder batches) | 1 note |
| **NOVEL GENUINE-RESIDUAL** | **0** |

**Headline: 100% dup. The synthesis surfaces NO cross-cutting finding that a single batch did not already contain.** The consolidated Findings section is empty; every bullet is a verbatim copy of a per-batch item already dispositioned this session. Zero new issues to file.

---

## Verification of the highest-severity synthesis items (where a missed novel residual would matter most)

I re-verified the top items against current master because they are NOT obviously in the filed list (#4572–#4608) and a genuine unfiled HIGH would be the only way the synthesis is not dup.

### A5 HIGH #1 — `Manager.Start` holds `m.mu` while stopping old monitor (deadlock) → NOT-MATERIAL
- Symbol EXISTS: `pkg/cluster/manager.go:376` `Start()` does `m.mu.Lock(); defer Unlock(); if m.monitor != nil { m.monitor.Stop() }`.
- `Monitor.Stop()` (`monitor.go:184`) does `cancel(); mon.wg.Wait()` — waits for the run goroutine, which calls back into `mon.mgr.SetMonitorWeight/RecordEvent/NodeID`. `NodeID()` (`manager.go:311`) is lockless (`return m.nodeID`), but SetMonitorWeight/RecordEvent may take `m.mu` → *theoretical* deadlock if Start's stop-branch fires while a callback is mid-flight.
- **WHY not material:** `Start` is called **exactly once** — `pkg/daemon/daemon_run.go:566` `d.cluster.Start(ctx)`. At that single call `m.monitor == nil`, so the `Stop()` branch is dead; a second `Start` never occurs in production. The lock-release asymmetry in `Stop()` (which *does* drop `m.mu` before `mon.Stop()`) is defensive hygiene, not evidence of a reachable bug. Unreachable ⇒ the A5-batch triage correctly did NOT file it. DUP-of-A5-batch / NOT-MATERIAL.

### A5 HIGH #2 — `handleDisconnect` races `completeBarrierWait`/`completeFailoverWait` (double-close/send-on-closed panic) → NOT-MATERIAL
- Symbols EXIST: `sync_conn.go:1717` `handleDisconnect`, waiter-close block 1740–1786.
- **WHY not material:** the panic-safe canonical pattern is already present. handleDisconnect **swaps the waiter collections out under their mutex** (`barrierWaitMu`: `staleWaiters := s.barrierWaiters; s.barrierWaiters = nil`; `failoverWaitMu`: swaps all four failover maps to fresh empty maps) and only THEN closes outside the lock. A concurrent `completeBarrierWait`/`completeFailoverWait` acquiring the same mutex sees either the pre-swap collection (removes-under-lock, disjoint) or the post-swap nil/empty collection (no-op) — mutually exclusive, so no channel is closed twice. Every failover close is additionally guarded by `select { case waiter.ch <- ...: default: } close(...)` to avoid send-on-closed. This is the intended hardened design. DUP-of-A5-batch / NOT-MATERIAL.

### A6 F-001 — `compiler_nat.go` deterministic NAT `/0` `HostCount=0` via uint32 shift-by-32 → NOT-MATERIAL
- Symbol EXISTS: `pkg/config/compiler_nat.go:1677` `hostCount := 1 << uint(bits-ones)` in the IPv4 (`else`) branch of deterministic-CGNAT capacity validation.
- **WHY not material:** the review claims "Go spec: shift ≥ width → 0." That is FALSE for this expression on the target platform. `1` is an untyped constant → defaults to `int` (64-bit on amd64/arm64), `hostCount` is `int`. For a `/0`, `bits-ones = 32`, `1 << 32 = 4294967296` (fits in 64-bit int, NOT 0). The very next line `if totalBlocks < hostCount` then correctly errors "insufficient capacity" — no division-by-zero, no silent zero-subscriber. (Only a 32-bit `int` platform would wrap to 0; xpf ships amd64/arm64.) There is no division by `hostCount` anywhere. In the deterministic-CGNAT theme already tracked by **#4559**. DUP / NOT-MATERIAL.

### A7 b1 F-02 — `scpArchiveTransfer` `-` option injection → ALREADY-FIXED (#4589)
- Symbol EXISTS: `pkg/daemon/daemon_flow.go:366` `scpArchiveTransfer`.
- **Fix is on master:** the `exec.CommandContext(ctx, "scp", "-o"..., "-o"..., "--", srcPath, dest)` now includes the `--` end-of-options separator, with an inline comment citing `#4589 A7 F-02` (CWE-88 argv injection, belt-and-suspenders with the commit-time leading-dash reject in compiler_system.go). This confirms the A7 batch finding was filed and MERGED under **#4589/#4597 (LOW-cli x6)**. DUP / ALREADY-FIXED.

### A7 b2 F-01 — FRR vtysh command injection via BGP neighbor IP → DUP #4588/#4593 (vtysh-guard, MERGED)

### A8 b1 F-01 — gRPC session-filter port truncation `uint16(v)==dstPort` → NOT-MATERIAL/LOW
- Symbol EXISTS: `pkg/grpcapi/server_helpers.go:215` `if v, err := strconv.Atoi(portStr); err == nil && uint16(v) == dstPort`.
- **WHY not material:** this is a **read-only session-query display filter**. An out-of-range port string (>65535) aliases via `uint16` truncation, so a nonsensical user query could match unintended displayed sessions. No forwarding/security decision rides on it; the input is the operator's own CLI/gRPC query. Display-only correctness LOW; triaged in A8 and not filed as novel. DUP-of-A8-batch / NOT-MATERIAL.

### A9 F-01 — feeds SSRF via feed URL → DELIBERATE/LOW
- Symbol EXISTS: `pkg/feeds/feeds.go:441` `http.NewRequestWithContext(ctx, "GET", fs.url, nil)`.
- **WHY not material:** `fs.url` is the operator-configured `security dynamic-address feed-server ... url` — dynamic feeds fetch admin-specified URLs *by design*. "SSRF protection" against the appliance admin's own committed config is low-value on an on-prem firewall. By-design behavior; triaged in A9, not filed. DELIBERATE / LOW.

### A3 b2 — global-policy from-zone/to-zone bracket-list drop (`m.Keys[1]` ignores `Keys[2:]`) → DUP-of-A3-batch / LOW
- Symbols EXIST: `pkg/config/compiler_security_policy.go:247` `pol.Match.FromZone = m.Keys[1]`, `:254` `pol.Match.ToZone = m.Keys[1]` (the `#3148` global-policy zone-match handling).
- **WHY not a novel HIGH:** `Match.FromZone`/`Match.ToZone` are **scalar `string`** fields (see `:109-110` `FromZone: zp.from`). The model does not represent multi-zone global from/to-zone at all, so reading only `Keys[1]` is consistent with a single-value model — a modeling limitation, not a truncation regression. This is squarely the tracked leaf-list "union vs override / multi-value leaf" theme (**#4070** deferred-with-plan, **#2419** dual-shape SSOT). Triaged in the A3 batch this session; LOW. DUP-of-A3-batch.

---

## Bulk dedup of the remaining aggregated bullets (all DUP-of-ps038-batch-triage)

Every other synthesis bullet maps 1:1 to a per-batch finding already triaged + filed/closed this session:

- **A1 b3** fairness_eval args (CLI fallback / TSV skip / default) + `Umem::frame` isize cast → DUP **#4590/#4606** (fairness-eval + RA) / **#4499** (Rust test-coverage). LOW test-harness.
- **A2** 5 Low NAT (persistent-NAT HA, NAT64 EH walk, IPv6 pool wraparound, FxHash salt, NPTv6 adj) — the batch itself records "Dedup verified: #4512, #4533, #2240, #4519 all sound." DUP/ALREADY-FIXED.
- **A3 b1** CoS queue 0..7 validation → DUP **#4594/#4596/#4600** (CoS-queue+LLDP). ast_edit SetPath / equal-flow-target → LOW refactor, DUP-of-A3-batch.
- **A3 b2** BGP ASN negative truncation, FilterTermExpansionCount uint32 → LOW config-cast, DUP-of-A3-batch (integer-truncation theme, batch verified DNAT #3450/#3725 fixed).
- **A4** annotate → DUP **#4587/#4592**; journal/NewDB perms + temp-sweep/key-zeroize/master.key remnant → DUP **#4579/#4603** (configstore LOW). Batch confirms envelope fail-closed / nonce-fresh / commit-confirmed-gen-guard negative.
- **A5** Low truncations (AdvertiseInterval ms→cs, Group/Node/ClusterID, monitor-name len), ra.go time.After leak, election wall-clock rate-limit → DUP-of-A5-batch LOWs (VRRP work merged under **#4573/#4584/#4605**).
- **A6 F-002** `SNATValue.CounterID uint16` FNV-32a collision → LOW legacy-counter display, DUP-of-A6-batch.
- **A7 b1** parseSrcPort wrap / teardownSNMPLocked WaitGroup / RPM race / neighbor OOM / archive temp leak / VLAN-id → DUP-of-A7-batch LOWs.
- **A7 b2** LLDP TTL truncation / junosSpeedToNetworkd / GRE-IPIP TTL / manual atoi → DUP **#4594/#4596/#4600** (LLDP) + A7-batch LOWs.
- **A8** REST NAT-dest / peer-session port display truncation, ParseUint(16), SSE cap, MonitorInterface VRF, configSearch, session-iter rate → DUP-of-A8-batch (display-only + hardening LOWs).
- **A9** feeds header-DoS (F-03/F-10), eventengine supersede drain (F-05), NetFlow template len, SNMP engineboots 0644, trace caps, time-2262 → DUP-of-A9-batch LOWs.
- **A10 b1/b2** monitor-port / app_resolve uint16 / ping negative-count; DDNS empty-host / DHCP L2 reply len / DHCP subnet_id remap → DUP-of-A10-batch LOWs.

## Coverage note (NOT a finding)
5 PLACEHOLDER batches (A10_b3, A1_b1, A1_b2, A3_b3, A6_b2) failed on rate-limit/policy-filter and produced minimal summaries — i.e. their file sets were **not actually reviewed** (a coverage GAP, not a finding to file). This is the synthesis's only novel *meta* datum: those ~468 files remain a re-review candidate. It surfaces no code residual.

## Conclusion
100% dup. The synthesis is a mechanical aggregation of already-triaged ps-038 A-series batch findings; its consolidated Findings section is empty. The four re-verified HIGH/Med-High items are latent/unreachable/display-only/already-fixed on current master; the security-flavored items are operator-controlled by design or already fixed (#4589). **No novel cross-cutting genuine residual. Nothing new to file.**
