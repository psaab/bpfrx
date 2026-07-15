# Triage result — ps-review-037-A5-b1 (A5: HA — cluster, VRRP, RA, conntrack sync)

**Subsystem:** HA — `pkg/cluster/*`, `pkg/vrrp/*`, `pkg/ra/*`, `pkg/conntrack/gc.go`
**Review base:** d4506d4450e23f9a3fc572206b3c82f6b6c99029 (Merge PR #4571)
**Current master:** 463ef8b94edfc6ebec6e46d8267eab806a8c79e4
**base ≈ master?** YES — only delta in scope is the VRRP VRID guard (#4573, `vrrp/manager.go` + `vrrp/vrrp.go` + `vrid_guard_4573_test.go`). None of the A5 findings touch that path, so all findings are effectively against exact current master.
**Cohort:** Codex per-subsystem audit (ps-037 A-series), ~90% genuine, heavily overlapping.

## Outcome counts
| Disposition | Count | Findings |
|---|---|---|
| GENUINE-RESIDUAL (NOVEL) | 3 | A5-02 (MED), A5-03 (LOW), A5-07 (LOW) |
| DUP | 1 | A5-01 → #4549 F9 |
| NOT-MATERIAL | 2 | A5-04, A5-05 |
| DELIBERATE | 1 | A5-06 |
| NEGATIVE | 3 | A5-08, A5-09, A5-10 |

All cited symbols EXIST on origin/master (no confabulations).

---

## A5-01 — heartbeat IPv4-only (udp4) → dual-primary on IPv6 control link — **DUP #4549 F9**

**Verified present.** `pkg/cluster/heartbeat_manager.go:44,50,57,65` hardcode `"udp4"` in
`ResolveUDPAddr`/`ListenPacket` — an IPv6 control-link address cannot form heartbeat.

**Why DUP, not novel:** #4549 (OPEN, LOW batch) **F9** is verbatim this: *"HA heartbeat is
IPv4-only. `pkg/cluster/heartbeat_manager.go:44,50,56,63` hardcode `udp4` … an IPv6 control link
is unsupported."* Same file, same lines, same root cause. The prompt dedup list explicitly names
`#4549 LOW batch (… HA IPv4-only …)` as do-not-re-report.

**On the HIGH severity-upgrade claim (LOW→HIGH):** weak, and does not justify a new issue.
1. Not silent — the caller `daemon_ha_sync.go:937` wraps `StartHeartbeat` in a retry loop that
   logs `"heartbeat bind not ready, retrying"` and finally `slog.Error("cluster heartbeat failed
   after retries")`. An IPv6 control link produces a *visible* boot error, not a silent proceed.
2. The dual-VIP consequence is bounded by VRRP, not the cluster heartbeat: even if both cluster
   RGs promote (never-seen path), VRRP runs on the **RETH data link** (up), and its own
   priority/address tie-break arbitrates a single VIP owner. So "duplicate VIP, ARP conflict" is
   over-stated.
3. IPv6-only HA control links are uncommon (control link is near-universally a direct
   point-to-point IPv4 link on em0/fxp0), which is why #4549 rated it LOW.

**Disposition:** DUP #4549 F9. The severity argument is a note for #4549 prioritization, not a
separate filing.

---

## A5-02 — preempt hold-time: a held lower-priority master that DIES mid-hold blackholes up to holdTime — **GENUINE-RESIDUAL (MEDIUM), NOVEL**

**The finding's PRIMARY described mechanism is REFUTED**, but its FIRST trace identifies a real
gap. Careful separation required:

**Refuted mechanism (the "corrected trace"):** the claim that at the `masterDownTimer` fire, a
strict `Since(lastMasterSeen) > masterDown` check mis-classifies a *dead* master as "live lower"
is WRONG. `handleBackupRx` (instance.go:~831) calls `recordMasterAdvert` FIRST (sets
`lastMasterSeen = time.Now()` at instance.go:1536), THEN resets `masterDownTimer` later in the
same handler. So `lastMasterSeen` is stamped *before* the timer arm point, and Go timers fire
at-or-after their deadline (never early; jitter positive). At a true dead-master fire,
`time.Since(lastMasterSeen)` is therefore strictly **>** `masterDown` → `preemptingLiveLowerMaster()`
(instance.go:723) returns `false` (dead-master path) → immediate `becomeMaster()`. The boundary
concern is dominated by positive timer jitter. No blackhole on a plain dead-master timeout.

**Genuine gap (the finding's FIRST trace — correct):** when a preempt hold-time is armed to defer
preemption of a *live* lower-priority master, `masterDownTimer` is left IDLE for the whole hold,
so a held master that dies mid-hold is not detected until the hold expires:
- `stepBackup` masterDownTimer.C case (instance.go:819-829): on arming, calls
  `armPreemptHold(preemptHoldTimer, hold)` then `return false`. It does **not** re-arm
  `masterDownTimer`. `armPreemptHold` (instance.go:776-782) only touches `preemptHoldTimer`.
- During the hold, the held master (lower priority) keeps sending; `handleBackupRx`'s reset gate
  `if !vi.getPreempt() || int(pkt.Priority) >= pri` is **false** for `preempt && lower`, so
  `masterDownTimer` is never reset — it stays idle (fired-and-drained). Adverts only refresh
  `lastMasterSeen` via `recordMasterAdvert`.
- The only running timer is `preemptHoldTimer`. No watchdog observes the held master's silence.
  When the master dies, nothing fires until `preemptHoldTimer` expires; the preemptHoldTimer.C
  path (instance.go:833-852) then re-runs `shouldPreemptObservedMaster()`, sees a stale
  `lastMasterSeen` → dead → `becomeMaster()`. Takeover delayed by up to the full configured hold.

This VIOLATES the design's own stated invariant (`preemptingLiveLowerMaster` doc, instance.go:715:
*"A genuinely dead master … takeover stays immediate"*). #2900 explicitly enumerated what the hold
does NOT catch (preempt-disabled, track-demote) but omitted the held master DYING — an unhandled case.

**Reachability confirmed:** `preempt hold-time <seconds>` is a real Junos leaf — compiled at
`compiler_interfaces.go:749/849/854` into `vg.PreemptHoldTime`, plumbed to `Instance.PreemptHoldTime`
(instance.go:477), read by `preemptHoldDuration()` (instance.go:702). Default 0 = immediate (no
hold), so this affects only deployments that explicitly set `preempt hold-time`.

**Scenario:** Node A (pri 100, preempt, `preempt hold-time 300`) returns after a reboot; Node B
(pri 90) is the live MASTER owning the RETH VIP and forwarding traffic. A enters BACKUP;
`masterDownTimer` fires (~100 ms — B's lower adverts don't reset it); `preemptingLiveLowerMaster`
is true → A arms the 300 s hold to let routing converge before preempting. B then crashes at, say,
hold-start + 5 s. No timer watches B's silence; A takes over only at hold-start + 300 s → ~295 s
traffic blackhole for a dead master that should fail over in ~100 ms.

**Fix direction:** when arming the preempt hold, also arm a liveness watchdog for the held master —
e.g. re-arm `masterDownTimer` for `masterDownInterval()`; on its fire while `preemptHoldArmed`,
test `lastMasterSeen` staleness: stale (held master dead) → `disarmPreemptHold` + `becomeMaster()`
immediately; fresh (still forwarding) → re-arm the watchdog and continue holding. Restores
"dead master → immediate takeover" without weakening live-master preemption deferral.

**Severity:** MEDIUM. Blackhole up to holdTime (seconds–minutes), but gated on `preempt hold-time`
being configured (non-default) AND the held lower-priority master dying within the hold window.

**Dedup:** NOVEL. #2850 introduced the hold; #2900 added re-validation but not this case. No open
issue covers it.

---

## A5-03 — RA configEqual compares NAT64Prefix (and all CIDR fields) as raw strings → spurious sender restart on non-canonical input — **GENUINE-RESIDUAL (LOW / cosmetic), NOVEL**

**Verified present.** `ra.go:811` `a.NAT64Prefix != b.NAT64Prefix` is a raw-string compare;
`sender.go:806` parses it via `netip.ParsePrefix` for the wire. `configEqual` also raw-string
compares `Prefixes[i].Prefix` (ra.go:~828) — this is the consistent design, not NAT64-specific.

**Assessment:** technically real but near-zero impact. The config *source* string is stable across
commits (the compiler emits the same text for the same config), so churn only occurs if an operator
manually re-types an equivalent-but-different CIDR form (e.g. `64:ff9b::/96` → `0064:ff9b::/96`).
The consequence is one spurious RA sender restart (sub-second RA gap); the wire stays correct
because `buildRA` re-parses to `netip.Prefix`. Codex itself rated it LOW confidence and conceded
"not a correctness bug."

**Fix direction:** normalize CIDR fields via `netip.ParsePrefix` before comparing in `configEqual`
(or store normalized form in `RAInterfaceConfig`). If filed, scope to all CIDR fields, not just NAT64.

**Severity:** LOW / cosmetic. Barely worth a standalone issue; a candidate for a LOW hardening batch.

**Dedup:** NOVEL — distinct from #4570 (ReachableTime/RetransTimer) and the earlier
SourceLinkLocal fix.

---

## A5-04 — heartbeatStartupGrace 30s insufficient when VRF bring-up >30s (preempt RGs dual-primary) — **NOT-MATERIAL**

**Verified present** structurally: the never-seen single-node hold
(`election.go:105-106` and `electSingleNode` at `election.go:383`) is
`!rg.Preempt && !m.peerEverSeen && … StateSecondary && m.controlInterface != ""` — it holds only
NON-preempt RGs; preempt RGs promote at grace expiry. `heartbeatStartupGrace = 30s`
(heartbeat.go:74); `neverSeenConfirmed` (heartbeat.go:845) drives single-node election after grace.

**Why NOT-MATERIAL:**
1. **The 30s grace is a deliberate #4386 heuristic** with ~2x margin over the documented worst-case
   config-apply disruption ("10-15+ seconds", heartbeat.go:58-73). Holding preempt RGs during
   never-seen would break the legitimate single-node deployment (a genuinely-absent peer must
   promote), which is exactly why the design holds only non-preempt.
2. **The concrete reachability premise is flawed.** The finding's example (FRR takes 40s to
   converge with a large RIB) does NOT block the heartbeat receive path — the control-link UDP
   socket listens once the VRF is bound + config apply completes; FRR *RIB convergence* affects
   data routes, not the already-listening control socket. The 30s window covers config-apply
   disruption (VRF bind, RETH MAC down/up), which completes well under 30s.
3. **cluster-RG-primary ≠ VIP owner.** Even if both cluster RGs briefly promote, VRRP runs on the
   RETH data link (up in this scenario) and independently arbitrates a single VIP owner via
   priority/address tie-break. GARP is emitted only by the VRRP master (`becomeMaster`), so a real
   dual-VIP window is bounded by VRRP convergence (~100 ms), not the cluster grace.

**Disposition:** NOT-MATERIAL — deliberate #4386 grace heuristic; flawed reachability premise; VIP
ownership bounded by VRRP. The structural observation (grace is heuristic, preempt RGs not held) is
technically true but does not establish a realistic dual-VIP path.

---

## A5-05 — sync-auth downgrade guard rejects a legitimate peer with transient key-unavailable at boot — **NOT-MATERIAL (premise unreachable)**

**Verified present:** `syncAuthDecision` (sync_auth.go:262-279) rejects `keyConfigured && !peerKeyed
&& peerAuthSeen` with "missing auth handshake"; `syncPeerAuthSeen` (sync_auth.go:143-153) consults
sticky state + `HeartbeatPeerAuthSeen`.

**Why NOT-MATERIAL — the premise (`ControlLinkAuthKey()` returns nil during boot while sync starts)
is unreachable:**
- The PSK is NOT read from a separately-transient `master.key` at sync-handshake time. It is
  plumbed from the **already-decrypted config** via `UpdateConfig` — `group_state.go:68-73`:
  `if k := cfg.ControlLinkAuthKey.Reveal(); k != "" { m.controlAuthKey = []byte(k) }` — and cached.
  `controlLinkAuthKey()` (manager.go:320-323) just returns the cached `m.controlAuthKey`. No
  per-handshake key read exists.
- `cfg.ControlLinkAuthKey` and the sync-start parameters (peer address, control interface) come
  from the SAME decrypted config. If `master.key` is unavailable at boot, the whole `active.json`
  fails to decrypt → the daemon has no cluster config → it never starts the sync stream. So the
  posited state (sync stream started as unkeyed while the peer is keyed) cannot arise from a
  transient key read; it can only arise if the operator actually removed the PSK from config, which
  is a genuine downgrade that the guard is *designed* to reject.
- The rejection is also not permanent: once the key is present and `UpdateConfig` runs, the node
  reconnects keyed (proof exchanged) and is accepted; heartbeat auth (also keyed) flows in parallel.

**Disposition:** NOT-MATERIAL. Disproving file:line — `group_state.go:68-73` (PSK sourced from
decrypted cfg) + `manager.go:320-323` (cached read, no transient master.key path).

---

## A5-06 — VRRP acceptArrivalIfindex fails OPEN when arrival ifindex == 0 (cross-VLAN leak) — **DELIBERATE**

**Verified present:** `acceptArrivalIfindex` (instance.go:1066-1071) returns true when
`arrivalIfindex <= 0 || expectedIfindex <= 0`.

**Why DELIBERATE:** the fail-open is explicitly documented (instance.go:1046-1065): *"arrivalIfindex
== 0 means the platform did not report an arrival interface … we fail OPEN … so we never regress
real delivery on a kernel/socket combination that omits the control message — the VRID/TTL/self-IP
gates still apply."* The receiver *enables* the per-packet interface control message, so
`arrivalIfindex == 0` only occurs on kernels that omit it (rare); the VRID/TTL/self-IP gates remain
in force. Codex itself concedes this is "a LOW residual of #2886, not a new bug." It is a documented,
intentional availability-over-isolation trade-off — part of #2886's design, not a novel defect.

**Disposition:** DELIBERATE (documented). No new filing warranted. If ever revisited, the only
improvement is a warning log when `arrivalIfindex == 0` on a VLAN sub-interface — cosmetic.

---

## A5-07 — GARP burst not paced across many RGs (large-chassis flood) — **GENUINE-RESIDUAL (LOW / speculative), NOVEL**

**Verified present:** `garp.go` — `SendGratuitousARPBurst`/`runARPBurstFollowups` (garp.go:150,233)
pace a *single* RG's burst at 50 ms gaps (garp.go:236-237), count operator-bounded. There is no
inter-RG pacing: on a mass failover, N RGs each fire their own burst concurrently.

**Assessment:** a legitimate scaling observation, but no concrete harm is demonstrated. 100 RGs ×
~4 sub-64-byte GARP frames spread over ~150 ms is far below typical upstream storm-control
thresholds (usually thousands of pps / Mbps of broadcast); the per-RG bursts are already paced and
are the intended neighbor/switch-convergence mechanism; the count is operator config; and 100+ RETH
VRIDs is an extreme chassis. Codex rated it LOW/LOW and framed it as "could cause" — speculative.

**Fix direction (if pursued):** cap aggregate GARP burst rate or add a small inter-RG stagger on a
mass failover.

**Severity:** LOW / speculative. Near-zero materiality; candidate for a LOW batch or fold, not a
priority.

**Dedup:** NOVEL — not previously filed.

---

## A5-08 / A5-09 / A5-10 — NEGATIVE (clean-area confirmations)

- **A5-08** — VRRP checksum (packet.go), IPv6 EH walk, AF_PACKET VLAN filter, RA goodbye ordering.
- **A5-09** — HA election / preempt / dual-active nodeID tie-break / transfer-commit grace.
- **A5-10** — conntrack GC sweep / aging hysteresis / session limit / pnat GC.

Reviewer asserts these areas verified clean; consistent with recent hardening (#4570, #4549 F8/F11,
#3440, #3604). Accepted as NEGATIVE — no action. (Not independently re-derived line-by-line; these
are the reviewer's positive controls, not findings.)

---

## Bottom line
3 NOVEL genuine-residuals — one MEDIUM (A5-02, preempt-hold-time held-master-death blackhole, with
a corrected mechanism vs Codex's write-up), two LOW/cosmetic-speculative (A5-03 RA configEqual CIDR
string-compare, A5-07 GARP inter-RG pacing). A5-01 is a DUP of the OPEN #4549 F9 (its HIGH upgrade
is weak). A5-04/A5-05 refuted as NOT-MATERIAL (deliberate #4386 grace + VRRP-bounded VIP;
unreachable transient-key premise). A5-06 is a documented DELIBERATE fail-open. A5-08/09/10 negative.
