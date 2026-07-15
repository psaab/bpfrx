# opus-review-171 — Wide Coverage Campaign (dataplane depth)

**Reviewer:** opus (Opus 4.8). **Mode:** coverage campaign per
`fable-do-review-audit.txt` — breadth of coverage, ≥20 non-duplicate
findings if credible, honesty rule for a smaller documented count.
**Directive:** go deep, go wide, find NEW things, don't duplicate prior
findings. Deliberately targets the domains NOT deep-swept by the recent
fable-16x/17x campaigns (which covered day-0, CoS, vSRX-parity, reth,
drop-in, core-firewall): **screen/IDS, NAT dataplane, session/conntrack,
AF_XDP forwarding core, HA/VRRP/session-sync, IPsec/DHCP/flowexport
runtime.**

## 1. Base commit reviewed

`f1c298e0f` — "Merge pull request #4371 from psaab/fix/4082-fabric-up-select"
(tip of `origin/master`). Reviewed via a detached read-only worktree.

Protocol-mandated `git pull --rebase`: could not run — the primary
checkout carries a pre-existing unmerged `_Log.md` conflict, unchanged
across campaigns 165–171. Reviewed against a detached worktree of
`origin/master` (current code, no repo mutation).

## 2. Output path

`/tmp/opus-review-171.md` (whoami=opus; joins the highest existing
campaign number, 171).

## 3. Duplicate suppression summary

Dedup baseline: all `/tmp/{fable,codex,agy}-review-*.md` (≈180 files
across ~17 campaigns), the wide-domain issue history, and
`docs/feature-gaps.md`. Per-domain suppression lists were embedded in each
reviewer's brief; a dedicated dedup pass cross-checks. Key suppressed
clusters by domain are recorded in §5 and per-finding dedup notes.

## 4. Domain checklist

| # | Domain | Module | Status |
|---|--------|--------|--------|
| 1 | Screen / IDS | `userspace-dp/src/screen/*` | agent SC-* |
| 2 | NAT dataplane | `userspace-dp/src/nat/*`, nat64, nptv6 | agent NA-* + §5 indep |
| 3 | Session / conntrack | `userspace-dp/src/session/*`, `pkg/conntrack` | agent SE-* |
| 4 | AF_XDP forwarding core | `afxdp/{forwarding,checksum,gre,icmp*,frame}`, tcp_flags | agent FC-* |
| 5 | HA / VRRP / sync | `pkg/cluster`, `pkg/vrrp`, fabric | agent HA-* |
| 6 | IPsec / DHCP / flowexport | `pkg/{ipsec,dhcp,dhcpserver,flowexport}`, WG | agent IO-* |

Confidence tiers: **High** = verified in source this run (top items
re-verified line-by-line by the coordinator); **Medium** = likely defect
needing runtime confirmation; **Low** = smell / parity nuance.

## 5. Module-by-module inspection log

Independent coordinator inspection (three agent-uncovered surfaces, all
clean): **hot_hash_seed** (#2364 per-boot getrandom DoS-resistance seed) —
verified applied at every attacker-key hasher (session table via
`FxSeededState`, flow cache `set_index_seeded`, ECMP, worker); remaining
`FxHashMap::default()` uses are keyed by internal handles (RG id, zone id,
slot), not tuples — no residual hole. **NAT port allocator** — leak-aware
(#3047, paired lease-expiry indexes). **state_writer** — crash-safe
temp+rename+fsync, pid+start_time liveness; not attacker-facing.

Six domain reviewers swept screen/IDS, NAT, session/conntrack, forwarding
core, HA/VRRP/sync, IPsec/DHCP/flowexport; a dedicated dedup pass
cross-checked every candidate against ≈180 prior-review files. The
forwarding-core mutation kernels (checksums, MSS clamp, GRE, ICMP embed/
PTB, NAT64 header xlate, VLAN, IPv6 ext-header walks) and the HA
session-sync serialization/generation-guard/election machinery came back
**verified-correct** (§9) — the novel findings sit at state-lifecycle and
config-transition edges, not in the steady-state fast path.

Two agent candidates were dropped as duplicates on dedup: DHCPv6
valid-lifetime-0 (= fable-161 **F-264**) and NAT64 v6→v4 zero-checksum UDP
fragment (= fable-161 **F-240**). One folded as a citation (v4→v6
fragmented-ICMP checksum, same class as **F-238**). The session agent also
confirmed **F16/M-1** (half-open promotion) is now FIXED (promotion
requires a genuine reverse SYN-ACK at all three sites).

## 6. Findings — HIGH

### H-1 · `limit-session` per-IP cap is bypassed for a warm-up window after the feature is enabled on a live box

- **Severity:** High (security control silently ineffective) · **Confidence:** High
- **Domain:** session/conntrack
- **Evidence:** `userspace-dp/src/session/mod.rs:731-763` — `session_limit_inc`
  runs only if `session_limit_active` is true *at install*; `session_limit_dec`
  (the sole removal sink, `mod.rs:1586-1588`) decrements for any counted-class
  entry whenever active, with **no per-entry record of whether it was counted**.
  `set_session_limit_active` (`mod.rs:698-704`) clears the maps on ON→OFF but
  does nothing on OFF→ON; the README calls not-back-counting "benign."
- **Trace:** (1) `limit-session` disabled; source X has 50 live sessions,
  none counted. (2) operator enables it → maps empty, the 50 stay uncounted
  in the table. (3) new session C from X → `count[X]=1`. (4) a pre-existing
  X session tears down → `session_limit_dec` → `count[X]: 1→0→evicted`. (5)
  `count[X]` is 0 though C is live → X can open a full fresh allotment. The
  cap is bypassed by up to the churn of pre-existing flows — exactly when
  the operator first turns the control on for a busy box. `saturating_sub`
  hides it (no panic).
- **Why it matters:** re-opens the DoS/limit bypass that #2128/#3122/#2134
  exist to prevent, and the "benign" comment is wrong for the decrement side.
- **Fix direction:** add a `counted: bool` to `SessionEntry` set at the
  increment site; decrement only when set (clear with the maps on disable).
  Or rebuild both count maps by walking counted-class entries on the OFF→ON
  edge.
- **Labels:** security-control, session-limit, dos, bug
- **Dedup note:** distinct from #2128 (phantom-zero), #3122 (peer-synced
  origin count), #2134 (feature), agy-132/133. The enable-transition
  decrement asymmetry is unreported and contradicts the documented "benign"
  assumption.

### H-2 · VRRP dual-stack equal-priority tie-break is family-split → both nodes step down → permanent no-master flap

- **Severity:** High (total RG outage via master oscillation) · **Confidence:**
  Medium (needs dual-stack + equal priority + disagreeing v4/v6 orderings —
  the default on cold boot)
- **Domain:** HA / VRRP
- **Evidence:** `pkg/vrrp/instance.go:1585-1602` — the RFC 5798 §6.4.3 equal-
  priority tie-break compares a **v4** advert against `getLocalIP()` (lowest
  v4) but a **v6** advert against `getLocalIPv6()` (link-local, EUI-64/random).
  A dual-stack instance sends BOTH adverts (`:1673-1788`), from two unrelated
  source addresses; `CollectRethInstances` defaults priority 100 on both
  nodes until weights differ (`vrrp.go:118`).
- **Trace:** Node A v4 `10.0.0.10` (higher) / LL `fe80::a` (lower); Node B v4
  `10.0.0.5` (lower) / LL `fe80::b` (higher). Both briefly MASTER on
  simultaneous boot. A hears B's **v6** advert → `fe80::b > fe80::a` → A steps
  down. B hears A's **v4** advert → `10.0.0.10 > 10.0.0.5` → B steps down.
  Both BACKUP → both masterDownTimers expire → both MASTER → same split →
  permanent flap, no stable master. Secondary bug: unresolved `localIP==nil`
  at equal priority leaves the node MASTER (treats "unresolved" as "we win").
- **Fix direction:** one family-consistent comparison regardless of the
  arriving advert's family (compare the v4 primary when the instance has any
  v4 VIP; link-local only for v6-only instances), or per-family state machines.
- **Labels:** ha, vrrp, split-brain, rfc5798, bug
- **Dedup note:** distinct from F-076 (masterDownInterval operand), F-077
  (accept-data), F-054 (GARP .1), F10/L-4 (checksum pseudo-header), F22
  (owner reclaim), fable-167 I-1 (auth). The equal-priority *address*
  tie-break being family-split is unreported.

### H-3 · Cold-boot split-brain: the "peer never seen" path promotes after 500 ms while the "peer was seen" path has a 30 s grace

- **Severity:** High (dual-primary / GARP storm on simultaneous boot) ·
  **Confidence:** Medium (window real; reach depends on control-link taking
  >500 ms to pass traffic — which the 30 s-grace comment asserts happens)
- **Domain:** HA / cluster
- **Evidence:** `pkg/cluster/heartbeat.go:727-748` — the `lastNano == 0`
  branch calls `handlePeerNeverSeen()` after only `threshold*interval`
  (5×100 ms = 500 ms) then `continue`s, so the 30 s config-apply grace at
  `:746` is unreachable when the peer was never seen. `handlePeerNeverSeen`
  (`heartbeat_manager.go:429`) sets `peerEverSeen=true` + `electSingleNode`;
  `election.go:325` gates the readiness check on `&& m.peerAlive`, so a
  never-seen node skips readiness and promotes on `Weight>0`.
- **Trace:** both chassis power on together; config apply (FRR reload, fabric
  creation, RETH MAC down/up) disrupts the control-link RX for 10-15 s (the
  exact reason the 30 s grace exists), so first heartbeats drop and
  `lastSeen` stays 0 on both. At T0+500 ms both hit `handlePeerNeverSeen` →
  both StatePrimary → both claim the RETH virtual MAC + GARP → 10-15 s
  split-brain until the link recovers and dual-active resolution demotes one.
- **Fix direction:** apply a startup floor (≥ the ~15 s config-apply
  disruption, ideally 30 s) to the never-seen path before it may promote;
  steady-state `threshold*interval` is right for a *lost* peer, too aggressive
  for deciding a peer *never existed* at boot.
- **Labels:** ha, cluster, split-brain, cold-boot, bug
- **Dedup note:** cluster-manager heartbeat layer; distinct from VRRP F-054
  and the heartbeat items F-168/F-202/agy-147-02.

### H-4 · `commit confirmed` timer is not cancelled on RG0 demotion → the rollback fires on the new standby → config divergence

- **Severity:** High (silent config-divergence surfacing at the next failover)
  · **Confidence:** Medium-High
- **Domain:** HA / commit-confirmed
- **Evidence:** `pkg/daemon/daemon_ha.go:349-351` — the RG0
  `StateSecondary`/`StateSecondaryHold` branch only calls
  `SetClusterReadOnly(true)`; it never cancels the armed confirm timer.
  `executeConfirmedRollback`/`PromoteRollback` bypass the read-only gate
  (`store_commit.go` #3893), so read-only doesn't protect the standby. The
  #3861 mitigation (`clearPendingConfirmLocked`) fires only in `SyncApply`
  (received config) and plain `Commit` — a clean failover produces neither on
  the demoted node.
- **Trace:** A (RG0 primary) runs `commit confirmed 10` → C2, arms a 10-min
  timer, syncs C2 to B. A monitor-weight drop flips roles: B→primary,
  A→secondary (read-only, timer still armed). B's become-primary path doesn't
  re-push config and there's no periodic reconciliation, so A never receives
  a sync. 10 min later A's timer fires → reverts A's store + dataplane to C1;
  the #3868 re-sync no-ops because A is secondary. Result: primary B=C2,
  standby A=C1 — divergence surfacing on the next failover to A.
- **Fix direction:** on the RG0 demotion transition, treat the pending window
  as confirmed (`ConfirmCommit()`, ignore "none pending") — the cluster's
  active is now the primary's C2. Symmetric to #3861 but triggered on the
  demotion event, not a subsequent sync.
- **Labels:** ha, commit-confirmed, config-divergence, bug
- **Dedup note:** distinct from F-012/F-047/F-150/F-156/F-211 and M-2 (single-
  node timer/ordering) and F-048 (clusterReadOnly). #3861 is closest prior
  art and covers only the received-sync path.

## 7. Findings — MEDIUM

### M-1 · Slow-scan detection evasion: the scan/sweep tracker cleanup floor (1 s) reaps state for operator-configured windows > 1 s that the compiler accepts

- **Severity:** Medium (fail-open / detection-evasion) · **Confidence:**
  Medium-High
- **Domain:** screen/IDS
- **Evidence:** `screen/scan.rs:120-128,354-374` — `cleanup` expires any
  per-source entry with `now - start >= CLEANUP_WINDOW_MICROS` (a hardcoded
  1 s floor), not the per-zone window. `compiler_security_screen.go:135-140`
  only WARNS (`outOfRange`, advisory) on a window beyond the 1 s Junos max
  and passes it to the dataplane unclamped.
- **Trace:** operator sets `ip ip-sweep threshold 30000000` (30 s; warned,
  accepted). A slow sweeper touches distinct destinations over ~25 s toward
  `SCAN_DETECT_COUNT=10`. At the next ≥30 s cleanup tick (inside almost every
  30 s window), `now - start ≥ 1 s` evicts the partial distinct-destination
  set; the next probe recreates a count-1 entry. The count never reaches 10 →
  ip-sweep/port-scan never fires. No test covers a window > 1 s (they use 1 s,
  where the floor coincides).
- **Fix direction:** make cleanup window-aware (track per-zone `window_micros`
  / a per-zone max), or have Go hard-clamp the window to the 1 s max instead
  of advisory-only. (Raising the constant unbounds memory — wrong.)
- **Labels:** screen, scan-sweep, fail-open, detection-evasion, bug
- **Dedup note:** distinct from #4114 (count-vs-window semantics) and F11
  (threshold value). The cleanup-floor-vs-configurable-window mismatch is
  unreported.

### M-2 · Forward/reverse session halves have independent idle timers → an asymmetric flow reaps one half and forwards on a stale companion (NAT-remap on resumption)

- **Severity:** Medium (state divergence from Junos single-session semantics)
  · **Confidence:** Medium
- **Domain:** session/conntrack
- **Evidence:** `session/lookup.rs:192` gates companion propagation behind
  `propagate.close || propagate.established` only — no idle propagation;
  `account_packet` (`mod.rs:949-983`) folds counters onto the forward entry
  but does not re-stamp `last_seen_ns`; idle expiry removes exactly one key
  (`expire.rs:269`).
- **Trace:** UDP one-way media: client sends one packet → forward + reverse
  companion installed at `now`. Server streams back; every reply keys the
  reverse entry (touches only it). The forward entry idle-reaps at 60 s. Now
  replies keep forwarding via the reverse entry with no live forward session
  (no policy re-eval, forward Close already synced to the peer); if the client
  later sends, it's a MISS → a new forward+reverse pair, possibly with a
  different SNAT port colliding with the still-live old reverse entry.
- **Fix direction:** fold both directions' activity onto a shared `last_seen`,
  or on idle reap of one half propagate a short-window/removal to the companion
  the way close (#4109) does.
- **Labels:** session, dual-entry, stale-forwarding, nat, bug
- **Dedup note:** sibling of fable-163 F17 (which covers FIN/RST close
  propagation); the plain-idle-timeout companion gap is uncovered. Not #2387
  (key omits VLAN/zone/VRF).

### M-3 · Fabric-redirect NAT is applied on a session *hit* but not a *miss* — a demoted owner double-NATs an in-flight redirected flow

- **Severity:** Medium (broken/double NAT across the failback window the fabric
  path exists to protect) · **Confidence:** Medium (receiver-side
  fabric-ingress re-NAT not fully traced)
- **Domain:** HA / fabric
- **Evidence:** `poll_descriptor/mod.rs:957` sets `apply_nat_on_fabric = true`
  on every session hit; the new-flow miss redirect keeps `:778` default
  `false`. `frame/rewrite/mod.rs:82`: `apply_nat = !fabric_redirect ||
  apply_nat_on_fabric`. `session_glue/commands/demote_owner_rgs.rs:57-65`
  builds the demote alias with `..decision`, preserving the original NAT while
  flipping disposition to FabricRedirect.
- **Trace:** A owns a NATed session; VRRP demotes A→B. An in-flight packet
  (network not yet re-homed) hits A's alias → hit → `apply_nat_on_fabric=true`
  → A NATs then redirects the already-translated frame to B. The miss contract
  has the *receiver* NAT; if B re-runs NAT lookup on the translated tuple it
  misses its owner session → re-NAT or drop.
- **Fix direction:** make the fabric-redirect NAT contract single and
  hit/miss-independent (redirector always NATs + receiver pure-egresses, or
  redirector never NATs). Add a `test-failover` variant driving a NATed flow
  across the exact demotion instant.
- **Labels:** ha, fabric, nat, failover, bug
- **Dedup note:** distinct from #4082/#4090 (dual-fabric selection) and F-081
  (redirect pins fabrics[0]); this is the NAT-application asymmetry across the
  demote alias.

### M-4 · NAT64 performs no port/ICMP-identifier translation — v6 clients sharing a pool v4 collide on the reverse tuple (RFC 6146 BIB absent)

- **Severity:** Low-Medium (correctness/availability, input-dependent) ·
  **Confidence:** Medium
- **Domain:** NAT / NAT64
- **Evidence:** `nat64.rs` `forward_decision` returns `rewrite_src_port: None`
  / `rewrite_dst_port: None`; `allocate_v4_source` is bare round-robin over
  `pool_v4` (`pool_index.fetch_add`) with no `(addr, id/port)` uniqueness. The
  source is a real multi-address pool (`pool_v4: Vec<Ipv4Addr>`, "IPv4 source
  pool addresses for SNAT").
- **Trace:** two v6 hosts A and B ping the same v4 server through a
  single-address pool (or a multi-address pool where round-robin lands both on
  one `snat_v4`). Neither the ICMP echo Identifier nor a TCP/UDP source port
  is translated → the reverse key `(server → snat_v4, id/sport)` is identical
  for both flows → the second install collides and replies are mis-associated
  — the exact class #4074/#4088 fixed for *pool SNAT*, with no NAT64 analog.
- **Fix direction:** allocate NAT64 sources through a flow-keyed allocator
  guaranteeing `(snat_v4, id/port)` uniqueness (translating the id/port like
  pool-SNAT `allocate_translation`), or document/enforce a 1:1-sized pool.
- **Labels:** nat64, pat, rfc6146, reverse-collision, bug
- **Dedup note:** #4074/#4088 and F-186/F9 are the *pool-SNAT* id fix; NAT64
  is a distinct translator with no equivalent. Not #2358 (NAT46) or agy-134-03
  (frag cache).

## 8. Findings — LOW

### L-1 · Per-source SYN-flood count-min sketch uses compile-time constant seeds, not the per-boot `hot_hash_seed` — targeted false-positive throttling

- **Severity:** Low · **Confidence:** Medium · **Domain:** screen/IDS
- `screen/syn_rate.rs:108-160` — `ROW_SEEDS` are public compile-time constants
  (golden-ratio words) + `FxHasher`; the sketch does NOT fold in the #2364
  per-boot `hot_hash_seed` that the session table / flow cache / ECMP all use.
  An attacker can precompute spoofed source IPs colliding a chosen legit
  source's 4 cells (over-count is fail-closed → can't hide a flood, but can
  false-positive-throttle a targeted source in the non-cookie regime). The
  module doc's collision-resistance claim holds only via the aggregate cap.
- **Fix:** derive the row seeds from the per-worker SYN-cookie master key (or
  the hot_hash_seed), or use the in-tree SipHash for the sketch index.
- **Dedup note:** distinct from F-248 (hot_hash_seed getrandom fallback
  downgrade) and agy-151-02 (ip-sweep collision, different sketch). Novel; it
  is the one attacker-key hasher the #2364 mitigation skips.

### L-2 · DHCPv6 IA_NA parse keeps only the last-enumerated address (multi-address / multi-IA reply)

- **Severity:** Low · **Confidence:** High · **Domain:** DHCP
- `pkg/dhcp/dhcp.go:1392-1404` — the nested loop over every `OptIANA`/
  `OptIAAddress` overwrites `addr`/`validLT` each iteration, so the installed
  address is whichever IAADDR enumerated last, with that address's lifetime
  used for the whole lease. Order-dependent; could pick a deprecated address
  over a preferred one.
- **Fix:** prefer the first address with the longest preferred-lifetime, or
  document single-address support and pick deterministically.
- **Dedup note:** distinct from F-264 (valid-lifetime-0) and F-218 (renewal
  timers). Novel.

### L-3 · Dead-but-wrong incremental TCP checksum in the segmentation path (latent corruption landmine)

- **Severity:** Low (currently unreachable; would be High corruption if a
  refactor flips the gate) · **Confidence:** High · **Domain:** forwarding core
- `afxdp/frame/tcp_segmentation.rs:266-322` — the `enforced_ports.is_none()`
  branch adjusts the copied ORIGINAL TCP checksum only for NAT src/dst/port,
  not for the per-segment payload chunk, rewritten seq, cleared PSH, or changed
  pseudo-header length — wrong for every real segment. It is currently dead
  (`enforced_ports = expected_ports.or(live_frame_ports_from_meta_bytes(...))`
  is always `Some` for a valid segmentable TCP frame, so the correct
  full-recompute `else` always runs), but the guarding comment claims the
  branch is "the common fabric case," inviting a refactor that makes it live
  silent corruption on every NAT'd/tunneled oversized TCP flow.
- **Fix:** delete the incremental branch (incremental-from-original is never
  valid per-segment), or fix the comment and assert unreachability.
- **Dedup note:** novel; not in the forwarding-core corpus.

### L-4 · IPsec SA sync never pushes the empty set → administratively-downed tunnels resurrected on failover

- **Severity:** Low · **Confidence:** Medium · **Domain:** HA / IPsec
- `pkg/daemon/daemon_ha.go:1306-1313` — `if len(names) > 0 { QueueIPsecSA(names) }`;
  the receiver overwrites wholesale. Once the primary's active set drops to
  zero it stops advertising, so the standby keeps the last non-empty snapshot
  and `reinitiateIPsecSAs` re-establishes downed tunnels on takeover.
- **Fix:** push the empty set too (the DHCP-lease codec already distinguishes
  "serve none").
- **Dedup note:** novel; distinct from the IPsec-SA-sync correctness set (which
  covers wire codec, not the empty-set edge).

### L-5 · NAT64 first-fragment ICMP (v4→v6) leaves the ICMPv6 checksum zeroed → invalid packet (same class as F-238, opposite direction)

- **Severity:** Low · **Confidence:** Medium · **Domain:** NAT / NAT64
- `nat64.rs` `write_v4_to_v6_into` (~1123-1138): for `is_fragment` only
  TCP/UDP trigger the incremental adjust; ICMP is skipped, but
  `translate_icmpv4_message_to_icmpv6` zeroed the checksum for the caller to
  recompute — which never happens for a fragment → invalid ICMPv6 checksum on
  a first fragment (offset 0, MF=1). Fix: drop fragmented ICMP at the NAT64
  boundary (can't be checksummed from one fragment), consistent with the
  zero-checksum-UDP-fragment drop.
- **Dedup note:** the same fragmented-ICMP-should-be-dropped thesis as
  fable-161 **F-238** (which is the v6→v4 direction) — cited, folded as the
  v4→v6 sibling, not claimed as an independent finding.

## 9. Negative results (verified correct — the coverage the honesty rule requires)

Recorded because a clean sweep of a heavily-reviewed area is a load-bearing
result:

- **Forwarding-core mutation kernels:** RFC 1624 incremental checksums
  (scalar + AVX2 bit-identical), TCP MSS clamp (bounded option walk, SYN-only,
  non-first-frag gated), GRE encap/decap (RFC 6040 ECN, DF, checksum region),
  ICMP embedded-packet NAT reversal + PTB/local-error generation (quote caps,
  MTU floors, source suppression), NAT64 header/DF/fragment translation, VLAN
  push/pop, IPv6 ext-header walks (all four bounded, fail-closed at the cap) —
  no OOB, no corruption, no wrong-mutation found.
- **HA session-sync + election:** v4/v6 serialization offsets exact + length-
  gated, 16 MB frame cap, hostile DHCP-lease-count clamp; clock-offset before
  bulk; generation guards refuse older installs / record greater tombstones;
  dual-active resolution and tie-breaks symmetric/deterministic; RETH virtual
  MAC includes node-id (no L2 collision); fabric has no redirect loop / wrong-
  chassis / MTU expansion; heartbeat loss detection conservative; #4107
  auth/anti-replay sound.
- **NAT:** SNAT allocate↔release key reconstruction leak-free across SNAT /
  DNAT+SNAT / NPTv6+SNAT compositions; port allocator FIFO-recycle + lease-
  expiry indexes balanced, cursor can't wrap; static-NAT reverse tuple + port
  un-translation bidirectionally symmetric; NPTv6 checksum-neutral corner;
  NativeEndian/BE byte-order consistent.
- **IPsec/WireGuard/DHCP/NetFlow (runtime):** swanctl crypto rendering (AEAD
  PRF, AH-not-as-ESP, injection-sanitized TS/id/secret), WireGuard RFC 6479
  anti-replay + roaming + handshake TAI64N-after-AEAD, NetFlow v9/IPFIX record
  sizing/sequence/byte-order, DHCP relay reply-source allow-list + hop-count-
  before-increment + giaddr binding, DHCPv4 degenerate-mask reject — all clean.
- **Coordinator infra:** hot_hash_seed applied at every attacker-key hasher;
  NAT allocator leak-aware; state_writer crash-safe.

## 10. Suggested issue split

1. **[bug][security][session-limit] Per-IP cap bypassed after enable** — H-1.
2. **[bug][ha][vrrp] Dual-stack equal-priority family-split tie-break →
   permanent no-master flap** — H-2.
3. **[bug][ha][cluster] Cold-boot 500 ms never-seen promotion vs 30 s grace →
   split-brain** — H-3.
4. **[bug][ha] commit-confirmed timer survives RG0 demotion → divergence** — H-4.
5. **[bug][screen] Scan/sweep cleanup floor vs accepted >1 s window →
   slow-scan evasion** — M-1.
6. **[bug][session] Forward/reverse independent idle timers → stale companion
   + NAT remap** — M-2.
7. **[bug][ha][fabric] Fabric-redirect NAT hit/miss asymmetry double-NATs a
   demoted flow** — M-3.
8. **[bug][nat64] No PAT/BIB → pool-shared v4 reverse-tuple collision** — M-4.
9. **[bug][screen] SYN sketch uses constant seeds, not hot_hash_seed** — L-1;
   plus the fold/cleanup batch (L-2 DHCPv6 multi-address, L-3 dead segmentation
   checksum, L-4 IPsec empty-set, L-5 NAT64 frag ICMP).

## 11. Campaign summary

- **13 novel findings** (4 High, 4 Medium, 5 Low), each source-verified and
  dedup-checked against ≈180 prior-review files across ~17 campaigns. Two
  agent candidates were dropped as duplicates (F-264, F-240) and one folded as
  a citation (F-238) — the discipline the "don't duplicate" directive demands.
- **The novel risk clusters at state-lifecycle and config-transition edges,
  not the fast path:** a security control (`limit-session`) that under-counts
  the moment it's enabled (H-1); three HA failure-mode gaps that surface on
  boot or role change (H-2 family-split VRRP flap, H-3 cold-boot split-brain,
  H-4 confirm-timer-survives-demotion); and a screen detection-evasion the
  compiler's accept-with-warning enables (M-1).
- **The steady-state fast path is verified correct** (§9): forwarding-core
  packet mutation, HA session-sync serialization/election, the NAT allocator +
  checksum machinery, and the IPsec/WireGuard/DHCP/NetFlow runtime all came
  back clean under adversarial reading — a load-bearing negative result for a
  codebase this heavily reviewed.
- Count is honest, not padded to 20: a wide sweep of six densely-covered
  domains yielded 13 genuinely-novel candidates after filtering, plus the
  documented negatives (§9) that prove the coverage behind that number.
  (Highest-priority *still-open prior* regressions worth pairing with this
  work, cited not re-counted: WG TAI64N anti-replay disarmed on config change
  (fable-163 F5 / #4092), NAT64 #2405 fix unmerged (F-131), fabric fragment-
  hash split (F-252 / #2357).)
