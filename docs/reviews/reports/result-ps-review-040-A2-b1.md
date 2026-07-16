# Triage Result — ps-review-040-A2-b1

- **Subsystem:** A2 batch 1 — NAT/CGNAT userspace fast-path
  (`userspace-dp/src/nat/allocator.rs`, `userspace-dp/src/nat/destination.rs`)
- **Base == master?** Mixed. `destination.rs` findings (2,3) cite current-master
  line numbers (base ≈ master for that file). `allocator.rs` finding (1) cites
  PRE-#2852 symbols that no longer exist — the reviewer read a stale allocator
  snapshot (predates the #2852 Phase-1 lock-free rewrite, PR #4648, on master).
- **Master SHA:** 95b33d49634d56086269a62a92e213dae7926f88
- **Repo:** real bpfrx (`/home/ps/git/bpfrx`) — no avacado-xpf fork citations.
- **Outcome counts:** 3 findings → 0 GENUINE-RESIDUAL, 1 ALREADY-FIXED
  (+ NOT-MATERIAL residual), 2 NOT-MATERIAL (1 also DELIBERATE, 1 confabulated-behavior).

---

## Finding 1 — "Unbounded recycled port queue scan + dup accumulation under GLOBAL mutex" (allocator.rs, claimed HIGH)
**Disposition: ALREADY-FIXED (base drift + #2852 Phase-1 rewrite); residual NOT-MATERIAL.**

WHY:
- The cited code (lines 528-545) and its symbols — `recycled_ports_by_addr[addr_index]`,
  `assign_owner_locked`, `owner_by_translated`, `claim_free_port_locked`,
  `next_port_offset_by_addr`, `release_translated_locked` — **do not exist on
  current origin/master.** `git show origin/master:.../allocator.rs` + grep return
  nothing for those names; the file header (lines 1-16, 279-283) documents them
  explicitly as the **"pre-#2852"** design that was removed.
- **The HIGH-severity driver is refuted.** The finding's core claim is
  "throughout this scan the GLOBAL Mutex on `PortAllocatorLiveState` is held,
  blocking all other worker threads." On master the recycle drain lives in
  `AddressOccupancy::claim()` (lines 384-401) and is called from
  `allocate_translation` at **line 729 (`occ.claim()`) — BEFORE** the global
  `self.shared.live.lock()` at line 736. `claim()` takes only the **per-ADDRESS**
  `recycle: Mutex<VecDeque<u16>>` (struct field, lines 286/305), documented at
  header lines 34-45 as "never the global allocator mutex … the recycle mutex is
  innermost." Port ownership itself is a lock-free atomic-bitmap CAS
  (`claim_offset`, `fetch_or`, lines 322-333). So no global lock is held during
  the scan; cross-worker contention on other pool addresses is impossible.
  This was delivered by commit 6cbb10615 (#2852 Phase 1) — squarely inside the
  #4517-#4685 hardening range noted in the task context.
- **"Duplicate accumulation" is refuted.** `free_recycle` (lines 415-425) pushes
  a port back ONLY on a real 1→0 bit transition (`free_offset` gate); `claim`
  pops a port before setting its bit; the retain-on-collision path re-queues
  popped occupied ports (net-zero count). The set bit is the sole ownership
  token, so a port cannot be double-pushed. The reviewer's cited
  `release_translated_locked` "inserts unconditionally" no longer exists.
- **Residual (NOT-MATERIAL):** the recycled phase is still an O(range) loop
  when a pool address is genuinely exhausted AND every recycled port collided
  with an out-of-band occupant (persistent lease / HA-synced install seeded via
  `reserve`). But it is (a) bounded by `range` (≤ ~64K, cursor can't exceed
  range, queue can't exceed range), (b) under the per-address recycle mutex only,
  (c) reached only in the exhausted/degraded state, and (d) the retain-not-discard
  is a DELIBERATE, code-commented tradeoff (062-10: "a transient collision cannot
  permanently shrink the reusable pool"). Not the HIGH-severity global-contention
  bug described. A scan-budget is a possible micro-opt, not a material defect.

---

## Finding 2 — "DNAT rule shadowing / precedence reversal via `*existing = entry`" (destination.rs:914-955, claimed MEDIUM)
**Disposition: NOT-MATERIAL (DELIBERATE, heavily-hardened dedup).**

WHY:
- Symbol EXISTS on master (`insert_entry`, line 914; `*existing = entry;` line 951;
  sibling `insert_prefix_slot`, line 875). So not confabulated.
- The overwrite is **intentional dedup**, not a bug, and is documented across
  five hardening PRs in the surrounding comments: #2394 (dedup on zone + source
  constraint), #3096 (interface/RI scope in key), #3437 (source-port + ICMP
  type/code in key), #3449 (dst-port range in key), #3844 (off-vs-translate kept
  distinct). The `.find()` predicate compares **all 11 match dimensions**
  (`from_zone`, `from_interface`, `from_routing_instance`, `source_constrained`,
  `source_v4`, `source_v6`, `match_src_ports`, `match_dst_ports`,
  `match_icmp_type`, `match_icmp_code`, `off`). It collapses ONLY rules that are
  byte-identical in every match dimension — i.e. rules that are indistinguishable
  at match time. No rule that *should* remain distinct is dropped.
- The **only** observable divergence is which VALUE (translation target) wins
  when a config has two rules identical in all 11 match fields but different pools.
  That is a degenerate misconfiguration: in Junos the later such rule is
  unreachable (shadowed by first-match), so it is already an operator error, not a
  realistic parity-critical scenario. Blast radius is one shadowed rule's pool
  choice, not unmatched traffic.
- The reviewer's proposed fix ("remove the overwrite, append all, match in config
  order") would **REGRESS** the deliberate dedup #2394/#3096/#3437/#3449/#3844
  built — appending byte-identical entries reintroduces the double-fire /
  double-count-hit-counter class those PRs closed. Not GENUINE; the dedup note's
  AGY-134-01 static-NAT reference is a different table but the behavior here is
  intended, not the same latent bug.

---

## Finding 3 — "Missing proxy-ARP for /31 (net.hosts() empty) → blackhole" (destination.rs:1032-1042, claimed MEDIUM)
**Disposition: NOT-MATERIAL (confabulated crate behavior; disproven by source).**

WHY:
- Code EXISTS (`destination_ips_scoped`, line 1007; the v4 `net.hosts()` loop,
  lines 1033-1044). So the anchor is real.
- **The central factual premise is WRONG.** The finding asserts "in the `ipnet`
  crate, `Ipv4Net::hosts()` … for a `/31` subnet returns an empty iterator."
  The vendored ipnet **2.12.0** (Cargo.lock) source
  (`.../ipnet-2.12.0/src/ipnet.rs:847-857`) is:
  ```rust
  pub fn hosts(&self) -> Ipv4AddrRange {
      let mut start = self.network();
      let mut end = self.broadcast();
      if self.prefix_len < 31 {           // ← ONLY excludes below /31
          start = start.saturating_add(1);
          end   = end.saturating_sub(1);
      }
      Ipv4AddrRange::new(start, end)
  }
  ```
  For `/31`, `prefix_len < 31` is FALSE (RFC 3021 point-to-point), so it returns
  the **full range** = BOTH `192.0.2.0` and `192.0.2.1`. Not empty. The reviewer
  is describing pre-RFC-3021 / a different crate version.
- **Even if it were empty, no blackhole:** `slot.network()` (line 246 →
  `p.addr()`) is pushed at line 1030 **unconditionally, for every prefix size**,
  so the network base `192.0.2.0` is always registered regardless of the
  `hosts()` expansion.
- For `/30`, `hosts()` does exclude network+broadcast (returns 2 usable hosts),
  but the base is covered by the `slot.network()` push, leaving only the subnet
  *broadcast* unregistered — a non-scenario (no one configures DNAT VIPs onto a
  subnet broadcast). The IPv6 arm uses `Ipv6Net::hosts()` = full
  `network()..broadcast()` range (ipnet.rs:1231, no exclusion), so no v6 gap.
- Refuted; the proposed `net.iter()` change is unnecessary.

---

## Summary
0 genuine residuals. Finding 1 = fixed by #2852 Phase-1 lock-free allocator
(reviewer read a stale pre-#2852 file); Finding 2 = deliberate, hardened dedup
whose "fix" would regress five PRs; Finding 3 = misreads ipnet 2.12.0 /31
handling (RFC 3021) and ignores the unconditional network-base registration.
Consistent with the expectation that this heavily-hardened NAT scope yields ~0
residuals.
