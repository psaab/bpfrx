# Triage result — ps-review-030 (Cohort 7: Forwarding core)

## Header

- **Review**: xpf deep audit Cohort 7 — Forwarding core (`poll_descriptor/`,
  `poll_stages.rs`, `forward_request.rs`, `forwarding/`, `frame/`,
  `flow_cache.rs`, `userspace-xdp/src/lib.rs`).
- **Review base**: `b1bd96fb6` (merge PR #4531). **FRESH** — ≈ current master.
- **Triaged against**: `origin/master` = **`af5b739308d548e4fb542fdff634a871b936ac35`**
  (fetched this run).
- **Real bpfrx or avacado fork?**: **REAL bpfrx.** Every cited symbol exists on
  current master (`FlowCacheLookup::for_packet`, `SessionKey`, `MAX_EXT_HDRS`,
  `MAX_IPV6_EXT_HEADERS`, `parse_l4`, `reap_expired_sessions`). No confabulation.
  This cohort did NOT hit the ps-021 avacado-fork failure mode.
- **Outcome counts** (5 actionable findings + 1 refuted prior + 8 review-negatives):
  - GENUINE-RESIDUAL: **1** (M-02, Low/Informational perf parity)
  - ALREADY-FIXED: **1** (N-01 → #3776, present even at review base)
  - DUP (tracked OPEN): **2** (V-01 → #2387; L-01 → #2387 VLAN facet)
  - NOT-MATERIAL: **1** (L-02, cosmetic; no behavioral harm)
  - Prior-finding refutations verified correct: H-01 (=#2387), H-02 (NEGATIVE),
    M-01 (=M-02), plus review Negatives N-01..N-08 — all confirmed.

Method note: weight-verified HARD per skill. The single Medium "new" finding
(N-01) turned out to be a re-discovery of an ALREADY-SHIPPED, tested fix — the
review looked in the wrong place (`SessionTable` GC internals) and missed the
worker-level reap handler. This is exactly the "misread of a hardened path"
false-positive the triage discipline guards against.

---

## Per-finding dispositions

### [V-01] Flow-cache + session VLAN/VRF confusion → **DUP #2387** (OPEN, tracked)

- **Symbol check**: PASS. `flow_cache.rs:161-174` `FlowCacheLookup::for_packet`
  sets `ingress_ifindex: meta.ingress_ifindex as i32` (raw physical parent).
  The stored `FlowCacheEntry` (flow_cache.rs ~476) also uses
  `ingress_ifindex: meta.ingress_ifindex as i32`. `set_index_seeded`
  (flow_cache.rs:769-780) hashes `key` + physical `ingress_ifindex`.
  `session/key.rs:10-17` `SessionKey` = bare 5-tuple (addr_family, protocol,
  src/dst ip, src/dst port) — no ifindex/VLAN/zone/VRF. All as the review states.
- **Note the near-miss**: `from_forward_decision` DOES call
  `resolve_ingress_logical_ifindex` (flow_cache.rs:405-410) — but only to look up
  DSCP/per-packet-L4 filter state; the value is NOT used for the cache key or
  the stored entry (both keep raw `meta.ingress_ifindex`). So the review's claim
  survives this potential rebuttal — the logical resolution exists but does not
  reach the identity.
- **Disposition**: DUP #2387 — the issue is titled *"session/flow identity is the
  bare 5-tuple — omits logical ingress (VLAN/zone/VRF), cross-context session
  reuse"*, state OPEN, label `plan-deferred-operator`. The review itself says
  "this IS #2387, verified still present." Confirmed still present on
  `af5b73930`. No new issue — tracked.
- **Severity reconcile (review said Medium-High, fail-open)**: Concur it is a
  genuine fail-open (cross-context PERMIT/NAT reuse), but the exploit precondition
  is narrow: two logical subifs on the *same physical parent NIC*, overlapping
  address space so the attacker's spoofed src is routable in both zones, AND the
  attacker knowing a victim 5-tuple recently permitted on the sibling VLAN, AND
  that flow being cacheable (established-TCP-ACK/UDP + ForwardCandidate). It is a
  structural isolation gap for overlapping-subnet multi-tenant, not a remote
  one-packet bypass — which is why #2387 is `plan-deferred-operator` (identity
  redesign needs an operator-visible model decision), not a hotfix. Not lower
  because it defeats a zone boundary; not higher because of the same-parent +
  known-tuple + cacheable-decision preconditions.

### [N-01] Flow-cache NAT-port stale reuse → reverse collision → **ALREADY-FIXED #3776**

- **Symbol check**: PASS (symbols real), but the **claim is refuted** on current
  master AND at the review's own base.
- **The review's disproving premise**: N-01's refutation says *"Checked if session
  GC also invalidates flow cache: No, `SessionTable` GC does not touch
  `FlowCache`. GC is per-worker, flow cache is per-binding, no linkage."* This is
  the **wrong review-step** — it inspected `SessionTable` internals and never
  looked at the worker-level GC teardown handler.
- **Disproving code path**: `userspace-dp/src/afxdp/worker/loop_body/mod.rs`,
  `reap_expired_sessions` (fn at :1338, called from the GC sweep at :713-727 via
  `sessions.expire_stale_entries_ha(...)`). For EVERY reaped session, one loop
  iteration (:1347-1379) does BOTH:
  - `release_source_nat_allocation(...)` — frees the SNAT port, AND
  - `for binding in bindings.iter_mut() { binding.flow.flow_cache.invalidate_slot(&expired_entry.key, binding.ifindex) }`
    — drops the backing flow-cache slot on every binding.
  Because both happen in the same iteration, **there is no window where the
  flow-cache descriptor survives after its NAT port is released** — the precise
  window N-01 requires does not exist.
- **Provenance**: the fix is #3776 (issue CLOSED, title *"flow-cache: session
  expiry/removal does not invalidate the cache — stale-descriptor forward +
  released-SNAT reuse after the owning session is gone (incomplete #2220
  closure)"*), commit `fc6cab371`. The doc comment (:1302-1322) narrates N-01's
  exact scenario ("a SNAT port that `release_source_nat_allocation` may already
  have handed to a different flow (NAT-port reuse / reverse-path collision)")
  and the two regression tests `reaped_session_flow_cache_slot_is_invalidated`
  and `reaped_snat_descriptor_is_not_reused` (:1432+) pin it.
- **Timing**: `invalidate_slot` appears 4× in `worker/loop_body/mod.rs` at the
  review base `b1bd96fb6` — so the fix was already merged in the very commit the
  review audited. This is a straight miss, not a "fixed-post-base" case.
- **Also-covered secondary paths**: RST teardown independently evicts the slot
  (`worker/lifecycle.rs:230-235`, "Evict from flow cache so stale entries aren't
  used after RST"), and the #2220 keepalive (`touch_if_stale` on every cache hit,
  flow_cache_hit.rs:292) prevents an actively-forwarding flow from being reaped
  out from under a live entry. Belt and suspenders.
- **Severity reconcile (review said Medium)**: N/A — refuted. Had it been live,
  the review over-stated "connection hijack": replies map via the reverse NAT
  index to the *legitimate* new owner (Flow C), so no data leaks to the attacker;
  the realistic harm would have been blind forward-direction injection into a
  colliding flow (RST/data needing seq-window guessing) — Low-to-Medium at most.
  Moot given #3776.

### [M-02] XDP `MAX_EXT_HDRS=6` vs userspace `MAX_IPV6_EXT_HEADERS=8` → **GENUINE-RESIDUAL (Low / Informational, perf parity)**

- **Symbol check**: PASS. `userspace-xdp/src/lib.rs:33` `const MAX_EXT_HDRS = 6`;
  `frame/inspect.rs:31` `MAX_IPV6_EXT_HEADERS = 8`. Real divergence, no existing
  tracking issue (searched — empty).
- **Fail-closed, no bypass (confirmed)**: XDP `parse_ipv6` (lib.rs:1257-1289) walks
  ≤6 EH; on the bound it exits with `protocol` = the last EH type and calls
  `parse_l4`. For an EH next-header, `parse_l4`'s default arm
  (`_ => Some((l4_offset, 0, 0, 0, 0))`, lib.rs:1527) yields proto=EH, ports 0 →
  the session lookup key can never match a userspace-installed session (those are
  only TCP/UDP/ICMP) → **XSK redirect to userspace**, which walks 8 and enforces
  full policy. Divergence direction is fewer-in-XDP, so it fails toward MORE
  evaluation (userspace), never a kernel PASS. No zone/policy bypass — the review
  is correct.
- **Why Low/Informational (review said Low)**: the only real effect is that an
  *established* flow whose packets carry 7+ EH never benefits from the XDP session
  fast path (every packet redirects to userspace). Real traffic carries 0-2 EH;
  7+ is essentially synthetic. The review's "DoS amplification" framing is weak:
  new-flow packets already all go to userspace regardless of EH count, so a flood
  of 7-EH *new* packets is no worse than a flood of 0-EH new packets. Genuine
  parity gap, real code, untracked → file as Low (or fold into the parity/
  test-coverage backlog #4422). Not zero (real 6≠8 divergence) but not Medium
  (no security impact, negligible perf surface).
- **Distinct from #4517**: #4517 = userspace walkers terminating at unenumerated
  EH *types* (MOBILITY 135 / HIP 139 / Shim6 140 / exp 253-254), fixed post-base
  in `aea5919cf`. M-02 = walk *count* (6 vs 8) with the standard enumeration
  {0,43,60,51,44,59}. The XDP shim also still lacks the #4517 type additions — a
  related XDP-side parity item, same Low class.

### [L-01] Cross-VLAN flow-cache eviction DoS → **DUP #2387 (VLAN facet) / NOT-MATERIAL beyond it**

- **Symbol check**: PASS. `set_index_seeded` (flow_cache.rs:769-780) hashes the
  key + physical `ingress_ifindex`; two VLAN subifs on one parent share the set
  space. Per-boot `hot_path_hash_seed()` blocks offline set precomputation.
- **Disposition**: DUP #2387 for the VLAN-specific angle — #2387's fix (put
  logical ingress into flow-cache identity) also partitions VLAN subifs into
  distinct sets, removing the *cross-VLAN* eviction vector. The residual
  ("attacker on same interface floods 4096 flows to evict a victim's set") is
  **NOT-MATERIAL as a distinct bug**: it is inherent to any bounded set-associative
  cache, and eviction only downgrades the victim to the *correct* slow path
  (session lookup + policy) — traffic is still forwarded correctly, just without
  the perf optimization. No fail-open, no drop. A shared 4096-entry perf cache
  degrading to its authoritative backing store under load is by-design, not a
  security defect.
- **Severity reconcile (review said Low)**: concur Low, and further: the VLAN
  framing adds no exploitability over "any co-tenant on the same interface can
  churn the shared cache." Tracked via #2387's identity fix; no separate issue.

### [L-02] XDP non-first IPv6 fragment stamps garbage ports → **NOT-MATERIAL (Informational, cosmetic)**

- **Symbol check**: PASS. XDP `parse_ipv6` `NEXTHDR_FRAGMENT` arm (lib.rs:1281-1284)
  sets `protocol = frag[0]; offset += 8` and does NOT test the fragment offset, so
  a non-first fragment's payload bytes are handed to `parse_l4` as if a header.
- **No harm (confirmed)**: for a non-first fragment, `parse_l4` either fails the
  length/`data_offset<20` guards (→ None → drop) or yields garbage ports → the
  XDP session lookup misses → XSK redirect → userspace. Userspace
  `frame_is_non_first_fragment` → `parse_session_flow_from_bytes` returns None →
  **flowless** (ports 0, `l4_present=false`, port-bearing terms fail closed).
  Crucially, non-first fragments were NEVER going to have an XDP fast-path session
  (they are flowless by construction), so the "garbage ports force a miss" outcome
  IS the correct outcome — the miss routes them to exactly the flowless userspace
  path they belong in. No behavioral difference, no perf regression versus the
  ideal, no bypass.
- **Severity reconcile (review said Informational)**: concur — this is a
  cosmetic/robustness nicety (XDP could set ports 0 explicitly), not an
  actionable defect. NOT-MATERIAL.

---

## Prior-finding + review-negative verification (all confirmed correct)

- **H-01** (prompt) = **V-01** above = **#2387**, still present. Correct.
- **H-02 tiny-fragment port evasion — NEGATIVE (refutation correct)**: XDP
  `parse_l4` TCP (lib.rs:1490-1504) reads 14 bytes (→ None if truncated), requires
  `data_offset >= 20`, then reads the full `data_offset` header (→ None if
  truncated). Tiny first-fragment TCP is dropped, not admitted. Non-first
  fragments go flowless in userspace. No bypass. Refutation verified.
- **M-01** (prompt) = **M-02** above. Correct downgrade to Low (perf, not bypass).
- **Review Negatives N-01..N-08** (tiny-frag / EH-6v8 / config-gen invalidation /
  DSCP-per-packet-L4 decline / neighbor-MAC epoch TOCTOU #3918 / NAT-family
  fail-closed #963 / checksum RFC1624+8200 / QinQ-to-kernel): spot-checked the
  load-bearing ones (parse_l4 guards, `_ => break` EH bound, `should_cache`
  gate, `invalidate_slot` on reap) — all consistent with the code. QinQ single-tag
  is a documented intentional gap, not a bug. No mislabeled negative found.

## Bottom line

No new driveable security bug in this cohort. One Low/Informational perf-parity
residual (M-02, XDP EH walk 6 vs 8) is genuine and untracked. The one "new
Medium" (N-01) is a re-discovery of the already-shipped #3776 fix — the review
inspected `SessionTable` GC and missed the worker `reap_expired_sessions`
handler that co-locates SNAT release with flow-cache invalidation. V-01/L-01 are
the known, tracked #2387 identity gap.
