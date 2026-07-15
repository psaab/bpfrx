# Triage Result — ps-review-036-cohort6.md (Session / Conntrack RE-AUDIT)

- **Cohort**: 6 — Session / conntrack (userspace-dp)
- **Review base**: `33b891d11` (2026-07-07). **Current master**: `0b4109522`.
- **Base freshness**: base is 3 commits behind master. The delta
  (`33b891d11..0b4109522`) is #4548/#4549 (VRRP hop-limit/interval-clamp,
  cluster dup-node-id) + #4512 (nat64 HA cross-node pool-port reservation). It
  touches `session_glue/commands/{delete,upsert}_synced.rs`, `nat/source.rs`,
  `nat64.rs`, `pkg/vrrp`, `pkg/cluster` — **NONE** of `session/install.rs`,
  `session/key.rs`, `tcp_flags.rs`, `session_timeout_ns`,
  `afxdp/flow_cache.rs` reap/invalidate, or `should_cache_local_delivery`.
  → **The "3 commits behind" caveat is benign for cohort 6.** Every finding is
  equally (in)valid on current master; no stale-base false-open or false-close.
- **Confabulation check**: PASS. Every cited symbol and line predicate was
  confirmed via `git show origin/master:<path>`. Unlike the avacado-sourced
  ps-029 sibling caveat, this review's line refs and predicates are ACCURATE
  (install.rs:158 exact; tcp_flags predicates exact; session_timeout_ns exact;
  should_cache at forwarding/mod.rs:1741; reap invalidate_slot at
  loop_body/mod.rs:1377). No confabulated symbols.
- **Outcome counts**: 0 NOVEL genuine-residual · 2 DUP(#2387, OPEN-tracked) ·
  2 ALREADY-FIXED(#3776, #4539/#4553) · 2 DUP-of-ps029-S002 + DELIBERATE(#3152)
  · 17 NEGATIVE (coverage-proof). **No new filing warranted.**

---

## Per-finding dispositions

### C-01 — Bare 5-tuple SessionKey → cross-zone/VRF/VLAN hijack → **DUP #2387 (OPEN, tracked)**

- **Symbol verified**: `session/key.rs` `SessionKey { addr_family, protocol,
  src_ip, dst_ip, src_port, dst_port }` on master — bare 5-tuple, no
  zone/VRF/VLAN/logical-ingress. Confirmed present.
- **Disposition**: DUP of **#2387** (OPEN: "userspace-dp: session/flow identity
  is the bare 5-tuple — omits logical ingress (VLAN/zone/VRF), cross-context
  session reuse"). The review itself correctly labels it "CONFIRMED STILL
  PRESENT — #2387 OPEN, not re-filed (coverage proof)."
- **Why**: This is the same P0 fail-open ps-029 dispositioned as C-01/S-001 →
  #2387, and the prompt lists #2387 as the OPEN needs-decision tracker. The
  root symbol is unchanged on master. Correct to NOT re-file. The finding is
  genuine (real fail-open surface) but already tracked — no action.
- **Severity note (for the tracker, not a re-file)**: High/fail-open is the
  right rating — cross-context reuse of an ALLOW verdict is a real policy
  bypass in multi-tenant VRF/overlapping-subnet deployments. Bounded by:
  requires overlapping 5-tuples across two contexts sharing a physical parent
  ifindex; the flow-cache `set_index` includes physical ifindex (so isolation
  survives across *different* physical NICs, only collides across VLAN units of
  the *same* parent). This bounding is exactly why #2387 stays P0-needs-decision
  (SessionKey widening is a slab/index-wide change) rather than a quick fix.

### C-02 — Flow-cache session expiry does not invalidate cache → **ALREADY-FIXED #3776**

- **Symbol verified**: `reap_expired_sessions` at
  `afxdp/worker/loop_body/mod.rs:1338`, with
  `binding.flow.flow_cache.invalidate_slot(&expired_entry.key, binding.ifindex)`
  at **line 1377** on master. Tests present in the same file (the review's
  "reaped_session_flow_cache_slot_is_invalidated" narrative matches the
  test-comment blocks at 1440/1583).
- **Disposition**: ALREADY-FIXED. **#3776 CLOSED** (confirmed via `gh issue
  view 3776` → CLOSED: "flow-cache: session expiry/removal does not invalidate
  the cache … incomplete #2220 closure").
- **Why**: The GC reap path now invalidates every flow-cache slot backing every
  expired session on every binding. Next packet on the same 5-tuple after idle
  timeout MISSES the cache and re-runs full session lookup + policy + fresh NAT
  allocation. The review correctly marks it FIXED (severity N/A). No residual.

### C-03 — should_cache_local_delivery caches non-handshake TCP first packet → **ALREADY-FIXED #4539 / PR #4553 (= ps-029 M-02)**

- **Symbol verified**: `should_cache_local_delivery_session_on_miss` at
  `afxdp/forwarding/mod.rs:1741` on master. Body gates on a single positive
  `has_syn` predicate; the in-code comment explicitly cites "#4539
  (gate-consistency hardening; subsumes #2151 + #4487)" and describes the exact
  pure-PSH/null/URG residual the review names.
- **Disposition**: ALREADY-FIXED. **#4539 CLOSED** ("ps-029 M-02, LOW"), fixed
  by PR **#4553** per the prompt's dedup list; the review cites commit
  `5e66d37`. Non-TCP always caches; TCP caches only off the handshake; declined
  packets still reach the host via LocalDelivery reinject (not dropped).
- **Why**: This IS ps-029's M-02 finding, already merged. The review's own
  cross-check correctly notes this fix is scoped to the **LocalDelivery
  host-inbound cache gate** and does NOT change the **transit** ESTABLISHED-300s
  behavior — which feeds directly into the NEW-01 analysis below. No residual on
  the LocalDelivery path.

### C-04 — VLAN cross-VLAN flow-cache / session reuse → **DUP #2387 (OPEN, tracked)**

- **Symbol verified**: same `SessionKey` bare 5-tuple + flow-cache `set_index`
  keyed by physical parent ifindex (VLAN units share a parent ifindex).
- **Disposition**: DUP of **#2387** — the VLAN-specific surface of the same
  bare-5-tuple root as C-01. The review correctly says "same root as C-01 /
  #2387 OPEN … not re-filed as new."
- **Why**: No independent code path; it is C-01 restricted to the
  same-parent-different-VLAN case. Tracked under #2387. No separate action.

### C-05 — Bare ACK 300s DoS → **DUP ps-029 S-002 + DELIBERATE #3152 (subsumed by NEW-01 framing)**

- **Disposition**: DUP of ps-029 **S-002** (which ps-029 dispositioned as
  **documented-intentional #3152 mid-stream pickup**). The review explicitly
  folds C-05 into NEW-01 ("Do not file S-002 separately — NEW-01 covers it").
- **Why**: See NEW-01 — the bare-ACK case is one flag-variant of the same
  deliberate non-SYN→ESTABLISHED behavior. Not novel. No action.

### NEW-01 — Non-SYN TCP first packet (bare ACK / PSH+ACK / pure PSH / null / URG) → ESTABLISHED 300s "15× DoS amplification" → **DUP ps-029 S-002/M-01 + DELIBERATE #3152 + PROPOSED-FIX-REGRESSES**

This is the review's headline "NEW filing" claim. It is **NOT a novel genuine
residual.** Three independent grounds, each disproving:

1. **DUP of ps-029 S-002 + M-01.** Per the prompt, ps-029 dispositioned
   C-02/S-002 (bare ACK 300s) as **documented-intentional #3152 mid-stream
   pickup**, and M-01 (PSH+ACK) as **dup of S-002**. NEW-01 is *exactly* the
   union bare-ACK + PSH+ACK + pure-PSH + null + URG. The "15× amplification" and
   "concrete 437-pps" numbers are new *rhetoric*, not new *code* — the
   underlying install predicate and timeout table are byte-identical to what
   ps-029 evaluated. `/tmp/all_findings.txt` and `gh issue list` contain no
   separate filing because ps-029 concluded it is deliberate, not a bug.

2. **DELIBERATE — the install site carries an explicit #3152 comment.**
   `session/install.rs:150-158` on master:
   ```rust
   // #3152: a TCP session created by a bare SYN (SYN set, ACK
   // clear) starts OPENING (`established=false`); every other
   // first packet (non-TCP, or a TCP mid-stream pickup such as a
   // SYN-ACK or data segment) starts ESTABLISHED, preserving the
   // pre-#3152 full-established-timeout behaviour.
   established: !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
   ```
   `#3152` (CLOSED) was *itself* a DoS-hardening fix — its title is "bare-SYN
   sessions get the full tcp_established_ns … enabling low-rate half-open table
   exhaustion." The fix deliberately gave the short OPENING window to **bare SYN
   only**, and deliberately **kept non-SYN at the full established timeout**
   because a non-SYN first packet is a mid-stream pickup of an
   **already-established** connection (handshake happened before the firewall
   saw the flow — restart, asymmetric routing). ESTABLISHED/300s is the
   *semantically correct* verdict for that packet, not a bug.

3. **The proposed fix would REGRESS the deliberate #3152 feature.** NEW-01
   proposes `established = !TCP || is_syn_ack(tcp_flags)`, i.e. force every
   non-SYN first packet onto the 20s OPENING window. That is precisely the
   pre-#3152 behavior #3152 *deliberately preserved for non-SYN*: a genuine
   long-lived idle connection picked up mid-stream (BGP keepalive, SSH,
   DB pools) would be reaped after 20s idle and torn down. The proposed cure is
   worse than the "disease" for the exact scenario mid-stream pickup exists to
   support.

**Is the underlying DoS concern real at all?** Partially, but generic and
already-mitigated / already-scoped:
- Any attacker holding an **ALLOW** policy can exhaust a stateful session table
  — this is inherent to stateful firewalling, not specific to non-SYN. The fair
  cost comparison is 1-packet-bare-ACK (→300s) vs 3-packet-full-handshake
  (→300s) = **3×, not 15×**. The review's "15×" compares against a SYN-flood
  that only builds **20s half-open** state — an apples-to-oranges denominator
  (a SYN flood targets half-open state, not the full session table).
- Per-source/per-dest **session-limit screens exist** (`new_flow_session_limit_drop`,
  #2134) and bound the varied-source-IP variant; they apply equally to a
  full-handshake flood.
- The *correct* mitigation for "drop non-SYN new flows" is a full
  **strict-syn-check** config knob — and that is exactly the scope decision
  **#4400** already recorded ("no strict-syn-check parity"), which deliberately
  drops **bare RST/FIN only** as "the safe minimal hardening"
  (`strict_syn_check_drops_new_flow` at poll_descriptor/mod.rs:614 — verified:
  `PROTO_TCP && is_closing && !has_syn`). Extending strict-syn-check to drop
  bare-ACK/PSH+ACK/data new flows is a **feature request in #4400's orbit**, not
  a default-timeout change, and not a novel bug.

**Net**: NEW-01 does not present evidence that overturns ps-029's
documented-intentional disposition. It re-frames a deliberate behavior as a bug
and proposes a regressing fix. Disposition: DUP ps-029 S-002/M-01 + DELIBERATE
#3152. **Do not file.** (If a hardening item is ever wanted, it is "optional
full strict-syn-check to drop non-SYN new flows" — a #4400-adjacent feature, not
the NEW-01 timeout change.)

---

## Negatives 1-17 (§5 of the review) → **NEGATIVE (coverage proof), accepted**

All 17 verified-negatives reference issues confirmed CLOSED (spot-verified via
`gh`): #4400/#4453/#4487 (RST/FIN, three gated paths), #4399/#4438 (NAT 1:N
multimap SmallVec buckets), #4380 (companion keepalive), #4377 (session-limit
enable-transition rebuild), #4109 (SYN-ACK-only promotion), #3776 (flow-cache
invalidate). The two I re-verified in code on master:
- **#3776 invalidate_slot** — present at loop_body/mod.rs:1377. Confirmed.
- **#4539 has_syn gate** — present at forwarding/mod.rs:1741. Confirmed.
No negative was found to be a false "fail-closed" claim; the coverage-proof
list is sound.

---

## What to relay to parent

- **NOVEL GENUINE-RESIDUALS: NONE.** No fresh fail-open or robustness bug in
  cohort 6 survives verification against current master.
- The review's own headline "NEW filing" (NEW-01) is a re-report of ps-029
  S-002/M-01, which is a **deliberate** behavior (explicit `#3152` comment at
  `session/install.rs:158`), and its proposed fix would **regress** the
  mid-stream-pickup feature #3152 preserved. Do not file.
- All other findings are DUP #2387 (OPEN, tracked — C-01/C-04) or ALREADY-FIXED
  (#3776 C-02, #4539/#4553 C-03). No confabulation; base-delta is benign for
  this cohort.
