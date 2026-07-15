# Triage result — ps-review-036-cohort7 (Forwarding core, RE-AUDIT)

## Header

- **Review**: ps-review-036, Cohort 7 — forwarding core deep security audit
  (`poll_descriptor`, `poll_stages`, `forwarding/mod`, `frame/*`, `flow_cache`,
  `icmp_embed`, `icmp_ptb`, `userspace-xdp/lib`).
- **Review base**: `33b891d11` (Merge #4560). **STALE by 3 commits** vs current
  master `0b4109522` (Merge #4564 — VRRP advert clamp / cluster hardening /
  NAT64-HA cross-node). None of the 3 substantive findings touch
  VRRP/cluster/NAT64-HA, so **no stale-base false-opens**; all three verified
  against CURRENT master `0b4109522`.
- **Cites real bpfrx code** (not the avacado fork): every cited symbol
  (`parse_embedded_v6_l4`, flowless transit zone-policy arm, `matches()`
  l4_present gate, `TxVlanTag`, `set_index`, `FlowCacheEntry` stamp) EXISTS on
  master. No confabulation.
- **This is a RE-AUDIT** of the cohort ps-030 covered (M-02 → #4555). Prior
  dispositions honored: N-01→#3776, V-01/L-01→#2387, L-02 not-material.
- **Outcome counts**: 1 GENUINE-RESIDUAL (NOVEL, F-001) · 1 DUP #4533 (F-002,
  improved trace) · 1 NOT-MATERIAL/cosmetic (F-003) · 4 STILL-PRESENT dedups
  correctly not re-filed (#2387, #3776, #4555, #4533) · 22 verified NEGATIVEs.
- The review is **self-disciplined**: it explicitly does NOT file F-002 or F-003,
  and correctly labels the STILL-PRESENT set as dedups. Only F-001 is proposed
  as new — and it holds up.

---

## Per-finding dispositions

### F-001 [MEDIUM→ I rate LOW-MEDIUM] Non-first fragment bypasses a port-bearing DENY policy when a later PERMIT-any rule exists — **GENUINE-RESIDUAL (NOVEL)**

**Disposition: GENUINE-RESIDUAL. File as a new issue.** This is the one novel
finding and it verifies end-to-end on current master.

**Verified mechanism (input → wrong output), all on master `0b4109522`:**

1. **Reachability** — a non-first fragment is made flowless by design (#2344):
   `parse_session_flow_from_bytes → None` so payload bytes are never read as L4
   ports. It then enters the flowless transit arm at
   `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3433+`. Confirmed by the
   code's own comment at `mod.rs:3433-3450`.
2. **Policy IS evaluated** (this is the #3291/#4024 fix) — the flowless transit
   arm calls `evaluate_policy_result_l3_aware(..., proto, 0, 0, policy_icmp,
   len, false /*l4_present*/)` at `mod.rs:3586-3620`. So the total-bypass /
   deny-all case is already fail-closed. F-001 is a **residual of that fix**,
   not the bypass #3291 closed.
3. **The residual** — the application matcher `ApplicationMatcher::matches()` at
   `userspace-dp/src/policy.rs:1856-1876` gates every port-bearing term behind
   `if l4_present`. With `l4_present=false, dst_port=0`, an exact-port term
   (`junos-https`→443) and any non-empty range term are **skipped**, so
   `matches()` returns **`None` = "rule does not apply"** — NOT a deny. First-
   match evaluation therefore **continues to the next rule**. A later
   `permit any/any/any` term has `match_any → Some(None)` → **PERMIT → the
   fragment is forwarded.**

**Why this is NOT covered by the existing closed issues (dedup is clean):**
- **#3291 (CLOSED)** fixed the case where *no policy at all* ran on flowless
  transit (deny-all bypass). With its fix, a `deny-all` default DROPS the
  fragment (fail-closed). F-001 needs a *specific ordering* — a port-bearing
  DENY **earlier** + a broad PERMIT-any **later** — that #3291 does not address.
- **#4024 (CLOSED)** fixed the flowless MissingNeighbor FIB-reinject bypass
  (again the total-bypass/deny-all direction).
- The code comment at `mod.rs:3446-3450` documents only the **fail-CLOSED**
  direction: "L4-specific-PERMITTED fragmented flows ... fall to the default
  policy, the documented fail-closed limitation." It never considered the
  **fail-OPEN** twin (an L4-specific-DENY skipped, then a later PERMIT-any
  admits). That blind spot is exactly F-001. Genuinely novel.
- Not in #2387 (bare 5-tuple cross-zone/VLAN/VRF session reuse) or #4533
  (embedded-EH overflow). Distinct interaction.

**Severity reasoning — I rate LOW-MEDIUM (review said MEDIUM); reconciling:**
- **Exploitability**: an attacker on the ingress zone crafts a fragmented
  datagram toward a service the operator DENIED with a port-bearing rule, in the
  very common "deny-specific-then-permit-rest" policy ordering. No auth beyond
  on-net position. Realistic config, realistic trigger.
- **Blast radius / direction**: fail-OPEN of the policy contract — non-first
  fragments of a flow the operator configured to DENY are forwarded to the
  destination. It also diverges from Junos, which associates fragments with the
  first-fragment verdict (the deferred fragment-association-cache).
- **Bounding factor the review under-weighted (why not full MEDIUM/HIGH)**: the
  FIRST fragment — the one carrying the L4 header with the denied port — is
  DROPPED by the port-bearing DENY (its L4 is present, so the rule matches and
  denies). The destination therefore **cannot reassemble a complete transport
  datagram** of the denied flow; only non-first fragments (payload without a
  transport header) leak. The residual real harm is (a) reassembly-buffer DoS on
  the destination (fragments parked until reassembly timeout) and (b) theoretical
  overlapping-fragment evasion (RFC 1858/3128) — both bounded by destination-OS
  reassembly hardening (RFC 5722 mandates dropping overlapping IPv6 fragments;
  most IPv4 stacks drop/ignore overlaps). No complete PDU reaches the blocked
  service.
- **Why not LOWER**: it is nonetheless a real policy fail-open — "deny X" does
  not drop all packets of X — and a genuine Junos divergence the deferred
  fragment-association-cache was supposed to close. File-worthy, not cosmetic.
- **Net**: LOW-MEDIUM. The review's MEDIUM is defensible but did not credit the
  first-fragment-dropped cap; I record MEDIUM-with-that-cap = effectively
  LOW-MEDIUM.

**Fix direction (as the review proposes)**: minimal = when `l4_present=false`
and a DENY rule was skipped only because its port-bearing app term could not be
evaluated, do not let a later broad PERMIT admit the fragment (fail-closed the
L4-ambiguous fragment against any L3-overlapping DENY). Principled = the deferred
fragment-association-cache (apply the first fragment's verdict to all fragments
of the same IP-ID + src/dst), matching Junos.

---

### F-002 [MEDIUM] `parse_embedded_v6_l4` 6-iteration EH bound returns garbage protocol on 7+ EH — **DUP #4533 (OPEN)**

**Disposition: DUP #4533 (OPEN). Do NOT file separately — attach the improved
trace to #4533.** The review itself says exactly this; confirmed correct.

**Verification on master `0b4109522`:** `parse_embedded_v6_l4` at
`userspace-dp/src/afxdp/icmp_embed/parse.rs:108` still uses `for _ in 0..6`
(line 114) and still falls through to `Some((offset, protocol))` at loop
exhaustion (line 158) — so a 7-EH quoted packet returns the 7th EH's type
(e.g. DestOpt=60) *as if it were the L4 protocol*, with ports read from EH bytes.
This is precisely the case **#4533** ("align `parse_embedded_v6_l4` EH-overflow
to fail-closed None, matches inspect/nat64 #2292/#4435") tracks, and #4533 is
**OPEN**. The canonical walker at `frame/inspect.rs` uses
`MAX_IPV6_EXT_HEADERS = 8` and returns `None` (fail-closed) at its bound — the
inconsistency #4533 exists to fix.

**Why DUP not NOVEL**: same root cause (6-vs-8 bound + Some-fallthrough on
exhaustion), same symbol, same file. F-002 adds a concrete 7-EH → wrong-protocol
→ PMTUD-blackhole trace, which is a *materially better trace* for #4533, but not
a separate defect. Severity of the underlying issue is LOW-MEDIUM: 7+ EH quoted
inner packets are vanishingly rare, and the failure mode is a silent PMTUD
blackhole for that one flow (embedded NAT reversal misses), not a forwarding
bypass — consistent with #4533 being left OPEN at low priority. Recommend
pasting F-002's trace as a comment on #4533.

---

### F-003 [LOW] `frame/mod.rs:505` bare `vlan_id > 0` vs `TxVlanTag::emits()` — **NOT-MATERIAL (cosmetic, verified equivalent)**

**Disposition: NOT-MATERIAL / cosmetic. Correctly NOT filed by the review.**

**Verification on master:** `frame/mod.rs:505` is `let eth_len = if
params.vlan_id > 0 { 18usize } else { 14usize };` (confirmed; also 1399/1466).
`TxVlanTag::From<u16>` sets `present: vid > 0` (`headers.rs:132`) and
`emits() = present && tci != 0` (`headers.rs:112`). For a pure VID with no PCP
(the only thing egress carries — `tx_vlan_id` is a bare u16 from
`EgressInterface`, PCP comes from CoS not the VLAN tag), `tci == vid`, so
`vid > 0 ⇔ present && tci != 0`. The two checks are **equivalent**; the header
length and the actual tag emission agree. No divergent behavior, no security
impact. The priority-tagged VLAN-0 (VID=0, PCP≠0) egress case does not arise
because egress does not carry PCP in the VLAN tag. Cosmetic clarity nit only —
the review's "not filing" is the right call.

---

## STILL-PRESENT known-open items — dedup confirmed, correctly NOT re-filed

These are the review's §3/§8 "confirmed still present" set. I verified each is
the cited open issue (not a novel defect), so the dedup is accurate:

- **#2387 (OPEN P0) — bare 5-tuple / `set_index`.** `flow_cache.rs:759`
  `set_index(key: &SessionKey, ingress_ifindex: i32)` and `SessionKey` remain
  the 5-tuple core. Note: `FlowCacheKey::from_forward_decision` now derives the
  key ifindex via `resolve_ingress_logical_ifindex(... meta.ingress_vlan_id)`
  (VLAN-aware) at `flow_cache.rs:405-410`, so the flow-cache half is *partially*
  VLAN-disambiguated on master — but the session-layer bare 5-tuple
  (`session/key.rs`) that #2387 P0 centers on is unchanged. Dedup to #2387
  stands; not novel.
- **#3776 (OPEN MED-HIGH) — flow-cache outlives idle-reaped session / NAT-port
  reuse.** Confirmed: `FlowCacheEntry` stamp carries only `config_generation`,
  `fib_generation`, `owner_rg_id/epoch/lease_until` (`flow_cache.rs:122-126`) —
  **no session-GC epoch, no NAT-allocator epoch**. The N-01 residual the review
  describes is real and is #3776. ps-030 N-01 noted the same; #3776 remains OPEN.
- **#4555 (OPEN LOW) — XDP shim `MAX_EXT_HDRS = 6` vs userspace 8.** 7+ EH IPv6
  → XDP fast-path miss → userspace slow-path re-parses with the 8-bound (fail-
  closed parity, not a bypass). LOW; already the subject of #4555 (= ps-030
  M-02). Not novel.
- **#4533 (OPEN) — `parse_embedded_v6_l4` 6-vs-8** = F-002 above.

---

## Verified NEGATIVEs (coverage proof) — spot-checked, no hidden defect

The review's §7 lists 22 fail-closed proofs (N-01..N-22): NAT64 no-pool/exhaust
drop, `declared_l3_end` port-read bounding (#2361), non-first-frag L4-skip in NAT
leaves, `term_match_extra_from_frame` l4_present=false fail-closed, 8-bound
fail-closed EH walkers in `inspect.rs`, RFC-1624 checksum deltas, TTL-1 `0xFEFF`
delta, UDP-0 canonicalization (#1839/#1840), PTB suppression gates
(#2325/#2367/#2487), `packet_eligible`/`should_cache` gates (#2151/#2652), AF
mismatch rejection (#963). These are asserted-correct with issue provenance and
are consistent with the code I read (the flowless policy arm, the `matches()`
l4_present gate, the checksum family). I found **no negative that actually hides
a live defect** — the one place the review's own "fail-closed" framing has a hole
is the DENY-then-PERMIT ordering, which it correctly surfaced as F-001 rather
than burying in a negative. No additional novel finding beyond F-001.

---

## Method note

- Triaged against CURRENT master `0b4109522` via `git show origin/master:<path>`,
  not the review's "confirmed" nor the stale local checkout.
- The review base (`33b891d11`) trails master by 3 commits, but the delta
  (VRRP/cluster/NAT64-HA, #4564) does not intersect any of the three findings —
  no stale-base false-open risk here.
- Weight: this is a `ps-*` self-authored deep review, and it verifies well —
  every cited symbol exists, F-001's mechanism traces cleanly through
  `poll_descriptor/mod.rs` → `policy.rs::matches()`, and it is honestly scoped
  (only 1 of 3 proposed as new; the other two self-deduped). The only severity
  adjustment I make is F-001 MEDIUM → LOW-MEDIUM for the first-fragment-dropped
  bounding factor the review omitted. No over-reporting.
