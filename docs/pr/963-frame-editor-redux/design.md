# Design: PacketEditor / Frame Builder Refactor (#963 redux)

**Status:** Revision 4 (after three rounds of Codex hostile + Gemini Pro adversarial review of the design, plus two rounds of code review on the PR-A implementation).
**Scope cut:** Steps 2 and 3 (NAT64 / NPTv6 fast paths) dropped per
both reviewers — speculative without perf evidence. Doc focuses
on **PR-A** (release-strength family-consistency guard in
`FlowCacheEntry::from_forward_decision`) and **PR-B** (helper consolidation into
`frame/byte_writes.rs`), as two separate sequential PRs.

---

## 1. Issue (#963) and its prescription

Issue #963 (filed before the flow-cache fast path landed)
characterises `rewrite_forwarded_frame_in_place` as a "massive God
Function" handling L2 / L3 / L4 / NAT inline and prescribes:

> 1. Extract specialised editors (`Ipv4Editor`, `Ipv6Editor`)
> 2. Resolve VLAN offset once during ParseStage
> 3. Decouple NAT from L2/L3 rewriting via methods
> 4. Compile-time specialise (`rewrite_ipv4_tcp_no_vlan` etc.)

## 2. Current state (precise survey)

The repo has a precomputed-descriptor fast path that achieves
prescription #1, #2, #3 for **cached TCP/UDP NAT44 / NAT66 / non-NAT
flows**. NAT64 and NPTv6 do *not* go through this path today — they
flow either through `build_nat64_forwarded_frame` (a copy builder
that reconstructs frames from scratch — `frame/mod.rs:121-163`,
called from `tx/dispatch.rs:391-419` and `tx/dispatch.rs:551-573`)
or through the generic in-place rewrite.

### 2.1 `RewriteDescriptor` (in `flow_cache.rs`)

Per-flow precomputed rewrite plan. Cached on first session miss for
TCP/UDP NAT44 / NAT66 / non-NAT flows; explicitly *not* cached for
NAT64 (`should_cache` (in `flow_cache.rs`, `impl FlowCacheEntry`) rejects them).

```rust
pub(super) struct RewriteDescriptor {
    pub(super) dst_mac: [u8; 6],
    pub(super) src_mac: [u8; 6],
    pub(super) fabric_redirect: bool,
    pub(super) tx_vlan_id: u16,
    pub(super) ether_type: u16,           // 0x0800 / 0x86dd, picked once
    pub(super) rewrite_src_ip: Option<IpAddr>,
    pub(super) rewrite_dst_ip: Option<IpAddr>,
    pub(super) rewrite_src_port: Option<u16>,
    pub(super) rewrite_dst_port: Option<u16>,
    pub(super) ip_csum_delta: u16,
    pub(super) l4_csum_delta: u16,
    pub(super) tx_selection: CachedTxSelectionDescriptor,
    pub(super) nat64: bool,
    pub(super) nptv6: bool,
    pub(super) apply_nat_on_fabric: bool,
    /* + tx_ifindex / target_binding_index / egress_ifindex */
}
```

**No tunnel endpoint field.** TX dispatch separately gates in-place
rewrite to non-tunnel egress (`tx/dispatch.rs:392-418`); GRE / native
tunnel encap goes through `build_forwarded_frame_into_from_frame`
(`frame/mod.rs:184-185`), a copy path. Step 1 helpers must not be
called from a tunnel-forwarding context — they assume non-tunnel
egress.

### 2.2 `apply_rewrite_descriptor` (`frame/mod.rs:777-1037`)

The cached-flow fast path. Explicit gates (this is **not** branchless):

- L2 ether_type: `match rd.ether_type { 0x0800, 0x86dd, _ => None }`
- VLAN offset: `eth_len = if rd.tx_vlan_id > 0 { 18 } else { 14 }`
- TTL: `if !skip_ttl { ... }` (gated by `meta.meta_flags & 0x80`)
- NAT: `if apply_nat { ... }` (gated by fabric redirect rule)
- Expected ports: `if let Some((exp_src, exp_dst)) = expected_ports { ... }`
- L4 protocol: `match meta.protocol { TCP, UDP, _ }` for csum offset
- UDP zero-checksum: `if old_l4_csum != 0 || meta.protocol != UDP`

The win over the generic path is **precomputed checksum deltas**
(`rd.ip_csum_delta`, `rd.l4_csum_delta`) plus **direct byte writes**
for IPs/ports without sum-and-fold of the whole header. The branches
above are inherent to the work, not noise.

The v4 arm (lines 846-946) is ~100 LOC of interwoven address-rewrite
+ TTL + IP-checksum + L4-port + L4-checksum logic. Gemini correctly
notes that this is itself a smaller-but-similar-shaped God Function.

### 2.3 `rewrite_forwarded_frame_in_place` (`frame/mod.rs:644-717`)

The generic fallback. Used when:

- First packet of a flow (descriptor not cached yet).
- `expected_ports` mismatch in the fast path returns `None` and falls
  through (DMA-race guard, see §3.3).
- `RewriteDescriptor.nat64` or `RewriteDescriptor.nptv6` set
  (descriptor-construction flips but cache-construction rejects
  NAT64 today, so this is currently unreachable for NAT64 specifically;
  NPTv6 is constructible but seldom).
- VLAN trunk mismatch (single-tag only — see §3.2 invariant).

Calls `rewrite_prepare_eth` then dispatches to `rewrite_apply_v4` or
`rewrite_apply_v6` after a `match meta.addr_family`.

### 2.4 Generic-path helpers (frame/mod.rs)

- `rewrite_prepare_eth` (484-548): eth header + payload shift, vlan
  offset, fabric-ingress TTL gate.
- `rewrite_apply_v4` (551-604): TTL, NAT44 IP/port writes,
  `restore_l4_tuple_from_meta`, IP checksum recompute, L4 enforce/recompute.
- `rewrite_apply_v6` (607-642): TTL, NAT66 IP/port writes,
  `restore_l4_tuple_from_meta`, L4 enforce/recompute.
- `apply_nat_ipv4` / `apply_nat_ipv6`: byte-write helpers for NAT.
- `restore_l4_tuple_from_meta` (1323-1342): **NOT** a port-restoration
  fallback — for TCP/UDP it returns `Some(false)` and does nothing. It
  only repairs ICMP / ICMPv6 *identifier* bytes from
  `meta.flow_src_port`. (Codex review correction.)

### 2.5 Dispatcher (`poll_descriptor.rs:344-369`)

```rust
let is_self_target = target_bi == Some(binding_index);
if is_self_target && owned_packet_frame.is_none() {
    let frame_len = apply_rewrite_descriptor(&*area, desc, meta,
                                             &cached_descriptor,
                                             expected_ports)
        .or_else(|| {
            rewrite_forwarded_frame_in_place(&*area, desc, meta,
                                             &cached_decision,
                                             cached_descriptor.apply_nat_on_fabric,
                                             expected_ports)
        });
    /* push to TX */
}
```

Cached + same-binding hits take the fast path. Hairpin and
cross-binding redirects go through other paths.

## 3. Invariants the helpers depend on (and that the doc must state)

### 3.1 Async NDP cache invalidation

`MissingNeighbor` resolutions are non-cacheable; cached `FabricRedirect`
descriptors are invalidated when local NDP resolution converges or
lapses (`types/forwarding.rs:180-193`,
`forwarding/mod.rs:561-577`). Step 1 helpers operate post-cache-hit
so this is upstream of them, but if the helpers are ever reused in a
cache-validation path the invalidation contract matters.

### 3.2 VLAN trunk: single-tag only

`write_eth_header_slice` emits one 0x8100 tag. `frame_l3_offset`
recognises both 0x8100 and 0x88a8 as 18-byte L2
(`frame/mod.rs:1474-1483`, `frame/inspect.rs:109-120`). **QinQ
(double-tag, S+C) is not supported by the fast path** — `eth_len`
would be wrong and L3 contents would shift by 4 bytes. Step 1 must
not introduce a helper that gets called against a QinQ frame.

### 3.3 `expected_ports` race guard

`apply_rewrite_descriptor` v4 arm at lines 862-870 checks
`(cur_src, cur_dst)` against `expected_ports` before touching ports.
Mismatch → return `None` → fall through to generic path. This is the
guard against flow-cache stamp races between a flow-update and a
stale-descriptor application (Gemini review note).

### 3.4 No tunnel endpoint in descriptor

See §2.1: TX dispatch routes tunnel encap through
`build_forwarded_frame_into_from_frame` separately. Helpers
introduced in Step 1 are not safe for tunnel egress; the upstream
gating in `tx/dispatch.rs:392-418` is what makes the assumption valid.

### 3.5 Mismatched address-family construction

Gemini flagged the case where `RewriteDescriptor` is constructed with
`ether_type = 0x0800` but `rewrite_src_ip = Some(IpAddr::V6(_))`.
**Reachability and effect analysis:**

- `compute_l4_csum_delta` (`checksum.rs:48-69`) gates on family match
  via `match (flow.src_ip, new_src) { (V4,V4)=>..., (V6,V6)=>..., _=>{} }`.
  A mismatch produces 0 contribution from that IP, so the delta is
  consistent with "IP not rewritten".
- `apply_rewrite_descriptor` v4 arm only writes V4 NAT (`if let
  Some(IpAddr::V4(_))`, `frame/mod.rs:872-879`). V6-in-V4-descriptor
  → IP NAT silently skipped. Port NAT IS still applied (no family
  gate at `frame/mod.rs:882-893`).
- Port-only checksum delta from `compute_l4_csum_delta:94-103` is
  consistent with "ports rewritten, IPs not".
- **Net effect: silent NAT skip, not packet corruption.** The
  forwarded packet has the wrong source/dest IP (original, not
  NAT'd), correct port (NAT'd), and a checksum that matches that
  bizarre state.

**Reachability — current code:**

- `RewriteDescriptor` has exactly one production construction site:
  `FlowCacheEntry::from_forward_decision` in `flow_cache.rs` (the descriptor literal at lines ~211-242 of HEAD). Test
  construction sites are at `flow_cache_tests.rs:25`,
  `session_glue/tests.rs:1787,1866`, `frame/tests.rs:3819,4366`.
- In `from_forward_decision`, `ether_type` is derived from
  `meta.addr_family`, so the eth side is always self-consistent.
- `rewrite_src_ip` / `rewrite_dst_ip` come straight from
  `decision.nat`, with no family check at construction
  (in the same descriptor literal).
- The upstream proof — that `decision.nat.rewrite_src` is typed by
  the same family as `meta.addr_family` — is *not visible at the
  cited construction site*. It depends on the NAT pipeline always
  producing same-family decisions, which is plausible given that NAT
  rules are typed by family in the policy compiler, but I have not
  traced the full chain.

Codex round 2 correctly objects to "no current code path produces
this" without a cited proof.

**Proposal — release-strength guard, not just debug_assert:**

Make `FlowCacheEntry::from_forward_decision` (in `flow_cache.rs`) — the sole
production construction site that builds a `RewriteDescriptor` —
return `None` when the families of `decision.nat.rewrite_src` /
`decision.nat.rewrite_dst` (when `Some`) don't match
`meta.addr_family`. The flow then falls through to the generic
in-place rewrite path (uncached for that miss; the next miss may
succeed if the upstream bug is transient, or stay uncached if the
bug is persistent).

This is **defense in depth**: the runtime cost is two enum-discriminant
compares once per flow (not per packet). It converts a silent NAT
skip into a graceful degradation — uncached but functionally correct
(the generic path's separate v4/v6 dispatch handles the actual
mismatch correctly). The PR-A test will construct a
deliberately-mismatched-family `SessionDecision` and verify
`FlowCacheEntry::from_forward_decision` returns `None`.

We retain the upstream invariant analysis as documentation, but no
longer rely on it for correctness.

## 4. What the issue's prescription actually buys vs. current state

| #963 prescription                                  | Current state                                                                                                       |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Extract `Ipv4Editor` / `Ipv6Editor`                | Already split: `apply_rewrite_descriptor`'s v4/v6 arms + generic-path `rewrite_apply_v4` / `rewrite_apply_v6`. Cached-TCP/UDP only. |
| Resolve VLAN offset once                           | Already: `rd.tx_vlan_id` precomputed at flow miss; offset picked once in apply.                                     |
| Decouple NAT from L2/L3 via methods                | Done as data: `RewriteDescriptor` carries everything. No method API; descriptor-as-data is denser.                  |
| Compile-time specialise `rewrite_ipv4_tcp_no_vlan` | **Not done.** Both reviewers say leave it off the table — combinatorial L1-i bloat outweighs realistic per-packet win. |

The prescription is **substantively addressed for cached TCP/UDP
flows.** It is **not** addressed for NAT64 (out of scope by design —
copy builder, not in-place) or NPTv6 (constructible descriptor but no
fast path; rare traffic share).

## 5. Proposal

### 5.1 PR-A — release-strength family-consistency guard

Modify `FlowCacheEntry::from_forward_decision` in `flow_cache.rs` (the
production construction site) to validate that `ether_type` and the
families of `rewrite_src_ip` / `rewrite_dst_ip` are consistent
*before* the entry is returned:

- If `meta.addr_family == AF_INET`, both `decision.nat.rewrite_src`
  and `decision.nat.rewrite_dst` (when `Some`) must be `IpAddr::V4`.
- If `meta.addr_family == AF_INET6`, both must be `IpAddr::V6`.

On mismatch, return `None`. The flow stays uncached for this miss
and falls through to the generic in-place rewrite path — which
handles each family with its own dispatch (`rewrite_apply_v4` /
`rewrite_apply_v6`) and is correct in either family.

Cost: two enum-discriminant compares once per flow miss, not per
packet. Adds a `debug_assert!` *in addition* to the release guard so
that the dev-build sanity check catches mismatches as panics during
testing (instead of silent uncached operation).

Test will verify that `FlowCacheEntry::from_forward_decision` returns `None` when
given a mismatched-family decision (test constructs a synthetic
`SessionDecision` with V6 rewrite_src on a V4 meta and asserts the
return value is `None`).

**This is PR-A. Independent of Step 1; lands first.**

### 5.2 PR-B — extract unconditional byte-write kernels

Per Gemini's reshape feedback, the helpers are **maximally stupid**:
unconditional, no `Option`, the conditional logic stays in the
caller. This avoids the LLVM phase-ordering risk where pushing
`Option`-matching into a helper might confuse constant-folding /
dead-branch-elimination.

**Module placement:** new file `userspace-dp/src/afxdp/frame/byte_writes.rs`.
Codex round-2 reviewer correctly notes that `frame/checksum.rs` is
delta math (`compute_ip_csum_delta` / `compute_l4_csum_delta`) while
these helpers are packet byte mutation — different concerns. The
existing `frame/inspect.rs` (parsing) and `frame/tcp_segmentation.rs`
(TCP-specific) establish the per-concern-per-file pattern.

**Helpers (in `userspace-dp/src/afxdp/frame/byte_writes.rs`):**

```rust
#[inline(always)]
fn write_ipv4_src(packet: &mut [u8], ip: usize, addr: Ipv4Addr) {
    packet[ip + 12..ip + 16].copy_from_slice(&addr.octets());
}

#[inline(always)]
fn write_ipv4_dst(packet: &mut [u8], ip: usize, addr: Ipv4Addr) {
    packet[ip + 16..ip + 20].copy_from_slice(&addr.octets());
}

#[inline(always)]
fn write_ipv6_src(packet: &mut [u8], ip: usize, addr: Ipv6Addr) {
    packet[ip + 8..ip + 24].copy_from_slice(&addr.octets());
}

#[inline(always)]
fn write_ipv6_dst(packet: &mut [u8], ip: usize, addr: Ipv6Addr) {
    packet[ip + 24..ip + 40].copy_from_slice(&addr.octets());
}

#[inline(always)]
fn write_l4_src_port(packet: &mut [u8], l4: usize, port: u16) {
    if packet.len() >= l4 + 2 {
        packet[l4..l4 + 2].copy_from_slice(&port.to_be_bytes());
    }
}

#[inline(always)]
fn write_l4_dst_port(packet: &mut [u8], l4: usize, port: u16) {
    if packet.len() >= l4 + 4 {
        packet[l4 + 2..l4 + 4].copy_from_slice(&port.to_be_bytes());
    }
}
```

**Call sites for the helpers:**

The byte-write work currently happens at two distinct families of
call sites (Codex round-2 correction):

1. **Fast path inline writes** in `apply_rewrite_descriptor`
   (`frame/mod.rs:872-893`):
   ```rust
   if let Some(IpAddr::V4(new_src)) = rd.rewrite_src_ip {
       packet[ip + 12..ip + 16].copy_from_slice(&new_src.octets());
   }
   /* analogous for dst, src_port, dst_port */
   ```
   These get replaced with calls to the new helpers, with the
   `if let Some(IpAddr::V4(_))` matching staying at the call site.

2. **Generic-path NAT helpers**: `apply_nat_ipv4` / `apply_nat_ipv6` /
   `apply_nat_port_rewrite` (`frame/mod.rs:1039-1212`). These are
   themselves byte-writing helpers used by `rewrite_apply_v4` /
   `rewrite_apply_v6`, but they take a `NatDecision` and dispatch
   on the `Option`s internally. Refactor them to *call* the new
   `byte_writes.rs` helpers for the actual mutation, while keeping
   their existing `NatDecision`-dispatch wrappers as the API surface
   for the generic path.

This means `rewrite_apply_v4` (`frame/mod.rs:551-604`) does NOT call
the byte-write helpers directly — it goes through `apply_nat_ipv4`
which does. The helper-extraction touches `apply_rewrite_descriptor`
+ `apply_nat_ipv4` + `apply_nat_ipv6` + `apply_nat_port_rewrite`.

**LOC reduction:** ~25-30 lines of duplication eliminated across
fast-path inline writes + generic-path NAT helpers. Helpers
themselves ~30 lines. Net wash on LOC, clear correctness win on
having one definition of "byte 12-15 is the v4 source IP".

### 5.3 Steps 2 (NAT64) and 3 (NPTv6) — DROPPED

Both reviewers concur: zero perf evidence either is rewrite-bound, so
the work is speculative.

Replacement plan: if NAT64 throughput becomes a hot button, run
`perf record -g` on `userspace-dp` during an iperf3 NAT64 flow. If
`rewrite_forwarded_frame_in_place` (or `build_nat64_forwarded_frame`)
ranks in the top-3 by self-time, *then* file a follow-up with the
profile and re-propose the fast path. Don't pre-optimise.

## 6. Validation plan

### 6.1 Unit tests

Existing `frame/tests.rs` covers `apply_rewrite_descriptor` at lines
4364-4399 (the NAT64 fallback assertion). PR-B must keep those green.
PR-A's release-strength guard needs at least one new test that
constructs a mismatched-family `SessionDecision` (e.g. V6
`rewrite_src` with V4 `meta.addr_family`) and asserts that
`FlowCacheEntry::from_forward_decision` returns `None`. A complementary test
should also verify a matching-family decision still returns
`Some(entry)` so the guard isn't accidentally over-broad.

### 6.2 Codegen / microarchitectural check

Per Gemini's pushback: cargo-asm output is too sensitive to register
allocation to predict perf. Replace with `perf stat` on an isolated
core. PR-B (helper extraction) is the codegen-sensitive change. PR-A
(release-strength guard) has trivial release-mode codegen impact —
two enum-discriminant compares on the cold flow-miss path — but
should also be measured for completeness.

**Method:**

```bash
# On loss:xpf-userspace-fw0, isolate one CPU for the test
sudo cpupower frequency-set -g performance
taskset -c 4 ./xpf-userspace-dp <args> &
DP_PID=$!

# Drive iperf3 -P 16 -t 60 against best-effort port. Repeat 5 times
# back-to-back. Capture cycles, instructions, L1-icache-load-misses,
# branch-misses, stalled-cycles-frontend (Gemini round-2 add — frontend
# stalls catch instruction-fetch pressure even when L1-i miss count
# stays flat).
sudo perf stat -p $DP_PID \
  -e cycles,instructions,L1-icache-load-misses,branch-misses,stalled-cycles-frontend \
  -- sleep 60
```

**Comparison rules** (Codex round-2 tightening):

- 5 runs back-to-back per branch (master baseline + post-PR).
  Compare **medians**, not single-run values, to suppress 1-shot
  scheduler / interrupt noise.
- `cycles` and `instructions`: median within ±2%.
- `L1-icache-load-misses`: median within ±5% (explicit tolerance
  rather than exact-count rule, since absolute miss count is
  workload-dependent).
- `branch-misses`: no regression beyond ±10% (branch-prediction state
  is sensitive to scheduling order and irrelevant to codegen quality
  for this change).
- `stalled-cycles-frontend`: must not regress beyond ±5% (this is
  the most direct codegen-quality signal).

If any threshold is exceeded, investigate before push. Single-worker
isolated-core testbed, NOT multi-worker — codegen diff is the goal,
not realism.

PR-A (release-strength guard in `FlowCacheEntry::from_forward_decision`) does have
codegen impact in release because it adds two enum-discriminant
compares plus a branch on the cold flow-miss path. The cost is
trivial (cache miss, not per-packet) but it's not zero, so PR-A
should also pass the perf-stat thresholds above when measured.

### 6.3 Smoke

Deploy on `loss:xpf-userspace-fw0/1`; cluster healthy + ICMP transit
forwarding. iperf3 7-class smoke is contingent on the WAN target rig
at `172.16.80.200` having listening servers — currently down (see
#1133 smoke note); not a blocker for Step 1 since the change is
mechanical.

## 7. Risks (revised after review)

| Risk                                                                             | Mitigation                                                                                                                    |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Helper extraction adds inline barrier and regresses fast path                    | `#[inline(always)]` + perf-stat diff on iperf3 before commit (§6.2). Helpers are unconditional — no Option-matching to confuse LLVM. |
| Step 0 assert changes semantics in debug builds                                  | `debug_assert!` only; release builds unchanged. Tests use `#[should_panic]` to exercise it.                                   |
| Mismatched-family descriptor reachability is wrong                               | §3.5 reasons through it; if reviewers find a path that produces mismatched families, Step 0 catches it.                       |
| Helpers reused in tunnel / QinQ / non-cached paths break invariants              | §3.2 / §3.4 document the assumptions. PR description must say "these helpers are not tunnel/QinQ-safe; upstream gating required". |
| Smoke can't fully validate                                                       | Step 1 is unit-test bounded; perf-stat is the codegen check; full smoke deferred until WAN rig available.                     |

## 8. Open questions for second-round reviewers

**Q1.** Step 0 (family-consistency assert): is the reachability
argument in §3.5 watertight, or is there a code path where a
mismatched-family descriptor genuinely could be constructed? If yes,
the assert is P1 not "defensive only".

**Q2.** Step 1 helper signatures (§5.2) — are the `Ipv4Addr` / `u16`
parameter types what you'd want, or should they be `&[u8; 4]` / `[u8; 4]`
to avoid the `addr.octets()` round-trip? Codegen-equivalent in practice,
but the byte-array form is more "kernel" in spirit.

**Q3.** `frame/checksum.rs` vs new `frame/byte_writes.rs` for the
helpers? Cohesion argues for `checksum.rs` (it already has
`compute_ip_csum_delta` etc.); modularity argues for a separate file.

**Q4.** Is the perf-stat methodology in §6.2 correct? Specifically:
should we drive multiple workers (current cluster runs ~12 workers per
binding) or single-worker for codegen-only diff? Multi-worker has more
realistic cache footprint but more noise.

**Q5.** Should Step 0 (assert) and Step 1 (helpers) be the same PR or
separate? Separate is cleaner for review, same PR reduces churn on
`apply_rewrite_descriptor`.

---

**If you're a second-round reviewer:**

Answer Q1-Q5 explicitly. Then pick one of:
- **PROCEED-AS-PROPOSED** (this revision is sound)
- **PROCEED-WITH-CHANGES** (list the specific changes)
- **CLOSE-AS-DONE** (Step 0 + Step 1 don't move the needle; close #963)
- **NEEDS-DEEPER-INVESTIGATION** (specify what)

---

## Appendix: revision history

### Revision 1 → Revision 2 (round-1 reviews)

Per Codex round-1 review (a9652df98d5b96cfc):

- Narrowed "substantively addressed" to cached TCP/UDP only (was: all flows). [§2 intro, §4]
- Fixed `restore_l4_tuple_from_meta` description: ICMP IDs only, not ports. [§2.4]
- Dropped Step 2 (NAT64): TX dispatch sends NAT64 to copy builder, not generic rewrite. [§5.3]
- Dropped Step 3 (NPTv6): no traffic-share evidence. [§5.3]
- Added §3.4 tunnel endpoint invariant.
- Added §3.2 VLAN/QinQ invariant.
- Removed "branchless" claim from §2.2; enumerated the actual gates.
- Fixed test line numbers (was 3811-4380, actual NAT64 fallback at 4364-4399). [§6.1]
- Removed cargo-asm validation; replaced with perf-stat. [§6.2]

Per Gemini Pro round-1 review (task-monpfl6h-ww1ahu):

- Added §3.5 mismatched address-family analysis + §5.1 Step 0 defensive assert.
- Reshaped Step 1 helpers to "maximally stupid" unconditional kernels (was: helpers took `Option`). [§5.2]
- Added §3.3 expected_ports race-guard discussion.
- Added §6.2 perf-stat methodology (cycles/instructions/L1-i misses/branch misses on isolated core).
- Acknowledged §2.2 v4 arm is itself a smaller-but-similar God Function; the doc no longer claims the fast path is clean.

### Revision 2 → Revision 3 (round-2 reviews)

Per Codex round-2 review (task-monpt1na cancelled at 57m, restarted as a957d243caeee5471):

- §3.5 reachability proof now honest about its limit ("upstream proof not visible at construction site").
- §5.1 upgraded from `debug_assert!`-only to a release-strength guard:
  `FlowCacheEntry::from_forward_decision` returns `None` on family mismatch, flow falls
  through to generic path. Cost: two integer compares once per flow miss.
- §5.2 helper call-site description corrected: byte writes happen inline in
  `apply_rewrite_descriptor` AND inside `apply_nat_ipv4` / `apply_nat_ipv6` /
  `apply_nat_port_rewrite`. `rewrite_apply_v4` does NOT call helpers directly.
- §5.2 module placement decided: new `frame/byte_writes.rs` (per Codex's
  "different concern from delta math" reasoning, overriding Gemini's
  cohesion-with-checksum.rs argument).
- §5.1 / §5.2 wording: "Test will verify" (future tense) — assert / guard
  doesn't exist yet.
- §2.2 v4 arm line range corrected: 846-946 (not 846-960).
- §6.2 perf-stat methodology tightened: median over 5 runs (not single
  run), explicit tolerances per counter, single-worker isolated-core only.

Per Gemini Pro round-2 review (task-monpsw6i-aa7r0x):

- §6.2 added `stalled-cycles-frontend` counter (frontend-pipeline pressure
  signal that catches instruction-fetch issues even when L1-i miss count
  stays flat).
- §3.5: P0 corruption framing from round 1 explicitly walked back — net
  effect is silent NAT skip, not corruption (Gemini concurred).
- Step 0 (now PR-A) and Step 1 (now PR-B) confirmed as separate sequential
  PRs (already implicit, now explicit in §5).
