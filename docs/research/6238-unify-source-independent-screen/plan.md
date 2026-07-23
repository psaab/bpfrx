# #6238 — Unify flow-present vs flowless source-independent screen ordering

## 1. Status

**DRAFT / PLAN-READY for adversarial review.** Research + design only; no
production source touched. Class B (security hot-path unification, NOT pure
code-motion). This plan **rejects the issue's literal boundary** — a single
contiguous `check_source_independent(profile, pkt, addrs_known)` owning
`LAND → ping → teardrop → icmp-fragment → source-route` — because that ordering
is **not reproducible** on the full path (TCP-flag screens are interposed
between LAND and ping). It substitutes a narrower, provably behavior-preserving
two-helper split. The narrowing must be adjudicated by the reviewer; PLAN-KILL
is acceptable if the residual mirror surface (LAND) is judged too small a win
for hot-path churn.

Base: `origin/master` @ `5fc235716`. Worktree:
`research/6238-unify-source-independent-screen`.

## 2. Issue framing

`userspace-dp/src/screen/mod.rs` has TWO entry points that manually mirror the
same source-independent security checks:

- **Flow-present** `check_packet_with_zone_id_opts` (lines 846–1129): full
  screen enforcement for a packet with a real transport flow.
- **Flowless** `check_flowless_screens_opts` (lines 1219–1270): the
  source-independent subset for a packet with no transport flow — a non-first
  IP fragment, or a non-query ICMP/ICMPv6 control message that
  `parse_session_flow_from_bytes` deliberately leaves flowless (#2344/#3290).

Both paths re-list the stateless L3 screens, both repeat the fabric
`skip_rate_flood` early-return, and both repeat the ICMP/UDP flood enforcement.
Because the orchestration is hand-mirrored, a new source-independent screen (or
an exception to one) can again be added to only one path. That is precisely the
**fail-open** class that bit #3902, #4155, and #4567 — each required a parallel
amendment after one path diverged.

## 3. Honest scope & value

The win is **correctness-hardening**, not modularity for its own sake:
single-source the check families that historically diverged, so the next
addition covers both entry points by construction.

**But the value is NARROW, and the plan is honest about the ceiling.** The two
paths are **not** a clean "flowless ⊂ full-present" subset. Three structural
divergences (see §7) mean a *single* unifying helper cannot cover *all* the
mirrored checks:

- **LAND cannot join the shared helper.** In the full path LAND runs, then
  TCP-flag screens, then the fragment/route tail. A contiguous helper that
  bundles LAND with the tail would have to be called either before TCP-flag
  screens (moving the tail ahead of them) or after (moving LAND behind them) —
  both reorder drop precedence. LAND therefore stays a per-path call and remains
  mirrored (unconditional in full, `addrs_known`-gated in flowless).
- **TCP-flag screens and the whole SYN-flood/cookie block are full-only** and
  stay in place.

So this PR single-sources the **fragment/source-route tail** (`ping-of-death →
teardrop → icmp-fragment → source-route`) and the **ICMP/UDP flood rate block**
— which is exactly the surface #3902 (source-route + flood additions) and
#4155/#4567 (fabric skip + UDP zero-port) patched — while LAND, TCP-flag, and
SYN remain path-specific by necessity. It **narrows** the mirror surface; it
does not eliminate it.

**PLAN-KILL is acceptable** if the reviewer judges that (a) leaving LAND
mirrored means the fail-open risk is not actually retired, only reduced, and
the residual doesn't justify hot-path churn; or (b) the four tail checks are so
rarely amended that the extraction's insurance value is below the risk of
touching a per-packet security path at all.

## 4. What is already shipped (the parallel amendments)

| Issue | SHA(s) | The mirror-divergence bug it patched |
|-------|--------|--------------------------------------|
| **#3902** | `b5055b720` (PR #3907) | Before #3902 the flowless branch ran ONLY the three fragment screens (ping/teardrop/icmp-fragment). LAND, ip-source-route, and the ICMP/UDP flood counters were **BYPASSED** on the flowless path — a crafted non-first fragment / non-query ICMP transited unscreened (screen fail-open). #3902 hand-added those checks to the flowless path to match the full path. |
| **#4155** | `508aa3c97` (PR #4160) | Fabric-redirected traffic was already rate-screened on the ingress node. The `skip_rate_flood` early-return (suppress re-counting the rate floods on the RG owner) had to be added to **BOTH** `check_packet_with_zone_id_opts` and `check_flowless_screens_opts` in parallel. |
| **#4567** | `8be52dfeb` (PR #4574) | A flowless non-first UDP fragment carries `dst_port == 0`; it was landing in a stray `(ip, 0)` sketch cell instead of the per-destination-IP bucket. Fixed inside `udp_flood_drop` (the `dst_port == 0` fold) — shared today, but the flowless call site had to be reasoned about separately. |

These three are the empirical evidence that the hand-mirror is a live
fail-open hazard, and they are the fail-on-revert coverage this PR must retain.

## 5. Concrete design

**Reject** the issue's `check_source_independent(profile, pkt, addrs_known)`
mega-helper. **Adopt** a two-helper split that preserves byte-for-byte
precedence:

### 5a. `stateless::check_fragment_and_route` — the common stateless tail

```rust
/// Contiguous common tail shared by the flow-present and flowless paths:
/// ping-of-death → teardrop → icmp-fragment → source-route, in the exact
/// order both paths already run them. Side-effect-free (reads &profile,
/// &pkt only). Does NOT include LAND (address-gated + precedes TCP-flag
/// screens on the full path) or the TCP-flag screens (full-only).
#[inline]
pub(super) fn check_fragment_and_route(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if let Some(r) = check_ping_of_death(profile, pkt) { return Some(r); }
    if let Some(r) = check_teardrop(profile, pkt)      { return Some(r); }
    if let Some(r) = check_icmp_fragment(profile, pkt) { return Some(r); }
    if let Some(r) = check_source_route(profile, pkt)  { return Some(r); }
    None
}
```

Both entry points call it at the **same precedence slot** they use today:

- **Full path** (mod.rs ~847–864):
  `check_land` (unconditional) → `check_tcp_flag_screens` →
  **`check_fragment_and_route`** → fabric-skip → rate → SYN.
- **Flowless path** (mod.rs ~1222–1236):
  `check_land` (gated on `addrs_known`) → **`check_fragment_and_route`** →
  fabric-skip → rate → Pass.

Behavior-preserving **by construction**: those four checks are already
contiguous and identical (same order, same guards, same reason strings) in both
paths. Extracting the already-adjacent run reorders nothing. LAND stays an
explicit per-call at each site; TCP-flag screens stay full-only, in place.

### 5b. `enforce_common_rate_floods` — the common ICMP/UDP flood block

```rust
/// Common source-independent rate enforcement: ICMP flood then UDP flood,
/// mutating disjoint sub-fields of the already-looked-up ZoneScreenState.
/// UDP zero-port folding is handled INSIDE udp_flood_drop, so this helper
/// needs no flowless mode flag. Returns the drop reason or None.
#[inline]
fn enforce_common_rate_floods(
    zstate: &mut ZoneScreenState,
    pkt: &ScreenPacketInfo,
    now_ns: u64,
) -> Option<&'static str> {
    let icmp_t = zstate.profile.icmp_flood_threshold;
    if icmp_t > 0
        && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
        && zstate.icmp_flood_drop(&pkt.dst_ip, icmp_t, now_ns)
    { return Some("icmp-flood"); }

    let udp_t = zstate.profile.udp_flood_threshold;
    if udp_t > 0
        && pkt.protocol == PROTO_UDP
        && zstate.udp_flood_drop(&pkt.dst_ip, pkt.dst_port, udp_t, now_ns)
    { return Some("udp-flood"); }
    None
}
```

Both paths call it **after** the fabric-skip gate. The full path then continues
into the SYN-flood/cookie block; the flowless path returns `Pass`. The zero-port
fold already lives in `udp_flood_drop` (`if dst_port == 0` → `increment(dst_ip)`
per-IP bucket), so the flowless caller passing `dst_port == 0` needs **no** mode
argument.

### 5c. Fabric skip stays inline

The `if skip_rate_flood { return ScreenVerdict::Pass; }` gate returns the whole
function; it is three identical lines and stays at each call site. Folding it
into a helper would require the helper to signal "caller must return Pass",
adding no value. This matches the reviewer's caution.

### 5d. Helper placement — NO new `rate_enforcement.rs`

The issue proposed a new `screen/rate_enforcement.rs`. **Do not create it for
one small orchestration helper.** `check_fragment_and_route` goes in the
existing `stateless.rs` (its siblings live there and are already `pub(super)`).
`enforce_common_rate_floods` is a small `impl`/free helper next to its callers
in `mod.rs`, or a `ZoneScreenState` method in `mod.rs`/`rate.rs`. A new file is
justified only if a coherent larger responsibility later accretes.

## 6. Public API preservation

- The two public entry points keep their **exact signatures**:
  `check_packet_with_zone_id_opts(zone, zone_id, pkt, now_ns, now_secs,
  skip_rate_flood)` and `check_flowless_screens_opts(zone, pkt, addrs_known,
  now_ns, now_secs, skip_rate_flood)`, plus the `check_packet_with_zone_id` /
  `check_flowless_screens` second-granularity wrappers. Callers in
  `afxdp/poll_stages.rs` (604, 682) are untouched.
- `ScreenVerdict` variants, the reason strings, and
  `screen_reason_drop_index`/`SCREEN_REASON_DROP_COUNT` (=15) are unchanged.
- New helpers are `pub(super)`/private — no crate surface added. No proto/wire
  change; the `protocol_wire_v1.json` fixture length is untouched.

## 7. Hidden invariants (side-by-side table — each MUST be preserved)

Verified firsthand against `5fc235716`. `#N` = `screen_reason_drop_index`
ordinal (mod.rs 163–182); "agg" = folds to aggregate `screen_drops` (index
`None`).

| # | Full path (`check_packet_with_zone_id_opts` 846–1129) | Flowless (`check_flowless_screens_opts` 1205–1270) | Same? |
|---|--------------------------------------------------------|-----------------------------------------------------|-------|
| Zone lookup | `self.zones.get_mut(zone)` else `maybe_warn_missing_profile` + `Pass` (836–844) | `self.zones.get_mut(zone)` else `maybe_warn_missing_profile` + `Pass` (1205–1218) | **IDENTICAL** (one lookup each) |
| **LAND** | `check_land` **unconditional** (847) → Drop `land-attack` (#5) | `check_land` **gated on `addrs_known`** (1222) → Drop `land-attack` (#5) | **GUARD DIFFERS** |
| **TCP-flag** | `check_tcp_flag_screens` (850) → `tcp-syn-fin`(#8)/`tcp-no-flag`(#9)/`tcp-fin-no-ack`(#10)/`winnuke`(#11)/`syn-frag`(#13) | **ABSENT** | **FULL-ONLY, interposed** |
| ping-of-death | `check_ping_of_death` (853) → `ping-of-death` (#6) | `check_ping_of_death` (1225) → `ping-of-death` (#6) | **IDENTICAL** |
| teardrop | `check_teardrop` (856) → `teardrop` (#7) | `check_teardrop` (1228) → `teardrop` (#7) | **IDENTICAL** |
| icmp-fragment | `check_icmp_fragment` (859) → `icmp-fragment` (agg) | `check_icmp_fragment` (1231) → `icmp-fragment` (agg) | **IDENTICAL** |
| source-route | `check_source_route` (862) → `ip-source-route` (#12) | `check_source_route` (1234) → `ip-source-route` (#12) | **IDENTICAL** |
| fabric skip | `if skip_rate_flood { return Pass }` (881) | `if skip_rate_flood { return Pass }` (1241) | **IDENTICAL** (same slot) |
| ICMP flood | `icmp_flood_drop(&dst_ip, thr, now_ns)` (912) → `icmp-flood` (#1) | `icmp_flood_drop(&dst_ip, thr, now_ns)` (1251) → `icmp-flood` (#1) | **IDENTICAL** |
| UDP flood | `udp_flood_drop(&dst_ip, dst_port, thr, now_ns)` (922) → `udp-flood` (#2) | `udp_flood_drop(&dst_ip, dst_port=0, thr, now_ns)` (1263) → `udp-flood` (#2) | **IDENTICAL call**; flowless always `dst_port==0` (folds to per-IP bucket inside the method) |
| SYN-flood + cookie | full block 948–1102 → `syn-flood`(#0)/challenge/bypass | **ABSENT** | **FULL-ONLY** |
| Tail | `SynCookieBypass` or `Pass` (1125) | `Pass` (1270) | full may bypass |

**The three divergences a unification must respect:**

1. **TCP-flag screens are interposed between LAND and the fragment tail on the
   full path.** This is the crux: it makes the issue's contiguous
   `LAND → ping → teardrop → icmp-fragment → source-route` helper impossible to
   place without reordering precedence. *Concrete collision:* a TCP packet
   carrying an LSRR/SSRR IPv4 option that is ALSO `syn-fin` (or `syn-frag` on a
   first fragment) drops as `tcp-syn-fin`(#8)/`syn-frag`(#13) TODAY, because
   TCP-flag screens precede `check_source_route`. A contiguous helper run before
   the TCP-flag screens would flip that to `ip-source-route`(#12). Both drop,
   but the recorded per-reason counter changes — an observable behavior change.
   A LAND packet that is also `syn-fin` (`src==dst`, TCP SYN+FIN) drops as
   `land-attack`(#5) today; a contiguous helper run *after* TCP-flag screens
   would flip it to `tcp-syn-fin`(#8).
2. **LAND is `addrs_known`-gated on the flowless path, unconditional on the
   full path** — a per-call guard the shared helper must not absorb.
3. **SYN-flood/cookie is full-only**, layered after the common rate block.

**Additional invariants (must survive the refactor):**

- **One `ZoneScreenState` lookup** per packet on each path (the #4969
  consolidation). The helpers receive `&zstate.profile` (stateless tail) or
  `&mut zstate` (rate helper) — no second `self.zones.get`.
- **Reason string = counter key.** The per-reason drop counter is assigned by
  `screen_reason_drop_index(reason)` in `afxdp/mod.rs:748` from the returned
  string. Preserving the reason *and its precedence* preserves the counter.
  Every stateless check in `stateless.rs` is already side-effect-free (returns
  `Option<&'static str>`, mutates nothing) — the tail helper adds no state.
- **UDP zero-port bucketing** is inside `udp_flood_drop` (#4567); the rate
  helper must keep passing `pkt.dst_port` verbatim so the method's
  `dst_port == 0` fold still fires on flowless fragments.
- **Worker-local counters only** — `icmp_counter`/`udp_counter` and the
  per-destination sketches are per-`ZoneScreenState` (worker-local); no shared
  atomics/locks introduced.
- **No packet-path allocation / dispatch / copy.** Helpers are `#[inline]`,
  take borrows, return `Option<&'static str>`; no trait objects, no `Box`, no
  endian conversion, no UMEM ownership transfer.
- **Disjoint-borrow discipline** (#2209/#4969): the stateless tail reads
  `&zstate.profile`; the rate helper mutates disjoint sub-fields; the
  whole-`self` SYN-cookie epoch call stays on the mint return path after
  `zstate`'s last use. The extraction must not lengthen any borrow across a
  `&mut self` call.

## 8. Risk table

| Risk | Sev | Why | Mitigation |
|------|-----|-----|------------|
| **Reorder flips a screen fail-open↔fail-closed or changes the winning drop reason** on a multi-trigger packet | **HIGH (crux)** | Per-packet security fast path; precedence between TCP-flag screens and the fragment/route tail, and between LAND and TCP-flag, is observable (§7 collisions) | Do NOT bundle LAND/TCP into the shared helper; extract only the already-contiguous 4-check tail + the ICMP/UDP block. Add multi-trigger precedence tests (LAND+TCP, TCP+source-route, ping+source-route). |
| Helper changes a guard (e.g. drops the `addrs_known` LAND gate, or the `is_fragment`/protocol guards) | HIGH | Silent screen bypass or false-drop | LAND gate stays at the flowless call site; the tail helper only *moves* existing bodies, guards intact. Retain #3902 fail-on-revert. |
| Double-count a rate flood (helper called from both the common slot AND a leftover inline) | MED | Would false-trip a flood Drop / defeat fabric fwd | Delete the inline blocks when extracting; assert one increment per packet in tests. Retain #4155 fabric-skip + #4567 zero-port fail-on-revert. |
| Borrow lengthened → forces a clone or an extra lookup | MED | Reintroduces the pre-#2209 per-packet clone / pre-#4969 double lookup | Keep the profile scalars copied up front on the full path; assert single lookup; check optimized asm. |
| Perf regression on the screen hot path | MED | Per-packet | `#[inline]` helpers; compare optimized asm + iperf on loss cluster; acceptance ≤1% either entry point. |
| New file `rate_enforcement.rs` over-scopes | LOW | Adds a module for one helper | Keep helpers in `stateless.rs`/`mod.rs`; no new file. |

## 9. Test plan

- **`make test-rust`** (cargo) — the `screen/tests.rs`, `stateless`, and
  `poll_stages_tests.rs` suites must stay green (short `TMPDIR=/tmp` for the
  socket-bind tests).
- **Fail-on-revert that proves BOTH paths route through the shared helpers**
  (the core anti-mirror guarantee):
  - *Tail helper:* a test that enables `source-route` (and separately
    `teardrop`) and asserts BOTH `check_packet_with_zone_id_opts` (full) and
    `check_flowless_screens_opts` (flowless) return the same Drop reason for
    equivalent inputs. Neutralizing one call to `check_fragment_and_route` must
    turn exactly one of them RED. (This is the structural analogue of "add a
    check to the helper, assert both paths enforce it".)
  - *Rate helper:* enable `icmp-flood`/`udp-flood`, drive equivalent
    flow-present and flowless ICMP/UDP over threshold, assert both Drop with one
    increment each; keep the #4567 UDP-zero-port-folds-to-IP-bucket assertion
    (tests.rs ~2440, 5612) and the #4155 fabric-skip assertions (tests.rs
    ~5545–5680).
- **Multi-trigger precedence tests** (new — single-feature tests cannot catch a
  reorder): LAND+`syn-fin` → `land-attack`; `syn-fin`+source-route →
  `tcp-syn-fin`; `syn-frag`(first-frag SYN)+source-route → `syn-frag`;
  ping-of-death+source-route → `ping-of-death`. Each pins the winning reason so
  a precedence flip goes RED.
- **Invariant assertions**: one zone lookup, one rate increment, unchanged
  alarm-without-drop behavior, unchanged fabric bypass, unchanged SYN
  placement, preserved flowless `addrs_known` LAND gate (tests.rs ~5330 already
  covers unknown-address LAND skip).
- **Optimized-asm / no-alloc check** for both entry points (acceptance: no new
  allocation; ≤1% regression).
- **Loss-cluster smoke** (screen is hot-path): `make cluster-deploy` + a screen
  profile with the fragment/flood checks on, plus a sustained iperf3 v4+v6
  through `172.16.80.200` to confirm no forwarding regression and no false
  flood-drops (per `feedback_verify_forwarding_with_sustained_iperf`).

## 10. Out of scope

- **Inline SYN-flood / SYN-cookie logic** (mod.rs 948–1102) — the issue
  explicitly excludes it; it is full-only and does not participate in the
  mirror. No change.
- **Scan/sweep and per-IP session-limit** (`scan_sweep_drop_on_new_flow`) —
  live at the new-flow hook (#2210/#2134), not on either screen entry point.
- **The broad `poll_descriptor` decomposition** — different issue.
- **Any threshold semantics / verdict-consumer** (`poll_stages.rs`
  alarm-without-drop, event emission) — untouched.
- **Unifying LAND / TCP-flag / SYN into the shared helper** — explicitly
  rejected as behaviorally invalid (see §5, §7).

## 11. Open questions (each PLAN-KILL-invitable)

1. **Is narrowing the mirror worth it if LAND stays mirrored?** The extraction
   single-sources the fragment/route tail + rate block but leaves LAND (and its
   `addrs_known` gate) hand-mirrored, because it cannot cross the TCP-flag
   interposition. If a future source-independent screen belongs at the "LAND
   slot" (address-only, pre-TCP), it must STILL be added to both paths. Does
   that residual defeat the issue's stated goal enough to PLAN-KILL?
2. **Does the reviewer accept that the issue's "exact same order" premise is
   false?** The full path interposes TCP-flag screens between LAND and ping;
   the literal `check_source_independent(...LAND..source-route...)` helper
   cannot preserve precedence. If the reviewer insists on the issue's literal
   boundary, this plan cannot satisfy it without a mode flag / codegen
   specialization — PLAN-KILL over a design disagreement.
3. **Where should `enforce_common_rate_floods` live?** Free helper in `mod.rs`,
   a `ZoneScreenState` method, or `rate.rs`? The plan says NOT a new
   `rate_enforcement.rs` — is that the right call, or does the reviewer want the
   issue's proposed file for symmetry with `stateless.rs`?
4. **Is the fail-on-revert strong enough?** Neutralizing one call to the shared
   helper must turn exactly one path RED. Is a single-check "both paths enforce
   X" assertion sufficient, or does the reviewer require the full multi-trigger
   precedence matrix as the merge gate?
5. **Perf floor**: is ≤1% on either entry point measurable reliably on the loss
   cluster given screen is only one stage of `poll_descriptor`, or does the
   no-alloc optimized-asm check have to carry the perf argument alone?
6. **Should `icmp-fragment` (aggregate-only, index `None`) be promoted to a
   dedicated ordinal as part of this work**, since it is the one tail check
   without a per-reason counter? (Likely NO — out of scope, would change
   `SCREEN_REASON_DROP_COUNT` and the wire fixture — but a reviewer may want it
   called out.)
7. **Does moving the four tail bodies risk lengthening the #4969 disjoint
   borrow** such that the compiler forces a profile clone or a second lookup on
   the full path? Needs a compile + optimized-asm confirmation, not just a
   "should be fine".
