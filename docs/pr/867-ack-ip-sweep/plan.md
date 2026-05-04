---
status: DRAFT v2 — Codex round-1 PLAN-NEEDS-MAJOR + Gemini Pro 3 round-1 PLAN-NEEDS-MINOR addressed
issue: https://github.com/psaab/xpf/issues/867
phase: ACK-evasion of SCREEN_IP_SWEEP — post-conntrack accounting
---

## Changelog v2

Codex round-1 (`task-morrln7c-kd2m3n`) returned PLAN-NEEDS-MAJOR with
1 BLOCKER + 5 concerns. Gemini Pro 3 round-1 (`task-morrr9ub-vg166z`,
5m 39s) returned PLAN-NEEDS-MINOR with 4 required adjustments. Plan v2
addresses every finding:

**Codex BLOCKER (double-counting risk)**: ACK-only shape ≠ "screen
bypassed". When `SCREEN_TCP_NO_FLAG`, `SCREEN_LAND_ATTACK`, or v4
`SCREEN_IP_SOURCE_ROUTE` is configured, the fast-path actually
forces ACK-only TCP THROUGH `xdp_screen` (see
`bpf/headers/xpf_helpers.h:216-223` — the predicate gates off when
those flags are set). The proposed conntrack hook would then count
the same packet TWICE. **Fix**: introduce a new `META_FLAG_SCREEN_SKIPPED`
bit on `pkt_meta`, set by `resolve_ingress_xdp_target` only when
it explicitly bypasses screen via the ACK-only fast-path. The new
conntrack-miss sweep hook gates on this bit. Packets that reach
screen never have the bit set → handled by existing screen logic.
Packets that bypassed screen have the bit set → handled by the
new conntrack hook on session miss. Single accounting per packet,
unified threshold. (See §4.0.)

**Codex+Gemini agree (stack budget + correct seam)**: drop the
`iface_zone_map` lookup from the conntrack hook. `meta->ingress_zone`
is already populated by `resolve_ingress_xdp_target` before the
fast-path return (`bpf/headers/xpf_helpers.h:189-194`). Use
`meta->ingress_zone` → `zone_configs` → `screen_configs` instead.
Extract the entire hook into a `__noinline` helper so it gets its
own stack frame and the verifier doesn't have to combine its locals
with `xdp_conntrack_prog`'s already-substantial frame. (See §4.2.)

**Gemini Pro 3 (IPv6 coverage)**: the fast-path bypass applies to
both IPv4 and IPv6. Helper must be invoked on BOTH the IPv4
miss-path and the IPv6 miss-path in `xdp_conntrack.c`. Test plan
adds IPv6 evasion permutations. (See §4.2 + §8.)

**Codex (userspace divergence — out-of-scope clarification)**: the
Rust `userspace-dp/src/screen.rs` sweep tracker uses unique-dst
tracking (correct). The BPF-side `ip_sweep_track` uses src+zone
packet count (the bug under fix). The two paths diverge by design;
fixing the BPF semantic divergence is out of scope for this PR
(would require the HLL/CMS work from #867 Option 1). This PR only
closes the ACK-evasion bypass on the BPF path. Userspace path is
unaffected — the userspace dataplane doesn't have the same fast-path
optimization, so ACK probes already go through its sweep tracker.
(See §9.)

**Codex (§6 false-positive analysis was off)**: the previous draft
overstated daemon-restart risk. Normal eBPF restarts preserve
pinned `sessions` / `sessions_v6` / `nat64_state` maps
(`pkg/dataplane/loader_ebpf.go:18-36`). Real risks: full cleanup,
incompatible pinned-map ABI changes, mode transitions
(eBPF↔userspace), HA-sync gaps. **Gemini correction**: even when
sessions ARE lost, the false-positive surface is BOUNDED. After
restart, the FIRST ACK of each established flow misses CT, hits
this hook, increments by 1, then `xdp_policy` creates a `SYN_SENT`
session for the permitted ACK; subsequent ACKs hit that session
and bypass the hook entirely. Maximum extra increments per restart
= N (number of distinct established flows at restart time), not
unbounded. (See §6.)

**Gemini Pro 3 (§3 confirmation — security gate, not cosmetic)**:
verified that without the hook, an ACK-only probe that misses CT,
tail-calls to `xdp_policy`, hits an `ACTION_PERMIT` rule (e.g.
allow-all subnet) gets a fresh `SYN_SENT` session created and the
ACK forwarded to the target host. The target replies with RST,
the attacker maps the network. The sweep hook IS the only
security gate against this evasion. (See §6 invariant on `ct_state = NEW`.)

**Codex (test coverage)**: previous test plan missed false-positive
corners. v2 §8 adds: same-packet-no-double-count when
LAND/NO_FLAG/SOURCE_ROUTE flags configured, NAT64 reverse not
counted, SYN-ACK/FIN/RST/URG/fragment exclusion, disabled-profile
exemption, flow-cache hit doesn't enter conntrack, normal CT hit
doesn't trigger hook, both IPv4 AND IPv6 evasion permutations.

**Codex (counter ABI)**: `GLOBAL_CTR_SCREEN_IP_SWEEP_ACK` will be
appended at index 41 (current `MAX = 41`, so this becomes 41 and
new MAX is 42). ABI-safe. The userspace `GlobalCtrScreenDrops`
aggregate (`pkg/dataplane/userspace/manager_ha.go:524-530`) sums
from a fixed enum — must be updated to include the new counter
in its summation. (See §4.4.)


# #867 — ACK-based IP_SWEEP detection past the fast-path bypass

> *If reviewers conclude the perf gain is too small to justify
> the churn, PLAN-KILL is an acceptable verdict.*

## 1. Issue framing

Security audit #856 found that ACK-only TCP packets bypass
`xdp_screen` via `resolve_ingress_xdp_target` (returns
`XDP_PROG_ZONE`, tail-calling directly to zone), so
`ip_sweep_track` never sees ACK probes. An attacker doing an
ACK-based IP sweep evades SCREEN_IP_SWEEP detection.

PR #856's narrow fix re-required the ACK bit in the fast-path
predicate (closing the NULL-scan bypass) but **deliberately did
not** add SCREEN_IP_SWEEP to the gate, because Codex review
flagged that doing so would generate false positives:
`ip_sweep_track` is keyed only on `(src_ip, ingress_zone)` with
no destination IP, so every established ACK from a forwarding
host would increment the same counter and eventually trip the
threshold. Issue #867 explicitly tracks the follow-up.

## 2. Honest scope/value framing

This is a **security-correctness** PR, not a perf PR. Win:

- **Closes one named evasion technique** (ACK-only IP sweep) for
  operators who have configured `screen ids-option ... ip-sweep
  threshold N`. Without this fix, that config silently does
  nothing for ACK probes.
- The win at absolute scale is binary — either the bypass is
  closed or it isn't. There is no "small" version of this fix.

Cost (very small):

- ~30 lines of BPF C in `xdp_conntrack.c` (one new accounting
  block on the session-miss path).
- ~60 lines of Rust in `userspace-dp/src/screen.rs` to mirror
  for the userspace dataplane (parity with eBPF).
- 2-3 new screen tests (Rust + Go where applicable).
- One new global counter index `GLOBAL_CTR_SCREEN_IP_SWEEP_ACK`
  for observability of ACK-path drops vs original-path drops.
- No protocol-wire change (counter index is internal-only).
- No HA/cluster impact (sweep accounting is per-CPU LRU,
  doesn't sync across nodes today).

PLAN-KILL is on the table if reviewers decide:

- Option 1 (HLL/CMS distinct-dst counter) is the right answer
  instead. Heavier state, more complex, but eliminates the
  false-positive concern even in the existing screen stage.
- The session-miss-gate architecture is wrong because conntrack
  itself is supposed to be the authoritative drop path for
  unsolicited ACKs (see open question §10/Q4).

## 3. What's already shipped / partially batched

- `bpf/headers/xpf_helpers.h:178-227` — `resolve_ingress_xdp_target`
  fast-path. Today: requires ACK bit, gates off when
  `SCREEN_TCP_NO_FLAG`/`SCREEN_LAND_ATTACK`/`SCREEN_IP_SOURCE_ROUTE`
  is set. Does NOT gate on `SCREEN_IP_SWEEP` (#856 deliberate
  hold).
- `bpf/xdp/xdp_screen.c:940-975` — the main `ip_sweep_track`
  accounting block. Runs only for packets that reach screen
  (i.e., DIDN'T take the fast-path).
- `bpf/headers/xpf_maps.h:445` — `ip_sweep_track` LRU map.
- `bpf/xdp/xdp_conntrack.c:780-895` — session-miss path
  (IPv4 fwd_key + rev_key both miss).
- `userspace-dp/src/screen.rs` + `screen_tests.rs` — Rust
  mirror of the BPF screen logic. Has 3 existing IP-sweep
  tests (`ip_sweep_detected`, `ip_sweep_resets_on_window_expiry`,
  `ip_sweep_works_with_udp`).

## 4. Concrete design — chosen architecture: post-conntrack accounting

Approach: keep the screen-stage sweep accounting as-is for all
non-bypass packets. Add a new accounting helper that runs ONLY
on the session-miss path AND only when the fast-path explicitly
chose to skip screen (signaled by a new meta-flag). Single
accounting per packet, unified threshold against the existing
`ip_sweep_track` map.

### 4.0 Bypass marker on `pkt_meta` (Codex round-1 BLOCKER fix)

Add `META_FLAG_SCREEN_SKIPPED` to `bpf/headers/xpf_common.h`
(next free bit on `meta->meta_flags`):

```c
#define META_FLAG_SCREEN_SKIPPED   (1U << <next_free_bit>)
```

Set it in `bpf/headers/xpf_helpers.h::resolve_ingress_xdp_target`
ONLY when the function explicitly takes the ACK-only fast-path
return (the predicate at the current line ~213-223). When any of
`SCREEN_TCP_NO_FLAG`, `SCREEN_LAND_ATTACK`, or
`SCREEN_IP_SOURCE_ROUTE` (v4) is configured for the ingress zone,
the predicate falls through and `XDP_PROG_SCREEN` is returned —
the bit is NOT set, the packet goes through `xdp_screen` as
today, and the existing screen-stage sweep accounting handles it.
No double-count.

The new conntrack-miss helper (§4.2) gates on this bit. Packets
without the bit do NOT trigger the helper.

### 4.1 Counter ABI append

Add `GLOBAL_CTR_SCREEN_IP_SWEEP_ACK` at the end of the global
counter enum in `bpf/headers/xpf_common.h` (current values
0..40, `MAX = 41` — new value becomes 41, new `MAX = 42`).
Mirror in `pkg/dataplane/types.go` (`GlobalCtrScreenIPSweepAck`)
and update `pkg/dataplane/userspace/manager_ha.go::summing` so
`GlobalCtrScreenDrops` aggregate includes the new counter (per
Codex round-1 §6 finding).

Operator UX:
- `cli show security flow statistics` shows the per-counter
  breakdown including ACK-evasion drops separately.
- The aggregate `screen drops` line continues to include all
  paths (including ACK-evasion) for backward compatibility.

### 4.2 Conntrack miss-path helper (Gemini Pro 3 IPv6 fix)

Extract the accounting logic into a `__noinline` helper in
`bpf/xdp/xdp_conntrack.c` (or a new
`bpf/headers/xpf_screen_ack.h` if cleaner). Helper signature:

```c
static __noinline int
ip_sweep_track_ack_evasion(struct pkt_meta *meta, __u64 now_sec);
/* returns SCREEN_DROP_RC if threshold tripped, 0 otherwise */
```

Helper body:
1. Fast-bail if `!(meta->meta_flags & META_FLAG_SCREEN_SKIPPED)`.
2. Look up `zone_configs` by `meta->ingress_zone`. (NO
   `iface_zone_map` lookup — `ingress_zone` is already resolved.)
3. Look up `screen_configs` by `zone_configs.screen_profile_id`.
4. Bail if `(sc->flags & SCREEN_IP_SWEEP) == 0` or
   `sc->ip_sweep_thresh == 0`.
5. Compute `(src_ip-or-v6-fold, ingress_zone)` key matching the
   existing `xdp_screen.c:943-951` algorithm.
6. Same window/counter logic as `xdp_screen.c:953-975`. On
   threshold trip, increment `GLOBAL_CTR_SCREEN_IP_SWEEP_ACK`
   AND return drop. (Existing screen-stage logic increments
   `GLOBAL_CTR_SCREEN_IP_SWEEP` instead — the ACK-specific
   counter is the diagnostic split.)

Invocation sites — IMPORTANT, BOTH families:

- **IPv4 miss path**: `bpf/xdp/xdp_conntrack.c` ~line 891-895
  (after the NAT64 reverse lookup at :785-799 and before
  `meta->ct_state = SESS_STATE_NEW`).
- **IPv6 miss path**: equivalent post-NAT64 / pre-ct_state-NEW
  position in the IPv6 branch.

Both miss paths gate on `(meta->protocol == PROTO_TCP) &&
!meta->is_fragment && (ACK & !(SYN|FIN|RST|URG))` plus
`meta->meta_flags & META_FLAG_SCREEN_SKIPPED` before calling
the helper. (Cheap predicate fail-fast.)

### 4.3 No userspace mirror in this PR

The userspace dataplane (`userspace-dp/src/screen.rs`) already
implements unique-dst tracking for IP sweep, so it does NOT
have the BPF-path bug being fixed here. Userspace does not have
the `resolve_ingress_xdp_target` fast-path optimization (it's a
BPF-only construct), so ACK probes already go through the
userspace sweep tracker. No userspace changes needed.

The semantic divergence between BPF (src+zone packet count) and
userspace (unique-dst tracking) is documented in §9 as
out-of-scope.

### 4.4 BPF verifier stack budget

Pulling the helper into a `__noinline` frame is the primary
mitigation. Drop the redundant `iface_zone_map` lookup
(meta->ingress_zone is already resolved). After implementation,
verify with `bpftool prog dump xlated` and a `clang --print-stats`
build that the conntrack frame stays ≤512 bytes combined.

## 5. Public API preservation

- No protocol-wire change.
- No CLI command change. The new counter shows up under
  existing `show security flow statistics`.
- Existing `screen ids-option ... ip-sweep threshold N` config
  continues to work as before; behavior change is that previously-
  bypassed ACK probes now count toward the same threshold.
- No Rust public API change.
- One new BPF global-counter index — internal only.

## 6. Hidden invariants the change must preserve

- **Conntrack-miss path may also be a legitimate new connection
  attempt.** Specifically, a SYN-flooded victim's initial SYN-ACK
  back to a forged source could land here as a session-miss.
  But SYN-ACK has both SYN and ACK set; the trigger predicate
  requires ACK *without* SYN/FIN/RST/URG, so SYN-ACK is
  excluded. ✓
- **NAT64 reverse path** runs after the fwd_key+rev_key miss.
  Make sure the new sweep-accounting hook is positioned BEFORE
  the NAT64 reverse lookup so NAT64-translated v4 traffic that
  legitimately matches a v6 session isn't accidentally counted.
  Or AFTER, so we don't double-count. Need to verify the right
  order. (See §10/Q3.)
- **Daemon restart / session loss (corrected v2)**: normal
  eBPF restarts preserve pinned `sessions` / `sessions_v6` /
  `nat64_state` maps (`pkg/dataplane/loader_ebpf.go:18-36`).
  Real risks: full cleanup, incompatible pinned-map ABI changes,
  eBPF↔userspace mode transitions, HA-sync gaps. **Bounded**
  even when sessions ARE lost: after restart, the FIRST ACK of
  each established flow misses CT, takes the ACK-only fast-path
  bypass, hits this helper, increments by 1, then `xdp_policy`
  creates a `SYN_SENT` session for the permitted ACK; subsequent
  ACKs hit that session and bypass the helper entirely. Maximum
  extra increments per restart = N (number of distinct established
  flows at restart), not unbounded. (Per Gemini Pro 3 round-1.)
- **Asymmetric routing**: legitimate ACKs that arrived on the
  wrong interface miss conntrack. With this change, those
  count. Existing screen-stage sweep had this same property
  for non-ACK-only packets; the new path extends it to ACK-only.
- **Per-CPU map ordering**: `ip_sweep_track` is BPF_MAP_TYPE_LRU_HASH,
  not per-CPU. Concurrent updates from multiple CPUs are racy
  on `count++`. Existing screen code uses `bpf_map_update_elem`
  with `BPF_ANY` (last-writer-wins on the entire value). Same
  hazard exists today; the PR does not introduce a new race.

## 7. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | **MED** | New drop path on conntrack-miss. False-positive possible on daemon restart / asymmetric routing — both already-known properties of the existing screen-stage sweep, just now reachable for ACK shape. |
| Lifetime / borrow-checker | **LOW** | Rust mirror is a few lines, no lifetime gymnastics. |
| Performance regression | **LOW** | New code is on the conntrack-miss path which is already the slow path (most packets hit a session and tail-call). Extra cost: one LRU map lookup + at most one update on the miss-path. |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | **MED** | Splitting sweep accounting across xdp_screen and xdp_conntrack is layering churn. Reviewers may prefer Option 1 (HLL distinct-dst) which keeps the accounting in xdp_screen. Defer to PLAN-KILL if that's the call. |

## 8. Test plan

- `make generate` (regenerate Go BPF bindings).
- `cargo build --release` clean.
- `cargo test --release`: 962+ pass, plus the following new
  tests covering the false-positive corners flagged by Codex
  round-1 and the IPv6 path flagged by Gemini Pro 3 round-1.
  Each test runs against the BPF eBPF program loader (no
  userspace-dp involvement; userspace doesn't have the bug):

  Positive admission (drops correctly):
  - `ip_sweep_ack_evasion_detected_v4` — ACK probes from one
    source to N distinct dst v4 addresses; no matching session;
    drops after threshold.
  - `ip_sweep_ack_evasion_detected_v6` — same shape, IPv6.
  - `ip_sweep_ack_evasion_threshold_unified_with_screen_path` —
    half SYN probes (via screen) + half ACK probes (via new
    helper); drops on combined count against unified `ip_sweep_track`.

  Negative (no drop, hook not entered):
  - `ip_sweep_ack_no_drop_when_session_matches_v4` — established
    session, N ACKs all match; assert no drop, counter unchanged.
  - `ip_sweep_ack_no_drop_when_session_matches_v6` — same, IPv6.
  - `ip_sweep_ack_no_double_count_when_land_attack_configured` —
    profile has `SCREEN_LAND_ATTACK | SCREEN_IP_SWEEP`. Send N
    ACK probes; verify they go through `xdp_screen` (not the
    fast-path bypass) and count exactly once via the existing
    screen-stage logic. `META_FLAG_SCREEN_SKIPPED` must NOT be
    set on these packets.
  - `ip_sweep_ack_no_double_count_when_tcp_no_flag_configured` —
    profile has `SCREEN_TCP_NO_FLAG | SCREEN_IP_SWEEP`. Same
    expectation.
  - `ip_sweep_ack_no_double_count_when_source_route_configured` —
    profile has `SCREEN_IP_SOURCE_ROUTE | SCREEN_IP_SWEEP` (v4
    only — the v6 fast-path doesn't gate on source-route).
  - `ip_sweep_ack_excludes_syn_ack_fin_rst_urg_fragment` — the
    helper's predicate must reject any of these flag shapes
    even with the SCREEN_SKIPPED bit set (defense-in-depth).
  - `ip_sweep_ack_disabled_when_thresh_zero` — `ip_sweep_thresh = 0`
    or `SCREEN_IP_SWEEP` not set in `screen_flags`; helper bails
    after the first config check; counter unchanged.
  - `ip_sweep_ack_nat64_reverse_not_counted` — IPv4 ACK that
    is the reverse direction of a v6 NAT64 session; the v4 miss
    path looks up `nat64_state`, finds match, tail-calls to
    nat64; the helper position (post-nat64-miss) is NOT reached.
- `cargo test --release ip_sweep` 5x flake check.
- `go test ./...` clean (Go-side change is the new counter
  rendering only).
- Smoke matrix per `triple-review` SKILL.md Step 6: full Pass A
  + Pass B 30 measurements. Expected: zero throughput delta —
  the new accounting block runs only on the conntrack-miss path
  which is already the slow path.
- Manual security test on standalone VM: configure
  `screen ids-option scan-screen ip-sweep threshold 5`, send an
  ACK scan (`hping3 -A -p 80 -c 10 <victim-range>`), confirm
  drop after the 5th probe.

## 9. Out of scope (explicitly)

- Option 1 (HLL/CMS distinct-dst counter). If reviewers prefer
  this, KILL this plan and spin up a separate one.
- ACK-flood rate-limiting (Option 3 in the issue). Different
  semantic from sweep detection; can be added independently if
  operators ask for it.
- TCP port-scan ACK evasion. Same fast-path bypass also affects
  port-scan; same fix shape would work but is a separate
  feature flag.
- HA sync of `ip_sweep_track`. Today the map is local to each
  node; a synced version would need a wire format and
  reconciliation policy.
- Performance benchmarking of the new conntrack-miss accounting
  block under DDoS load (Codex/Gemini may flag this; defer to
  Phase 2 if measured cost is non-trivial).

## 10. Open questions for adversarial review

1. **Architectural choice**: post-CT accounting (this plan) vs
   HLL distinct-dst counter (issue Option 1) vs ACK rate limit
   (issue Option 3). Is the post-CT split the right tradeoff,
   or is it layering churn that should be a PLAN-KILL?
2. **Daemon-restart false positive**: post-restart, established
   flows look like "ACK with no session" until they retransmit.
   Is the documented mitigation ("set threshold high enough")
   acceptable, or does this need a "warmup" exemption?
3. **NAT64 ordering**: should the new accounting hook fire BEFORE
   or AFTER the NAT64 reverse lookup? Mis-ordering either
   double-counts or misses a real evasion. Proposed: AFTER, so
   NAT64-translated traffic with a real v6 session is
   exempted. Confirm.
4. **Conntrack semantic overlap**: shouldn't conntrack already
   drop unsolicited ACKs by default (TCP state machine doesn't
   accept ACK-without-prior-SYN)? If yes, then by the time the
   sweep hook fires, the packet is already destined for a drop
   downstream — making the counter purely informational rather
   than a security gate. Verify by walking the conntrack
   miss-path tail-calls and seeing what happens to an
   ACK-only no-session packet today.
5. **Stack budget**: BPF verifier 512-byte combined-frame limit
   is tight. Adding ~30 lines + a map lookup + an update may
   push the conntrack frame over. Need to compile and check
   stack usage. Worst case: extract the new block into a
   `__noinline` helper (own frame).
6. **Why not just gate the fast-path on SCREEN_IP_SWEEP and
   accept that ACKs go through screen?** That's the
   alternative implementation. The original PR #856 review
   rejected it for false-positive reasons, but those reasons
   apply to the existing src+zone keying. Could we keep that
   gate AND add session-state visibility to screen (somehow)?
   Or is post-CT genuinely the better seam?
