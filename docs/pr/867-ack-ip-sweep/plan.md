---
status: DRAFT v1 — pending adversarial plan review
issue: https://github.com/psaab/xpf/issues/867
phase: ACK-evasion of SCREEN_IP_SWEEP — post-conntrack accounting
---

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
non-bypass packets. Add a new accounting block in
`xdp_conntrack.c` that runs ONLY on the session-miss path AND
only for the ACK-only TCP shape that the fast-path bypasses
screen for. Both paths increment the same `ip_sweep_track` map
so the operator-configured threshold is unified.

### 4.1 Trigger condition

Inside `xdp_conntrack_prog`, after both `fwd_key` and `rev_key`
return `NULL` (and after the NAT64 reverse check that also
misses), AND before any session-creation logic:

```c
/* #867: ACK-evasion gate. The resolve_ingress_xdp_target
 * fast-path lets ACK-only TCP skip xdp_screen, so an ACK-based
 * IP sweep would otherwise evade SCREEN_IP_SWEEP. We catch it
 * here, on the conntrack-miss path, where:
 *   - by definition the packet has no matching session, so a
 *     legitimate established ACK is NOT counted (it hits CT)
 *   - the threshold and Junos semantic match the existing
 *     screen-stage sweep (same map, same counter)
 */
if (meta->protocol == PROTO_TCP &&
    !meta->is_fragment &&
    (meta->tcp_flags & 0x10 /* ACK */) &&
    !(meta->tcp_flags & (0x02|0x01|0x04|0x20))) {
    struct iface_zone_key zk = {
        .ifindex = meta->ingress_ifindex,
        .vlan_id = meta->ingress_vlan_id,
    };
    struct iface_zone_value *izv =
        bpf_map_lookup_elem(&iface_zone_map, &zk);
    struct screen_config *sc = ...; /* same lookup as screen */
    if (izv && (izv->screen_flags & SCREEN_IP_SWEEP) &&
        sc && sc->ip_sweep_thresh > 0) {
        /* Same counting logic as xdp_screen.c:940-975, but
         * increments GLOBAL_CTR_SCREEN_IP_SWEEP_ACK on drop
         * for observability. */
        ...
    }
}
```

### 4.2 New observability counter

Add `GLOBAL_CTR_SCREEN_IP_SWEEP_ACK` to `bpf/headers/xpf_common.h`
(next free index, currently 17 or 18 — verify). Operators see
two counters in `cli show security flow statistics`:
- `Screen ip-sweep drops (SYN/UDP)` → original path
- `Screen ip-sweep drops (ACK-evasion)` → new path

The map and threshold are unified; the counters split is purely
diagnostic — distinguishing "scan with SYN/UDP" from "scan with
ACK only" tells the operator what the attacker is using.

### 4.3 Userspace dataplane mirror

`userspace-dp/src/screen.rs` mirrors the BPF logic. Add the same
post-conntrack accounting block in the equivalent Rust path.
Mirror the new counter constant.

### 4.4 BPF verifier budget

Adding ~30 lines to `xdp_conntrack_prog` is risky against the
512-byte combined-frame stack limit (CLAUDE.md "BPF Verifier"
rules). Mitigations:

- Reuse the existing `iface_zone_map` lookup if it can be
  hoisted to before the session lookup (already done?). Verify.
- Use `__noinline` if necessary to keep the new block in its
  own frame.
- The new block is post-CT-miss, which is the slow-er path
  (most packets hit a session and tail-call away). Even an
  extra map lookup is acceptable here.

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
- **Daemon restart / session loss**: a fresh daemon with no
  sessions will see ACKs from established flows as "no session"
  for a brief window. With this change, those would count
  toward `ip_sweep_track`. This is a real false-positive
  scenario. Mitigation: HA replicates sessions; standalone
  restart is rare. Operators concerned can set
  `ip_sweep_thresh` higher than typical post-restart ACK
  bursts (typical: a few thousand ACKs over 1 sec — set
  threshold ≥ 10k).
- **Asymmetric routing**: legitimate ACKs that arrived on the
  wrong interface miss conntrack. With this change, those
  count. Existing screen-stage sweep already had this same
  property; behavior unchanged.
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
- `cargo test --release`: 962+ pass, plus 2-3 new tests:
  - `ip_sweep_ack_evasion_detected` — fixture sends N ACK probes
    from one source to N distinct destinations with no matching
    session; assert drop after threshold.
  - `ip_sweep_ack_evasion_no_drop_when_session_matches` —
    fixture creates a session, then sends N ACKs that match;
    assert no drop and counter not incremented.
  - `ip_sweep_ack_evasion_threshold_unified_with_screen_path` —
    half SYN probes (counted via screen) and half ACK probes
    (counted via conntrack-miss); assert drop on combined count.
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
