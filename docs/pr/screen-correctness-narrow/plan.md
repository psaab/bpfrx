# PR D-narrow — Screen correctness (BPF-only)

Closes GitHub issues #853 and #856 from the security audit (slice D).
Issue #860 (SCREEN_PING_OF_DEATH dead code from u16 pkt_len) is
explicitly **out of scope** — it has cross-dataplane ripples into
Rust userspace-xdp/userspace-dp and DPDK and will be filed as its own
PR.

## Scope

1. **#853** — TC egress false-drops TCP fragments as NULL-scan; the
   `SCREEN_SYN_FRAG` check is simultaneously dead code.
2. **#856** — `resolve_ingress_xdp_target` skips `xdp_screen` for
   NULL-scan and ACK-sweep TCP packets, rendering `SCREEN_TCP_NO_FLAG`
   unreachable for SYN-less probes and bypassing IP-sweep accounting
   on pure ACK scans.

Both are BPF-only changes.

## Root cause

### #853

`bpf/tc/tc_main.c:26-28`:

```c
__builtin_memset((__u8 *)meta + 32, 0, sizeof(*meta) - 32);
```

This zeros `tcp_flags` and `is_fragment` unconditionally at the top of
the TC egress pipeline.

`bpf/tc/tc_main.c:65-69`:

```c
if (!meta->is_fragment) {
    if (parse_l4hdr(data, data_end, meta) < 0)
        return TC_ACT_SHOT;
}
```

For fragmented IPv4/IPv6, `is_fragment` is set to 1 by
`parse_iphdr`/`parse_ipv6hdr`, so `parse_l4hdr` is skipped and
`tcp_flags` stays `0`.

`bpf/tc/tc_screen_egress.c:140-141`:

```c
if ((sc->flags & SCREEN_TCP_NO_FLAG) && tf == 0)
    return screen_drop_tc(meta, SCREEN_TCP_NO_FLAG);
```

Evaluates against `tf=0` for every TCP fragment → false NULL-scan
drop whenever the zone has `TCP_NO_FLAG` enabled.

`bpf/tc/tc_screen_egress.c:154-156`:

```c
if ((sc->flags & SCREEN_SYN_FRAG) &&
    (tf & 0x02) && meta->is_fragment)
    return screen_drop_tc(meta, SCREEN_SYN_FRAG);
```

Because the top-level `meta->tcp_flags = 0` memset happens before
`parse_l4hdr` is gated off for fragments, `tf` is always `0` when
`is_fragment` is true. The `(tf & 0x02) && meta->is_fragment`
predicate is mutually exclusive → dead code.

### #856

`bpf/headers/xpf_helpers.h:205-213`:

```c
if (meta->protocol == PROTO_TCP && !meta->is_fragment) {
    __u8 tf = meta->tcp_flags;
    if (!(tf & (0x02 | 0x01 | 0x04 | 0x20)) &&
        !(screen_flags & SCREEN_LAND_ATTACK) &&
        !(meta->addr_family == AF_INET &&
          (screen_flags & SCREEN_IP_SOURCE_ROUTE)))
        return XDP_PROG_ZONE;
}
```

NULL scan (`tf=0x00`) satisfies `!(0 & anything)` → returns
`XDP_PROG_ZONE`, skipping `xdp_screen`. If the ingress zone has
`SCREEN_TCP_NO_FLAG` configured, the check is unreachable in XDP.

ACK-only sweep packets (`tf=0x10`) likewise skip `xdp_screen`, so
per-source-IP IP-sweep accounting misses the connection attempt.

## Fix design

### #853 — `bpf/tc/tc_screen_egress.c`

Guard the entire `if (meta->protocol == PROTO_TCP) { ... }` block
(lines 131-157) with `!meta->is_fragment`, mirroring the
`parse_l4hdr` gate already present in `tc_main.c:66`. Since
`parse_l4hdr` did not run for fragments, the L4 fields
(`tcp_flags`, `src_port`, `dst_port`) are unreliable and must not be
used.

The `SCREEN_SYN_FRAG` branch inside this block becomes unreachable
(correctly — it would have been dead code either way under the
current `meta->tcp_flags = 0` memset). Add an explicit comment
referencing a new follow-up issue so operators who configure the
flag can track the real work:

```c
/* TCP-specific stateless checks.
 *
 * Gated on !is_fragment because tc_main.c skips parse_l4hdr for
 * fragments, so tcp_flags / ports are stale (always 0 for
 * fragments under the current top-of-pipeline memset).
 *
 * TODO(#NNN): a real SCREEN_SYN_FRAG detection requires parsing
 * the L4 header on the first fragment (frag_off.offset==0 &&
 * MF=1) so we can see the TCP SYN bit. Until then the SYN_FRAG
 * branch below is gated off by !is_fragment and remains dead but
 * intentionally preserved for clarity.
 */
if (meta->protocol == PROTO_TCP && !meta->is_fragment) {
    ...
    if ((sc->flags & SCREEN_SYN_FRAG) &&
        (tf & 0x02) && meta->is_fragment)  /* unreachable; see TODO */
        return screen_drop_tc(meta, SCREEN_SYN_FRAG);
}
```

**Before committing,** file the new GitHub issue ("Real
SCREEN_SYN_FRAG detection via first-fragment L4 parse") and replace
`#NNN` with the actual issue number in the source comment.

**Parity note.** `bpf/xdp/xdp_screen.c:711-738` has the same
structure but is not symmetric-ally affected:

- xdp_main at `bpf/xdp/xdp_main.c` also skips `parse_l4hdr` for
  fragments (mirror of tc_main behavior).
- xdp_screen's TCP block has no `!is_fragment` gate either.
- The XDP fast-path in `resolve_ingress_xdp_target` already routes
  most fragment traffic to `XDP_PROG_ZONE` (because
  `tcp_flags == 0` after the fragment skip hits the NULL-scan-like
  fast-path). That means XDP is **already silently bypassing** the
  fragment screen checks in practice — but the buggy branch logic
  is still present and will trigger if the fast-path is not taken
  (e.g. when LAND or IP_SOURCE_ROUTE is configured).

We include the same `!meta->is_fragment` guard in `xdp_screen.c` for
symmetry and to avoid the exact same false NULL-scan drop on the
slow-path. This is an additional code change beyond the strict
`#853` text, but it's a one-line guard that fixes the same class of
bug in the same file family. The Codex plan review will be asked
explicitly whether this expansion is acceptable; if it pushes back
we'll split.

### #856 — `bpf/headers/xpf_helpers.h::resolve_ingress_xdp_target`

Tighten the fast-path to require the ACK bit AND gate off when
sweep-tracking is configured:

```c
if (meta->protocol == PROTO_TCP && !meta->is_fragment) {
    __u8 tf = meta->tcp_flags;
    if ((tf & 0x10 /* ACK */) &&
        !(tf & (0x02 /* SYN */ | 0x01 /* FIN */ |
                0x04 /* RST */ | 0x20 /* URG */)) &&
        !(screen_flags & (SCREEN_TCP_NO_FLAG | SCREEN_IP_SWEEP)) &&
        !(screen_flags & SCREEN_LAND_ATTACK) &&
        !(meta->addr_family == AF_INET &&
          (screen_flags & SCREEN_IP_SOURCE_ROUTE)))
        return XDP_PROG_ZONE;
}
return XDP_PROG_SCREEN;
```

This:

- Requires `ACK` set, so pure NULL scans (`tf=0x00`) no longer
  qualify and will take the screen path.
- Gates off when `SCREEN_TCP_NO_FLAG` is configured (redundant
  with the ACK-required check above but explicit and cheap).
- Gates off when `SCREEN_IP_SWEEP` is configured, so ACK-only
  sweep probes are counted in `ip_sweep_track`.

Established TCP data/ACK traffic (by far the hot path) still
fast-paths when the zone has none of:
`TCP_NO_FLAG | IP_SWEEP | LAND_ATTACK | (IP_SOURCE_ROUTE & v4)`.

That is the expected common case (screens off, or only
rate-flood screens on), so perf impact should be nil.

## Files touched

| File | Change |
|------|--------|
| `bpf/tc/tc_screen_egress.c` | Wrap TCP stateless check block with `!meta->is_fragment`; add TODO comment referencing new follow-up issue. |
| `bpf/xdp/xdp_screen.c` | Same `!meta->is_fragment` wrap (symmetry with TC) + same TODO. |
| `bpf/headers/xpf_helpers.h` | Tighten `resolve_ingress_xdp_target` fast-path predicate (require ACK; gate on `SCREEN_TCP_NO_FLAG | SCREEN_IP_SWEEP`). |

No changes to Go, Rust (userspace-dp), DPDK, or protobuf. No maps
added or removed. No new fields in `struct pkt_meta`. No compiler
side-table or config path changes.

## Non-goals

- Fixing `SCREEN_PING_OF_DEATH` (#860 — separate PR).
- Implementing real `SCREEN_SYN_FRAG` detection (follow-up issue).
- Touching the userspace-dp (Rust) screen module — those programs
  have their own L4 parse model and the bug does not reproduce
  there.
- Mirroring the xpf_helpers.h tightening into userspace Rust /
  DPDK. Those pipelines do not tail-call-skip a screen stage the
  same way; their equivalents can be audited separately if needed.

## BPF verifier risk

The new `!meta->is_fragment` guard adds a trivial boolean branch.
`is_fragment` is already read in the same program (`SCREEN_SYN_FRAG`
branch, tear-drop branch) so it's in scratch/map already.

The `resolve_ingress_xdp_target` change adds one more bit in an
existing compound predicate. It is called from `xdp_main`, which
already inlines this function. Stack and instruction-count impact
is negligible.

We will nonetheless rebuild and load all 14 programs to confirm
verifier acceptance on kernel 6.18.9 (the test VM kernel).

## Test plan

1. **Unit**
   - `make generate && make build` — bpf2go + BPF verifier pass on
     6.18.9, Go binary builds clean.
   - `go test ./...` — 29 packages green.
   - `cargo test -p xpf-userspace-dp --release` — 760+ tests green
     (no Rust source touched; regression-only run).

2. **Deploy to loss cluster** (see deploy procedure in task brief):
   - Build + push xpfd to `xpf-userspace-fw0` + `xpf-userspace-fw1`.
   - Restore the correct `ha-cluster-userspace.conf` (deploy
     script pushes the wrong one by default).
   - Wait 20s for daemon + VRRP convergence.

3. **Functional** (loss cluster):
   - Ping + TCP forwarding from `cluster-userspace-host` to
     `172.16.80.200` (inside zone) — must pass.
   - Forwarding to `1.1.1.1` (WAN NAT path) — must pass.
   - `journalctl -u xpfd` on both firewalls must show no
     "xdp verifier failed" / "prog load failed" lines.

4. **Perf** (loss cluster):
   - `iperf3 -c 172.16.80.200 -P 16 -p 5203 -t 30` from
     `cluster-userspace-host`.
   - **Acceptance: ≥ 23 Gbps sustained** and no > 5% regression
     versus the most recent pre-PR baseline.

5. **NULL-scan negative test (optional, deferred)**:
   - hping3 NULL-scan against the firewall from trust side with
     `SCREEN_TCP_NO_FLAG` enabled on the trust zone. Should be
     dropped by `xdp_screen` and counted in
     `GLOBAL_CTR_SCREEN_TCP_NO_FLAG`.
   - Not blocking for this PR (the audit finding documents the
     bug; the fix matches upstream Juniper semantics).

## Engineering workflow (from task brief)

1. Write this plan. ✅
2. Codex plan review (hostile). Re-submit until PLAN YES.
3. Implement.
4. Codex code review on the diff.
5. Address HIGH / MED findings; re-review if re-spun.
6. Push branch `pr/screen-correctness`.
7. Deploy + test per §Test plan.
8. Open PR referencing both issues and review rounds.
9. Report PR number; do NOT merge.
