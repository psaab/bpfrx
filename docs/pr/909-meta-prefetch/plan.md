# Plan: #909 — fix metadata-header prefetch address

Issue: #909

## 1. Problem

`poll_binding_process_descriptor` (`userspace-dp/src/afxdp.rs:632`) consumes
10.6 % of total CPU under iperf3 -P 128 / 25 Gb/s elephant load on the
loss userspace cluster. **One single instruction** — the `jne` after a
`cmpl $0x42505553` against a stack-relative address — owns 33 % of that
function's self-time, i.e. ~3.5 % of total CPU.

The constant matches `USERSPACE_META_MAGIC = 0x4250_5553`
(`userspace-dp/src/afxdp.rs:145`). The branch is the magic check at the
top of `try_parse_metadata` (`userspace-dp/src/afxdp/frame.rs:3104`):

```rust
let meta = unsafe { *(bytes.as_ptr() as *const UserspaceDpMeta) };
if meta.magic != USERSPACE_META_MAGIC || meta.version != USERSPACE_META_VERSION {
    return None;
}
```

`UserspaceDpMeta` is 96 bytes (verified by struct-field sum and by the
`cmpw $0x60` length check immediately following the magic check). It
sits at `desc.addr - 96` — i.e. **before** the frame head, on a
different set of cache lines than the frame.

The existing prefetch in `poll_binding_process_descriptor`
(`userspace-dp/src/afxdp.rs:670-682`) targets `desc.addr` (the frame
head). It does NOT cover `desc.addr - 96`. Comment says "before metadata
parse" — intent right, address wrong. So the CPU brings the frame head
into L1 ahead of the parse, but `try_parse_metadata` reads on a
different cache line and stalls on the cold DRAM load every packet.

## 2. Goal

Prefetch the 96 bytes of metadata at `desc.addr - 96` so the magic /
version / length checks land in cache when `try_parse_metadata` runs.
Keep the existing frame-head prefetch (the L3/L4 parse later still needs
it).

## 3. Approach

In `poll_binding_process_descriptor` just before the existing frame
prefetch, add a metadata prefetch:

```rust
// Prefetch the userspace-dp metadata header (96 bytes) that sits
// just BEFORE the frame at desc.addr - meta_len. try_parse_metadata
// reads this first and currently stalls on cold DRAM. The metadata
// straddles two cache lines (96 bytes on a 64-byte CL — see §3.1
// for the alignment proof), so issue two prefetches.
#[cfg(target_arch = "x86_64")]
{
    debug_assert!(desc.addr % 64 == 0,
        "UMEM frame at desc.addr={} should be 64-byte aligned", desc.addr);
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    if (desc.addr as usize) >= meta_len {
        let meta_offset = (desc.addr as usize) - meta_len;
        if let Some(pf_meta) = unsafe { &*area }.slice(meta_offset, meta_len) {
            unsafe {
                core::arch::x86_64::_mm_prefetch(
                    pf_meta.as_ptr() as *const i8,
                    core::arch::x86_64::_MM_HINT_T0,
                );
                // Second cache line of the 96-byte metadata.
                core::arch::x86_64::_mm_prefetch(
                    pf_meta.as_ptr().add(64) as *const i8,
                    core::arch::x86_64::_MM_HINT_T0,
                );
            }
        }
    }
}
```

The existing frame-head prefetch (`desc.addr`) stays put — the L3/L4
parse downstream still wants it warm.

The `desc.addr >= meta_len` guard is the same precondition
`try_parse_metadata` already enforces (`frame.rs:3098`). If
`desc.addr` is too small to have a metadata prefix, no prefetch (and
the parse will return `None` later, taking the no-meta fallback path).

### 3.1 Cache-line alignment invariant (Codex R1 #8)

`desc.addr` is 64-byte aligned by construction: UMEM frames are 4096
bytes (`userspace-dp/src/afxdp.rs:147`, frame_size=4096) with a 256-byte
headroom (`:155`); both are 64-byte multiples and `desc.addr` is
`frame_idx * frame_size`. The 96-byte metadata at `desc.addr - 96`
therefore starts at byte `(desc.addr - 96)`, which is `desc.addr - 64
- 32`. With `desc.addr` 64-byte aligned, `desc.addr - 64` is also
64-byte aligned and is the start of the second cache line; the bytes
`[desc.addr - 96, desc.addr - 64)` are the last 32 bytes of the
preceding cache line. So the metadata always spans **exactly 2 cache
lines** and the two `_mm_prefetch` calls (one at the start of each)
cover all 96 bytes.

The kernel-side bridge (`userspace-dp/csrc/xsk_bridge.c:164`) does not
explicitly assert this alignment — it copies `desc.addr` from the RX
ring as-is. The invariant relies on UMEM frame size + headroom being
64-byte multiples. To make this less fragile we add a
`debug_assert!(desc.addr % 64 == 0)` near the prefetch site, so an
unexpected misalignment trips loudly in dev/test rather than silently
under-fetching the third cache line in release.

### 3.2 Cache-line size

x86-64 cache lines are 64 bytes; `_mm_prefetch` fetches one line per
call. The plan is x86-64-only (`#[cfg(target_arch = "x86_64")]` guard,
matching the existing prefetch). On other targets the prefetch is a
no-op and we fall back to the cold-load behavior — no functional
change.

## 4. What this is NOT

- Not a redesign of `try_parse_metadata` or `UserspaceDpMeta`.
- Not a change to UMEM layout or descriptor placement.
- Not a fix for the cross-NIC memcpy — that's separately tracked
  (effectively unfixable at the AF_XDP layer on this cluster).
- Not a tunable. The prefetch is unconditional on x86_64; the
  `cfg(target_arch = "x86_64")` guard matches the existing prefetch.

## 5. Files touched

- `userspace-dp/src/afxdp.rs` — add 2 prefetches at the top of the
  per-descriptor loop, before the existing frame-head prefetch. Net
  ~20 lines including the comment.

No new tests — this is a microarchitectural prefetch. Validation is
empirical (re-profile on the cluster, see §6).

## 6. Validation

### 6.1 Build + unit tests

`cargo build --release` and `cargo test` pass for the userspace-dp
crate. The change is a pure addition; no logic changes.

### 6.2 Deploy + smoke

`make cluster-deploy` to the loss cluster. Smoke check:
`make test-failover` — verify session-sync / VRRP failover still
clean.

### 6.3 Assembly check (Codex R1 #16)

Before re-profiling, confirm the prefetch was actually emitted in the
expected position in the compiled binary:

```
incus exec loss:xpf-userspace-fw0 -- bash -c \
    "objdump -d /usr/local/sbin/xpf-userspace-dp \
       | awk '/poll_binding_process_descriptor>:/,/^$/' \
       | grep -A 2 -B 2 prefetch"
```

We expect to see at least **two** `prefetcht0` instructions near the
top of the function, both before the `cmpl $0x42505553` site. If the
compiler hoisted/elided the prefetches, this check fails and the perf
gain (if any) isn't attributable to this change.

### 6.4 Re-profile

```
incus exec loss:cluster-userspace-host -- sh -c \
    "iperf3 -c 172.16.80.200 -p 5203 -P 128 -t 90 -i 5 --forceflush"
```

Concurrently:
```
incus exec loss:xpf-userspace-fw0 -- perf record -F 99 -g \
    -p $(pidof xpf-userspace-dp) --call-graph dwarf \
    -o /tmp/perf-after.data sleep 30
incus exec loss:xpf-userspace-fw0 -- \
    perf report -i /tmp/perf-after.data --stdio \
    --no-children -n -s symbol --percent-limit 1.0 -g none | head -20
incus exec loss:xpf-userspace-fw0 -- \
    perf annotate -i /tmp/perf-after.data --stdio --no-source \
    xpf_userspace_dp::afxdp::poll_binding_process_descriptor \
    | awk '$1 ~ /^[0-9]+\.[0-9]+/ && $1+0 >= 1.0' | head
```

PASS gate (per §7):
- The `jne` instruction at the magic-check site shows < 10 % of
  `poll_binding_process_descriptor` self-time (down from 33 %).
  **This site-level check is the primary proof** (Codex R1 #15);
  throughput improvement is secondary because other bottlenecks at
  25 Gb/s can mask aggregate gain.
- Aggregate iperf3 -P 128 throughput improves over the 7.20 Gb/s
  baseline (no precise target — report the delta).
- No new INVALID-* markers in mouse-latency reps.

## 7. Acceptance

### 7.1 Merge gates

- Builds green; existing unit tests green.
- Codex hostile plan + code review: PLAN-READY YES + MERGE YES.
- Copilot inline review: addressed.
- Cluster smoke (one rep of `test-mouse-latency.sh 0 1 60` after deploy)
  produces a valid probe.json — proves no regression on the no-elephant
  path.
- Re-profile evidence collected and committed under
  `docs/pr/909-meta-prefetch/findings.md`.

### 7.2 Decision threshold (reported, not gating)

- Magic-check stall drops by ≥ 50 % (i.e. from 33 % of fn self to
  ≤ 16.5 %). If the drop is smaller, the diagnosis was incomplete and
  we need follow-up; if larger, even better.
- Aggregate iperf3 -P 128 throughput moves up by ≥ 5 % (7.20 → 7.56
  Gb/s or higher).

## 8. Risks

- **Prefetch pollutes L1 if metadata never accessed.** Mitigated: the
  metadata IS always accessed by `try_parse_metadata` later in this
  same loop (Codex R1 #13: every descriptor reaches the single
  `try_parse_metadata` call before the valid/no-meta split — confirmed
  in `userspace-dp/src/afxdp.rs:807, :2983`). The prefetch has 5-10 µs
  of useful work to hide DRAM latency before the load.
- **Bounds-check on `desc.addr`.** Mitigated: the same precondition is
  already enforced by `try_parse_metadata`; we replicate it before the
  prefetch.
- **`_mm_prefetch` is unsafe-ish but well-defined.** Already used by the
  existing frame prefetch — same idiom.
- **Two prefetches per packet** — small budget hit (~2-4 µops). At
  -P 128 / 7 Gb/s ≈ 580K pps, that's 1.2M extra prefetches/sec across
  6 workers, well below CPU dispatch limits.
- **Empirical regression**: if for some reason the metadata is already
  warm via some other path I haven't seen, the prefetches are wasted
  cycles. The re-profile catches this — if `jne` self-time doesn't move,
  back the change out.

## 9. R1 disposition

| #  | Sev | Topic                                    | Status |
|----|-----|------------------------------------------|--------|
| 1-4| -   | diagnosis points (try_parse_metadata, struct size, prefetch site, every-packet path) | CONFIRMED — no plan change needed |
| 5  | NIT | path typo (`src/frame.rs` vs `src/afxdp/frame.rs`) | NO-OP — review prompt typo, plan was correct |
| 6  | UNVERIFIED | assembly evidence not in checkout | NO-OP — assembly came from live perf annotate output, recorded in issue body |
| 7  | -   | UMEM frame alignment confirmed           | CONFIRMED |
| 8  | CONCERN | `desc.addr` alignment not asserted in code | RESOLVED — §3.1 documents the invariant; debug_assert added in §3 snippet |
| 9  | -   | cache-line size unverified for non-x86   | RESOLVED — §3.2 explicit, prefetch is x86-only |
| 10-11| -   | precondition consistency confirmed     | CONFIRMED |
| 12 | NIT | `parse_userspace_dp_meta` typo           | RESOLVED — §8 risk now cites the correct `try_parse_metadata` |
| 13-14| -   | wasted-prefetch paths confirmed clean  | CONFIRMED |
| 15 | CONCERN | site-level evidence is primary, not throughput | RESOLVED — §6.4 PASS gate calls out the site-level check as primary |
| 16 | CONCERN | no assembly-emission verification step | RESOLVED — §6.3 added objdump-based check before re-profile |

## 10. Acceptance checklist

- [ ] Plan reviewed by Codex; PLAN-READY YES.
- [ ] Implemented; builds green.
- [ ] Existing unit tests pass.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Deploy to loss cluster; `make test-failover` clean.
- [ ] Assembly check: `prefetcht0` × 2 emitted near top of
      `poll_binding_process_descriptor`, before the magic compare.
- [ ] Re-profile on iperf3 -P 128 / iperf-c; magic-check stall
      drops ≥ 50 %.
- [ ] Findings committed.
- [ ] PR opened, Copilot review addressed.
