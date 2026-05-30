# #1282 — DBG SEG_MISS journal spam + TX errors on reverse egress ifindex 5

Status: DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude-SMR)

## Issue framing

A reverse all-class CoS fairness sweep (`fairness-cos-class-sweep.sh`,
`cos-iperf-symmetric.set`, `iperf3 -R -P 12 -t 75`) on master @ `1a4699f6`
logged 120 `DBG SEG_MISS` lines (`frame_len=1518 egress_mtu=Some(1500)
egress_if=5 tx_if=5 proto=6`) plus `315288` "TX errors" on
`loss:xpf-userspace-fw0`. The issue asks two questions:

1. Is `DBG SEG_MISS` a real defect or benign debug spam?
2. Are the reverse-egress TX errors real drops or counter mislabeling?

## Diagnosis (reproduced on current master)

The repo has moved well past `1a4699f6`. **Both halves were already
addressed by merged work; current master no longer reproduces the spam
or the unexplained TX errors.**

### Half 1 — SEG_MISS false positive: FIXED by #1283

PR #1283 (`0ce930385`, ancestor of HEAD) made the segmentation precheck
`forwarded_tcp_may_need_segmentation` prefer the *parsed* frame L3 offset
(`frame_l3_offset(frame)`) over the metadata `l3_offset`, which could lag
at 14 for a VLAN-normalized 1518-byte frame and falsely compute
`1518 - 14 > 1500`. The segmentation builders already re-derive L3 from
the frame, so the precheck now agrees with them. The `frame_len=1518 /
egress_mtu=1500 / proto=6` shape in the issue is exactly the VLAN
false-positive that #1283 removed.

### Half 2 — "TX errors": counter mislabeling, FIXED by #85858ec0d

Commit `85858ec0d` ("userspace: attribute CoS admission TX errors",
2026-05-15, ancestor of HEAD) added a `TX errors non-admission` line plus
per-cause CoS drop counters to `show chassis cluster data-plane
statistics` (`statusfmt.go:465`). The top-level `TX errors` counter
aggregates CoS *admission* drops (`dbg_cos_queue_overflow`, flow-share,
buffer drops on shaped/exact queues under saturated reverse iperf) with
genuine TX-ring/submit failures. The issue's 315k were ~300k admission
drops, not ring/submit errors — the author's own follow-up comment
already decomposed them (`299,949` `dbg_cos_queue_overflow`, `0`
`tx_submit_error_drops`).

### Repro on current binary (post-#1283, post-#85858ec0d)

Deployed binary on `loss:xpf-userspace-fw0` (`160c296ab`, today's
`smoke/1635-noregress` merge = current master + #1635). All historical
SEG_MISS lines in the journal trace to PIDs predating today's deploy
(latest burst PID 3306 @ May 28 03:04, capped at 20). Current PID 1798
started 21:39 UTC with `0` SEG_MISS at baseline.

Symmetric CoS fixture applied, then concurrent high-rate reverse
all-class load (`-R -P 12`):

| Run | Target | Port/class | Aggregate | Retr (sender) |
|---|---|---|---|---|
| v4 24g | 172.16.80.200 | 5210 | 16.9 Gb/s | 0 |
| v4 uncapped | 172.16.80.200 | 5211 | 1.24 Gb/s | 0 |
| v6 24g | 2001:559:8585:80::200 | 5210 | 15.7 Gb/s | 793* |
| v6 uncapped | 2001:559:8585:80::200 | 5211 | 1.24 Gb/s | 116* |

\* v6 retrans are shaped-class TCP backoff, not drops on the unshaped
path; `TX errors non-admission` stayed `0`.

Post-run dataplane stats: **`TX errors non-admission: 0`** (the 618
top-level TX errors are the 100m-shaped-class admission drops, matching
the 618 retrans on that run). Journal over the entire repro window:
**`0 DBG SEG_MISS` lines** (v4 and v6).

**Conclusion: #1282 does not reproduce on current master.** The
false-positive is gone (#1283), and the TX-error label is now
decomposed (#85858ec0d).

## Residual defect (the only thing left to fix)

The `eprintln!("DBG SEG_MISS...")` at `tx/dispatch/mod.rs:410` is **not**
gated behind `cfg!(feature = "debug-log")`, while every sibling
diagnostic in the same file *is* (lines 254, 332, 515, 663, 793). It is
soft-capped at 20 per worker thread via a `thread_local! SEG_MISS_LOG`
cell, but:

- It is a `DBG`-prefixed line that writes to **stderr → journald in
  release builds** (default feature set is `default = []`, so `debug-log`
  is OFF in production). This is precisely the CLAUDE.md logging-rules
  violation: high-frequency `DBG` diagnostics belong behind a flag /
  at debug level, not in the production journal.
- Post-#1283 it no longer fires on the VLAN false positive, but the
  remaining trigger (`seg_needed_but_none`: TCP segmentation genuinely
  needed but both builders returned `None`) is a real driver/MTU edge
  case that *would* still emit unconditional journald lines in
  production, with no operator opt-in.

The matching telemetry counter (`dbg.seg_needed_but_none`, incremented in
`count_forwarded_tcp_segmentation_miss_if_needed`) is the durable,
operator-visible signal and stays. Only the ad-hoc eprintln becomes
opt-in.

## Concrete design

Gate the `SEG_MISS_LOG` eprintln block behind `cfg!(feature =
"debug-log")`, matching its five siblings in the same file. The counter
`seg_needed_but_none` is unchanged (always increments — it is the real
signal). Pure logging-hygiene change; no behavioral change to the
dataplane, no change to the counter, no change to the #1283 precheck.

```rust
if count_forwarded_tcp_segmentation_miss_if_needed(
    dbg, copied_source_frame, tcp_segmentation_needed,
) {
    if cfg!(feature = "debug-log") {
        thread_local! {
            static SEG_MISS_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        SEG_MISS_LOG.with(|c| { /* unchanged eprintln body */ });
    }
}
```

## Public API preservation

No public API change. `count_forwarded_tcp_segmentation_miss_if_needed`
signature and return semantics unchanged. `DebugPollCounters::
seg_needed_but_none` unchanged. CLI stats output unchanged.

## Hidden invariants preserved

- `seg_needed_but_none` still increments unconditionally (counter is the
  signal of record; only the eprintln becomes opt-in). Verified by the
  existing truth-table test (`#1283` added
  `forwarded_tcp_may_need_segmentation` / seg-miss-counter tests).
- No allocation change, no hot-path branch added in release (the
  `cfg!(feature)` collapses to a const-false → the whole block DCEs
  out, same as the siblings).
- No HA / GC / map interaction.

## Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression | LOW | Counter unchanged; only an eprintln gated. DCE in release. |
| Lifetime / borrow | LOW | No signature change; block moves under a `cfg!`. |
| Performance | LOW (positive) | Removes a potential journald write on a rare path in release. |
| Architectural mismatch | LOW | Matches the established sibling pattern in the same file. |

## Test plan

- `cargo build` clean (release, default features → eprintln DCE'd).
- `cargo build --features debug-log` clean (eprintln retained).
- `cargo test --release` full suite + seg-miss truth-table test 5×.
- Go suite (no Go change, sanity only).
- Cluster: already reproduced clean (0 SEG_MISS, 0 non-admission TX
  errors). Parent runs the final no-regression smoke.

## Alternative considered: close-with-evidence, no code

Defensible — the spam is already benign (false-positive removed, doesn't
fire in the repro). But the ungated eprintln is a genuine, low-risk
logging-rules inconsistency that would re-bite if a real seg-miss edge
case ever occurs in production. Gating it is a one-line hygiene fix that
brings the site in line with its five siblings. If reviewers prefer
close-with-evidence over the micro-PR, that is an acceptable verdict.

## Out of scope

- The remaining all-class fairness CoV failures at 10G+ classes — that is
  the known RSS/workload-distribution problem (#936/#937 family), not
  #1282. Explicitly not touched here.
- Renaming the top-level `TX errors` counter — `85858ec0d` already added
  the non-admission decomposition; renaming is a separate operator-UX
  decision.

## Open questions for adversarial review

1. Is gating the eprintln behind `debug-log` correct, or should the
   project instead close #1282 with evidence and leave the eprintln as-is
   (since it's capped at 20 and the false positive is gone)?
2. Does the `seg_needed_but_none` counter being the durable signal fully
   satisfy "operators can still diagnose a real seg-miss" without the
   journald line in release?
3. Is there any code path where a *genuine* (non-false-positive)
   seg-miss is expected at steady rate in production, such that losing
   the release-build log would hurt diagnosis? (Repro shows 0 on current
   master.)
4. Is the repro methodology sound — does concurrent v4+v6 `-R -P 12`
   high-rate all-class load actually exercise the same MTU-sized VLAN
   reverse-egress path as the original `1a4699f6` sweep?
5. Should the cap (`< 20`) also move, or stay as a guard inside the
   `cfg!(feature)` block?
