# #1282 — DBG SEG_MISS journal spam + TX errors on reverse egress ifindex 5

Status: PLAN-READY v2 — Codex PLAN-NEEDS-MINOR + AGY PLAN-NEEDS-MINOR
(both minors applied below) + Claude-SMR PLAN-READY.

## Reviewer dispositions (v1 → v2)

- **Codex** (`task-mprtr0ce-hmo6nh`, PLAN-NEEDS-MINOR, ran sandbox-blind,
  assessed from facts): direction right, do NOT close-with-evidence-only.
  Minors: (1) include the ancestry `git merge-base --is-ancestor` checks;
  (2) cite the exact `forwarded_tcp_may_need_segmentation` parsed-offset
  win; (3) make gate order short-circuit before the cap counter;
  (4) state the durable operator signal explicitly; (5) validate both
  feature modes. **All applied.** Honest framing applied: this PR does
  NOT claim to fix the original SEG_MISS false positive or TX-error
  accounting — those are already on master (#1283, 85858ec0d).
- **AGY** (`adversarial-review-mprtr52y-la8h95`, PLAN-NEEDS-MINOR, 1613
  tests pass): core diagnosis verified accurate, but flagged that
  Codex's point #4 rests on a false premise — `seg_needed_but_none` is
  `pub(in crate::afxdp)` and is **never** exported to Go/CLI (verified:
  it only feeds the periodic `seg_miss={}` debug-log string in
  `worker/loop_body/mod.rs:1040`). So naive gating makes a genuine
  production seg-miss **100% silent** (the fallback forwards the
  oversized frame → silently dropped by NIC/switch → black-holed
  connection, no trace). **Fix adopted:** surface a genuine seg-miss via
  the existing `record_exception("tcp_segmentation_miss", ...)`
  infrastructure so it appears under `Recent exceptions` in `show
  chassis cluster data-plane statistics`.
- **Claude-SMR**: PLAN-READY on the gate; ratified AGY's blindspot
  finding (independently confirmed `seg_needed_but_none` has no Go/CLI
  surface). Added a rate cap on the `record_exception` call so a
  pathological per-packet seg-miss cannot spin the `recent_exceptions`
  mutex on the hot path (engineering-style "rare error → bump counter,
  continue").

## Ancestry verification (run in worktree)

```
$ git merge-base --is-ancestor 0ce930385 HEAD && echo "#1283 ancestor"
#1283 ancestor
$ git merge-base --is-ancestor 85858ec0d HEAD && echo "TX-attr ancestor"
TX-attr ancestor
```

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
`count_forwarded_tcp_segmentation_miss_if_needed`) is `pub(in crate::afxdp)`
and has **no Go/CLI export**, so it is not operator-visible. Naive gating of
the eprintln would leave a genuine seg-miss 100% silent in release. The
`record_exception` call below closes that blindspot. Only the ad-hoc eprintln
becomes opt-in.

## Concrete design (v2 — gate + durable operator signal)

Two changes at the seg-miss site (`tx/dispatch/mod.rs:392-420`), both
inside the existing `if count_forwarded_tcp_segmentation_miss_if_needed(...)`
block. The `dbg.seg_needed_but_none` counter is unchanged (always
increments inside the counting helper). No change to the #1283 precheck.

1. **Gate the `DBG SEG_MISS` eprintln behind `cfg!(feature =
   "debug-log")`** inside the existing rate-cap block. Release builds still
   execute the cap check and `record_exception` (both always-on); only the
   packet-shape `eprintln!` body is DCE'd. Matches the intent of the five
   sibling gates in this file (lines 254/332/515/663/793).

2. **Record a first-class exception** so a genuine seg-miss is visible to
   operators in release via `show chassis cluster data-plane statistics`
   (`Recent exceptions`). This closes the blindspot AGY identified:
   `seg_needed_but_none` is `pub(in crate::afxdp)` with no Go/CLI export.
   The call is rate-capped by the same `< 20`-per-thread counter so a
   pathological per-packet seg-miss cannot spin the `recent_exceptions`
   mutex on the hot path.

```rust
if count_forwarded_tcp_segmentation_miss_if_needed(
    dbg, copied_source_frame, tcp_segmentation_needed,
) {
    thread_local! {
        static SEG_MISS_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }
    SEG_MISS_LOG.with(|c| {
        let n = c.get();
        if n < 20 {
            c.set(n + 1);
            // Durable, operator-visible signal (release-safe): surfaces
            // under `Recent exceptions` in data-plane statistics. Rate-
            // capped to 20/thread so a pathological per-packet seg-miss
            // cannot spin the recent_exceptions mutex.
            record_exception(
                recent_exceptions,
                ingress_ident,
                "tcp_segmentation_miss",
                source_frame.len() as u32,
                Some(request.meta.into()),
                None,
                forwarding,
            );
            // Debug-build-only packet-shape sample. Gated to match the
            // five sibling DBG prints in this file; default features =
            // [] so this DCEs out of release builds.
            if cfg!(feature = "debug-log") {
                let egress_mtu = forwarding.egress
                    .get(&request.decision.resolution.egress_ifindex)
                    .or_else(|| forwarding.egress.get(&request.decision.resolution.tx_ifindex))
                    .map(|e| e.mtu);
                eprintln!("DBG SEG_MISS[{}]: frame_len={} proto={} egress_if={} tx_if={} egress_mtu={:?} target_if={} src_frame_bytes={}",
                    n, source_frame.len(), request.meta.protocol,
                    request.decision.resolution.egress_ifindex,
                    request.decision.resolution.tx_ifindex,
                    egress_mtu, request.target_ifindex, source_frame.len());
            }
        }
    });
}
```

I will confirm `recent_exceptions` and `ingress_ident` are in scope at
the seg-miss site (they are used by the sibling `record_exception` call
at line 342 inside the same function) before editing.

## Public API preservation

No public API change. `count_forwarded_tcp_segmentation_miss_if_needed`
signature and return semantics unchanged. `DebugPollCounters::
seg_needed_but_none` unchanged. CLI stats output unchanged.

## Hidden invariants preserved

- `seg_needed_but_none` still increments unconditionally (counter is the
  signal of record; only the eprintln becomes opt-in). Verified by the
  existing truth-table test (`#1283` added
  `forwarded_tcp_may_need_segmentation` / seg-miss-counter tests).
- No allocation change in release. The `cfg!(feature)` collapses to
  `const false`, so the `eprintln!` body DCEs out, but the rate-cap check
  and `record_exception` remain in release (intentionally always-on so a
  genuine seg-miss surfaces under `Recent exceptions`). The behaviour
  differs from the pure-log siblings in this file which DCE the entire
  block.
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
- `cargo build --features debug-log` — compiles the gated block, but **fails
  with a pre-existing `ICMPV6_EMBED_LOGGED private` visibility error
  unrelated to this PR** (tracked in #1678; not in scope here).
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
