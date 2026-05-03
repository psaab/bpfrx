# #916 — CoS deadlock when interface has no shaping-rate

## Status

REV-2 — addresses Codex round-1 PROCEED-WITH-CHANGES (4 required fixes).

Round-1 deltas:
- §Cause analysis updated: Codex confirmed the runtime-deadlock the
  issue describes is currently MASKED by an upstream skip in
  `forwarding_build.rs:641-643` that drops the entire CoS runtime for
  zero-shaping interfaces. The user-visible symptom is therefore
  "CoS classifier silently doesn't apply on the no-shaping interface"
  (packets fall through to non-CoS forwarding via the
  `cos_classify.rs:694` `None`-return path). Either way the fix is
  the same: build the runtime with transparent semantics.
- §Fix expanded from 3 changes to 5 (add upstream-skip removal +
  zero `transmit_rate_bytes` fallback policy).
- §Risks §"shared_root_lease at rate 0": Codex CONTRADICTED the
  plan's "never accessed" claim. Updated to acknowledge the lease's
  `consume` call paths are still hit, document that they're
  saturating/benign, OR add explicit skip.
- §Tests expanded: cover the upstream skip removal + transparent-root
  + per-queue exact cap interaction + mixed-interface configs +
  zero queue-rate behavior.

## Bug

If a Junos config sets up CoS classes/queues on an interface without
`set class-of-service interfaces <ifd> unit <unit> shaping-rate <bps>`,
all CoS traffic on that interface drops to zero. From the issue:

1. `build_cos_interface_runtime` stores `shaping_rate_bytes = 0` from
   the snapshot (no `shaping-rate` configured → snapshot defaults to 0).
2. `root.tokens` initializes to 0; `maybe_top_up_cos_root_lease` would
   normally refill but the `shared_root_lease` has rate 0 too.
3. `estimate_cos_queue_wakeup_tick` calls
   `cos_refill_ns_until(0, need, 0)` → returns `None`.
4. The queue is never parked (caller of `estimate_cos_queue_wakeup_tick`
   bails out on `None`) AND never served (root.tokens < head_len
   forever).
5. Result: every CoS queue on the interface stays in limbo.

Reproduction (described in #916): apply CoS scheduler-map + classifier
+ filter to an interface but omit `shaping-rate`. Send traffic. All
classes drop to zero.

## Cause analysis

The token-bucket helpers (`token_bucket.rs`) treat `rate=0` as "the
caller is mistaken, return `None`" — a defensive sentinel for unit
tests. But `shaping_rate_bytes == 0` from the config is NOT a
defensive case: it's a valid Junos configuration that means
"no rate cap on this interface" (Junos default behavior — without
explicit `shaping-rate`, traffic is line-rate-limited only). The bug
is that the code treats the absent-config case as the malformed-call
case.

## Fix

**Treat `shaping_rate_bytes == 0` as "transparent root"** — the root
token bucket is bypassed entirely; the per-queue token buckets
continue to function. This matches both the Junos semantic
("no shaping-rate" → "no shaping at the interface level") and the
issue's own proposed fix #1 ("transparent mode").

### Changes

1. **`forwarding_build.rs:641-643` upstream skip removal**: the
   condition `iface.cos_shaping_rate_bytes_per_sec == 0 { continue; }`
   currently drops zero-shaping interfaces from CoS state entirely.
   With transparent-root semantics, zero-shaping is a valid
   configuration. Change the guard to skip ONLY on `iface.ifindex <= 0`;
   permit zero shaping rate through to the runtime build path.

2. **`token_bucket.rs::maybe_top_up_cos_root_lease`**: at the top, if
   `root.shaping_rate_bytes == 0`, fast-path-fill the bucket to
   `burst_bytes.max(COS_MIN_BURST_BYTES)` and return. Skip the shared
   lease acquire (which would also be 0-rate).

3. **`queue_service/mod.rs::estimate_cos_queue_wakeup_tick`**: if
   `root_rate_bytes == 0`, treat the root-refill check as an
   immediate pass (bypass the `cos_refill_ns_until` call for the
   root). The per-queue refill check still runs.

4. **Zero `transmit_rate_bytes` fallback policy** (Codex finding 6):
   `forwarding_build.rs:660` falls back to
   `iface.cos_shaping_rate_bytes_per_sec` when the scheduler
   provides no rate. With transparent root, that fallback resolves
   to 0 and the per-queue token-bucket also deadlocks. Explicit
   policy: when the resolved `transmit_rate_bytes == 0` AND the
   parent root is transparent, ALSO treat the queue as
   transparent — initialize tokens to `buffer_bytes.max(COS_MIN_BURST_BYTES)`
   and bypass the per-queue refill check in `estimate_cos_queue_wakeup_tick`
   (extend the same `rate == 0` guard).

5. **`builders.rs::build_cos_interface_runtime`**: belt-and-
   suspenders — if `shaping_rate_bytes == 0`, initialize `root.tokens`
   to `burst_bytes.max(COS_MIN_BURST_BYTES)` instead of 0. Same for
   per-queue tokens when both root and queue are transparent.

6. **`token_bucket.rs::cos_refill_ns_until`**: keep current `None`
   return for `rate=0` (correctness-as-an-invariant). Add a doc
   comment cross-referencing the bypass logic in callers. Codex
   finding 4 noted that `shared_root_lease.consume` is still called
   on the apply path (`tx_completion.rs:314-320`, `:442-448`,
   `:508-513`) even after top-up bypass; the consume is
   `saturating_sub`-style and is benign at rate=0 (lease starts with
   burst credits and never refills). Document this in the lease
   wrapper rather than adding bypass branches at every consume site.

### What this PR does NOT do

- **No "auto-fill shaping-rate to link rate" auto-detection.** That
  would require netlink ETHTOOL_GLINKSETTINGS plumbing which isn't
  cleanly available in the userspace dataplane. Transparent root is
  cleaner and matches Junos semantics.

- **No `cos_refill_ns_until` API change.** Callers can be audited to
  ensure they handle the `rate=0` case explicitly; the helper's
  current contract is "tells you when tokens will be enough; if rate
  is 0 there's no answer". Changing this would be a bigger surface
  change than the bug warrants.

- **No fix for queue-level `transmit_rate_bytes == 0`.** That's a
  separate (similar) deadlock case but #916 is specifically about
  root shaping-rate. Filed as a follow-up note in the design doc;
  if reviewers think it belongs in scope, will widen.

## Tests

- **`forwarding_build_tests.rs`** (Codex finding 7):
  - `build_cos_state_includes_zero_shaping_rate_interface` — assert
    a snapshot interface with `cos_shaping_rate_bytes_per_sec = 0`
    + a non-empty scheduler-map produces a `CoSState` entry, not
    skipped silently.
  - `build_cos_state_zero_shaping_rate_queue_inherits_transparent` —
    when the scheduler has no transmit-rate AND the interface has
    no shaping-rate, queue is built with transparent semantics
    (rate 0 + tokens initialized to buffer cap).

- **`cos/builders_tests.rs`**:
  - `build_cos_interface_runtime_zero_shaping_rate_starts_with_full_root_tokens`
    — `root.tokens == max(burst_bytes, COS_MIN_BURST_BYTES)` when
    `shaping_rate_bytes == 0`.

- **`cos/token_bucket_tests.rs`**:
  - `maybe_top_up_cos_root_lease_transparent_when_shaping_rate_zero` —
    construct a root with `shaping_rate_bytes = 0` and a lease with
    rate 0; assert tokens are at the burst cap and no lease acquire.

- **`cos/queue_service/tests.rs`**:
  - `estimate_cos_queue_wakeup_tick_root_rate_zero_returns_some` —
    `root_rate_bytes = 0` + queue with non-zero rate → `Some(_)`.
  - `estimate_cos_queue_wakeup_tick_both_rates_zero_returns_some` —
    transparent root + transparent queue → `Some(_)`.
  - `transparent_root_preserves_per_queue_exact_cap` (Codex finding 7
    coverage gap) — transparent root + per-queue exact cap of
    1G; assert that drain does NOT exceed the per-queue cap.

- **`cos/builders_tests.rs` mixed-interface**:
  - `build_cos_state_mixed_zero_and_nonzero_shaping_rate` — snapshot
    with two interfaces, one shaping-rate=25G, one shaping-rate=0;
    assert both produce CoSState entries with the correct
    transparent vs non-transparent root semantics.

- Integration / smoke (see Acceptance gate below).

## Acceptance gate

- `cargo test --release` — all existing tests pass + ~7 new unit
  tests (build_cos_state coverage + transparent-root semantics).
- `cargo build --release` — clean, no new warnings.
- **Cluster smoke (loss userspace cluster)**:
  - **Pre-fix repro** (current master behavior):
    deploy current master; apply a CoS config WITHOUT
    `shaping-rate` on a test interface; verify the symptom
    (CoS classifier silently doesn't apply — packets bypass
    classification, no DSCP-based scheduling).
  - **Post-fix verification**: deploy this PR, repeat the
    no-shaping-rate config; verify CoS classifier applies AND
    traffic flows at line rate (transparent root: no interface cap).
  - **Per-queue exact cap regression** (transparent root must
    preserve per-queue caps): apply a config with no shaping-rate
    BUT with iperf-a's 1G `transmit-rate exact`. Verify iperf-a
    is shaped to 1G (exact cap honored) while best-effort runs
    at line rate (no interface cap).
  - **Standard regression**: re-apply the standard CoS config WITH
    `shaping-rate` (`./test/incus/apply-cos-config.sh
    loss:xpf-userspace-fw0`); run the standard 6-class iperf3
    smoke against BOTH `172.16.80.200` (IPv4) AND
    `2001:559:8585:80::200` (IPv6). All classes pass at expected
    rates with 0 retransmits.

## Risks

1. **Transparent root + non-zero queue rate**: the per-queue token
   bucket still gates the queue; transparent root only removes the
   interface-level cap. Confirm by reading queue-service code that
   `root.shaping_rate_bytes == 0` doesn't accidentally skip
   per-queue accounting.

2. **Multi-interface mixed config**: an HA cluster where one
   interface has shaping-rate and another doesn't. Both should
   work — the fix is per-interface (root_ifindex keyed). Smoke
   should cover this.

3. **shared_root_lease with rate 0**: currently the coordinator
   allocates a 0-rate shared root lease for a 0-rate interface. After
   this fix, that lease is never accessed (transparent root short-
   circuits before `lease.acquire`). Verify by code-audit; should be
   benign (the lease object exists but is no-op).
