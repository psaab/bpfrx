# Triage result — ps-review-033.md

## Header
- **Review type:** Single-cohort deep security audit (**Cohort 8 — firewall
  filters + PBR + routing**). NOT the 884-line all-cohort synthesis the task
  brief described — the actual file is 423 lines / 8 findings (F-001..F-008)
  under the heading "xpf firewall deep audit — Cohort 8". Task/file mismatch
  noted; triaged the actual content.
- **Review base:** 8cd816e35 (Merge PR #4545).
- **Current master at triage:** 29fc0d45d (Merge PR #4554).
- **Base freshness:** effectively current. Base→master is only 4 PRs
  (#4544 host-inbound-dup, #4539 session-cache-has-syn, #4543 malformed-IPv4-
  option, #4547 IPsec DNS) — NONE touch cohort-8 filter/PBR/routing code.
  `git merge-base --is-ancestor 8cd816e35 origin/master` = YES. All cited
  symbols re-verified on origin/master.
- **Repo:** real bpfrx (verified — every cited symbol present on
  origin/master with matching line ranges; no avacado-fork tells).
- **Outcome counts (8 findings):**
  - NOVEL GENUINE-RESIDUAL: **0**
  - ALREADY-FIXED (verified on master): 4 (F-004 #4535, F-005 #4534,
    F-006 #4514, F-007 #4287/#4296/#4426)
  - NEGATIVE (correct code, no bug): 1 (F-008)
  - NOT-MATERIAL / DEFENSE-IN-DEPTH / DOCUMENTED: 3 (F-001, F-002, F-003)
  - CONFABULATED: 0
- **Dedup accounting:** The review is *self-dedup'd* — its own
  "Duplicate-suppression summary" pre-suppresses ~30 items against the
  session's filed/merged issues (#4535/#4534/#4526/#4525/#4524/#4521/#4519/
  #4518/#4517/#4514/#4400/#4453/#4487/#4399/#4438/#4392/#4384, plus #4549/
  #4548/#4547/#4546/#4544/#4533/#4515/#4512/#2387 listed OPEN-not-re-reported).
  Those match the parent's filed/merged list — no re-report. Of the 8
  findings actually written up: 4 are its own NEGATIVE re-confirmations of
  session PRs, 1 NEGATIVE, 3 are known/moot residuals it explicitly declines
  to file. **0 novel driveable issues.** This matches the review's own
  conclusion ("New findings: 0 High/Med fail-opens... Suggested issue split:
  NONE").

---

## Per-finding disposition

### F-001 — flex_mask == 0 turns flexible-match-range into match-all
**Disposition: NOT-MATERIAL (defense-in-depth only; Go/config path provably safe). Known reviewer-aggregation item (F-236), not a session GH issue.**

The finding claims `(val & term.flex_mask) == term.flex_value` at
`matching.rs:149` becomes match-all when `flex_mask == 0`. Verified the line
exists (comment at matching.rs:101 explicitly documents `flex_value` is
"pre-masked"). But the exploitable sub-case (mask=0, value≠0 → never-match →
fail-open on a discard term) **cannot arise through any config path**, for two
independent reasons proven on master:

1. **Value is pre-masked at the boundary.** `filters.go:298`:
   `Value: fm.Value & fm.Mask`. If mask=0, the snapshot value is forced to 0,
   so `(val & 0) == 0` is always true = match-all = the *correct* Junos
   semantics for an explicit zero mask.
2. **The config compiler never emits mask==0 anyway.** `compiler_firewall.go`
   (the `if fm.Mask == 0 { ... }` block, ~line 998) *re-defaults* a zero mask
   to the low `BitLength` bits (0xFFFFFFFF for 32-bit). This runs
   unconditionally when `fm.Mask == 0`, so even an explicit
   `match-value 0x0/0x0` is rewritten to a non-zero mask before it reaches the
   snapshot. mask==0 is therefore unreachable via commit.

So the only way to reach mask=0 with value≠0 is a hand-built / version-drifted
/ corrupt snapshot that violates the Go builder's invariant — not an attacker-
or config-reachable path. The project's other flex integrity failures (length
out of 1..4, unsupported match-start) are backstopped by
`SnapshotIntegrityError`; adding a symmetric `mask==0` reject would be a
consistent hardening, but it is strictly defense-in-depth. **Why not higher:**
no config/attacker path; Go invariant closes it. **Why not dismissed
outright:** the sibling-backstop asymmetry is a real (low) DoD gap. The review
itself already reaches this conclusion and declines to file it; it is the
reviewer's own aggregation id F-236, not a session-filed issue. No new issue
warranted.

### F-002 — PBR / next-table global ip rule has no iif selector
**Disposition: DELIBERATE (documented widening) + per-RI next-table = known gap (reviewer id F-174). Not novel.**

PBR mirror installs `from <src> to <dst> lookup <table>` with no `iif`
(rules.go BuildPBRRules / pbrManager.Apply — verified present). The review
correctly identifies this as the *documented* widening vs Junos per-interface
FBF (listed under "Intentional divergences" in the file's own header and in
CLAUDE.md's routing notes). The per-RI next-table non-programming
(daemon_apply.go passes only main-table StaticRoutes + Inet6StaticRoutes to
nextTableManager) is a parity gap the reviewer tracks as F-174 — a
documented-limitation, not a fail-open (nothing is mis-steered; per-RI
next-table simply isn't installed, and per-RI routes go through the VRF
mechanism). The review explicitly marks this "VERIFIED DOCUMENTED GAP (not a
new finding)". **Why not material:** no security regression — a widened rule
matches a *superset* by source prefix, and the co-located discard/reject
fail-open that *would* make widening dangerous is already closed by #4534
(F-005). No issue warranted.

### F-003 — filter_term_semantics_match omits flex_* fields
**Disposition: NOT-MATERIAL / DUP-of-prior-triage (ps-review-024 M-02). Moot via flow-cache decline.**

Verified: `cache_sensitive.rs::filter_term_semantics_match` does not compare
flex fields. But this is moot for cache correctness because
`mod.rs:267-276 has_per_packet_l4_match()` includes `flex_enabled` (line 276),
and `flow_cache.rs:431-443` DECLINES caching
(`interface_input/output_filter_has_per_packet_l4_match` → `return None`) for
any filter carrying flex. With no cached verdict to replay, a missed flex-field
change in the semantics comparison has nothing to invalidate. This is the exact
item already triaged NOT-MATERIAL as ps-review-024 M-02 (referenced in the
file's own dedup header). Pure defense-in-depth against a hypothetical future
where the decline path is removed. **Why not higher:** no live replay path
exists. No issue warranted.

### F-004 — Three-color policer color-blind default
**Disposition: ALREADY-FIXED #4535 (verified on master).**

`compiler_firewall.go:171-178`: the loop defaults `tcp.ColorBlind = true` when
neither `ColorBlindConfigured` nor `ColorAwareConfigured` is set (verified via
`git show origin/master`). Before the fix, an unspecified color mode →
ColorBlind=false → `snapshot_three_color_shape_supported` false → fail-closed
drop-all → whole dataplane disarmed. Fix present and unchanged on 29fc0d45d.

### F-005 — PBR discard/reject kernel-mirror fail-open
**Disposition: ALREADY-FIXED #4534 (verified on master).**

`rules.go:778-800`: a term co-locating `then routing-instance` with terminating
`discard`/`reject` skips building the steering ip rule ("deny wins", mirroring
the userspace drop of #4392), and `validateFilterRoutingInstanceConflictStrict`
rejects it at strict commit / warns lenient. Verified present on master. This
closes the fail-open VRF-leak where the kernel steered a packet the dataplane
dropped.

### F-006 — Single-rate policer silently unenforced
**Disposition: ALREADY-FIXED #4514 (verified on master).**

`compiler.rs:82-106`: single-rate `firewall policer` token buckets are lowered
into the three-color srTCM runtime (`parse_single_rate_policer_runtime`,
distinct `single_rate_policer_runtime_id` namespace). Verified present. Before
#4514 the policers map was never consumed and `then policer X` was a no-op.

### F-007 — Family any IPv6 dual-compile
**Disposition: ALREADY-FIXED #4287/#4296/#4426 (verified — see F cohort header).**

`compiler_firewall.go` family-any dests span both maps;
`validateFirewallFilterFamilyAnyMatchesAST` rejects single-family matches and
single-family prefix-lists under `family any`. Consistent with the session's
prior merges. No residual bypass.

### F-008 — is-fragment match on non-first fragment
**Disposition: NEGATIVE (correct code, no bug).**

`matching.rs:56`: `if term.is_fragment && !extra.is_fragment { return false; }`
— `is_fragment` is L3-derived and NOT gated by `l4_present`, so non-first
fragments (which carry the IP fragment flag but no L4 header) still match
`from is-fragment` terms. Correct Junos semantics. Verified.

---

## Cross-cutting check (the point of a synthesis triage)
The task's value-add would be a cross-cohort finding no single audit surfaced.
This file is a *single* cohort-8 audit, not the multi-cohort roll-up the brief
named, and it self-concludes 0 new fail-opens. I independently verified the
three residuals it declines to file are each bounded by an existing, verified
mechanism (F-001 by the Go pre-mask + mask re-default; F-002 by the #4534
deny-wins fix removing the only dangerous widening interaction; F-003 by the
flow-cache decline). No cross-cutting novel residual exists in this file.

## Bottom line
0 NOVEL genuine residuals. 4 already-fixed re-confirmations (all verified on
current master), 1 clean negative, 3 known/moot/documented DoD items the review
itself declines to file. No new issue to open; nothing to drive.
