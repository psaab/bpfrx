# PR #1957 (#1946) — reviewer task ids + verdicts

Final SHA at review dispatch: `85b322c85a6a2415aec5165052738b921b7ef198`

## Plan-review (research phase)

| Round | Reviewer | Verdict | Task id |
|-------|----------|---------|---------|
| r1 | Claude SMR | PLAN-READY | (in-conversation) |
| r1 | Codex | PLAN-NEEDS-WORK → addressed | task-mqi86st4-5n620c |
| r1 | AGY | PLAN-NEEDS-WORK → addressed | adversarial-review-mqi87f3t-vf66ct |
| r2 | Codex | PLAN-READY | task-mqi8g0px-katnme |
| r2 | AGY | PLAN-READY | adversarial-review-mqi8g6qf-jyxikq |

## Implementation review (PR #1957)

Final SHA: `af7a89a7fa4795d9bb8cdd815978361ee2707bf1`

| Round | Reviewer | Verdict | Task id |
|-------|----------|---------|---------|
| r1 | Claude SMR | MERGE-READY | (in-conversation) |
| r1 | Codex | NEEDS-WORK (Prebuilt MEDIUM) → fixed | task-mqi8y8o1-s7jt76 |
| r2 | Codex | **MERGE-READY** | task-mqi976f2-o57x7u |
| r1 | AGY | (tool-loop glitch, timed out — re-run) | adversarial-review-mqi8ygo5-qlac5c |
| r2 | AGY | **MERGE-READY** | adversarial-review-mqi97f3r-ogk85j |
| r1 | Copilot | **no comments** (18/18 files) | (PR review) |

### Convergence

4-way MERGE-READY on the implementation: Claude SMR + Codex r2 + AGY r2
(AGY re-ran the suites: 2019 Rust tests pass, Go PASS) + Copilot clean.
STOP per parent instruction — no cluster smoke, no merge. The parent
runs the serialized failover gate (fabric fallback is exercised on VRRP
failback) and merges.

### Codex r1 finding → disposition

- MEDIUM (Prebuilt FabricRedirect dropped without the counter): **FIXED**
  in commit `af7a89a7f` — both Prebuilt early-exit arms now gate
  FabricRedirect (`fabric_redirect_no_binding` /
  `fabric_redirect_build_failed`) on the shared counter, with regression
  `enqueue_pending_forwards_counts_prebuilt_fabric_redirect_no_binding`.
  Codex r2 confirmed MERGE-READY and verified no other silent
  FabricRedirect path remains.

## Claude SMR (r1) — MERGE-READY

Read the full diff origin/master...HEAD.

- **No-binding block (mod.rs):** the FabricRedirect arm now bumps
  `ingress_live.fabric_redirect_unsendable_drops` (the BindingLiveState
  param that snapshot.rs/refresh_bindings.rs read), records the
  `fabric_redirect_no_binding` exception with
  `Some(request.meta.into())` (ForwardPacketMeta: From impl at
  types/mod.rs:183 → UserspaceDpMeta; Copy), then recycles + continues.
  `source_frame`/`ingress_area` are no longer touched on this path, so
  the Owned/Live decap/meta hazard is moot. No borrow conflict:
  `ingress_live` (shared &BindingLiveState, atomic bump) and
  `ingress_binding` (recycle) are distinct refs; both shared.
- **Build-failure gate (slow_path.rs):** the FabricRedirect early-return
  is placed after the `forward_build_failed` exception and BEFORE the
  `fallback_to_slow_path` reinject, using `live` (the BindingLiveState
  param) + `binding` + the already-`into()`'d `meta`. ForwardCandidate
  and every other disposition still reach the reinject — gate is
  FabricRedirect-only.
- **Plumbing:** all 7 sites match the `tunnel_encap_unresolved_drops`
  precedent (verified each: umem field+ctor, snapshot, worker rollup,
  refresh copy+zero, reset zero, protocol serde, Go field). Fixture
  regen added exactly `"fabric_redirect_unsendable_drops": 0`.
- **Tests:** both build-failure tests would fail if the gate were
  removed (drop test would see `slow_path_drops==1` /
  `fabric_redirect_unsendable_drops==0`; ForwardCandidate guard would see
  the counter wrongly bumped). Wire-key test uses a full-default
  serialization minus the key (BindingStatus has required fields, so a
  bare `{}` fails — handled).
- **No other ungated path:** Codex r2 + AGY r2 already swept; the
  remaining `_from_frame` callers are the gated chokepoint, the
  ForwardCandidate build-failure reinject, dispatch no-binding (now
  gated), and tests.
- **Docs:** slow_path.rs + forwarding.rs comments now state one remaining
  intentional unfiltered caller (ForwardCandidate). Accurate.

No blocking findings. MERGE-READY pending Codex + AGY + Copilot.
