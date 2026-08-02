# Codex adversarial plan-review — round 87 (plan v88 @ 4183be25c5ef)

Codex companion task-msbb4fgb-hhyiz7 (session 019fc0c1-60db-7220-a47f-2953a89b10c6). Verdict: PLAN-NEEDS-MAJOR (1 MAJOR — the per-access fold is neither exhaustively inventoried nor adequately tested: v88's "complete 9+2=11" list omitted four optional sites — SessionCount's sessions/sessions_v6 at maps_session.go:327/:337 and setXDPAttachedFlag's vlan_iface_map at loader.go:730 plus iface_zone_map at :700; the true count is 13 if-ok + 3 nil-guard = 16; and the SUCCEEDS-only partial-registry oracle is NON-DISCRIMINATING — ClearNAT64Configs' required→optional→required chain (:319→:328→:340 via :309) is the discriminating path, assert success AND the count zeroed — 2 MINORS: A3 remains method-gated while §9 is per-access (class 1 should mean "contains at least one required access", gating at each required access); the Close-entry timing change omits direct IsLoaded observability — loader.go:456 feeds legacy_dataplane.go:86, health.go:104, server_show_status.go:19). Fold results otherwise: (handle, present, st) sufficient for required+optional; no conditionally-required production access; no sixth one-helper contract; the two-change lines correct; retained-registry claims match; no G+H+H2 leakage. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 1 major, 2 minors

Yes. Finding 1 is inside PR-1 and blocks `PLAN-READY` for #2114.

1. **MAJOR — the per-access fold is neither exhaustively inventoried nor adequately tested.**

   I found 132 production registry-read sites: 91 required, 41 optional, and zero whose absent outcome itself changes conditionally at runtime.

   | File | Required | Optional |
   |---|---:|---:|
   | `compiler.go` | 0 | 1 |
   | `loader.go` | 9 | 7 |
   | `maps_counters.go` | 3 | 2 |
   | `maps_fabric.go` | 5 | 0 |
   | `maps_filter.go` | 10 | 0 |
   | `maps_flow.go` | 2 | 0 |
   | `maps_mirror.go` | 2 | 0 |
   | `maps_nat.go` | 25 | 6 |
   | `maps_policy.go` | 17 | 1 |
   | `maps_screen.go` | 4 | 1 |
   | `maps_session.go` | 14 | 3 |
   | `maps_stale.go` | 0 | 19 |
   | `maps_stats.go` | 0 | 1 |

   The claimed “complete list—9 optional-if-ok + 2 nil-guard” actually enumerates 4 NAT + 7 stale + 2 nil-guard sites: 13, not 11 ([plan inventory](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4918)). Even under the narrow inline-comma-ok interpretation, it omits:

   - `SessionCount`’s two optional accesses ([maps_session.go:327](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go:327), [maps_session.go:337](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go:337)).
   - `setXDPAttachedFlag`’s optional `vlan_iface_map` access ([loader.go:730](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:730)); its preceding `iface_zone_map` access is also optional ([loader.go:700](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:700)).

   Those loader accesses materially compose into `AttachXDP`: required program lookup at `:495`, optional seed at `:591`, then deferred optional accesses at `:700/:730`.

   More importantly, the new oracle is non-discriminating. `SetNAT64Config` performs required `nat64_configs` work, then its optional lookup, then returns ([maps_nat.go:291](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:291), [maps_nat.go:299](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:299)). Both correct skip-and-fallthrough and an incorrect `if !present { return nil }` satisfy v88’s sole “SUCCEEDS” assertion ([plan.md:4936](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4936)).

   The discriminating existing path is `ClearNAT64Configs`:

   `required nat64_configs :319 → optional prefix :328 → required nat64_count :309 via :340`

   ([maps_nat.go:319](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:319), [maps_nat.go:328](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:328), [maps_nat.go:340](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:340)). The oracle must seed `nat64_configs` and a nonzero `nat64_count`, omit `nat64_prefix_map`, then assert success **and that the count was zeroed**, for armed and retained states. Otherwise a premature optional-miss return silently skips required work while all proposed tests remain green.

   Similar continuation hazards exist in `SessionCount`, `ClearSessionCounts`, `GetMapStats`, multi-map stale cleanup, and `setXDPAttachedFlag`.

   The artificial partial-registry fixture does not violate whole-batch publication; it is quiescent and orthogonal to the blocked-Start publication tests. It simply does not close the claimed oracle gap.

2. **MINOR — core A3 remains method-gated while §9 is per-access.**

   The normative A3 text still classifies a method and returns the typed error when it enters “the registry helper,” with only pure validation allowed before “the gate” ([plan.md:3680](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3680), [plan.md:3695](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3695)). §5.1 likewise says “gate before the first Start-state access” ([plan.md:4188](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4188)). That conflicts with §9’s rule that an optional access in any class must retain its skip/continue behavior ([plan.md:4909](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4909)).

   No current non-carve-out class-1 path starts optional-before-required; `Compile` is preempted by its existing loaded check. Thus this is presently a specification contradiction rather than a demonstrated runtime regression. A3 should say class 1 means “contains at least one required access,” and gating occurs at each required access—not at the method’s first Start-state access.

3. **MINOR — the Close-entry timing change still omits direct `IsLoaded` observability.**

   The lifecycle qualifications repeatedly limit the earlier false-store’s impact to the loaded-check set—attaches plus `CompileConfig` ([plan.md:3941](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3941), [§7](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4572), [§8](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4605)).

   But `Manager.IsLoaded()` directly exposes that same bit ([loader.go:456](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:456)), through the userspace adapter ([legacy_dataplane.go:86](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/legacy_dataplane.go:86)). REST and gRPC status observe it directly ([health.go:104](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/api/health.go:104), [server_show_status.go:19](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/grpcapi/server_show_status.go:19)). Moving false from Close exit to entry therefore also advances externally observable `IsLoaded()==false` and associated status/work gating during link closure. Name and test that impact.

Fold results otherwise:

- `(handle, present, st)` is sufficient for required and optional accesses, provided callers preserve exact skip/continue/return ordering.
- No production access is conditionally required; branch-selected accesses remain required whenever executed.
- The canary now correctly names both helpers plus `publishShimRegistryLocked`; I found no sixth normative one-helper contract.
- Both “exactly two fresh-state changes” lines correctly include class 1 plus `NewEventSource`.
- Retained-registry/no-drain claims otherwise match the code.
- No G+H+H2 dependency leaked into the PR-1 verdict surface.

Reviewed at `4183be25c5ef`; no files changed.

Codex session ID: 019fc0c1-60db-7220-a47f-2953a89b10c6
Resume in Codex: codex resume 019fc0c1-60db-7220-a47f-2953a89b10c6
