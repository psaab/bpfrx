# Codex adversarial plan-review — round 84 (plan v85 @ 9f1f3ab69)

Codex companion task-msb885pc-6jxj7m (session 019fc077-247d-7123-a924-4c3daa952d91). Verdict: PLAN-NEEDS-MAJOR (1 MAJOR — the v85 helper signature cannot implement the registry contract: a single `*ebpf.Map`-returning helper cannot serve the m.programs registry — program reads at loader.go:495/:609/:1086/:1156 — nor carry presence/classification; the retained XDP fixture's present-but-nil *ebpf.Program at xdp_shim_decouple_test.go:321 proves presence is observably required — 1 MINOR: the never-armed-Close qualification; New() starts empty at loader.go:89 and bootstrap can skip Start at daemon_run_bringup.go:483). Codex explicitly declined the mid-Close-publisher schedule as out-of-scope (v85 excludes re-arm linearizability and teardown lifetime ordering). Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 1 major, 1 minor

Yes. Finding 1 is inside PR-1 and blocks `PLAN-READY` for #2114.

1. **MAJOR — v85’s exact helper signature cannot implement A3’s registry contract.**

   The plan requires every `m.maps` and `m.programs` access to perform classification and handle selection atomically through one helper ([plan.md:3666](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3666)), but fixes that helper as:

   `func (m *Manager) registryLookupLocked(name string) *ebpf.Map`

   ([plan.md:4793](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4793)).

   That shape is insufficient:

   - The registries have different value types: `*ebpf.Program` and `*ebpf.Map` ([loader.go:37](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:37)). Program reads exist in `AttachXDP`, swap, `AttachTC`, and `Program` ([loader.go:495](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:495), [loader.go:609](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:609), [loader.go:1086](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1086), [loader.go:1156](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1156)). A `*ebpf.Map` result cannot serve them, and the exact allowlist names no program counterpart.
   - The result carries neither registry state nor presence. Class-1 and class-4 callers must distinguish fresh-empty, which gets `ErrDataplaneNotArmed`, from retained/armed missing-key behavior, which preserves the legacy outcome ([plan.md:3683](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3683), [plan.md:4486](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4486)). A pointer alone cannot communicate that distinction.
   - Presence is observably required: the retained XDP fixture deliberately inserts a present-but-nil `*ebpf.Program` ([xdp_shim_decouple_test.go:321](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/xdp_shim_decouple_test.go:321)), which current comma-`ok` lookup accepts; the plan says this fixture continues to work ([plan.md:4820](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4820)).

   Required fold: specify exact non-escaping map and program helpers returning handle, presence, and classification—or an equivalent typed result—and align the canary allowlist and negative fixtures with those actual signatures.

2. **MINOR — the teardown fold’s rationale is still unconditional where the code is not.**

   The loaded-check-set-only qualification itself is correct. However, the summaries say `Close` retains a nonempty registry and ordinary methods therefore classify retained ([plan.md:3889](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3889), [plan.md:4051](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4051), [plan.md:4504](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4504)).

   That is true only for an armed Manager. `New()` starts with empty registries ([loader.go:89](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:89)); bootstrap mode can skip `Start` while retaining the constructed backend ([daemon_run_bringup.go:483](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:483)); shutdown still calls `Close`/`Teardown` ([daemon_run_shutdown.go:214](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_shutdown.go:214)). Qualify the rationale as “an armed Manager’s Close”; a never-armed Close remains fresh and its false-store changes nothing.

Verified passes:

- No `range m.maps` or `range m.programs` exists. `GetMapStats` and `ClearSessionCounts` range descriptor/name lists and then perform keyed lookups. Publisher loops range acquisition-owned source collections, not the Manager registries.
- No production slice-of-handles return or long-lived raw `*ebpf.Map`/`*ebpf.Program` cache exists.
- The publisher is correctly specified as a direct-write leaf under `m.mu`; it must not call the lock-taking lookup helper, so no publisher self-deadlock is prescribed.
- A concurrent re-Start can overwrite Close’s entry false-store, but v85 explicitly excludes re-arm linearizability and teardown lifetime ordering. I do not count that as another PR-1 blocker.
- No other A3/§7/§9 contradiction survived.

HEAD and branch match `9f1f3ab69` / `research/2114-nat-pool-alarm-dp-race`. No files were changed.

Codex session ID: 019fc077-247d-7123-a924-4c3daa952d91
Resume in Codex: codex resume 019fc077-247d-7123-a924-4c3daa952d91
