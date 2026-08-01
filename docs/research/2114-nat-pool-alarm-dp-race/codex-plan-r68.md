# Codex hostile plan-review — round 68 (plan v69 @ ee70003a3)

Task: task-msaor22j-qq82yz (session 019fbe84-0763-7e62-a041-6b633d9b9f65).
Verdict: PLAN-NEEDS-MAJOR (1 MAJOR, 4 MINOR — the first PR-1-surface MAJOR since the r28/v69 split: the armed-state method gate). Structure confirmed clean list reproduced in-line. Raw companion output follows verbatim.

---

Verdict: **PLAN-NEEDS-MAJOR**

### Findings

1. **MAJOR 1 — atomic publication closes interface tearing, but not the claimed watcher-chain/backend initialization race.**

   The plan publishes at the existing construct site ([plan.md:3586](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3586)) and preserves program order ([plan.md:3821](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3821)). That gives readers a coherent `dpSlot`, but the referent is not yet started:

   - The cluster watcher starts at [daemon_run_bringup.go:203](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:203), and initial election synchronously queues transitions at [group_state.go:125](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/cluster/group_state.go:125) and [election.go:443](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/cluster/election.go:443).
   - The proposed Store replaces the assignment at [daemon_run_bringup.go:469](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:469), while `Start` remains later at [daemon_run_bringup.go:493](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:493).
   - The watcher can therefore load the coherent-but-starting backend and call `SetRGActive` at [daemon_ha.go:297](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:297).
   - `Start` populates the plain `bpfShim.maps` map at [loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185), while `SetRGActive` reads that same map at [maps_fabric.go:38](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go:38). These paths share no lock.

   This is a real concurrent Go-map read/write possibility. An atomic Store orders constructor writes preceding publication; it cannot order mutations performed by the later `Start`.

   Bootstrap has the same missing lifecycle distinction: servers capture the unarmed object at [daemon_run_servers.go:117](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_servers.go:117), later `Start` writes `loaded` at [loader.go:164](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:164), and request-time `IsLoaded` reads it unsynchronized at [loader.go:457](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:457).

   These hazards exist on master, so PR-1 does not worsen them. But that does not support the unqualified claim that PR-1 closes the watcher chain at the memory-ordering level ([plan.md:3493](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3493)), nor the requested “no half-initialized dataplane” property. G/H/H2 do not gate the ordinary cluster watcher.

   The plan needs an explicit constructed-versus-ready publication invariant or equivalent backend lifecycle synchronization. Moving publication after `Start` also requires delaying/replaying the initial HA transition so an event consumed while the cell is nil is not lost. Bootstrap needs separate treatment. Add a blocked-`Start` regression proving watcher/request methods cannot race backend initialization; the current nil-or-full fake test at [plan.md:3959](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3959) cannot detect this.

2. **MINOR 1 — a pure PR-1 RACE-3 test leg was swept into the follow-up.**

   [plan.md:3962](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3962) moves the whole confirm-timer test. But seed leg (b) at [followup-seed.md:4419](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md:4419) is solely an unordered `setDataplane` Store versus `d.dataplane()` Load. It has no G/H/H2 dependency and should remain `[CORE]`.

3. **MINOR 2 — sampler narrowing drops the existing nil-receiver contract.**

   The plan specifies `forwardingStatusDataplane()` as nil only for `d.opts.NoDataplane` at [plan.md:3420](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3420), whereas the current function explicitly accepts `d == nil` at [daemon_forwarding_status.go:123](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go:123). Preserve `if d == nil || d.opts.NoDataplane`.

4. **MINOR 3 — sampler documentation/deletion inventory is incomplete.**

   The “three files touched” inventory at [plan.md:3394](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3394) omits:

   - Updating the stale `DataPlaneAccessor.CachedStatus()` wording at [pkg/fwdstatus/README.md:33](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/README.md:33).
   - Updating “failed `Status()` call” at [sampler.go:48](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler.go:48).
   - Removing the now-unused `errors` import at [daemon_forwarding_status.go:3](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go:3).

5. **MINOR 4 — the PR-1 document still contains normative follow-up residue.**

   [plan.md:3106](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3106) says remaining G/H/H2 references are only pointers/history, but the full shutdown-admission invariant remains at [plan.md:3845](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3845), and normative H2 health-output text remains at [plan.md:3806](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3806). These are not load-bearing dependencies, but they contradict the extraction claim and should become seed pointers.

### Confirmed clean

- The census reconciles exactly: 163 matching production lines minus 29 full-line comments equals 134 executable sites, with exactly 5 writers and 129 readers. The plan table and source coordinate sets match exactly.
- Retyping `dp` to `dpCell` compiler-enumerates all current selectors and keyed literals.
- `dpSlot` immutability, fresh-slot Store, kind-gated typed-nil handling, and snapshot rules are otherwise sound.
- The collapsed one-method sampler adapter cannot satisfy `DataPlaneAccessor`; `Build`’s `Status()`-presence routing is therefore unmisroutable. The negative-satisfaction test correctly pins that.
- The `IndexExpr` matcher extension and package-local `dpCell` canary pin both boundary directions.
- No PR-1 conversion was found that worsens a G/H/H2 hazard, and PR-1 correctness does not depend on those units shipping.

**Does anything in PR-1 block PLAN-READY for #2114? Yes: MAJOR 1.** This is not PLAN-KILL—the atomic-cell premise correctly solves interface-pair tearing—but the publication/lifecycle architecture is incomplete and must be revised before implementation.

Codex session ID: 019fbe84-0763-7e62-a041-6b633d9b9f65
Resume in Codex: codex resume 019fbe84-0763-7e62-a041-6b633d9b9f65
