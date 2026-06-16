PLAN-NEEDS-REVISION (blockers)

**Blockers**
1. Copy/verify ordering contradicts itself: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:284) says staged `xpf-upgrade` copies into `/var/lib/xpf/versions/<N+1>/` before verify, but [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:347) says verify failure means nothing was copied to a runtime version. Pick one sequence.

2. Kernel scope still conflicts: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:175) and [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:682) say kernel bumps go through Path C/image-replace, while [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:435) defines an active `xpf-upgrade kernel <ver>` verify-gated in-place channel. This is an implementation-scope contradiction.

3. Config manifest wording regressed/stayed stale: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:539) correctly says the manifest must not be a second file, but risk #3 still prescribes `.configdb/manifest.json` at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:604).

**Confirmed**
- The two-package `xpf-dataplane` contradiction is removed from the active design. The only `xpf-dataplane` mention I found is historical open question #6 at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:726).
- The design now consistently says one `xpf` package plus `xpf-appliance` metapackage, shim embedded in `xpfd`, no separate shim artifact, and no cross-package `Depends:` lockstep.
- AGY Gap A/B/C are captured: GRUB save-default guard in §6.3c/risk 18, versions retention in §6.3c/risk 19, and HA session-sync back-compat in §6.5/risk 20.

Codex session ID: 019ecf2d-4a23-7c63-ac23-504699c3c035
Resume in Codex: codex resume 019ecf2d-4a23-7c63-ac23-504699c3c035
