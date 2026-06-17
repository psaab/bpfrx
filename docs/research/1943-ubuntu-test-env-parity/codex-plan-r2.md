   Evidence corrected later: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:403) says rollback is `git revert`, not runtime env override.

**New Issues**
- The current dirty r2 introduces an internal package-name contradiction: §6.3 says use `linux-modules-extra-$(uname -r)`, but the affected-files table, validation plan, risk table, and rollback text still say `linux-modules-extra-generic` at lines 100, 342, 347, 388, and 405. That must be made consistent.

- Minor but worth fixing: Path V2 says "`incus image import` the qcow2" at lines 240 and 366, but the repo’s install docs require metadata tarball + qcow2 for Incus VM import. The plan should name both artifacts.

Final verdict: PLAN-NEEDS-WORK. The direction is right and this is not PLAN-KILL, but r2 still has stale contradictory text on two r1 findings plus one new package-name inconsistency.
tokens used
84,422
Note: HEAD is `3f8952c04`, but `plan.md` is currently modified in the worktree. I reviewed the current file on disk.

**R1 Findings**
1. STILL-OPEN: A4 mechanism is fixed later, but stale false wording remains.
   Evidence still wrong: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:35) says "`grub-reboot` one-shot promote".
   Evidence corrected later: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:221) says "`efibootmgr --bootnext <inactive-slot>`" and [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:228) says vanilla cloud VM lacks the A/B substrate.

2. RESOLVED: kernel gate now includes extra NIC modules.
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:173) says "ADD `linux-modules-extra-$(uname -r)`"; [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:183) says to mirror the driver-dir assertion.

3. RESOLVED: package audit now covers the missing deltas.
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:186) maps `linux-perf` to `linux-tools-generic`; [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:188) drops `golang`; [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:195) maps `host` to `bind9-host`; [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:198) covers `frr-pythontools` and `ethtool`.

4. RESOLVED: grub drop-in reboot is retained.
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:148) says "KEEP the reboot step"; [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:153) says a single grub-apply reboot is retained.

5. RESOLVED: cluster validation now requires recreate, not deploy.
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:373) says "must RECREATE, not just deploy"; [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:375) says `cluster-deploy` will not pick up the image change.

6. STILL-OPEN: env default syntax is fixed, but the rollback fallacy remains in Path-C.
   Evidence fixed: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:122) says env override is for "pinning a different Ubuntu release" and "NOT a Debian fallback".
   Evidence still wrong: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:316) says keep `IMAGE_VM` overridable so rollback to `images:debian/13` is a one-liner.
   Evidence corrected later: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md:403) says rollback is `git revert`, not runtime env override.

**New Issues**
- The current dirty r2 introduces an internal package-name contradiction: §6.3 says use `linux-modules-extra-$(uname -r)`, but the affected-files table, validation plan, risk table, and rollback text still say `linux-modules-extra-generic` at lines 100, 342, 347, 388, and 405. That must be made consistent.

- Minor but worth fixing: Path V2 says "`incus image import` the qcow2" at lines 240 and 366, but the repo’s install docs require metadata tarball + qcow2 for Incus VM import. The plan should name both artifacts.

Final verdict: PLAN-NEEDS-WORK. The direction is right and this is not PLAN-KILL, but r2 still has stale contradictory text on two r1 findings plus one new package-name inconsistency.
