PLAN-NEEDS-REVISION (remaining blocker)

The round-3 operational blockers are resolved in the current v6 text, but the plan still has a package-model contradiction that blocks `PLAN-READY`.

**Remaining blocker:** §6.1 says there is one `xpf` binary package plus `xpf-appliance`, and that the protocol pair is enforced by the staged/runtime versioned paths, not dpkg `Depends` metadata. But §6.5 still says the `xpf` package `Depends:` on `xpf-dataplane (= same version)`, and §6.6 says the shim ships inside an `xpf-dataplane` package. See [plan.md:191](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:191), [plan.md:399](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:399), and [plan.md:463](/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:463). Fix by replacing those with: one `xpf` package contains matched `xpfd` + helper + embedded shim, and lockstep is enforced by `/usr/local/share/xpf/staged/` → `/var/lib/xpf/versions/<ver>/` plus the cut-over ordering.

Confirmations:

1. §6.3b is correct: config DB load errors must be fatal except the legitimate missing-`active.json` first-boot case. Current code maps missing `active.json` to nil/no error, so fresh install bootstrap is not broken.

2. The static staging/runtime versioned-dir model is now internally consistent in §6.1, §6.3a, §6.3c, postinst, risk table, and tests. It solves dpkg rollback-target deletion and mid-transaction re-exec, provided implementation creates runtime version dirs via temp+rename/refuses partial dirs.

3. `needrestart` coverage is sufficient in plan terms: blacklist plus non-dpkg running paths prevents a mid-apt dataplane cut.

4. The `softdog` language is now honest: HW/hypervisor watchdog is required for the early-boot no-brick guarantee.

5. `GRUB_DEFAULT=saved` is complete: bake/postinst set it, `update-grub` is required, and `xpf-upgrade kernel` asserts before arming.

Round-2/3 fixes still stand: old-reader-rejecting envelope is correct, `--no-stop-on-upgrade` is retained and tested, and stop-before-flip/versioned `ExecStart` remains the right closure for the old-daemon-resolves-new-helper window.

Codex session ID: 019ecf28-a843-71a1-a272-785bbe714d1a
Resume in Codex: codex resume 019ecf28-a843-71a1-a272-785bbe714d1a
