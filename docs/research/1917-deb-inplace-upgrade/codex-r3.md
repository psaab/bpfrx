PLAN-NEEDS-REVISION

Blocker 1 is resolved. The old-reader-rejecting envelope in [plan.md](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:437>) is fail-closed against the current `json.Unmarshal(data, *ConfigTree)` path in [db.go](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/configstore/db.go:124>). Prefix or top-level array both avoid the empty-tree object-envelope bug.

Blocker 2 is not fully resolved. v4 deletes the live-overwrite alternative, but it does not close the old-xpfd-respawns-new-helper window unless the running daemon is also pinned to a versioned path or stopped before the live symlink flips. Current service/config patterns use `/usr/local/sbin/xpfd` and `/usr/local/sbin/xpf-userspace-dp`, and `findBinary` also searches `filepath.Dir(os.Args[0])` then PATH. A symlink flip can therefore still let an old daemon find the new helper if it was launched via `/usr/local/sbin` or has explicit config pointing there. The plan needs to mandate versioned `ExecStart`/helper config override, resolved argv, or stop-before-flip ordering.

Blocker 3 is resolved. The watchdog language is now honest: watchdog armed before `grub-reboot`, promotion only after verify + health, old GRUB default preserved, and no-watchdog cases require external recovery.

Packaging confirmation fails as written. §6.3a correctly says `dh_installsystemd --no-stop-on-upgrade` and pins `debhelper-compat`, but the risk table/test plan still mention the deprecated `--no-restart-on-upgrade` alias at [plan.md](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:503>) and [plan.md](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:535>). No code changes made.

Codex session ID: 019ecf20-f956-7060-a9ff-96b90976b393
Resume in Codex: codex resume 019ecf20-f956-7060-a9ff-96b90976b393
