PLAN-NEEDS-REVISION

The v3 plan resolves several round-1 blockers, but it introduces or leaves three production blockers.

1. **`active.json` envelope is not first-upgrade-safe as written.**  
   [plan.md](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:419>) proposes `{ "manifest": ..., "tree": <ConfigTree> }`. Current legacy `ReadActive` unmarshals into `config.ConfigTree` at [db.go](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/configstore/db.go:124>), and `ConfigTree` only has `Children` at [ast.go](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/config/ast.go:98>). Go JSON ignores unknown object fields, so old binary N can parse the new object envelope as an empty tree instead of failing closed. That defeats the `min_reader` gate and can boot/rollback into empty config.  
   Required fix: use an old-reader-rejecting format for both plain and encrypted configs, such as a magic/header/top-level array that legacy `json.Unmarshal(..., *ConfigTree)` rejects, or ship one compatibility release that can read envelopes before any release writes them. Add a legacy-reader test proving N fails closed, not empty-loads.

2. **The immutable-path invariant is still contradicted by stale `postinst` wording.**  
   [plan.md](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:230>) mandates versioned paths and says dpkg never touches the live symlink, but [plan.md](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:264>) still allows the “simplest dpkg-native form” that installs into `/usr/local/sbin`. That reopens the old mismatch window: current xpfd resolves helpers from its dir/PATH in [process.go](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/dataplane/userspace/process.go:168>), so an old daemon can respawn a newly unpacked helper before the intended cutover.  
   Required fix: delete the live-overwrite alternative entirely. Also add `xpf-upgrade` to the package layout at [plan.md](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:192>) and require the staged orchestrator to invoke staged `xpfd`/helper by absolute path, not PATH or live symlinks.

3. **The kernel channel is directionally right, but not brick-proof yet.**  
   The `grub-reboot` one-shot model is the right correction for “cannot verify unbooted kernel” because `verify-dataplane` loads into the running kernel via `ebpf.NewCollection` at [verify_userspace_shim.go](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/dataplane/verify_userspace_shim.go:113>). But [plan.md](</home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md:345>) claims no-show/boot-hang fallback without specifying a watchdog that is armed before reboot and can reset the box if the candidate kernel never reaches systemd. Without that, a bad kernel can still strand the node until external recovery.  
   Required fix: specify the actual watchdog mechanism, deadline, and promotion marker semantics, or weaken “can never brick” to “old GRUB default is preserved, but early boot hangs require external watchdog/operator recovery.”

Resolved from round 1: embedded shim/no phantom `.o` is correct; HA auto-rollback is now honestly standalone-only/operator-driven; M-mech-2 zero-gap hot restart is correctly scoped as future daemon work; and `dh_installsystemd --no-stop-on-upgrade` is the right class of fix. Note: Debian documents `--no-restart-on-upgrade` as a deprecated alias, so the plan should prefer `--no-stop-on-upgrade` and pin debhelper compat explicitly. Source: Debian `dh_installsystemd` manpage.

Codex session ID: 019ecf19-e89a-7941-a39a-42acbc9de2fa
Resume in Codex: codex resume 019ecf19-e89a-7941-a39a-42acbc9de2fa
