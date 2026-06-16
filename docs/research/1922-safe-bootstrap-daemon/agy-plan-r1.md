I will view the plan file `docs/research/1922-safe-bootstrap-daemon/plan.md` to begin the hostile review.
I will list the contents of the `docs` directory to locate the plan or see what research directories exist.
I will run a command to see the files changed in the git diff target `0d7f0626291683a0d608d8ec236d0b65ccdd4a20...HEAD` to check where the plan is.
I will run `git log` to inspect the recent commits and see what revision we are on and where `0d7f0626291683a0d608d8ec236d0b65ccdd4a20` is relative to HEAD.
I will list all branches to see if there is a branch containing `0d7f0626291683a0d608d8ec236d0b65ccdd4a20` or a research branch.
I will search the repository for all files named `plan.md` to see if the plan file is in a different location or path.
I will run `git status` and check the current branch to see if we are already in a branch or detached HEAD.
I will check the details of commit `0d7f0626291683a0d608d8ec236d0b65ccdd4a20` to understand what revision it is and how it relates to our worktree.
I will check the full status of git to see which branch is checked out in this worktree.
I will check the git log for the branch `research/1922-safe-bootstrap-daemon` to see what commits are on it.
I will checkout the `research/1922-safe-bootstrap-daemon` branch to get access to the plan file and code changes.
I will list the git worktrees to see their paths.
I will view the plan file from the correct worktree path.
I will view `pkg/cli/cli.go` around line 289 to verify the SetCentralRollbackHandler registration and whether it is interactive-only.
I will view `pkg/cli/cli.go` from line 200 to 260 to identify the enclosing function for `SetCentralRollbackHandler`.
I will view `pkg/configstore/store.go` around `performAutoRollback` (lines 1160 to 1230) to check `prevCfg == nil` and empty-tree `writeActive` behavior.
I will search for the definition of `performAutoRollback` in `pkg/configstore/store.go` to inspect it.
I will view `pkg/configstore/store.go` around line 942 to see how `performAutoRollback` handles rollback and `prevCfg`.
I will search for `confirmPrevTree` and `confirmPrevCfg` usage in `store.go`.
I will view `store.go` from line 850 to 920 to see how `confirmPrevTree` and `confirmPrevCfg` are set when a confirmed commit is armed.
I will search for the definition of `Load` in `pkg/configstore/store.go` to see what gets loaded on fresh boot.
I will view `pkg/configstore/store.go` around line 83 to see how `Load` behaves.
I will search for `NewStore` to see how `s.active` is initialized.
I will find the definition of the `Store` struct.
I will view lines 20 to 80 of `pkg/configstore/store.go`.
I will search for `apply_serialize_test.go` or files related to serialization of apply.
I will view `/home/ps/git/bpfrx/pkg/daemon/apply_serialize_test.go` to inspect the concurrent apply serialization tests.
I will search for the definitions of `commitAndApply` and `commitConfirmedAndApply` in `pkg/daemon/`.
I will view `pkg/daemon/daemon_apply.go` from line 70 to 160 to inspect how `commitAndApply` and `commitConfirmedAndApply` are implemented and where `applySem` is acquired.
I will view `pkg/daemon/daemon_apply.go` around line 50 to 80 to see `applyConfig`.
I will view `pkg/configstore/envelope.go` to see the structure of the database envelope and check for any migration hazards or how it handles parsing errors.
I will list the files in `pkg/configstore` to find where the envelope or db code is located.
I will view `pkg/configstore/db.go` to see how the active configuration is stored, read, and written, and check how it handles errors and if there's any envelope.
I will search the codebase for `ErrConfigDBUnreadable` to see where it is defined and used.
I will run a git log search across all branches to see where `ErrConfigDBUnreadable` or the #1917 D1 commits are, and check if they are indeed merged into our current branch context.
I will show the changes in commit `e2ac27895` to see if `ErrConfigDBUnreadable` is defined there and check which files it modified.
I will perform a search for `ErrConfigDBUnreadable` in the `research/1922-safe-bootstrap-daemon` worktree, which contains the latest code (based on `origin/master` / `0d7f0626291683a0d608d8ec236d0b65ccdd4a20`), since the local master branch in `/home/ps/git/bpfrx` is 728 commits behind.
I will view `pkg/cli/cli.go` in the `1922-research-safe-bootstrap-daemon` worktree around line 289 to check the SetCentralRollbackHandler registration.
I will search for `performAutoRollback` in the target worktree's `pkg/configstore/store.go`.
I will view `pkg/configstore/store.go` in the target worktree around line 1166 to verify the rollback behavior.
I will search for `func New` in `pkg/configstore/store.go` in the target worktree.
I will view `pkg/configstore/store.go` from line 100 to 140 in the target worktree.
I will view `pkg/configstore/store.go` from line 140 to 180 to check how `Load` behaves when a config database is missing.
I will view `pkg/daemon/daemon_run.go` in the correct worktree from line 200 to 310 to inspect startup behavior, `ErrConfigDBUnreadable` handling, `bootstrapFromFile`, and `enumerateAndRenameInterfaces`.
I will search for `enumeratePCINICs` in `pkg/daemon/linksetup.go` to find the exact line range.
I will view `pkg/daemon/linksetup.go` from line 130 to 195 to see how `enumeratePCINICs` extracts PCI device details.
I will view `pkg/daemon/linksetup.go` from line 40 to 120 to see how `enumerateAndRenameInterfaces` uses the sorted list of PCI NICs.
I will view `pkg/daemon/linksetup.go` from line 285 to 330 to inspect `writeBootstrapFxp0Network`.
I will search for `compileZones` in `pkg/dataplane/compiler_iface.go` in the target worktree.
I will view the beginning of `compileZones` in `pkg/dataplane/compiler_iface.go` to see how it processes interfaces.
I will search for the term `Unmanaged` in `pkg/dataplane/compiler_iface.go` to find where the unmanaged interface assignment logic is.
I will view lines 1050 to 1160 of `pkg/dataplane/compiler_iface.go` to inspect the `Unmanaged` interface processing.
I will search for `always-down` in `pkg/networkd/networkd.go` to verify the ActivationPolicy.
I will view `pkg/networkd/networkd.go` from line 395 to 425 to check the generated configuration.
I will view `pkg/configstore/envelope.go` in the target worktree to inspect the format of the DB envelope and check for any migration/compatibility hazards.
I will view the rest of `pkg/configstore/envelope.go` to see how it handles unknown keys in the envelope header.
I will search for `persistDegraded` in `pkg/configstore/store.go` in the target worktree to understand how it behaves.
I will view lines 240 to 300 of `pkg/configstore/store.go` in the target worktree to inspect the persist retry loop.
I will search for `func (s *Store) writeActive` in `pkg/configstore/store.go` to see how it serializes the active config and writes the envelope.
I will view `pkg/configstore/store.go` from line 185 to 225 to inspect `writeActive`.
I will view `pkg/configstore/db.go` in the target worktree to see how the envelope is written.
I will view the rest of `pkg/configstore/db.go` from line 146 to 182.
I will search for `bootstrapFromFile` in `pkg/daemon/` to see how it loads the preseeded file.
I will view `pkg/daemon/daemon_apply.go` from line 25 to 60 to inspect `bootstrapFromFile`.
I will view `pkg/daemon/daemon_run.go` from line 310 to 360 to see what else is initialized in the `!d.opts.NoDataplane` block.
I will search for `d.frr` or `d.routing` usage in `pkg/daemon/daemon_apply.go` in the target worktree.
I will search for `d.routing` usage in `pkg/daemon/daemon_apply.go`.
I will search for all occurrences of `d.routing` in the `pkg/daemon/` directory to see if any are not nil-guarded.
I will view `pkg/daemon/daemon_rpm.go` around line 199 in the target worktree to see if it nil-guards `d.routing`.
I will search for `d.networkd` in `daemon_apply.go` to see if there are any dereferences that aren't nil-guarded.
I will view `pkg/daemon/daemon_apply.go` from line 490 to 520 to see if `d.networkd` is nil-guarded.
I will search for `d.dp.` usage in `daemon_apply.go` to check if it is nil-guarded.
I will view `pkg/daemon/daemon_apply.go` from line 440 to 480 to see if `d.dp` is nil-guarded when calling `ApplyConfig`.
I will view `pkg/daemon/daemon_apply.go` around line 567 to see if `d.dp` is nil-guarded.
I will view `pkg/daemon/daemon_apply.go` from line 1070 to 1099.
I will view `pkg/daemon/daemon_run.go` from line 360 to 420 in the target worktree.
I will view `pkg/daemon/daemon_run.go` from line 420 to 500 in the target worktree.
I will view `pkg/daemon/daemon_run.go` from line 500 to 560 to find the startup `applyConfig` call.
I will write the detailed hostile plan review as a markdown artifact in the app's artifact directory.
**Verdict:** `PLAN-NEEDS-CHANGES`

A detailed code-level review of the proposed research plan has been conducted against the actual code in the target worktree. While the plan is structurally well-conceived, it cannot be marked `PLAN-READY` due to two critical concurrency and initialization bugs, along with a high-severity migration risk.

The complete and detailed review has been written to the artifact: [adversarial_review.md](file:///home/ps/.gemini/antigravity-cli/brain/f4e67083-4581-470f-8d0a-5127fb28f0ae/adversarial_review.md). A summary of the key findings, severity, and quoted-line evidence is provided below:

---

### Finding 1: Concurrency Race in `performAutoRollback` (Atomicity Hazard)
* **Severity:** CRITICAL
* **Evidence:** 
  From [pkg/configstore/store.go:1209-1217](file:///home/ps/git/bpfrx/.claude/worktrees/1922-research-safe-bootstrap-daemon/pkg/configstore/store.go#L1209-L1217):
  ```go
	fn := s.centralRollbackFn
	s.mu.Unlock()

	slog.Warn("commit confirmed timed out, configuration rolled back")

	// Call dataplane re-apply outside the lock
	if fn != nil && prevCfg != nil {
		fn(prevCfg)
	}
  ```
* **Analysis:** The atomicity hazard is real. When the rollback timer fires, `performAutoRollback` locks `s.mu`, updates the store state, persists it, and then unlocks `s.mu` *before* executing the callback `fn(prevCfg)`. In the window between `s.mu.Unlock()` and the callback acquiring `d.applySem`, a concurrent comitter can run `commitAndApply`. Since `d.applySem` is currently free, the comitter will acquire it, lock `s.mu`, commit the new config, apply it, and release `d.applySem`. The rollback thread will then acquire `d.applySem` and apply the old reverted config. This leaves the store with the new config, but the running kernel with the old config, causing permanent state divergence.
* **Remediation:** Acquire `d.applySem` first, then update the store state and run the apply within the same critical section.

---

### Finding 2: Startup Manager Pointers Nil-Dereference and Apply Blackout
* **Severity:** CRITICAL
* **Evidence:**
  From [docs/research/1922-safe-bootstrap-daemon/plan.md:212-213](file:///home/ps/git/bpfrx/.claude/worktrees/1922-research-safe-bootstrap-daemon/docs/research/1922-safe-bootstrap-daemon/plan.md#L212-L213):
  > "Concretely this gates the !d.opts.NoDataplane block at daemon_run.go:231-307 (and the dataplane/FRR/VRRP init that follows) behind if !bootstrapMode."
* **Analysis:** Gating manager instantiation at boot leaves `d.routing`, `d.frr`, `d.networkd`, and `d.dp` as `nil`. When the first `commit confirmed` is issued to exit bootstrap mode, `commitConfirmedAndApply` runs `d.applyConfigLocked`. Since all manager calls in the apply path are nil-guarded (e.g., `if d.routing != nil`), they will be silently skipped. The config will never be applied to VRF/FRR/networkd, leaving the system permanently unconfigured.
* **Remediation:** Instantiate all managers unconditionally at startup. Gate only the *takeover* actions (interface renames, host tunables, BPF dataplane start, and boot-time config apply) behind `bootstrapMode`.

---

### Finding 3: Cluster Sync (`SyncApply`) Bootstrap Mode Exit Gap
* **Severity:** HIGH
* **Evidence:**
  From [docs/research/1922-safe-bootstrap-daemon/plan.md:214-216](file:///home/ps/git/bpfrx/.claude/worktrees/1922-research-safe-bootstrap-daemon/docs/research/1922-safe-bootstrap-daemon/plan.md#L214-L216):
  > "Exit from bootstrap mode happens exactly once, at the first successful confirmed commit (Item 1 / 4-gate below), which then runs the full normal startup reconcile."
* **Analysis:** A cluster secondary booting for the first time without a config will start in bootstrap mode. When it receives the configuration synced from the primary via `syncAndApply` (calling `s.store.SyncApply`), it will remain in bootstrap mode indefinitely because the plan only transitions out of bootstrap mode on local interactive commits. This prevents the secondary from taking over on primary failure.
* **Remediation:** Explicitly define that successful completion of `SyncApply` (and any other path applying a non-empty config to the store) triggers exit from bootstrap mode.

---

### Finding 4: Migration Hazard on Upgrade
* **Severity:** HIGH
* **Evidence:**
  From [docs/research/1922-safe-bootstrap-daemon/plan.md:188-191](file:///home/ps/git/bpfrx/.claude/worktrees/1922-research-safe-bootstrap-daemon/docs/research/1922-safe-bootstrap-daemon/plan.md#L188-L191):
  > "/engineer picks the representation — candidates: (a) a committed-generation counter persisted in the DB envelope (0 = never committed), (b) presence/absence of an active record distinct from "empty active record"."
* **Analysis:** If option (a) is selected, a DB written by an older build will lack the new envelope field. If the new build defaults the missing field to `committed=false` (never committed), an upgraded system with an existing active config will misclassify itself as degraded and boot into bootstrap mode, causing a major outage.
* **Remediation:** The envelope parser must treat a missing committed field in a valid envelope DB as `committed=true` (already committed). Option (a) is recommended over (b) because a field inside the envelope behaves like a standard JSON file write, allowing the `#1799` background-retry loop to naturally handle failed rollback writes.

---

### Open Questions Summary
* **OQ-A (lifeline vs fatal-exit ordering on corrupt DB):** Touch nothing and do not write a lifeline on a corrupt boot. Doing so on a failing process violates the fail-closed principle. Already-booted boxes rely on previously persisted networkd files.
* **OQ-D (protected-set semantics):** Auto-exempt the management interface from dataplane claim but allow normal zone configuration to apply security policy.
* **OQ-F (step-0 marker representation):** Stamping the committed status/generation in the envelope is the most robust option as it integrates cleanly with the `#1799` background-retry loop.
