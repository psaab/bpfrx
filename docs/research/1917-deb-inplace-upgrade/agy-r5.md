PLAN-READY

### Confirmation of Round-4 Resolutions

Each of the gaps, contradictions, and package split issues identified in Round 4 has been successfully and completely resolved in the Revision 7 plan with no new contradictions introduced:

1. **Gap A (GRUB_SAVEDEFAULT Boot Loop Risk):**
   * **Status:** **Resolved.**
   * **Evidence:** [§6.3c (Line 328–337)](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L328-L337) and [§6.7 (Line 464)](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L464) now explicitly mandate that the appliance image configure `GRUB_DEFAULT=saved` and set `GRUB_SAVEDEFAULT` to `false` (or leave it absent). Furthermore, `xpf-upgrade kernel` will assert that both constraints are met before arming a one-shot boot. This is tracked in [Risk 18](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L619) and verified in the test plan.

2. **Gap B (`/var/lib/xpf/versions` Retention Policy):**
   * **Status:** **Resolved.**
   * **Evidence:** [§6.3c (Line 338–340)](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L338-L340) now mandates an automated retention policy in `xpf-upgrade` to keep only the active version, the immediate rollback version ($N-1$), and the staged candidate, pruning the rest to prevent partition exhaustion. This is formalized in [Risk 19](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L620).

3. **Gap C (HA Session-Sync Wire Back-Compat):**
   * **Status:** **Resolved.**
   * **Evidence:** [§6.5 (Line 427–433)](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L427-L433) now mandates that if the session-sync wire format changes in $N+1$, it must maintain backward compatibility for at least one release (parsing version $N$ sync frames). If compatibility cannot be maintained, the release is explicitly flagged as not rolling-upgradable, forcing Path C (image-replace). This is tracked in [Risk 20](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L621).

4. **Stale Staging Path Contradictions:**
   * **Status:** **Resolved.**
   * **Evidence:** Stale references to `/usr/local/lib/xpf/<version>/` have been systematically removed. The plan consistently references `/usr/local/share/xpf/staged/` for dpkg-controlled staging, and `/var/lib/xpf/versions/<version>/` for runtime execution. The only remaining occurrences of the old path are in [§6.3c (Line 310–313)](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L310-L313) and [Risk 14](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L615) where they describe the *problem* being mitigated.

5. **Two-Package Contradiction:**
   * **Status:** **Resolved.**
   * **Evidence:** [§6.1 (Line 183–209)](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L183-L209) removes the separate `xpf-dataplane` package. All core binaries (including `xpf-userspace-dp`) and the embedded shim are bundled into a single `xpf` package, and `xpf-appliance` acts as a metapackage pulling in dependencies.

---

### Remaining Minor Gaps & Observations (Non-Blockers)

While the plan is ready for implementation, the following minor points should be addressed during the engineering phase:

1. **HA Test Plan Description Inaccuracy (Gap D from Round 4):**
   * **Location:** [§10 Test Plan - HA rolling upgrade (Line 640)](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L640)
   * **Finding:** The text still reads: *"Negative: protocol-version mismatch between staged xpfd and the peer's running helper..."*
   * **Correction:** As noted in Round 4, a node's `xpfd` does not directly communicate with the peer's running helper. The developer should correct this description to specify either a mismatch between *local `xpfd` and local helper* (M-mech-2) or *Node A's `xpfd` and Node B's `xpfd`* (HA session-sync level).

2. **First-Upgrade Auto-Rollback to Legacy Reader ($N+1 \rightarrow N$):**
   * **Scenario:** If $N+1$ successfully boots, loads the legacy config, and writes `active.json` using the new old-reader-rejecting envelope format, but subsequently fails health checks 10 seconds later, the system will trigger an auto-rollback to $N$.
   * **Risk:** The legacy daemon ($N$) does not contain the fatal parse-error fix specified in §6.3b. When it encounters the new envelope, it will return a parse error, log a warning, and proceed to overwrite the configuration database or start unconfigured.
   * **Mitigation:** The implementation must guarantee that either (a) the rollback mechanism restores the database to its $N$-format from the rollback slot prior to starting the legacy daemon, or (b) a intermediate compatibility release (which includes the fatal parse-error fix and the ability to parse envelopes) is deployed before any release writes the new format.
