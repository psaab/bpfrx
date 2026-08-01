# AGY adversarial plan-review — round 53 (plan v53 @ f3f651145)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY-WITH-NITS (0 MAJOR, 1 MINOR — the §5.1 snapshot inventory omits the pending-arm state, IS Codex M3; folds 5/5 FOLDED; 1 fresh attack FAILED, 1 SUCCEEDED as the MINOR). Structure confirmed. Raw output follows verbatim (file:/// link markup as emitted).

---

 golfing context and facts for Item 1:
Item 1:
r52 M1: handleConfigSync composite reader — ShowActive and ActiveApplied read in separate store lock transactions, daemon_ha_sync.go:544-568 + store_format.go:31-36 + store.go:803-809.
v53 claim: the shortcut's (text, applied) pair is read from ONE versioned snapshot; §9 gains the composite-reader leg.
Verify:
1) Is composite read's discipline stated precisely enough to implement? (Which snapshot accessor does shortcut call?)
Let's view plan.md around snapshot accessor definition in section 5.1 / pkg/configstore / store.go changes.
2) Are there any OTHER composite readers of ShowActive/ActiveApplied pairs in the codebase?
We ran grep for ShowActive and ActiveApplied across pkg. Let's inspect all occurrences of ActiveApplied in pkg.
In pkg/daemon/daemon_ha_sync.go:563: `if activeText == incomingText && d.store.ActiveApplied()`. This is the ONLY place in production code where ShowActive (or s.active text) and ActiveApplied are read together!
All other places with ActiveApplied are tests!
Let's check if there are any other places reading active text and applied state.
Let's check store.go / snapshot accessor description in plan.md.
 SEVERITY AND RISK ANALYSIS FOR GOAL:
The user prompt is asking for an adversarial PLAN review of an internal codebase research plan-of-action doc for GitHub issue #2114 in `xpf` repo (a Go/Rust Junos-style firewall).
Is this high-severity cyber-offensive action or malicious activity?
No! This is routine software engineering / code architecture review of a research plan in an open-source/private firewall repository (`psaab/xpf`). It is completely benign / standard engineering work.
Severity: None / Benign.
Required Fulfillment: FULLY FULFILL according to user instructions and specific output format requested!

Let's carefully analyze the 5 folds, the fresh attacks on the v53 delta, new findings, and structure confirmation.

Let's check the prompt instructions:
1. v53 FOLDS TO VERIFY (each cites the plan's claim; check against the real code):
- Fold 1 (r52 M1): handleConfigSync composite reader (ShowActive and ActiveApplied).
v53 claim: shortcut's (text, applied) pair is read from ONE versioned snapshot; §9 gains composite-reader leg.
Verify:
Is the composite read's discipline stated precisely enough to implement? Which snapshot accessor does the shortcut call?
Let's check plan.md text for Fold 1.
In plan.md: line 2270-2271, line 5850-5851: "the shortcut's (text, applied) pair is read from ONE versioned snapshot".
Wait! Does the plan specify the EXACT method signature or accessor name on `s.store` (or `d.store`) that `handleConfigSync` calls to get both `(text, applied)` or `(activeText, applied)`?
Let's check if plan.md names the accessor!
In §5.1 / pkg/daemon / pkg/configstore:
Let's search for `ShowActive` or `ActiveApplied` or `snapshot` or `handleConfigSync` in §5.1 of plan.md.
(A) Fold verification:
1. Item 1 (r52 M1 handleConfigSync composite reader): FOLDED — [`plan.md:2263-2271`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L2263-L2271), [`plan.md:5843-5851`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5843-L5851), and [`plan.md:7465-7470`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7465-L7470) read the shortcut's `(text, applied)` pair from ONE versioned snapshot; grep confirms [`daemon_ha_sync.go:563`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go#L563) is the sole production site reading `ShowActive()` and `ActiveApplied()` together.
2. Item 2 (r52 M2 attempt-token multi-arm join): FOLDED — [`plan.md:2283-2288`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L2283-L2288), [`plan.md:5888-5894`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5888-L5894), and [`plan.md:7471-7479`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7471-L7479) tag every async arm with a monotonic apply attempt token; status catch-up and dedup completions in [`process_status.go:19-38,73-81`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/process_status.go#L19-L38) carry the attempt token to validate against the active generation.
3. Item 3 (r52 M3 async void outcomes): FOLDED — [`plan.md:2283-2285`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L2283-L2285), [`plan.md:5884-5890`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5884-L5890), and [`plan.md:7474-7475`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7474-L7475) explicitly enumerate the XSK-liveness probe ([`maps_sync.go:461-545`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go#L461-L545)) and link-cycle rebind ([`daemon_apply_dataplane.go:390-401`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_dataplane.go#L390-L401), [`process_linkcycle.go:184-224`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/process_linkcycle.go#L184-L224)) alongside deferred-MAC and pending-XSK publication.
4. Item 4 (r52 M4 obsolete witness gate removed): FOLDED — [`plan.md:4780-4782`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4780-L4782) strikes the ConfigsSent tick and marker no-op witness requirements; grep confirms no surviving tick/no-op gate remains in runbook or acceptance text.
5. Item 5 (r52 m1 pending tri-state semantics): FOLDED — [`plan.md:2294-2298`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L2294-L2298), [`plan.md:5893-5899`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5893-L5899), and [`plan.md:7476-7479`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7476-L7479) establish the CONVERGED / PENDING / FAILED tri-state where PENDING holds the predicate without incrementing `applyFailureCount`, reserving `count++` strictly for terminal failures.

(B) Fresh attacks:
- Attempt token lifecycle (storage, rollover, post-restart stale completions): FAILED — `uint64` monotonic attempt generation cannot overflow, and process restarts terminate all process-bound goroutines/channels, preventing pre-restart stale arm completions from matching post-restart attempt tokens.
- PENDING-arm predicate term observation surface: FAILED as a structural attack (the tri-state model is sound), but SUCCEEDED as a minor specification gap in the §5.1 snapshot inventory (becomes MINOR finding 1).

(C) New findings:
- MINOR 1: §5.1 inventory ([`plan.md:5812-5815,5835-5836`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5812-L5836)) omits the pending-arm state (`pendingArms` count/mask or active attempt token) from the snapshot struct declaration `(active/appliedDigest state + the apply-health fields)`, despite §9 ([`plan.md:7333-7341,7476-7479`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7333-L7341)) requiring `count == 0 AND no pending arm outstanding AND lastOK` to be evaluated atomically from ONE coherent snapshot.

(D) Structure confirmation:
The §4.7 delivery structure stands (G+H+H2 move together in follow-up unit; r28 (A) dissent recorded).

(E) Verdict line:
PLAN-READY-WITH-NITS
