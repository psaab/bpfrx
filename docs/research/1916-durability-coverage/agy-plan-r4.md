# PLAN-READY

## AGY Adversarial Review (Round 4 / Final Convergence)

**Target Plan**: [docs/research/1916-durability-coverage/plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1916-research-durability-coverage/docs/research/1916-durability-coverage/plan.md) (Revision r4)
**Worktree**: `/home/ps/git/bpfrx/.claude/worktrees/1916-research-durability-coverage`

---

### 1. Verdict & Summary

**Verdict: PLAN-READY**

All criteria for final convergence have been successfully met in the revision r4 of the plan. The case-split logic introduced in Step 2b correctly and robustly addresses the timezone control-flow issue without introducing new regressions or crash windows.

---

### 2. Detailed Confirmations

#### (a) Verification of the r4 Case-Split (Crash Window Removal)
The r4 case-split addresses the "remove-correct-localtime crash window" by introducing explicit conditional gates:
1. **Case 1 (Early Return)**: If both `/etc/localtime` and `/etc/timezone` match the target, the function returns immediately. No mutations are performed.
2. **Case 2 (Localtime Update)**: If and only if `/etc/localtime` does NOT match the target, we execute the `os.Remove("/etc/localtime")` and `os.Symlink` sequence.
3. **Case 3 (Timezone Update)**: If `/etc/timezone` does NOT match the target, we write it using `fsatomic.WriteFileAtomic`.

Because the mutation in Case 2 is gated on `!localtimeMatches`, a system that already has a correct `/etc/localtime` will never execute `os.Remove("/etc/localtime")`. This removes the window where a crash immediately after `os.Remove` leaves the system without a valid `/etc/localtime`.

#### (b) Verification of the AGY r2 #3 Fix (Timezone Repaired)
If `/etc/localtime` is correct but `/etc/timezone` is stale/missing, `localtimeMatches` will be `true` and `timezoneMatches` will be `false`. 
- The early return `if localtimeMatches && timezoneMatches` does not trigger.
- The `!localtimeMatches` branch is skipped.
- The `!timezoneMatches` branch executes, calling `fsatomic.WriteFileAtomic("/etc/timezone", ...)` to correct the stale file.

This ensures `/etc/timezone` is repaired and does not remain stale forever.

#### (c) Verification Against Plan Regressions
A full diff comparison between `plan.md` at r3 (`25d79470c`) and r4 (`45d6cd0bf`) confirms that:
- No changes were made to other approved parts of the plan.
- The TLS persistence sequence (ordered, strict unlink contract, nil-error reporting on persistence failure) remains unchanged.
- The AST canary method keying (`relpath::[recv.]func`) remains unchanged.
- The `authorized_keys` atomic ownership fix via `WithOwner` + `lookupUIDGID` remains unchanged.
- The DNS B-route error routing remains unchanged.

---

### 3. Conclusion

The plan is fully converged, robust, and ready for implementation.
