Verdict: **PLAN YES** (0 findings)

### 1. Alias-as-Token External-Map Fencing Interleave (§5.2 Rule 5, Lines 928-956)
- **E1 Delete Sequence:** Alias compare-delete under canonical lock $\rightarrow$ External state delete (only if compare-delete wins).
- **E2 Publish Sequence:** Allocator retain $\rightarrow$ Alias write under canonical lock $\rightarrow$ External state publish (last-writer-wins).
- **Trace E1 Delete before E2 Alias Write:** E1 compare-delete matches E1 ID $\rightarrow$ wins $\rightarrow$ deletes external state. E2 subsequently writes alias (E2 ID) and publishes external state. Result: E2 state remains live and valid.
- **Trace E1 Delete after E2 Alias Write:** E2 writes alias (E2 ID). E1 compare-delete observes E2 ID $\neq$ E1 $\rightarrow$ loses $\rightarrow$ skips external state delete. Result: E2 published state is preserved.
- **Conclusion:** Atomic compare-delete under the canonical lock eliminates the E1-lookup $\rightarrow$ E2-overwrite $\rightarrow$ E1-delete race without bad outcomes.

### 2. Deferred Ownership Promote & Probation Enforcement (§5.5, Lines 1236-1250)
- **Trace Two-Packet Chain:**
  1. *Packet 1 (Refused Close):* Demote is refused; entry enters probationary state (`probation = true`).
  2. *Packet 2 (Blind Non-Close):* Resolve stage flags promotion candidate, but `probation == true` suppresses origin promotion, `Open` emission, replication, and family-clock updates.
  3. *Commit Arm:* Unproven/blind non-close does not clear probation; probation suppresses commit-arm promotion until a committed, validated non-close packet clears the flag.
- **Conclusion:** Two-packet demote/promote chain vulnerability is dead. The entry reaps safely at 20s unless cleared by authentic traffic.

### 3. Owned Hold Token Lifecycle (§5.2 Rule 5, Lines 862-888)
- **Atomic Transfer:** Upsert/re-import executes retain-before-replace in a single operation (`install.rs:322`), preventing leaks or double-release.
- **Complete Deletion Path Auditing:**
  - Non-reap deletions: `remove_entry` returns the entry; all callers explicitly drain the token (`session/mod.rs:1746`).
  - Worker shutdown: Table's remaining active tokens are drained (`loop_body/mod.rs:1428`).
  - Reverse synths: Reference forward allocation and release via forward refcount, bypassing reverse early-return (`source.rs:789`).
  - One-shot consumers (embedded ICMP): Managed via scoped guard tokens released on scope exit.
- **Conclusion:** No missing release paths and no double-release on transfer.
