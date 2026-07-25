VERDICT: PLAN YES

### Q1 (pre-ACK slots + barrier generation): SOUND
* **Plan Quote**: "EVERY installed connection carries an ABSOLUTE liveness teardown independent of prior ACK history... bound is a hard per-connection max-silence teardown... promoted from liveness query to teardown" (`docs/research/6461-blind-rst/plan.md:1282-1296`) and "admission (`preAuthMu`), generation capture, `barrierActive`, slot closure, and install rejection are ordered under the same mutex as the slot registry (`s.mu`) — `installConn` atomically rejects BOTH stale-generation setups AND any setup attempted while `barrierActive` is set" (`docs/research/6461-blind-rst/plan.md:1298-1305`).
* **Evaluation**: Atomic evaluation of `barrierActive` and generation under `s.mu` prevents mid-barrier install races, while the unconditional max-silence teardown guarantees blackholed pre-ACK slots are closed deterministically without relying on `peerHeartbeatAckEver`.

### Q2 (resetRecvGen wiping the fence): SOUND
* **Plan Quote**: "a bulk whose ID is not the current repair ID is WHOLLY NON-MUTATING... the reset is STAGED with the bulk and applies only when the bulk's BulkEnd validates (an aborted or wrong-ID bulk never touches the generation maps)" (`docs/research/6461-blind-rst/plan.md:1492-1511`).
* **Evaluation**: Staging `resetRecvGen` until `BulkEnd` validation ensures that the pre-repair generation map remains intact during stream transmission. In-flight stragglers continue to be validated against the active fence, preventing stale packets from bypassing generation checks.

### Q3 (no per-entry version & hold cell linearization): SOUND
* **Plan Quote**: "the version is `install_epoch`, the worker-local mutation counter rewritten on update AND promotion (`session/mod.rs:761, :1384`)... the recheck reads `(install_epoch, SessionIdentity)` inside the entry's table critical section" (`docs/research/6461-blind-rst/plan.md:1884-1891`) and "every token... points at a per-allocation HOLD CELL, whose content... swaps atomically inside the allocator critical section... promotion, reap, replacement, and conversion participate in ONE canonical version/CAS... a CAS failure swaps the cell BACK... the `Converted(old_state)` undo IS the swap-back, never a variant-specific decrement" (`docs/research/6461-blind-rst/plan.md:1845-1870`).
* **Evaluation**: Binding version checks to `install_epoch` (updated on both mutation and promotion) prevents un-serialized re-promotions, while shared hold cells ensure atomic CAS transitions and exact cell swap-back undos on failure.

### Q4 (staging visibility + empty-receiver budget): SOUND
* **Plan Quote**: "the staged budget is CONFIGURED-CAPACITY-based... the session-table capacity is CONFIGURED, so a legitimate full table ALWAYS fits" (`docs/research/6461-blind-rst/plan.md:1490-1497`) and "the staged rows apply to an INVISIBLE shadow store (not visible to lookups), committed by ONE atomic visibility switch at `BulkEnd` validation... no partial visibility ever" (`docs/research/6461-blind-rst/plan.md:1506-1510`).
* **Evaluation**: Sizing the staging budget from static configured capacity avoids infinite re-bulk loops on empty receivers, while committing shadow store rows via a single atomic visibility switch guarantees zero exposure of intermediate state.

### Q5 (journal discharge + pending queue clones): SOUND
* **Plan Quote**: "the journal seals at a SECOND cutoff... transmits IN ORDER on the SAME pinned repair stream... and terminates with an explicit JOURNAL-END marker... the receiver ACKs ONLY the marker" (`docs/research/6461-blind-rst/plan.md:1466-1476`) and "stage 1 checks EXTERNAL/live holders only (worker replicas, materialized entries, AND pending queue clones...); failed stage-1 families are RETAINED on a durable cleanup retry queue woken on EVERY external-clone drop" (`docs/research/6461-blind-rst/plan.md:2119-2125`).
* **Evaluation**: Pinning post-cut journal transmission to the repair stream ending with a single `JOURNAL-END` ACK eliminates cross-fabric out-of-order delta races. Counting pending queue clones in stage 1 and waking the durable retry queue on every external-clone drop guarantees complete cleanup without orphaned reservations or premature deletions.

---

### NEW Traces Folded Open in v9.9.29
None. All mechanisms in v9.9.29 (and v9.9.30) close the specified traces soundly without introducing new state-management vulnerabilities or race conditions.
AGY EXIT: 0
