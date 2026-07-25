# AGY hostile plan review — round 7 — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only, scoped sections). Scope: plan v7.2. Transcript: .scratch/r7-agy-out1.txt (verbatim below).

---

### Question 1: UNSOUND
**Adjudication**: Not every import class publishes a node-local shared alias whose deletion can serve as the single-producer ticket.
- **Evidence**: `session_glue` and `shared_ops.rs` publish shared aliases via `publish_shared_session` for `SyncImport` and `SharedMaterialize`. However, `WorkerLocalImport` (and `fabric_ingress` entries without NAT/wire aliases) are inserted directly into worker-local session tables without publishing a shared alias to `shared_sessions`.
- **Impact**: Reaping workers for these import classes find no shared alias to delete, causing Close authority to either fail to fire or lack single-producer serialization.

### Question 2: SOUND
**Adjudication**: Two workers cannot both win the shared-alias deletion race.
- **Evidence**: Shared alias removal in `shared_ops::remove_shared_session` occurs under `lock_shared_recover` (mutex protection).
- **Impact**: `sessions.remove(key)` is atomic: exactly one worker receives `Some(entry)` while concurrent or subsequent workers receive `None`. The single-producer ticket selection is strictly thread-safe and atomic under the mutex lock.

### Question 3: UNSOUND
**Adjudication**: Allowing idle entries to decay to untrusted without heartbeat-refresh is unsound for Phase 2's primary objective.
- **Evidence**: On a legit idle flow (e.g., SSH, BGP, management), sequence numbers do not move, so the stored anchor is 100% accurate. Because updates only fire when the anchor advances (§10.5), an idle flow emits zero `AnchorUpdate` messages.
- **Impact**: Receiver trust decay (~4s) prematurely invalidates accurate idle anchors to untrusted, forcing post-failover closes to refuse until new traffic arrives. This directly defeats Phase 2's goal of protecting quiet/idle sessions across failovers. Idle entries must heartbeat-refresh before `T_anchor` expires.
