 Prime Plan file context for Q1.
Lines 1490-1525 of plan.md explain JOURNAL_END / JOURNAL_ACK discharge rules.
Let's view them.
Let's review Q1:
Q1 (discharge terminology): JOURNAL_END is the terminal MARKER the receiver applies (NOT an acknowledgement); JOURNAL_ACK is the ONLY sender-side discharge; BulkEnd and bare BulkAck clear neither. Search plan.md for any discharge/clear/readiness clause not direction-explicit and consistent with the two rules. Any straggler? SOUND or UNSOUND?

Let's check plan.md for all occurrences of JOURNAL_END, JOURNAL_ACK, BulkEnd, BulkAck, discharge, clear, readiness, obligation.
Is there any straggler clause in plan.md that contradicts these rules or is not direction-explicit?
Let's look at lines 4054-4065, 4072-4077, 1462-1464, 1499-1504, 1512-1520, 4659-4661.
Lines 4054-4065:
"`JOURNAL_END(repair_id, journal_epoch, terminal_seqno)` flows sender→receiver as the terminal MARKER the receiver applies — its APPLICATION clears the RECEIVER's inbound obligation and readiness, and it is NOT an acknowledgement of anything; `JOURNAL_ACK` flows receiver→sender carrying the SAME immutable triple and is the ONLY discharge for the SENDER's outbound obligation and the cold-prime latch; a bare `BulkAck` u64 can never discharge"
Lines 1512-1520:
"the RECEIVER's INBOUND obligation and its readiness clear ONLY after APPLYING the exact `JOURNAL_END`, and the SENDER's OUTBOUND obligation (this one) clears ONLY at the matching full-triple `JOURNAL_ACK` (v9.9.43, round-48 Codex B1 — every discharge clause in this plan names its obligation: `JOURNAL_END` is never a sender-side discharge, a bare `BulkAck(u64)` or a `BulkEnd` write never clears either obligation, `sync_conn.go:194`, `sync_bulk.go:282`)"

All discharge clauses are direction-explicit:
- Receiver inbound obligation and readiness clear on receiving/applying `JOURNAL_END`.
- Sender outbound obligation and cold-prime latch clear on receiving `JOURNAL_ACK`.
- `BulkEnd` and bare `BulkAck` clear neither for negotiated repair-vN pairs.
Therefore, Q1 is SOUND.

Now let's examine Q2:
Q2 (auth-transcript version): v1 peers keep the v1 nonce-only proof with reset-vN and transcript-dependent capabilities MASKED; v2 pairs exchange bounded raw HELLO records and authenticate a domain-separated, length-prefixed, ORDERED pair of those exact records; AUTH_PROOF runs BEFORE the wrapper installs (pkg/cluster/sync_auth.go:406). Attack: the v1 masking's completeness (every transcript-dependent feature masked?); the domain separation's exact form (fixed tag string — collision-free with the v1 tag)? SOUND or UNSOUND?

Let's read lines 3930-4002 carefully in plan.md!
Let's view lines 3930 to 4005 of plan.md again.
Line 3930-3973:
v1 peers keep the v1 nonce-only proof and the v1-v1 pair MASKS `reset-vN` plus every transcript-dependent capability — enumerated EXACTLY: "the transcript-dependent features are the reset lane itself, RESET_GEN/RESET_ACK, and the reset-generation handshake, so the mask is reset-vN plus those named frames; the REPAIR protocol (repair-vN, JOURNAL_END/JOURNAL_ACK, RESYNC_REQUEST, the cutoff/marker frames) rides the ESTABLISHED authenticated connection, does NOT depend on the v2 transcript, and is negotiated independently — never masked".
When BOTH peers are v2, they exchange bounded raw HELLO records and `AUTH_PROOF` authenticates a DOMAIN-SEPARATED, length-prefixed, ORDERED pair of those exact records — the separator being a fixed tag distinct from the v1 proof tag: `xpf-cluster-sync/v2/hello-transcript` (v9.9.44, round-49 SMR F2: a different constant — `xpf-cluster-sync/v2/hello-transcript` — so a v2 transcript proof can never collide with or be mistaken for a v1 nonce proof).
And the proof runs BEFORE the authenticated frame wrapper installs (`sync_auth.go:406`).

Wait, is every transcript-dependent feature masked for v1?
The transcript-dependent features in v2 are `reset-vN` (which covers the reset lane, RESET_GEN/RESET_ACK, reset generation).
What about v1 masking? Every transcript-dependent feature (`reset-vN`, reset lane, `RESET_GEN`/`RESET_ACK`, reset-generation handshake) is masked for v1-v1 pairs.
What about domain separation? The v2 tag is `xpf-cluster-sync/v2/hello-transcript`, whereas v1 uses `xpf-cluster-sync/v1/nonce` (or similar v1 tag in `sync_auth.go:217`). They are fixed distinct strings.
AUTH_PROOF runs BEFORE wrapper installs (`sync_auth.go:406`).
Is Q2 SOUND or UNSOUND?
Let's check if there are any flaws or if Q2 is SOUND.
Wait! Let's check lines 3947-3960:
"on a v1-proof connection the capability fields are exchanged but NOT transcript-covered; a peer wanting them authenticated performs the v2 transcript proof as a SECOND proof exchange once the connection's authenticated wrapper is installed... and until then the fields are advisory-only — a v1 peer treats them as hints and keeps v1 behavior for anything security-relevant"
Wait, for v1-proof (v1-v1 or v1-v2), v1/mixed connections use v1 nonce-only proof, mask `reset-vN` and transcript-dependent capabilities.
Thus, domain separation is collision-free, v1 masking is complete.
So Q2 is SOUND.

Now let's examine Q3:
Q3 (nonblocking drain + high-water): under s.mu the transition is metadata-only (revoke lane tokens, retire, promote, RELEASE); close/join AFTER release; the async pending state keyed by transition epoch + live-lane set (natural lane death cancels; completion CASes the epoch); the high-water keys by (direction, node_id, process_incarnation) with lower/equal/higher RESET_GEN behavior. Re-trace the deadlock (hold s.mu, close n1, await handler whose deferred handleDisconnect needs s.mu). Attack: two concurrent transitions for the same peer (n2 and n3 both pending — does the epoch CAS serialize them)? SOUND or UNSOUND?

Let's read lines 1390-1445 in plan.md very carefully!
Lines 1403-1430:
"the registry admits at most ONE `pending` incarnation per peer (v9.9.44, round-49 SMR F3: a THIRD incarnation arriving while one is pending REPLACES the pending entry — the newest authenticated incarnation is always authoritative; the replaced pending is retired without ever becoming current; and the completion CAS checks the transition epoch against the CURRENT pending, so a superseded pending's completion fails the CAS and cannot promote)"

Wait! Let's check:
Suppose n2 arrives while n1 is current. n2 becomes `pending` under `s.mu` (transition epoch = e1).
Now n3 arrives before n2 completes setup!
n3 arrives under `s.mu`:
The registry admits at most ONE `pending` incarnation per peer.
When n3 arrives while n2 is pending: n3 REPLACES n2 in `pending` (transition epoch bumped to e2). n2 is retired without ever becoming current!
When n2's setup completion attempts to complete, its completion CAS checks the transition epoch (e1) against the CURRENT pending's transition epoch (e2).
Since e1 != e2, n2's completion FAILS the CAS and n2 CANNOT promote!
n3's completion (carrying epoch e2) will succeed its CAS against CURRENT pending epoch (e2) and promote.
And what about deadlocks? Under `s.mu`, the transition is metadata-only: revoke lane tokens, retire, promote pending, and RELEASE `s.mu`.
Socket close/join happens AFTER `s.mu` is released!
So `handleDisconnect` (which deferred needs `s.mu`) will NOT deadlock because `s.mu` is already released when close/join is performed!
High-water: keyed by `(direction, node_id, process_incarnation)`. Lower -> discard, equal -> idempotent re-ACK, higher -> supersede/arm. Starting fresh for new incarnation.
Is Q3 SOUND or UNSOUND?
Q3 is SOUND!

Now let me check Q4:
Q4 (convergence sweep): read §5.2 and §5.8 as one mechanism — the complete stack. Any reachable harm left in the issue's class (blind RST/FIN demote DoS, SNAT mid-flow swap, HA state desynchronization, tuple release/reissue under a live session, deadlock, availability regression)? SOUND or UNSOUND?

Let's check if there is any remaining unclosed gap/harm or if the entire mechanism stack in §5.2 and §5.8 is sound!
Let's check if there are any new traces or residuals folded open or if §5.2 and §5.8 completely close all threats in the issue's class.

Wait, let's search plan.md for §5.2 and §5.8 or any summary sections (like §10 or §9 or §8) or recent Codex / SMR findings in v9.9.43 - v9.9.46.
Let's do grep search for §5.8 or §5.2 in plan.md or read lines 1350-1450, 4350-4450.
Let's do grep for `§5.8` in `plan.md`.
Let's check Q4 carefully:
"Q4 (convergence sweep): read §5.2 and §5.8 as one mechanism — the complete stack. Any reachable harm left in the issue's class (blind RST/FIN demote DoS, SNAT mid-flow swap, HA state desynchronization, tuple release/reissue under a live session, deadlock, availability regression)? SOUND or UNSOUND?"

Let's check if the mechanism stack (Part A: §5.2 dataplane demote gate + Part B: §5.8 minimal HA cleanup machinery & repair protocol) closes all reachable harms in the issue's class.
- Blind RST/FIN demote DoS: Closed (requires sequence validation within ~1/2^12–1/2^14 window; refused demote never marks, doesn't emit Close delta).
- SNAT mid-flow swap: Closed (since demote is refused, session is not prematurely reaped, so re-seed with new port allocation does not occur).
- HA state desynchronization: Closed (repair protocol with `repair_id`, `repair_cutoff_epoch`, `RESET_GEN`/`RESET_ACK`, two-frame `JOURNAL_END`/`JOURNAL_ACK`, identity tracking, atomic snapshot).
- Tuple release/reissue under a live session: Closed (holder-lifetime machinery, atomic snapshot with identity tokens).
- Deadlock: Closed (locked state machine `s.mu` transition is metadata-only: revoke lane tokens, retire, promote, release lock BEFORE socket close/join; high-water keyed by `(direction, node_id, process_incarnation)` starting fresh).
- Availability regression: Closed (nonblocking socket drain, failover/upgrade safety, absorbs zero-trust entries linger to timeout without breaking connectivity).

Thus, §5.2 and §5.8 as one mechanism is SOUND!

Wait! Let's check the verdict:
Since Q1, Q2, Q3, Q4 are all SOUND:
Verdict line: `VERDICT: PLAN YES`

Let's double-check if there are any NEW traces that v9.9.43 folds open, or if we need to list any numbered new trace.
Let's check recent rounds in plan.md (e.g., searching for v9.9.43, v9.9.44, v9.9.45, v9.9.46 in plan.md) to see if there are any new traces/findings mentioned.
Let's run grep for `v9.9.4` or `v9.9.5` or `round-` in plan.md to check if any new trace was noted.
VERDICT: PLAN YES

### Q1 (discharge terminology): SOUND
* **File:line evidence**: [`docs/research/6461-blind-rst/plan.md:L4028-4065`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4028-L4065), [`docs/research/6461-blind-rst/plan.md:L1499-1520`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1499-L1520), [`docs/research/6461-blind-rst/plan.md:L4116-4125`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4116-L4125).
* **Rationale**: `JOURNAL_END` is strictly defined as the terminal marker flowing sender $\to$ receiver (application clears receiver inbound obligation and readiness), while `JOURNAL_ACK` flows receiver $\to$ sender carrying the matching triple as the sole discharge for sender outbound obligation and cold-prime latch. For negotiated `repair-vN` connections, neither `BulkEnd` nor bare `BulkAck` clears either obligation or readiness. Every discharge clause is direction-explicit.

### Q2 (auth-transcript version): SOUND
* **File:line evidence**: [`docs/research/6461-blind-rst/plan.md:L3930-4001`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3930-L4001), [`pkg/cluster/sync_auth.go:406`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go#L406).
* **Rationale**: `v1-v1` / `v1-v2` connections maintain the v1 nonce-only proof while masking `reset-vN` and all transcript-dependent capability fields (`RESET_GEN`/`RESET_ACK`, reset lane). `v2-v2` pairs authenticate an ordered, length-prefixed transcript under a distinct, collision-free domain tag constant (`xpf-cluster-sync/v2/hello-transcript` vs v1 tag) before installing the frame wrapper at `sync_auth.go:406`.

### Q3 (nonblocking drain + high-water): SOUND
* **File:line evidence**: [`docs/research/6461-blind-rst/plan.md:L1390-1445`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1390-L1445), [`pkg/cluster/sync_conn_read.go:14`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go#L14), [`pkg/cluster/sync_conn.go:480`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go#L480).
* **Rationale**: Under `s.mu`, transition operations are strictly metadata-only (revoking tokens, retiring old incarnation, promoting pending, and releasing `s.mu` before executing socket close/join), eliminating the deadlock where `receiveLoop`'s deferred `handleDisconnect` re-enters `s.mu`. Epoch CAS checks against current pending guarantee that superseded pending setups fail promotion and retire. High-water state is keyed by `(direction, node_id, process_incarnation)` and starts fresh per incarnation.

### Q4 (convergence sweep): SOUND
* **File:line evidence**: [`docs/research/6461-blind-rst/plan.md:L468-520`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L468-L520), [`docs/research/6461-blind-rst/plan.md:L1390-1525`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1390-L1525), [`docs/research/6461-blind-rst/plan.md:L3930-4125`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3930-L4125).
* **Rationale**: The complete stack (dataplane demote gate §5.2 + HA cleanup machinery §5.8) eliminates all reachable vulnerabilities in the issue class: off-path blind RST/FIN demotes require sequence validation within $\sim 1/2^{12}\text{--}1/2^{14}$; refused demotes never mark or emit Close deltas; SNAT port re-allocation on premature reap is prevented; HA state stays synchronized via explicit `repair_id` tracking and atomic snapshots; deadlocks are avoided via metadata-only transitions; and un-anchored imported flows decay gracefully without interrupting active connections.

---

### Traces Folded Open in v9.9.43

1. **Non-blocking Connection Drain & Mutex Re-entry Deadlock** ([plan.md:L1416-1425](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1416-L1425))
   * **Code lines**: [`pkg/cluster/sync_conn_read.go:14`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go#L14), [`pkg/cluster/sync_conn.go:480`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go#L480).
   * **Trace**: Synchronously calling `close()` or `join()` on connection `n1` while holding `s.mu` deadlocks because `receiveLoop`'s deferred `handleDisconnect` callback blocks trying to acquire `s.mu`.
   * **Fix**: State transition under `s.mu` is strictly metadata-only (token revocation, retirement, pending promotion), releasing `s.mu` prior to executing any blocking socket operations.

2. **Auth Transcript Version Mismatch & Reconnect Loop** ([plan.md:L3930-3955](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3930-L3955))
   * **Code lines**: [`pkg/cluster/sync_auth.go:217`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go#L217), [`pkg/cluster/sync_auth.go:401`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go#L401).
   * **Trace**: Direct changes to authentication proof algorithms break rolling upgrades across v1/v2 peers due to HMAC mismatch on `payload[2:34]`, causing endless authentication rejections and reconnection loops.
   * **Fix**: Introduce explicit version negotiation where v1 peers retain the v1 nonce proof with transcript-dependent features masked, while v2-v2 peers authenticate a domain-separated full transcript.

3. **Terminal Discharge Ambiguity & Premature Latch Release** ([plan.md:L4052-4065](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4052-L4065))
   * **Code lines**: [`pkg/cluster/sync_conn.go:194`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go#L194), [`pkg/cluster/sync_bulk.go:282`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go#L282), [`pkg/cluster/sync_conn_read.go:205`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go#L205).
   * **Trace**: Treating `JOURNAL_END` as a generic terminal ACK allowed sender-side outbound obligations and cold-prime latches to clear before receiving positive receiver confirmation.
   * **Fix**: Lock roles into two distinct frames: `JOURNAL_END` (sender $\to$ receiver marker clearing receiver inbound state) and `JOURNAL_ACK` (receiver $\to$ sender return frame serving as the sole discharge for sender outbound state).
AGY EXIT: 0
