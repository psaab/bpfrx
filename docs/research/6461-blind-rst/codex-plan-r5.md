# Codex hostile plan review — round 5 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion, resumed session 019f95f3-c124-7c60-9d1b-198b9629c197). Scope: plan v6 @ e1f58e4e8.
Run ledger: task-mrzlgpx5-odo1nx (19m33s, completed). Verbatim final output below (.scratch/r5-codex-final.txt).

---

PLAN NO

1. **BLOCKER — “Closing never promotes” leaves no authoritative cleanup producer after failover.**

   V6 says the old owner will eventually emit the authoritative `Close`, but owner demotion retags both shared and worker-local entries as `SyncImport` ([state.rs:73](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/state.rs:73), [shared_ops.rs:161](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:161), [install.rs:542](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:542)). The new owner’s unpromoted entry is `SharedMaterialize`; both origins are peer-synced, and peer-synced expiry emits no `Close` ([entry.rs:245](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:245), [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342)).

   Local reap releases allocator, BPF, and cache state but does not remove the shared aliases ([loop_body/mod.rs:1481](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1481)); shared deletion is driven by a `Close` delta ([session_delta.rs:406](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:406)). A stale shared NAT entry can therefore match and rematerialize later ([session_glue/mod.rs:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092)), without repeating the reservation performed during initial synchronized import ([upsert_synced.rs:80](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:80)). That permits stale NAT alias resurrection after allocator reuse.

   The hit is correctly re-resolved under current HA ownership before forwarding ([session_glue/mod.rs:1202](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1202)); this is an authority/cleanup failure, not a routing bypass. It directly contradicts [plan.md:561](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:561) and [plan.md:1066](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1066). V6 needs an activation-time cleanup authority transfer, sanitized promotion/tombstone, or explicit shared deletion.

2. **BLOCKER — Mutable `seq_hi` destroys the claimed exact OPENING proof.**

   A fresh SYN makes the initiating `seq_hi` trusted ([plan.md:479](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:479)); any committed non-close sample in that direction may then slide it forward by `FWD_SLACK` ([plan.md:526](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:526)). OPENING subsequently treats that same mutable value as both the SYN+ACK proof ceiling and the exact same-direction RST coordinate ([plan.md:681](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:681)).

   Brief trace: one non-close sample whose sequence end lands inside the forward-slide interval moves `seq_hi`; a following same-direction RST at that attacker-chosen new value passes the “exact” self-abort rule. Alternatively, a reverse SYN+ACK acknowledging the moved ceiling can authenticate the reverse side. The initial work factor is therefore approximately `FWD_SLACK / 2^32`—about 1/65,536 at the floor to 1/32,768 at the cap—not 1/2³². V6’s “walking does not worsen acceptance” argument ([plan.md:1218](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1218)) is valid only after establishment. OPENING needs an immutable `open_ack_hi`/SYN proof endpoint separate from the live tracker.

3. **BLOCKER — Phase 2’s promised current-anchor replication has no viable producer.**

   V6 proposes appending the anchor to `Open` and obtaining updates from the existing incremental sweep ([plan.md:1152](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1152), [plan.md:1170](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1170)). That sweep enumerates `SessionStore`, selects only entries whose `Created` crosses its threshold, and can skip entirely when NEW/CLOSED counters are unchanged ([sync_conn_sweep.go:125](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:125), [sync_conn_sweep.go:137](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:137)). Rust anchor changes alter neither signal.

   The userspace `Sessions()` path still exposes the BPF-compatible `SessionValue`, which has no anchor ([manager.go:387](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/manager.go:387), [types.go:15](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/types.go:15)). Rust emits only `Open` and `Close`; `MSG_SESSION_UPDATE` is unused ([entry.rs:277](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:277), [wire.rs:20](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/event_stream/codec/wire.rs:20)). The userspace sweep cadence is also 15 seconds active/60 seconds idle, not approximately one second ([manager.go:452](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/manager.go:452)).

   Even a real one-second delay exhausts 64–128 KiB of slack in roughly 52–105 μs at 10 Gbit/s or 21–42 μs at 25 Gbit/s. Old-decoder tail tolerance is sound, but V6 still needs a Rust dirty-epoch/coalesced-update pipeline, enqueue-confirmed retry watermark, and in-place import semantics.

4. **HIGH — The own-ACK leg uses the wrong direction’s advertised window.**

   For both `seg.seq` legs, the candidate is in stream D, so `FWD_SLACK` correctly derives from the receiver O’s advertised window ([plan.md:649](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:649)). For `seg.ack` versus `seq_hi(O)`, the candidate is instead in stream O, whose receiver is D; that leg must use `wnd(D)`, not `wnd(O)` ([plan.md:670](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:670)). The same rule applies while sliding `ack_hi(D)`, because it also represents stream O.

   Asymmetric windows therefore cause either excess acceptance or legitimate-close refusal. The own-ACK concept itself is correct for generated resets: when an incoming segment has no ACK, RFC 9293 places the reset’s acknowledgment at `SEG.SEQ+SEG.LEN`; when it has an ACK, the reset sequence is derived from `SEG.ACK` ([RFC 9293 §3.5.2](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5.2)).

5. **HIGH — Section 2 still understates blind-hit probability after adding the third leg.**

   V6’s probability discussion counts only the union of the two `seg.seq` windows ([plan.md:156](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:156)), while the actual rule also accepts an independently selected `seg.ack` against a third window ([plan.md:661](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:661)).

   With per-leg width `W`, a blind RST|ACK has approximately `3W/2^32` success when the two sequence windows do not overlap: about 1/10,923 at the floor and 1/7,282 at the cap, or 10.9–7.3 seconds at 1,000 packets/s. Even complete overlap of the two sequence windows leaves approximately `2W/2^32`: about 1/16,384 to 1/10,923. Section 2 must restate both the optimized three-leg probability and the overlap bounds.

6. **HIGH — The forwarding commit boundary still has both false-positive and missing commits.**

   Cross-worker `enqueue_tx_owned` returns success after calling `push_redirect_inbox` ([umem/mod.rs:1257](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/umem/mod.rs:1257)), but that helper can discard the incoming item at capacity without returning an error ([umem/mod.rs:1305](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/umem/mod.rs:1305)). A proposed “successful enqueue” hook would therefore advance the anchor for a packet already dropped. Queue pressure is traffic-driven, contrary to V6’s claim that the condition is not attacker-timed ([plan.md:435](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:435)).

   Conversely, failed ForwardCandidate dispatch can fall back to raw slow-path reinjection ([dispatch/mod.rs:898](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/mod.rs:898), [dispatch/mod.rs:1378](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/mod.rs:1378)), which can successfully enqueue to a local tunnel or the kernel ([slow_path.rs:223](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:223), [slow_path.rs:297](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:297)). V6 names transit TX and LocalDelivery reinjection only ([plan.md:419](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:419)). The first gap permits dropped samples to move the anchor; the second leaves accepted traffic untracked and can soft-refuse a later legitimate close.

7. **HIGH — Establishment promotion still occurs before packet acceptance.**

   Session resolution runs before input filtering and TTL enforcement ([poll_descriptor/mod.rs:411](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:411), [poll_descriptor/mod.rs:592](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:592), [poll_descriptor/mod.rs:846](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:846)); lookup currently performs state propagation and wheel updates immediately ([lookup.rs:129](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:129)). V6’s “post-borrow lookup” transition ([plan.md:582](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:582)) is therefore still pre-commit.

   A correctly proved SYN+ACK that is subsequently filtered, TTL-expired, or fails dispatch can promote the entry to ESTABLISHED and refresh its long lifetime despite never being forwarded. Exact proof limits off-path abuse but does not satisfy the plan’s mutation-only-after-acceptance invariant. Promotion must move into the successful commit arm.

8. **MEDIUM — Simultaneous-open support is represented in layout but absent from the state machine.**

   The anchor contains `rev_open_ack_lo` ([plan.md:383](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:383)), but V6 defines neither a trusted transition that populates it nor a valid bit governing it. A reverse bare SYN cannot prove its sequence under the per-field rules; promotion recognizes the reverse SYN+ACK against the original initiator’s interval ([plan.md:582](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:582)). In a legal simultaneous-open exchange where that reverse SYN+ACK is lost but the other SYN+ACK and final ACK complete the endpoints’ handshake, xpf remains OPENING and may reap a live flow on the opening trajectory. The behavior needs an explicit transition and test; simultaneous open is part of the standardized TCP state machine ([RFC 9293 §3.5](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5)).

9. **LOW — One mandatory HA test has an impossible expected outcome.**

   The test at [plan.md:1023](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1023) says a non-close packet materializes and promotes the entry, but then expects that entry to emit no `Close`. Promotion produces `SharedPromote`, which is not peer-synced ([entry.rs:245](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:245)); ordinary expiry therefore does emit `Close` ([expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342)). The test must distinguish unpromoted-close cleanup from later non-close promotion. The implementation prescription should also explicitly require `wrapping_add` for `seq+SEG.LEN` and a compile-time 32-byte layout assertion.

### Round-4 finding dispositions

R4-1 — **resolved.** Fabric-derived authority is removed consistently; fabric-return reverse seeds remain deliberately anchorless and refuse close demotion.

R4-2 — **partially resolved.** Closing packets no longer promote or accelerate a peer entry, but the replacement premise that the old owner remains an authoritative cleanup source is false.

R4-3 — **partially resolved.** Trusted self-direction sliding fixes the established-flow LocalDelivery/full-duplex stall, but it makes the OPENING proof mutable; the claim that inbound ACKs can pin an unseen outbound side is also false without that side’s trusted baseline.

R4-4 — **partially resolved.** V6 adds the lower bound, TFO-aware exact interval, and concrete layout. The upper proof endpoint remains mutable, promotion is pre-commit, and simultaneous-open transitions are undefined.

R4-5 — **partially resolved.** Most mutation hooks move toward enqueue/reinjection success, but cross-worker false-success drops and accepted ForwardCandidate fallback reinjection remain uncovered. GRE and NAT64 are otherwise routable through the proposed dispatch context.

R4-6 — **resolved.** The segment-wide trust laundering rule is removed and replaced by per-field proof plus the own-ACK leg. The new direction and three-window arithmetic defects are separate V6 issues.

R4-7 — **partially resolved.** Tail presence, trusted-only import, and old-decoder compatibility are sound. Update production, change detection, actual cadence, retry watermarking, and Rust in-place import remain unspecified or incompatible with the cited sweep.

R4-8 — **resolved.** `FreshPrimary` and `ReplacedSyncedLocal` now have distinct initialization rules and a mandatory regression test; a replaced synchronized entry cannot regain fresh SYN trust merely from its flags.

R4-9 — **partially resolved.** V6 adds pre-packet-window, midpoint, tracker, metrics, and fabric tests, but retains stale probability, pre-commit, impossible no-`Close`, and incomplete OPENING expectations.

R4-10 — **resolved.** The proposed field order is 32 bytes and the per-leg half-space assertion is correctly scoped. OPENING immutability and explicit wrapping arithmetic remain new requirements rather than failures of that narrow fold.

V6 fixes several important prior defects: fabric-derived authority is gone, no-baseline closes remain non-demoting, segment-wide trust adoption is removed, and established self-direction tracking addresses the original permanent-stall class. It is still not implementable safely as written: failover can strand shared/NAT cleanup with no authoritative `Close` producer, mutable OPENING state converts an exact proof into a window search, and Phase 2 relies on a sweep that cannot observe or transport anchor changes. The incorrect ACK-window direction, understated three-leg probability, and incomplete commit boundary reinforce the verdict.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
