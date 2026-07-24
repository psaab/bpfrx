# Codex hostile plan review — round 2 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion). Scope: plan v3 @ 396e24300.
Run ledger: task-mrzfkngy-ocvr2e (17m30s, turn failed at final-assembly — content-filter infra error after the analysis completed; partial output captured the PASS_TO_KERNEL finding); resumed task-mrzg8a40-gwcq3m (8m44s, completed) with a defensive-framing continue directive. Session 019f95f3-c124-7c60-9d1b-198b9629c197.
Verbatim final output below (.scratch/r2-codex-final.txt).

---

PLAN NO

1. **BLOCKER — The post-failover cluster-wide kill remains.**

A local imported hit reaches `lookup_with_origin` with the current close flags through [shared_ops.rs:594–603](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:594). With no anchor, v3 fail-opens and marks it.

The shared-only case is worse: reactive materialization installs using the current packet’s `tcp_flags` at [session_glue/mod.rs:1092–1115](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092), which seeds `closing/reset` at [install.rs:399](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:399) before the proposed promotion validator runs. V3’s “complete” packet-driven constructor inventory misses this site.

On the new owner, HA enforcement yields `ForwardCandidate`, satisfying the promotion guard at [promote.rs:86–107](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86). Promotion retags the entry `SharedPromote`; that origin is neither peer-synced nor transient at [entry.rs:245–274](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:245), so expiry emits a Close at [expire.rs:342–377](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342).

The trace’s gen-zero detail is not normally correct: promotion emits an Open delta at [session/mod.rs:1480–1530](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1480), Go stamps it, and the later Close draws a fresh higher delete generation at [sync_conn_write.go:53–82](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:53). That delete still applies at [sync_conn_gen.go:493–506](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:493). Gen-zero is only the missing-sender-stamp fallback, and is also unconditional. Therefore the cluster-wide outcome is confirmed.

2. **BLOCKER — The proposed anchor trusts packets before forwarding commitment.**

Site (b) runs during resolution at [poll_descriptor/mod.rs:411–431](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:411), before:

- input-filter drops at [poll_descriptor/mod.rs:592–638](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:592);
- LocalDelivery admission/filter drops at [poll_descriptor/mod.rs:640–844](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:640);
- TTL/hop-limit consumption at [poll_descriptor/mod.rs:846–880](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:846).

Thus a packet that never reaches an endpoint can slide the anchor or apply an accepted close. This directly invalidates v3’s claims that anchor walking is endpoint-data-injection-equivalent and that every sprayed close reaches RFC 5961 endpoints.

Site (a) is also not a delivery-commit point: slow accounting runs at [poll_descriptor/mod.rs:3497](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3497), before output-filter/CoS processing can return `None` at [forward_request.rs:264–290](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forward_request.rs:264) and [forward_request.rs:368](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forward_request.rs:368). Trusted updates and destructive marking require a post-filter, post-TTL forwarding-commit hook.

3. **BLOCKER — `!valid` seeding preserves the two-packet bypass; REFUSE-on-no-baseline alone is insufficient.**

V3 unconditionally adopts an ordinary first sample when a side is invalid at [plan.md:364–371](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:364). Consequently the stated trace is correct: an arbitrary non-close sample initializes the missing side, and a following close at that value validates. Flipping rule 3 would stop the first-packet post-failover close, but not this precursor-plus-close path because the close no longer sees “no baseline.”

The slide itself is also too permissive: it requires neither overlap nor positive `seg_len`. A zero-length sample may advance by the entire slack, contradicting the claimed `window/MSS` packet cost.

Additionally, v3 never requires ACK to be set before making `ack_hi` valid. A bare SYN’s insignificant ACK field is normally zero; if adopted, the later real ACK is likely too far away to repair it, leaving a predictable ESTABLISHED union leg near sequence zero. ACK validity must be gated by `has_ack`.

Correct disposition: no trusted baseline should **REFUSE-DEMOTE**, but imported/upgrade state must also remain demotion-ineligible until initialized from trusted handshake/HA state or bounded against an already-trusted opposite-direction anchor. Reactive materialization must likewise be gated before it derives flags from the current packet.

4. **BLOCKER — The coverage union misses translated forward-wire session hits.**

After `lookup_with_origin` misses, `lookup_session_across_scopes` can return a live local session through immutable `find_forward_wire_match_with_origin` at [shared_ops.rs:614–628](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:614) and [lookup.rs:258–293](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:258). Site (b) therefore never runs.

Site (a) still uses the wire/query key at [poll_descriptor/mod.rs:3494–3502](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3494), while `account_packet` accepts only canonical primary keys at [session/mod.rs:1043–1051](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1043) and [session/mod.rs:1183–1195](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1183). The resolver already knows the canonical key at [session_glue/mod.rs:1199–1256](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1199), but does not use it for accounting.

An arbitrarily long translated-wire stretch therefore freezes the authoritative anchor. Later canonical legitimate closes soft-refuse; a promotable synced close can instead reach `update_session` with no baseline and fail open.

5. **HIGH — LocalDelivery coverage is conditional; several named classes remain uncovered.**

Within AF_XDP, LocalDelivery hits do transit resolve and lookup. The actual hit re-evaluation is [poll_descriptor/mod.rs:640–654](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:640); v3’s cited line 1744 is the session-miss branch.

Peer-synced forward LocalDelivery entries without tunnels, however, are published as `PASS_TO_KERNEL` at [bpf_map/mod.rs:3–12](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:3) and [bpf_map/mod.rs:539–550](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:539). XDP then returns before AF_XDP at [userspace-xdp/src/lib.rs:584–605](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-xdp/src/lib.rs:584). Those packets cannot demote Rust state while bypassing, but they also never establish or advance an anchor; the first packet after a later REDIRECT/publish/HA transition encounters no-baseline fail-open.

Other requested classes:

| Class | Coverage and consequence |
|---|---|
| Fabric-return fast path | First non-close reverse seed bypasses both sites; bare close is excluded at [fabric.rs:410–430](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forwarding/fabric.rs:410). A later close can demote only the local reverse seed; `is_reverse` suppresses Close delta, so no owner kill. |
| Tunnel `UpsertLocal` | Outbound packets and five-second refreshes carry flags, not sequence state, at [tunnel.rs:691–742](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tunnel.rs:691). First inbound close can fail-open against an absent anchor; blast radius is local/tunnel state, not an authoritative Close delta. |
| Embedded ICMP lookups | Correctly pass flags zero and should pass `seg=None`; the quotation is not a TCP sample and cannot demote. |
| Native GRE | Covered: decap rebases `packet_frame` and metadata before flow parsing at [poll_descriptor/mod.rs:163–186](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:163). |
| NAT64 | Unfragmented traffic is non-cacheable and reaches slow resolution. Non-first associated fragments are flowless and cannot carry a TCP close/sample. |
| Exotic IPv6 chains | Remain the documented stale-anchor case: legitimate close may soft-refuse, but the exotic packets do not directly demote the protocol-6 session. |

6. **HIGH — Window arithmetic and the security headline remain wrong.**

`wnd(O)` is the correct direction for validating sequence progress in D, but `2 × raw_u16_wnd` can never exceed 131,070 bytes. The advertised 512 KiB cap is unreachable without window-scale tracking.

For two non-overlapping ESTABLISHED legs:

- Floor: `2 × (64 KiB back + 64 KiB forward + 1)` = 262,146 values, approximately **1/16,384**, not 1/32,768; about 16.4 seconds mean at 1,000 pps.
- Maximum reachable raw-window slack: 393,214 values, approximately **1/10,923**.
- Hypothetical reachable 512 KiB cap: 1,179,650 values, approximately **1/3,641**; “~1/3,800” is reasonable rounding.

The 1/32,768 claim applies only when the two floor legs overlap almost completely. Sections 2 and 8 must state the overlapping-to-disjoint range.

Forward slack represents only:

- 64 KiB: 52.4 µs at 10 Gbit/s; 21.0 µs at 25 Gbit/s.
- Reachable 131,070-byte maximum: 104.9 µs / 41.9 µs.
- Hypothetical 512 KiB cap: 419.4 µs / 167.8 µs.

A defensible TCP-derived input requires the opposite endpoint’s negotiated direction-specific scale (`raw << wscale`) and careful treatment of previously advertised right edges. The multiplier two is an unsupported heuristic. The midpoint `const` assertion is correct for each individual interval and should be typed/co-located with the constants; it does not bound the union probability.

7. **HIGH — Permanent stall is realistic, although the naive re-anchor escape hatch is still wrong.**

A route/asymmetry flap can allow both sequence and cumulative ACK progress to advance off-box, then rejoin more than the actual 64–128 KiB slack ahead. The endpoints already accepted that stretch, so no retransmission near the stale anchor is required; subsequent samples remain rejected indefinitely. Large path-switch reordering can exceed 128 KiB in tens of microseconds at target rates.

Plain downstream loss, ordinary jumbo frames, GRO, and keepalive-only periods do not by themselves create a permanent stall: XDP observes pre-GRO frames, keepalives do not advance sequence space, and normal retransmission can bridge a lost gap. The dangerous cases are genuinely unobserved/asymmetric stretches and path-switch reordering—several of which the coverage findings above prove exist.

Per connection, the direct result remains soft-refusal and ordinary-timeout aging. The understated worst case is aggregate table/SNAT retention across many flows after a path event, with stale authorization lasting the established/application timeout. Refusing an “N rejected samples” re-anchor is correct because it is stageable; recovery would need trusted HA state or independently corroborated progress.

8. **HIGH — Reverse skip-install is sound only when validation actually refuses; OPENING behavior is overstated.**

For a valid anchor, skip-install plumbing works:

- `created=false`, `install_failed=true` are returned at [session_glue/mod.rs:1330–1344](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1330);
- create telemetry is suppressed at [poll_descriptor/mod.rs:509–547](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:509);
- cache insertion is suppressed at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900);
- the synthesized decision still forwards and the next reply re-enters synthesis.

But a shared-NAT match has no anchor: `ForwardSessionMatch` carries only key/decision/metadata at [entry.rs:209](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:209), and shared lookup constructs one at [shared_ops.rs:638–665](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:638). Fail-open therefore still installs a born-dying `ReverseFlow` on the non-owner. `is_reverse` prevents a Close delta and local-only companion probing cannot reach the owner, but the absolute “mints nothing” claim is false. Its published shared reverse also lacks reverse-only expiry cleanup; shared removal is Close-driven at [session_delta.rs:406–452](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:406).

For a trustworthy SYN anchor, OPENING’s `ack == isn + SEG.LEN` equality is correct and TFO-aware; a blind first RST|ACK has a 32-bit ACK guess. However:

- the synthesized reverse is initialized ESTABLISHED because it was not created by a bare SYN at [install.rs:157–180](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:157), so subsequent validation must explicitly use the canonical forward entry’s OPENING state;
- the first accepted RST marks only the reverse entry;
- its nominal two-second expiry can be retained by the still-live forward OPENING companion at [expire.rs:318](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:318) and [expire.rs:468–523](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:468), normally until the 20-second opening window;
- only a later accepted hit propagates the mark to both halves.

Thus the exact-ACK validator is sound with a trusted anchor, but v3 does not yet preserve the claimed two-second whole-flow teardown chain.

9. **HIGH — Post-borrow marking is feasible, but “refused close is inert” is underspecified.**

Today, after the first mutable borrow ends, lookup does exactly:

1. companion propagation at [lookup.rs:198–213](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:198), including companion mark/reset/timeout/wheel at [session/mod.rs:1241–1277](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1241);
2. matched-entry wheel push at [lookup.rs:214–218](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:214).

The worker is single-threaded, so inserting validation and the matched-entry re-probe before those operations has no interleaving hazard. On acceptance, `reset |= RST` must still precede timeout selection, preserving #3046; OR-assignment preserves #3489. On refusal, moving all writes currently at [lookup.rs:150–172](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:150) plus the wheel push behind acceptance preserves the pre-packet trajectory.

Two holes remain:

- `promote_from_reverse` currently mutates `established` inside the first borrow at [lookup.rs:146–149](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:146). A refused SYN|ACK|RST can therefore still promote both halves unless every close-packet mutation is staged.
- A refused slow close later reaches `account_packet`. Site (a) receives no prior verdict. It must explicitly skip all FIN/RST anchor updates; site (b) must exclusively own accepted-close updating.

For ordinary or accepted slow packets, the double update is value-idempotent: the second identical seq/ACK/window sample is a no-op, and sequential borrows are safe. No dedup gate is required for correctness.

10. **MEDIUM — V3 is internally contradictory and does not specify required data plumbing.**

The normative skip-install rule is [plan.md:499–511](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:499), but:

- the constructor inventory still says “refused close → entry born ALIVE” at [plan.md:230](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:230);
- the required test expects that obsolete entry at [plan.md:639–643](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:639);
- open question 2 analyzes the discarded born-alive design at [plan.md:707](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:707);
- open question 3 still says `wnd(D)` at [plan.md:712](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:712).

V3 also claims no `lookup_with_origin` signature change while requiring a segment view at that site. Current `SessionInstall` carries only flags at [session/ctx.rs:31–48](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/ctx.rs:31), so install-time and reactive-materialization anchor seeding are not implementable as specified.

### Round-1 B1–B12 dispositions

- **B1 — partially resolved.** Pre-packet validation and bounded slides fix self-validation, but invalid-side adoption, ACK-without-ACK validity, sparse zero-length walking, and pre-forward tracking remain.
- **B2 — partially resolved.** Reverse synthesis is named and skip-install is the right valid-anchor action; reactive shared materialization, shared no-anchor fail-open, and contradictory born-alive requirements remain.
- **B3 — resolved.** One authoritative store, wrapping membership, and the serial-midpoint assertion remove the cross-store merge defect.
- **B4 — resolved mechanically.** The two-direction anchor is defined on the canonical forward entry and flow-cache state is removed. The forward-wire coverage failure is a new plumbing defect.
- **B5 — resolved.** The helper uses the active frame plus IP-declared, frame-clamped TCP length.
- **B6 — partially resolved.** AF_XDP LocalDelivery, GRE, and ordinary NAT64 are covered, but translated forward-wire, `PASS_TO_KERNEL`, fabric-return seed, and local-tunnel stretches remain.
- **B7 — partially resolved.** Direction was corrected and a floor added, but the cap is unreachable and union/security arithmetic remains wrong.
- **B8 — resolved for the original direct-replica case.** The Rust no-Close boundary is named and an exact regression is required. The post-promotion `SharedPromote` kill is a separate unresolved blocker.
- **B9 — partially resolved.** The opposite-ACK union and TFO-aware OPENING equality are correct, but ACK validity and canonical-forward lifecycle-state sourcing remain unspecified.
- **B10 — resolved as scope/framing.** V3 now distinguishes Junos default general sequence checking from RST-specific behavior and corrects the schema/reply-direction facts. Option A still fails on its mechanics.
- **B11 — resolved.** Refusal explicitly avoids mark, refresh, and wheel requeue.
- **B12 — partially resolved.** Small-frame and major regression gates were added, but the reverse-synth test contradicts v3, `iperf3 -l 64` is not a demonstrated line-rate minimum-frame generator, and the new coverage/bootstrap/pre-commit cases lack mandatory tests.

Bottom line: v3 fixes important round-1 defects—single-store state, pre-packet comparison, correct frame-length extraction, opposite-direction reset support, and inert refusal intent—but its trust boundary is still wrong. It learns from packets before the firewall commits to forwarding them, misses live translated and kernel-bypass paths, accepts destructive action with absent or attacker-initialized state, and understates both its acceptance probability and stall exposure. The plan needs a post-forward-commit anchor update design, REFUSE-DEMOTE on absent trusted state, trusted bootstrap/materialization semantics, canonical-key coverage, and corrected reverse/OPENING plumbing before implementation. No files were edited.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
