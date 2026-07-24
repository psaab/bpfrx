# Codex hostile plan review — round 4 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion, resumed session 019f95f3-c124-7c60-9d1b-198b9629c197). Scope: plan v5 @ 078009c78.
Run ledger: task-mrzjrykr-7io911 (2m47s, turn failed — content-filter infra error while reading the plan doc); resumed task-mrzjwgox-olobll (28m11s, completed) with defensive-framing directive. Verbatim final output below (.scratch/r4-codex-final.txt).

---

PLAN NO

1. **BLOCKER — Fabric ingress is not sequence authority; the exception restores the post-failover two-packet kill.**

   V5 treats every fabric-ingress segment as authenticated because “the owner forwarded it” ([plan.md:528–532](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:528)). That premise is false: an inactive node converts ordinary external traffic into `FabricRedirect` ([poll_descriptor/mod.rs:3438–3476](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3438), [fabric.rs:331–342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forwarding/fabric.rs:331)). The forwarding node is specifically the non-owner; forwarding through it proves neither sequence placement nor endpoint acceptance.

   Brief trace: after failover, a guessed-tuple non-close packet enters the old owner on a normal port, is redirected over fabric, and reaches the new owner’s zero-trust import. V5’s exception authenticates its arbitrary sample. A following redirected close then validates against that planted anchor and can produce the `SharedPromote` Close chain.

   Direct marker forgery is also possible on supported shared data/fabric-parent configurations: classification accepts either parent or overlay ([fabric.rs:179–193](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forwarding/fabric.rs:179)); the parent marker is only source-MAC magic plus a configured zone ID ([inspect.rs:1916–1944](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/frame/inspect.rs:1916)); and sharing the parent with a data interface is explicitly supported ([manager_interfaces_test.go:786–818](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/manager_interfaces_test.go:786)). A genuinely different non-fabric ifindex cannot forge `meta_flags`—XDP supplies the ifindex and initializes flags to zero ([lib.rs:426–429](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-xdp/src/lib.rs:426), [lib.rs:681–700](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-xdp/src/lib.rs:681)—but an off-fabric sender can still acquire the stamp through the normal HA redirect.

   Remove this exception unless the wire carries authenticated owner/flow/direction authority. The current packet’s classifier, never persisted `metadata.fabric_ingress`, must govern any eventual exception.

2. **BLOCKER — A refused promotion still turns a held replica into an expiring authoritative entry.**

   V5 retains the `SharedPromote` origin flip and Open delta while explicitly withholding `last_seen_ns` refresh and wheel re-bucketing ([plan.md:690–705](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:690)). That does not preserve the pre-packet expiry trajectory:

   - Promotion writes `SharedPromote`: [promote.rs:86–107](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86).
   - `SharedPromote` is not peer-synced: [entry.rs:242–250](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:242).
   - The original `SyncImport` on a newly active RG would self-heal and refresh/rebucket at expiry: [expire.rs:213–237](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:213), [expire.rs:549–561](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:549).
   - After the origin flip, the old wheel hint instead evaluates stale `last_seen_ns`, removes the forward entry, and emits Close: [expire.rs:159–168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:159), [expire.rs:322–377](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:322).

   Thus a blind first close after failover can suppress activation self-heal and accelerate an idle import into an authoritative Close even though it never received the 2-second mark. This directly contradicts the “promoted entry emits NO Close” test at [plan.md:944–949](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:944).

   A one-shot activation refresh is not spray-pinnable because promotion occurs once. Otherwise retain peer-synced expiry behavior or suppress Close authority until non-close traffic or a validated close establishes it.

3. **BLOCKER — The literal transaction rules freeze trusted anchors during fully observed traffic.**

   Every update to an already-trusted field requires the entire segment to authenticate ([plan.md:513–523](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:513)), but authentication is exclusively cross-directional ([plan.md:480–500](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:480)).

   Two ordinary cases therefore stall:

   - With only one observed LocalDelivery direction, an existing trusted `seq(D)` cannot authenticate its own next contiguous packet. No opposite trusted field exists, so rule (iii) forbids moving it. This contradicts [plan.md:419–424](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:419).
   - On full-duplex scaled-window traffic, `seq(D)` can exceed the opposite ACK by 131,070 bytes while `ack(D)` trails the opposite sequence by more than 65,536. Neither field proves, despite every packet being observed. At 10/25 Gbit/s those bounds represent only approximately 105/42 μs and 52/21 μs of flight time.

   This refutes “every real segment proves trivially” and the claimed stall taxonomy at [plan.md:541–560](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:541). Existing trusted fields must self-slide through their own bounded RFC-1982 continuity gate; cross-proof should govern only untrusted-to-trusted conversion.

4. **BLOCKER — The OPENING state machine cannot enforce its advertised exact predicate.**

   The interval itself is correct: SYN-SENT accepts `ISS < ACK <= SND.NXT`, rejects ACKs beyond `SND.NXT`, and TFO can acknowledge only SYN or SYN plus accepted data. No conforming peer needs an ACK above that bound. See [RFC 9293 §3.10.7.3](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.3) and [RFC 7413 §4.2.2](https://www.rfc-editor.org/rfc/rfc7413.html#section-4.2.2).

   The proposed representation cannot implement it. `TcpSeqAnchor` stores only `seq_hi` values ([plan.md:364–386](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:364)), while validation needs both endpoints of `[ISS+1, ISS+SEG.LEN]` ([plan.md:619–626](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:619)). Current `SessionEntry` retains neither ISS nor SYN-data span ([session/mod.rs:343–387](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:343)). Threading `TcpSegView` through installation does not persist the missing lower endpoint.

   In addition, current lookup promotes every non-closing reverse SYN-ACK before proof or forwarding commitment, refreshes its timeout, propagates establishment, and queues the wheel entry ([lookup.rs:129–172](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:129), [lookup.rs:197–218](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:197)). V5 suppresses only closing SYN-ACK promotion ([plan.md:533–539](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:533)). An unacceptable, TTL-expired, or filtered SYN-ACK can therefore convert the 20-second OPENING entry to ESTABLISHED before the exact proof; the plan does not specify whether the later hook still selects the strong predicate from an immutable pre-packet state.

   Persist the OPENING lower bound/span and move establishment promotion to successful commitment after `StrongHandshake` proof. The `≤1/2^21` TFO claim is also not universal: with the current 4096-byte frame ceiling ([afxdp/mod.rs:233–251](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/mod.rs:233)), the interval can approach `1/2^20`.

5. **HIGH — The proposed “commit hooks” still run before actual transmission or delivery commitment.**

   On the slow path, `build_live_forward_request_from_frame` merely completes policy/CoS selection and returns a request ([forward_request.rs:264–290](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forward_request.rs:264), [forward_request.rs:368–396](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forward_request.rs:368)); the caller only queues it at [poll_descriptor/mod.rs:3752–3855](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3752). Dispatch can subsequently drop it for missing binding, MTU, translation/build failure, oversize, or queue pressure ([dispatch/mod.rs:512–573](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/mod.rs:512), [dispatch/mod.rs:728–747](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/mod.rs:728), [dispatch/mod.rs:819–955](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/mod.rs:819)).

   Concrete requested class: NAT64 is non-cacheable and reaches the slow `ForwardCandidate` hook ([poll_descriptor/mod.rs:3738–3750](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3738)), but AH+TCP is parsed as TCP through AH ([lib.rs:1257–1294](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-xdp/src/lib.rs:1257)) and later rejected by NAT64 ([nat64.rs:1597–1620](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat64.rs:1597)). Its anchor would update although no packet is emitted.

   Cache-path learning after the drop gate is likewise before rewrite success/fallback ([flow_cache_hit.rs:269–271](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:269), [flow_cache_hit.rs:427–555](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:427)). LocalDelivery’s actual reinjection is only at [poll_descriptor/mod.rs:5117–5139](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5117), and reinjection can rate-limit, fill, exceed MTU, or fail enqueue ([slow_path.rs:186–357](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:186)).

   Learning must occur in successful prepared-TX/enqueue or reinject-acceptance arms, requiring corresponding session/segment plumbing.

6. **HIGH — Segment-wide weak adoption remains an unnecessary arbitrary-sequence promotion channel.**

   With only trusted `seq_fwd`, a reverse non-close segment whose ACK happens to hit `window(seq_fwd)` causes all its fields—including an unrelated reverse sequence—to become trusted under [plan.md:480–512](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:480). A later reverse close at that adopted value passes [plan.md:612–614](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:612). Endpoint acceptance of the precursor is unknown to the firewall.

   The claimed deadlock is real only for the `seq_rev`/`ack_fwd` pair under the chosen binary state, not as an architectural necessity. Safer alternatives exist:

   - Trust both meaningful fields on an ACK-bearing non-SYN primary pickup.
   - Represent `Absent | Observed/Associated | CloseAuthoritative`.
   - Promote only the field that directly proved; associated fields cannot validate or authenticate.
   - Permit an ACK-bearing close to prove directly through its ACK against trusted opposite sequence without blessing its arbitrary sequence. Bare one-sided RSTs may soft-refuse.

   In the exact one-sided state this precursor has one acceptance leg—approximately `1/32768` to `1/21845`, not `1/2^13`. “Real traffic closes the race” is also false for scaled-window/high-BDP streams.

7. **HIGH — Phase 2 is load-bearing but does not transport a current anchor.**

   The 18-byte additive field shape and “trusted sides only” rule are directionally sound. Existing payloads already use trailing length-gated fields ([sync_protocol.go:95–102](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go:95), [sync_protocol.go:470–497](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go:470)), so old decoders can ignore an additive tail.

   The proposed rolling mechanism is not real, however. `syncHeader` has no wire version or capability bitmap ([sync.go:21–36](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go:21), [sync.go:79–87](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go:79)); the auth HELLO carries only auth version, keyed flag, and nonce ([sync_auth.go:60–75](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go:60)). There is no existing “session-sync handshake version bitmap” matching [plan.md:1060–1065](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1060).

   More importantly, anchors evolve per packet, but Rust deltas only have Open and Close ([entry.rs:277–290](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:277)), and the normal Go sweep retransmits only newly created entries ([sync_conn_sweep.go:137–169](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:137)). An anchor carried only on initial Open is stale by failover once the flow advances beyond slack. The standby then still cannot authenticate ordinary post-failover traffic. The worker owner-RG export can snapshot live table truth ([session_glue/mod.rs:584–621](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:584)), but v5 specifies neither periodic/coalesced anchor updates nor a freshness bound.

   Phase 1 alone is security-safe only as a fail-closed compatibility mode. Given 300–86,400-second lingering and synced-upsert cap bypass, it is not a complete shippable HA solution. Phase 2 needs to land in the same feature-gated delivery, with the full Rust event → Go value → cluster wire → Go request → Rust import pipeline and current-anchor refresh semantics specified.

8. **HIGH — Constructor provenance is origin-complete but not context-complete.**

   The `LocalMiss` installer can first remove an existing peer-synced `LocalDelivery` entry and then reinstall the same key with `origin=LocalMiss` ([local_delivery.rs:75–113](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forwarding/local_delivery.rs:75)); `take_synced_local` explicitly accepts `SyncImport`/`SharedMaterialize` LocalDelivery entries ([lookup.rs:407–418](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:407)). The caller supplies `LocalMiss` unconditionally ([poll_descriptor/mod.rs:1950–1964](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1950)).

   Therefore “`LocalMiss` self-authenticates” is insufficient to enforce “genuinely new.” If that replacement branch runs, its driving SYN must remain untrusted; otherwise a peer-synced victim is reclassified as a fresh self-authenticating flow. The installer needs explicit `FreshPrimary` versus `ReplacedSyncedLocal` provenance, with a mandatory replacement test.

9. **MEDIUM — Several normative contradictions and validation gaps remain.**

   - Section 3 correctly says forward-wire matches can mark through promotion ([plan.md:301](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:301)), while §§5.6/7 still call them “never marks” or “demote-free” ([plan.md:755–758](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:755), [plan.md:875–879](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:875).
   - Section 2 correctly says zero-trust imports are absorbing ([plan.md:182–196](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:182)), but the PASS_TO_KERNEL residual still claims later local observation builds trust ([plan.md:880–885](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:880)).
   - Authentication must explicitly use the immutable pre-packet anchor, including old trusted `wnd`; otherwise a segment can widen the window used to authenticate itself. ACK proof must also name the receive-window direction independently.
   - Tracker tests need exact `0xfffffff0→0x20`, zero, `FWD_SLACK`, `FWD_SLACK+1`, and `2^31` deltas, plus OPENING wrap, trusted self-slide, dispatch-failure non-observation, fabric redirect trust, stale-wheel promotion, and LocalMiss replacement.
   - `tcp_close_seq_rejected` is adequate only if exported through ordinary worker statistics. A rate-limited structured RT_FLOW/screen event is desirable for attack attribution; debug-only logging is insufficient ([plan.md:656–659](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:656)).

10. **LOW — Requested negative checks that otherwise pass.**

   The remaining production constructors map conservatively:

   | Path | Origin / trust result |
   |---|---|
   | Primary miss ([poll_descriptor/mod.rs:2449–2458](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2449)) | `ForwardFlow`, self-authenticating |
   | Missing-neighbor seed ([poll_descriptor/mod.rs:4780–4795](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4780)) | `MissingNeighborSeed`, self-authenticating |
   | Reverse companion/synth ([poll_descriptor/mod.rs:2777–2787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2777), [shared_ops.rs:824–865](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:824)) | `ReverseFlow`, never self-authenticating |
   | Fabric-return seed ([poll_descriptor/mod.rs:927–989](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:927)) | `ReverseFlow`, never self-authenticating |
   | Wire/tunnel upsert ([upsert_synced.rs:18–79](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:18), [session_glue/mod.rs:756–800](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:756)) | sync-family origin, never self-authenticating |
   | Materialization ([session_glue/mod.rs:1092–1115](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092), [entry.rs:264–269](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:264)) | `SharedMaterialize`/`WorkerLocalImport`, untrusted-only |

   The SYN-cookie ACK path creates no session; it consumes a valid ACK and emits the bounded response ([poll_stages.rs:776–786](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_stages.rs:776), [poll_descriptor/mod.rs:887–916](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:887)). Outside finding 2’s promotion edge, refused-close spray neither pins nor accelerates an entry: accounting changes only counters/observed flags ([session/mod.rs:1177–1211](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1177)), and the wheel uses unchanged canonical expiry/rebucket state ([expire.rs:159–168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:159), [expire.rs:386–409](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:386)). The ESTABLISHED union arithmetic, precursor additive cost, trusted-window input, per-leg serial assertion, and 24-byte size are now correct.

### Round-3 finding dispositions

- **R3-1 — partially resolved.** Generic materialization/import self-authentication is fixed, but `LocalMiss` replacement lacks fresh-versus-synced context and the fabric exception recreates free trust.
- **R3-2 — partially resolved.** The RFC/TFO interval is correct; its lower endpoint is not stored, establishment still promotes before proof, and entropy is overstated.
- **R3-3 — partially resolved.** Replacement, monotonicity, untrusted non-authentication, and `wnd` trust are specified. Segment-wide blessing and the authenticated-only trusted slide remain wrong.
- **R3-4 — partially resolved.** The absorbing state and capacity cost are candidly documented, but Phase 2 has no current-anchor update mechanism or real capability gate; PASS_TO_KERNEL prose still contradicts absorption.
- **R3-5 — resolved.** Scope/snapshot, flags, both installation shapes, and `None` provenance are now specified. The corrected real commit boundary will require additional output-side plumbing under R3-6.
- **R3-6 — not resolved.** Hooks moved post-policy but remain pre-dispatch/pre-reinjection success.
- **R3-7 — not resolved.** Forward-wire site 8 is corrected only in one section, and refused promotion still changes expiry/Close authority.
- **R3-8 — resolved.** Union/overlap arithmetic, precursor cost, trusted `wnd`, raw-window residual, serial max, and the per-leg assertion are corrected.
- **R3-9 — partially resolved.** Deterministic cases were added, but the blocking self-slide, OPENING-storage, fabric, actual-commit, LocalMiss-replacement, evolving-wire-anchor, and stale-promotion tests are absent; one stated no-Close expectation is impossible.
- **R3-10 — resolved narrowly.** The anchor is correctly accounted as 24 bytes, and the previously approved reverse-synth/re-anchor mechanics remain sound. The new OPENING representation defect is separate and blocking.

Bottom line: v5 materially improves the provenance inventory, no-baseline behavior, arithmetic, and residual disclosure, but it is still not implementation-ready. Fabric routing is incorrectly elevated into TCP authority, refused promotion can still manufacture an authoritative expiry, the trust transaction freezes ordinary observed flows, and the exact OPENING predicate has neither sufficient state nor a proof-gated establishment transition. Phase 2 also needs a real current-anchor propagation design and must ship with the HA-enabled feature rather than as an unspecified fast-follow. No files were edited.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
