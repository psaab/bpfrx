# Codex hostile plan review — round 3 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion, resumed session 019f95f3-c124-7c60-9d1b-198b9629c197). Scope: plan v4.2 @ f99e1df0e.
Run ledger: task-mrzhtb46-hwfisv (26m05s, completed). Verbatim final output below (.scratch/r3-codex-final.txt).

---

PLAN NO

Reviewed v4.2 at `f99e1df0e`.

1. **BLOCKER — Constructor self-authentication reopens the two-packet SharedPromote kill.**

The plan makes a creating packet an unconditional trusted seed at [plan.md:428–435](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:428), while adding the current segment to `SessionInstall` at [plan.md:733–737](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:733). That constructor is also used for reactive shared materialization at [session_glue/mod.rs:1092–1115](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092).

Literal trace:

1. A non-close packet with arbitrary `seq=X` causes a shared victim to materialize.
2. Generic install seeding trusts `X+SEG.LEN`.
3. The new owner may immediately retag the entry `SharedPromote` through [promote.rs:86–107](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86).
4. A subsequent RST at the planted value validates; `SharedPromote` expiry is Close-eligible at [expire.rs:342–377](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342).

Section 5.6 suppresses only a closing packet’s materialization seed at [plan.md:695–705](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:695); it does not prohibit non-close self-authentication.

The plan needs an explicit provenance matrix. Only genuinely new, canonical, locally admitted flows may self-authenticate. `SyncImport`, `SharedMaterialize`, `WorkerLocalImport`, and reverse-companion synthesis must never receive unconditional install trust.

2. **BLOCKER — OPENING authentication is internally inconsistent and not TFO-correct.**

The plan simultaneously says:

- SYN-ACK authentication is effectively exact and requires the client ISN, `1/2^32`, at [plan.md:477–482](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:477);
- cross-authentication succeeds when a field lands “inside a trusted window,” at [plan.md:483–494](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:483) and [plan.md:875–879](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:875).

If OPENING uses the broad window, a spoofed non-closing SYN-ACK needs only a one-window ACK hit—approximately `1/32768` to `1/21845`. It then authenticates an attacker-chosen reverse sequence, promotes the flow, and makes a following RST deterministic. That is a large reduction from the claimed exact 32-bit proof.

Exact `ack == isn+SEG.LEN` is not the alternative either. A TFO server may reject the SYN data and acknowledge only the SYN. More generally, SYN-SENT accepts `ISS < SEG.ACK <= SND.NXT`; RFC 9293 specifically warns that equality with `SND.NXT` is wrong when a SYN carries data. [RFC 7413 §4.2.2](https://www.rfc-editor.org/rfc/rfc7413.html#section-4.2.2), [RFC 9293 §3.10.7.3](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.3).

OPENING needs a separately stored acceptable ACK interval `[ISS+1, SND.NXT]`. For a bare SYN it collapses to one exact value; for TFO it covers only the data actually placed on the SYN. Use that interval for both handshake authentication and OPENING RST validation.

3. **BLOCKER — The trust-bit transition algorithm is not safely defined.**

At [plan.md:453–494](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:453), the slide gate, “any field authenticates all fields,” and valid-but-untrusted storage conflict.

Two concrete failures follow:

- A one-sided midstream pickup trusts only `seq_hi(O)`. A direct close in D has no usable close-validation leg and is refused. A non-close packet in D can instead guess an ACK inside `window(seq_hi(O))`, authenticate the whole packet, install arbitrary trusted `seq_hi(D)=X`, then use RST `seq=X`. Cost is one single-window hit where direct-close probability was zero.
- An unauthenticated packet first stores untrusted `X`; a later legitimate packet authenticates via its other field but carries current value `L`. If the old max gate wins, `L` may never repair `X`. If the implementation merely sets the trust bit, it blesses attacker-controlled `X`.

Trust monotonicity is also unstated: a normal SYN retransmission has no trusted opposite field. “Unauthenticated samples are adopted untrusted” must not clear the original trusted SYN seed.

The plan must specify pre-packet transaction semantics:

- existing trusted fields remain trusted and use bounded serial advancement;
- an authenticated current sample replaces an untrusted stored value before trust is set;
- prior untrusted storage is never blessed;
- authentication/trust is per field, except for a narrowly specified OPENING handshake proof.

4. **BLOCKER — Zero-trust HA imports are an absorbing state; the HA-wire work is load-bearing.**

For `SyncImport`, pre-upgrade, PASS_TO_KERNEL transition, or re-imported entries with `trusted=0`, every observed packet remains unauthenticated: authentication requires an already-trusted opposite field, while untrusted state cannot confer trust. No amount of ordinary bidirectional traffic creates the first trusted bit.

The plan admits this at [plan.md:488–499](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:488), but contradicts it by saying local observation restores trust at [plan.md:818–823](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:818), pre-upgrade entries converge on first traffic at [plan.md:858](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:858), and post-failover traffic re-establishes trust at [plan.md:933–937](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:933). Those claims are false.

The capacity bound is not adequate:

- 131,072 entries/worker and 300-second default TCP timeout: [session/mod.rs:60–74](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:60).
- Per-application timeout can reach 86,400 seconds: [session/mod.rs:220–240](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:220).
- New local installs fail at the cap: [install.rs:113–125](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:113).
- Synced upserts deliberately bypass that cap and may exceed it: [install.rs:295–323](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:295), [tests.rs:5096–5114](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/tests.rs:5096).

Thus 131,072 is an admission ceiling, not “headroom.” After a high-churn failover, all imported flows that terminate can retain entries for 300 seconds or longer instead of 2/30 seconds, while new flows are refused. A shorter untrusted probation triggered by a close recreates the original blind-demotion primitive; applying it at failover kills idle SSH/BGP state. Carrying a trusted anchor or equivalent proof over HA cannot remain optional.

Promotion itself preserves an anchor because `update_session` mutates in place at [session/mod.rs:1388–1463](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1388). Re-import really does wipe it because `upsert_synced_with_origin` removes and reconstructs the entry at [install.rs:310–347](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:310).

5. **HIGH — Required provenance and segment data cannot be obtained safely with the specified types.**

Three independent plumbing defects remain:

- `ForwardSessionMatch` carries only key/decision/metadata at [entry.rs:208–213](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:208). `lookup_forward_nat_across_scopes` erases LOCAL versus SHARED and may deliberately select a shared entry while a local fabric placeholder coexists at [shared_ops.rs:638–665](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:638). Re-probing by key can therefore read the wrong local anchor. The match result must carry explicit scope plus the selected anchor/`established` snapshot.
- `SessionInstall` is only the synced-upsert context; fresh installs remain positional, as documented at [ctx.rs:8–17](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/ctx.rs:8) and implemented at [install.rs:106–122](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:106). Adding `seg` only to `SessionInstall` cannot seed a fresh SYN/pickup, especially LocalDelivery.
- `TcpSegView` is documented as only `(seq, ack, wnd, seg_len)` at [plan.md:533–547](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:533), while `close_seq_plausible` receives neither flags nor `has_ack` at [plan.md:552–565](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:552). It therefore cannot implement OPENING’s ACK-set predicate.

`seg=None` must also distinguish “trusted control-plane update with no packet” from “wire packet could not be parsed”; otherwise the validation-free control path can become a malformed-wire bypass.

6. **HIGH — The pre-forward observation rebuttal has a real new regression.**

Site (b) runs during resolution at [poll_descriptor/mod.rs:411–431](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:411), before input-filter rejection at [poll_descriptor/mod.rs:592–638](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:592) and TTL consumption at [poll_descriptor/mod.rs:846–880](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:846).

Concrete class: authenticated/bounded ACK-data packets with TTL=1 update or walk the anchor at site (b), then become ICMP Time Exceeded instead of reaching the endpoint. Once the anchor is walked more than `BACK_SLACK`, the endpoint’s subsequent legitimate close is refused and the entry retains its ordinary timeout. Master would accept that legitimate close and select the 2/30-second timeout. Input-filter drops have the same shape.

The slow accounting update also precedes output-filter/CoS discard: [poll_descriptor/mod.rs:3494–3503](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3494), [forward_request.rs:264–290](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forward_request.rs:264), [forward_request.rs:368–370](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forward_request.rs:368).

It is true that an accepted close is no worse than master’s current marking boundary. It is not true that the new anchor introduces no security or regression delta: pre-commit packets can now poison future validation.

7. **HIGH — “Forward-wire is demote-free” is false, and refused HA promotion is not transactional enough.**

An immutable forward-wire match does not mark directly, but it returns through [shared_ops.rs:614–628](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:614), then reaches `maybe_promote_synced_session` at [session_glue/mod.rs:1235–1252](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1235). A promotable origin calls `update_session` with the packet’s flags at [promote.rs:86–107](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86). On master, that path marks closing/reset at [session/mod.rs:1393–1435](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1393). After v4 it remains a validated demotion path, not a demote-free one.

For a refused closing promotion, validation must abort the entire update before reindexing, `next_epoch`, origin/metadata/`last_seen`, wheel push, Open delta, and shared publication. Sanitizing flags and promoting alive violates rule 3’s inertness. It also invalidates the test’s “ordinary reap emits no Close because nothing was marked”: any forward `SharedPromote` ordinary expiry emits Close regardless of `closing`, per [expire.rs:342–377](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342).

The coverage prose also conflicts internally: [plan.md:824–826](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:824) says a later fabric-return close demotes its reverse seed, while the missing-forward rule at [plan.md:385–390](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:385) requires refusal.

8. **MEDIUM — The core union arithmetic is corrected, but surrounding window claims remain wrong.**

Confirmed:

- Floor: 131,073 values/leg; 262,146 disjoint; `1/16383.875`; 16.384 seconds at 1,000 pps.
- Maximum raw-window case: 196,607/leg; 393,214 disjoint; `1/10922.722`; 10.923 seconds.
- The per-leg `<2^31` assertion at [plan.md:614–620](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:614) is correct.

Corrections still needed:

- Full overlap is `1/32768` only at the floor; at maximum it is approximately `1/21845`, so [plan.md:147–150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:147) is incomplete.
- A precursor can place independent guesses in `seq` and `ack`; its two chances remain additive even when the direct close’s two intervals overlap. “Identical cost” can therefore be optimistic by nearly 2×.
- `wnd` has no trust bit, while rule 2 lets zero-length unauthenticated samples update it. A no-knowledge precursor can advertise 65,535 and expand the union from `1/16384` to `1/10923`. Only authenticated/install-trusted segments may update the security window.
- Window scaling would make `raw << scale` larger, not shrink blind-hit probability as claimed at [plan.md:999–1003](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:999). `2×raw_wnd` is a heuristic, not a TCP-derived effective-window bound.
- “No-op via max” at [plan.md:453–457](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:453) must not mean ordinary `u32::max`, which fails across wrap. Specify a wrapping delta assignment and test tracker wrap separately from validator wrap.

9. **MEDIUM — The test plan cannot validate the stated design.**

At minimum:

- “Thousands of random closes → flow survives” at [plan.md:926–928](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:926) is probabilistic and can legitimately hit the admitted interval. Use deterministic out-of-window values.
- The post-failover expectation that later traffic restores trust is impossible under the normative rules.
- Missing mandatory cases include constructor provenance, non-close materialization and reverse-synth precursors, TFO partial ACK, valid-untrusted replacement, trust monotonicity across SYN retransmission, wrong-scope placeholder selection, unauthenticated-window poisoning, pre-filter/TTL poisoning, re-import wipe, tracker wrap, and fully transactional `SessionUpdate` refusal.
- The small-frame gate still names no demonstrated line-rate packet generator.

10. **LOW — Several mechanics are sound, with one accounting correction.**

Skipping `established` promotion for SYN-ACK+RST/FIN is correct: RST is an abort, and FIN is not a required SYN-SENT promotion signal. A normal bare three-way handshake bootstraps correctly once the OPENING predicate and trust transitions are made precise; simultaneous open eventually converges through the exchanged SYN-ACKs. Rejecting a count-based re-anchor hatch remains correct. Reverse skip-install and its telemetry/cache gating are also sound once match provenance is carried explicitly.

The proposed `TcpSeqAnchor` is 24 bytes, not approximately 26; the quoted 3 MiB/worker is the 24-byte result. The hot-path cost also includes reading `wnd` and determining segment length, not merely one 8-byte seq/ack read.

### Round-2 finding dispositions

- **R2-1 — partially resolved.** The direct first-close/no-baseline path is fixed, but non-close materialization self-authentication can recreate the cluster-wide kill.
- **R2-2 — partially resolved.** The endpoint-backstop framing was corrected, but pre-commit anchor poisoning creates a new legitimate-close refusal regression.
- **R2-3 — partially resolved.** `has_ack`, positive `seg_len`, closing-update exclusion, and refuse-on-no-baseline are correct; constructor provenance and trust-transition semantics remain unsafe.
- **R2-4 — partially resolved.** The immutable lookup itself does not mark, but downstream HA promotion does; the “demote-free” inventory is false.
- **R2-5 — partially resolved.** PASS_TO_KERNEL/tunnel/fabric classes are named, but PASS_TO_KERNEL observation cannot build trust and the fabric consequence contradicts the missing-forward rule.
- **R2-6 — partially resolved.** Disjoint-union values and dead-cap removal are corrected; overlap wording, multiplier derivation, untrusted window input, and wscale reasoning remain wrong.
- **R2-7 — resolved.** The permanent both-direction path-switch stall, aggregate retention, and rejection of an observation-count re-anchor are stated honestly.
- **R2-8 — partially resolved.** Shared no-anchor synthesis now refuses and accepted reverse semantics are honest; OPENING/TFO validation and match provenance are still wrong.
- **R2-9 — partially resolved.** The original lookup-path ordering, close-update skip, and SYN-ACK+close promotion defects are addressed; `SessionUpdate` refusal still needs an explicit all-or-nothing transaction boundary.
- **R2-10 — partially resolved.** Old v3 contradictions were swept and segment plumbing was acknowledged, but primary installs, `TcpSegView`, control-versus-wire provenance, and LOCAL-versus-SHARED match sourcing remain unspecified.

Bottom line: v4.2 correctly flips absent trust to refuse-demote, fixes the headline union arithmetic, and accepts the path-switch stall honestly. It still cannot proceed: generic constructor trust can recreate the two-packet cluster kill, OPENING authentication is either broadly spoofable or rejects legal TFO behavior, zero-trust HA state cannot recover without wire carriage, and several current types cannot preserve the provenance required to enforce the proposed rules. Make trust origin-specific and per-field, define the OPENING ACK interval, carry trusted HA state in this design, move security updates behind forwarding commitment, and specify transactional/source-aware plumbing before implementation. No files were edited.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
