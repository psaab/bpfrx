PLAN NO

Review pinned to v10.0.1, commit `43a4dec16d84dea844f2f317ce1ef245fad7677f`. The later docs-only branch update was not considered. No files were edited.

1. BLOCKER — the common `MissingNeighbor` constructor makes the close verdict non-terminal.

   A session hit returns through [poll_descriptor/mod.rs:411](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:411); the #4400 bare-close guard applies only to the true session-miss branch at [poll_descriptor/mod.rs:1607](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1607). If live re-resolution produces `MissingNeighbor`, the common disposition arm unconditionally installs:

   `MissingNeighborSeed(..., meta.tcp_flags)`

   at [poll_descriptor/mod.rs:4787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4787). That occurs after:

   - site 1 has REFUSED an implausible close;
   - site 2b has returned `created=false, install_failed=true`; or
   - site 2c has installed the intended ALIVE probation entry.

   `install_failed` is copied at [poll_descriptor/mod.rs:509](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:509), but only gates flow-cache insertion at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900). The installer removes/replaces the existing key and derives `closing`, `reset`, and the 2 s/30 s timeout from the refused packet’s raw flags at [install.rs:123](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:123) and [install.rs:163](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:163).

   Concrete surviving trace: an active imported or local flow has a cold next hop and no local companion—a supported state at [expire.rs:508](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:508). An out-of-window RST tuple-hits, the validator REFUSES, re-resolution returns `MissingNeighbor`, and the common arm replaces the live entry with a raw 2-second closing seed. Its reap runs the ordinary NAT/BPF cleanup. This is the original unjustified timeout transition despite the gate.

   It also breaks emission completeness: an accepted forward close can first mark the forward entry, then have that entry replaced with transient `MissingNeighborSeed`; the reverse companion is emission-silent and the replacement is excluded by [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342), leaving zero Close producers.

   Required correction is local: `MissingNeighborSeed` creation must be restricted to a genuine top-level session miss. Any successful `resolve_flow_session_decision`, including constructor REFUSE, must preserve its gated result through dispatch.

2. BLOCKER — a correctly installed probation entry still performs global teardown.

   This trace survives correction of finding 1. Worker A can install and publish a `MissingNeighborSeed` at [poll_descriptor/mod.rs:4780](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4780), but this path has no sibling-worker upsert corresponding to the ordinary replication at [poll_descriptor/mod.rs:2612](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2612). Worker B can therefore materialize the shared entry. Under `plan.md@43a4dec:901-925`, an implausible close installs ALIVE on 20-second probation.

   At expiry, probation suppresses the Close delta, but `ExpiredSession` carries no probation state, and the worker still unconditionally:

   - releases SNAT at [loop_body/mod.rs:1490](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1490);
   - deletes session-map keys at [loop_body/mod.rs:1507](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1507).

   The allocator’s same-flow reservation is idempotent, not reference-counted, at [allocator.rs:1664](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1664); a single release removes the shared record and frees the port at [allocator.rs:1318](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1318). BPF cleanup ignores origin and enumerates all canonical/wire/reverse family keys at [bpf_map/mod.rs:633](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:633) and deletes them at [bpf_map/mod.rs:704](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:704).

   These keys are process-global and still serve A’s live entry. The code explicitly documents that removing them stops userspace redirection and can provoke kernel RSTs that collapse the live connection at [session_glue/mod.rs:863](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:863). Thus “silent” means only “no HA Close delta”; it is not teardown-inert. FIN also moves this cleanup from master’s 30 seconds to 20 seconds.

   A probation expiry must be local-only, or NAT/global-map cleanup must be owner/final-holder safe. The removed distributed protocol is not required.

3. BLOCKER — fresh neighbor retry can drop a legitimate close admitted as a session hit.

   Under the plan’s intended REFUSE semantics, take a legitimate FIN/RST that arrives just before the entry’s ordinary expiry and soft-refuses because its baseline is stale or untrusted. It receives no refresh or wheel push, then is buffered at [poll_descriptor/mod.rs:5057](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5057).

   Before ARP resolves, the next worker loop expires the entry at [expire.rs:166](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:166). If the neighbor then resolves before the pending timeout, v10’s mandated full re-resolution sees a session miss and #4400 drops the bare FIN/RST at [poll_descriptor/mod.rs:1607](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1607). Master instead transmits the buffered packet using the stored decision at [neighbor_dispatch.rs:272](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:272).

   This converts an initially tracked legitimate teardown into a permanent close-after-timeout drop. A bounded local session/NAT lifetime hold or an admitted-hit retry marker is required; no HA lifecycle protocol is implied.

4. MEDIUM — the proposed commit boundary omits later drop-oldest queue eviction.

   Local and prepared TX queues evict their oldest already-admitted request when bounded at [tx/drain/mod.rs:33](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/drain/mod.rs:33) and [tx/drain/mod.rs:56](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/drain/mod.rs:56). Enqueue sites push first and bound afterward, for example [tx/dispatch/mod.rs:665](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/mod.rs:665) and [tx/dispatch/mod.rs:786](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/mod.rs:786).

   Therefore a packet whose anchor update has already run can be discarded by a later enqueue. This requires the same first in-window guess and does not lower the direct-kill probability, but it contradicts §5.2’s claim that all unlisted arms are commit-clean. The plan must either drop/report the current newest request before applying its hook, defer the hook, or document this runtime-capacity residual.

5. LOW — OPENING predicates should explicitly include trust.

   Section 5.4 names `open_valid(direction)` but does not repeat `open_trusted(direction)`. The overall validator contract at `plan.md@43a4dec:699-703`, trust invariant at `:1012-1023`, and untrusted-baseline test at `:1178-1183` make trust normative, so no exploit survives a whole-plan reading. The predicates should nevertheless be written explicitly as `open_valid && open_trusted`, with a mixed trusted-forward/untrusted-reverse test.

6. LOW — the Phase-2 brief still relies on removed machinery.

   `phase2-brief.md@43a4dec:20-21` cites the family-clock TTL sweep and reservation-purge hook as existing Phase-1 cleanup, while v10 cuts that machinery at `plan.md@43a4dec:1315-1327`. This does not require Phase 2 to ship, but its optionality rationale must be corrected.

7. nit — v10.0.1 identifies itself as v10.0.0 and says “no Go code” at `plan.md@43a4dec:3-9`, contradicting the additive Go status decode at `:983-987`.

Core gate verification:

- The anchor is exactly 40 bytes and forward-entry-only. The existing reverse-to-forward hop supports that layout; the new anchor hook must not copy `account_packet`’s missing-forward fallback at [session/mod.rs:1205](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1205).
- The five update/trust rules, pre-packet validation, RFC 1982 membership, and `<2^31` compile-time bounds are internally consistent.
- Receiver selection is correct under asymmetric windows: stream-D `seq` uses O’s advertised window; an ACK on D describes stream O and uses D’s advertised window.
- The arithmetic is correct:

  - Floor: `2×131,073 + 131,073 = 393,219`; `2^32/393,219 = 10,922.58`, approximately 1/10,923.
  - Cap: `2×196,607 + 262,141 = 655,355`; `2^32/655,355 = 6,553.65`, approximately 1/6,554.
  - At 1,000 packets/s: approximately 10.9 seconds and 6.55 seconds respectively.

- An unchanged imported entry is genuinely absorbing: per-field proofs and self-slides require prior trusted state, closing packets never learn, and an imported ESTABLISHED entry cannot invoke the strong OPENING bootstrap. No in-place packet sequence creates its first trusted bit. Finding 1 is an out-of-state-machine replacement path that must be closed to preserve this claim end to end.
- The `ForwardSessionMatch` clone is implementable: retain its key, install, then re-probe and mark the local forward entry sequentially on the same worker. “Atomic” should mean non-interleaved same-worker writes.

Legitimate teardown inventory:

| Site | ACCEPT | REFUSE / other outcome |
|---|---|---|
| 1 lookup hit | Nominally marks matched entry and companion, forwards packet. | Nominally inert and forwards; findings 1 and 3 break this on neighbor paths. |
| 2 `update_session` promote | Closing packets correctly skip both establishment and ownership promotion. | No close verdict here; the common downstream constructor remains outside this guard. |
| 2b reverse synth | Installs reverse and marks forward producer. | Intended skip-install/forward; finding 1 instead raw-installs on `MissingNeighbor`. |
| 2c materialize | No Phase-1 ACCEPT without a trusted imported baseline. | Intended ALIVE probation/forward; findings 1 and 2 invalidate its terminal behavior. |
| 3 primary miss | Bare transit closes remain #4400-dropped; SYN+close affects only its invented flow. | No validator verdict. Finding 3 newly converts an initially tracked close into this miss/drop class. |
| 4 HA wire import | The sending owner already validated before emitting Close. | Refused owner close emits nothing; no local packet exists to validate. |
| 5 tunnel local | Trusted-local constructor remains valid; inbound closes use site 1. | Nominal soft-refuse remains delivery-safe except for the neighbor traces. |
| 6 fabric-return seed | Bare closes remain excluded; SYN+close is reverse-silent. | Later no-baseline close soft-refuses. |
| 8 immutable forward-wire match | Cannot mark directly; an accepted owner path must come through a gated mutable entry. | Closing packet correctly skips ownership promotion, but `MissingNeighbor` still reaches finding 1. |

Asymmetric pickup, half-open exact-interval aborts, TFO partial acknowledgements, simultaneous open, `SO_LINGER(0)` RST+ACK, and RFC 9293 peer-restart resets are covered by the nominal validator. Loss-episode and changed-length TFO cases may soft-refuse as documented. Close-after-timeout was already dropped on master; finding 3 newly exposes a packet that was still a hit when admitted.

Section 11 answers:

1. Terminal cut: No; `MissingNeighbor` raw replacement and probation cleanup preserve deterministic state/NAT teardown paths.
2. Probation without family clock: No; its timer is per-entry, but ordinary expiry releases/deletes family-global state.
3. Emission posture: No duplicate producer was found, but an accepted forward close can lose its sole producer to `MissingNeighborSeed`; refused paths remain delta-silent while still causing destructive cleanup.
4. Pending neighbor: Re-resolution is implementable and loop-free, with no material non-close discrepancy found; however it can reclassify and drop a legitimate close after intervening expiry.
5. Arithmetic: Yes; the exact disjoint unions are 393,219 and 655,355, approximately 1/10,923 and 1/6,554.
6. Re-scope: Phase 2 and the removed lifecycle protocol need not ship; narrow hit-aware `MissingNeighbor`, admitted-close retry, and probation/owner-safe cleanup rules must ship because v10 directly exercises the #6522 class.

The core sequence validator remains substantially converged: ordinary hit-path blind closes are reduced to the documented window probability, imported trust is absorbing, and normal refused closes do not emit HA deletes. The revision is nevertheless unsafe because its verdict is not terminal across `MissingNeighbor`, its probation reaper still destroys live sibling state, and its fresh retry can suppress a legitimate teardown packet. Those are local, concrete defects; none requires reinstating the removed distributed protocol.
tokens used
448,945
PLAN NO

Review pinned to v10.0.1, commit `43a4dec16d84dea844f2f317ce1ef245fad7677f`. The later docs-only branch update was not considered. No files were edited.

1. BLOCKER — the common `MissingNeighbor` constructor makes the close verdict non-terminal.

   A session hit returns through [poll_descriptor/mod.rs:411](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:411); the #4400 bare-close guard applies only to the true session-miss branch at [poll_descriptor/mod.rs:1607](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1607). If live re-resolution produces `MissingNeighbor`, the common disposition arm unconditionally installs:

   `MissingNeighborSeed(..., meta.tcp_flags)`

   at [poll_descriptor/mod.rs:4787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4787). That occurs after:

   - site 1 has REFUSED an implausible close;
   - site 2b has returned `created=false, install_failed=true`; or
   - site 2c has installed the intended ALIVE probation entry.

   `install_failed` is copied at [poll_descriptor/mod.rs:509](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:509), but only gates flow-cache insertion at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900). The installer removes/replaces the existing key and derives `closing`, `reset`, and the 2 s/30 s timeout from the refused packet’s raw flags at [install.rs:123](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:123) and [install.rs:163](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:163).

   Concrete surviving trace: an active imported or local flow has a cold next hop and no local companion—a supported state at [expire.rs:508](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:508). An out-of-window RST tuple-hits, the validator REFUSES, re-resolution returns `MissingNeighbor`, and the common arm replaces the live entry with a raw 2-second closing seed. Its reap runs the ordinary NAT/BPF cleanup. This is the original unjustified timeout transition despite the gate.

   It also breaks emission completeness: an accepted forward close can first mark the forward entry, then have that entry replaced with transient `MissingNeighborSeed`; the reverse companion is emission-silent and the replacement is excluded by [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342), leaving zero Close producers.

   Required correction is local: `MissingNeighborSeed` creation must be restricted to a genuine top-level session miss. Any successful `resolve_flow_session_decision`, including constructor REFUSE, must preserve its gated result through dispatch.

2. BLOCKER — a correctly installed probation entry still performs global teardown.

   This trace survives correction of finding 1. Worker A can install and publish a `MissingNeighborSeed` at [poll_descriptor/mod.rs:4780](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4780), but this path has no sibling-worker upsert corresponding to the ordinary replication at [poll_descriptor/mod.rs:2612](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2612). Worker B can therefore materialize the shared entry. Under `plan.md@43a4dec:901-925`, an implausible close installs ALIVE on 20-second probation.

   At expiry, probation suppresses the Close delta, but `ExpiredSession` carries no probation state, and the worker still unconditionally:

   - releases SNAT at [loop_body/mod.rs:1490](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1490);
   - deletes session-map keys at [loop_body/mod.rs:1507](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1507).

   The allocator’s same-flow reservation is idempotent, not reference-counted, at [allocator.rs:1664](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1664); a single release removes the shared record and frees the port at [allocator.rs:1318](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1318). BPF cleanup ignores origin and enumerates all canonical/wire/reverse family keys at [bpf_map/mod.rs:633](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:633) and deletes them at [bpf_map/mod.rs:704](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:704).

   These keys are process-global and still serve A’s live entry. The code explicitly documents that removing them stops userspace redirection and can provoke kernel RSTs that collapse the live connection at [session_glue/mod.rs:863](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:863). Thus “silent” means only “no HA Close delta”; it is not teardown-inert. FIN also moves this cleanup from master’s 30 seconds to 20 seconds.

   A probation expiry must be local-only, or NAT/global-map cleanup must be owner/final-holder safe. The removed distributed protocol is not required.

3. BLOCKER — fresh neighbor retry can drop a legitimate close admitted as a session hit.

   Under the plan’s intended REFUSE semantics, take a legitimate FIN/RST that arrives just before the entry’s ordinary expiry and soft-refuses because its baseline is stale or untrusted. It receives no refresh or wheel push, then is buffered at [poll_descriptor/mod.rs:5057](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5057).

   Before ARP resolves, the next worker loop expires the entry at [expire.rs:166](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:166). If the neighbor then resolves before the pending timeout, v10’s mandated full re-resolution sees a session miss and #4400 drops the bare FIN/RST at [poll_descriptor/mod.rs:1607](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1607). Master instead transmits the buffered packet using the stored decision at [neighbor_dispatch.rs:272](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:272).

   This converts an initially tracked legitimate teardown into a permanent close-after-timeout drop. A bounded local session/NAT lifetime hold or an admitted-hit retry marker is required; no HA lifecycle protocol is implied.

4. MEDIUM — the proposed commit boundary omits later drop-oldest queue eviction.

   Local and prepared TX queues evict their oldest already-admitted request when bounded at [tx/drain/mod.rs:33](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/drain/mod.rs:33) and [tx/drain/mod.rs:56](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/drain/mod.rs:56). Enqueue sites push first and bound afterward, for example [tx/dispatch/mod.rs:665](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/mod.rs:665) and [tx/dispatch/mod.rs:786](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/mod.rs:786).

   Therefore a packet whose anchor update has already run can be discarded by a later enqueue. This requires the same first in-window guess and does not lower the direct-kill probability, but it contradicts §5.2’s claim that all unlisted arms are commit-clean. The plan must either drop/report the current newest request before applying its hook, defer the hook, or document this runtime-capacity residual.

5. LOW — OPENING predicates should explicitly include trust.

   Section 5.4 names `open_valid(direction)` but does not repeat `open_trusted(direction)`. The overall validator contract at `plan.md@43a4dec:699-703`, trust invariant at `:1012-1023`, and untrusted-baseline test at `:1178-1183` make trust normative, so no exploit survives a whole-plan reading. The predicates should nevertheless be written explicitly as `open_valid && open_trusted`, with a mixed trusted-forward/untrusted-reverse test.

6. LOW — the Phase-2 brief still relies on removed machinery.

   `phase2-brief.md@43a4dec:20-21` cites the family-clock TTL sweep and reservation-purge hook as existing Phase-1 cleanup, while v10 cuts that machinery at `plan.md@43a4dec:1315-1327`. This does not require Phase 2 to ship, but its optionality rationale must be corrected.

7. nit — v10.0.1 identifies itself as v10.0.0 and says “no Go code” at `plan.md@43a4dec:3-9`, contradicting the additive Go status decode at `:983-987`.

Core gate verification:

- The anchor is exactly 40 bytes and forward-entry-only. The existing reverse-to-forward hop supports that layout; the new anchor hook must not copy `account_packet`’s missing-forward fallback at [session/mod.rs:1205](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1205).
- The five update/trust rules, pre-packet validation, RFC 1982 membership, and `<2^31` compile-time bounds are internally consistent.
- Receiver selection is correct under asymmetric windows: stream-D `seq` uses O’s advertised window; an ACK on D describes stream O and uses D’s advertised window.
- The arithmetic is correct:

  - Floor: `2×131,073 + 131,073 = 393,219`; `2^32/393,219 = 10,922.58`, approximately 1/10,923.
  - Cap: `2×196,607 + 262,141 = 655,355`; `2^32/655,355 = 6,553.65`, approximately 1/6,554.
  - At 1,000 packets/s: approximately 10.9 seconds and 6.55 seconds respectively.

- An unchanged imported entry is genuinely absorbing: per-field proofs and self-slides require prior trusted state, closing packets never learn, and an imported ESTABLISHED entry cannot invoke the strong OPENING bootstrap. No in-place packet sequence creates its first trusted bit. Finding 1 is an out-of-state-machine replacement path that must be closed to preserve this claim end to end.
- The `ForwardSessionMatch` clone is implementable: retain its key, install, then re-probe and mark the local forward entry sequentially on the same worker. “Atomic” should mean non-interleaved same-worker writes.

Legitimate teardown inventory:

| Site | ACCEPT | REFUSE / other outcome |
|---|---|---|
| 1 lookup hit | Nominally marks matched entry and companion, forwards packet. | Nominally inert and forwards; findings 1 and 3 break this on neighbor paths. |
| 2 `update_session` promote | Closing packets correctly skip both establishment and ownership promotion. | No close verdict here; the common downstream constructor remains outside this guard. |
| 2b reverse synth | Installs reverse and marks forward producer. | Intended skip-install/forward; finding 1 instead raw-installs on `MissingNeighbor`. |
| 2c materialize | No Phase-1 ACCEPT without a trusted imported baseline. | Intended ALIVE probation/forward; findings 1 and 2 invalidate its terminal behavior. |
| 3 primary miss | Bare transit closes remain #4400-dropped; SYN+close affects only its invented flow. | No validator verdict. Finding 3 newly converts an initially tracked close into this miss/drop class. |
| 4 HA wire import | The sending owner already validated before emitting Close. | Refused owner close emits nothing; no local packet exists to validate. |
| 5 tunnel local | Trusted-local constructor remains valid; inbound closes use site 1. | Nominal soft-refuse remains delivery-safe except for the neighbor traces. |
| 6 fabric-return seed | Bare closes remain excluded; SYN+close is reverse-silent. | Later no-baseline close soft-refuses. |
| 8 immutable forward-wire match | Cannot mark directly; an accepted owner path must come through a gated mutable entry. | Closing packet correctly skips ownership promotion, but `MissingNeighbor` still reaches finding 1. |

Asymmetric pickup, half-open exact-interval aborts, TFO partial acknowledgements, simultaneous open, `SO_LINGER(0)` RST+ACK, and RFC 9293 peer-restart resets are covered by the nominal validator. Loss-episode and changed-length TFO cases may soft-refuse as documented. Close-after-timeout was already dropped on master; finding 3 newly exposes a packet that was still a hit when admitted.

Section 11 answers:

1. Terminal cut: No; `MissingNeighbor` raw replacement and probation cleanup preserve deterministic state/NAT teardown paths.
2. Probation without family clock: No; its timer is per-entry, but ordinary expiry releases/deletes family-global state.
3. Emission posture: No duplicate producer was found, but an accepted forward close can lose its sole producer to `MissingNeighborSeed`; refused paths remain delta-silent while still causing destructive cleanup.
4. Pending neighbor: Re-resolution is implementable and loop-free, with no material non-close discrepancy found; however it can reclassify and drop a legitimate close after intervening expiry.
5. Arithmetic: Yes; the exact disjoint unions are 393,219 and 655,355, approximately 1/10,923 and 1/6,554.
6. Re-scope: Phase 2 and the removed lifecycle protocol need not ship; narrow hit-aware `MissingNeighbor`, admitted-close retry, and probation/owner-safe cleanup rules must ship because v10 directly exercises the #6522 class.

The core sequence validator remains substantially converged: ordinary hit-path blind closes are reduced to the documented window probability, imported trust is absorbing, and normal refused closes do not emit HA deletes. The revision is nevertheless unsafe because its verdict is not terminal across `MissingNeighbor`, its probation reaper still destroys live sibling state, and its fresh retry can suppress a legitimate teardown packet. Those are local, concrete defects; none requires reinstating the removed distributed protocol.
