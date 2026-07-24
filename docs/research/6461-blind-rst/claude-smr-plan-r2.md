# Claude SMR hostile plan review — round 2 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v3
(`docs/research/6461-blind-rst/plan.md` @ 396e24300), which folds the
round-2 AGY findings into v2. Every claim below was re-traced against the
code in this worktree; nothing taken on authority. Round-1 verdict was
PLAN NO (13-section adjudication); v2/v3 correctly implemented the v2
checklist from that review (single forward-entry anchor, plausibility
gates, pre-packet validation, constructor gating, LocalDelivery coverage,
skip-install, wnd(O)).

**Verdict: PLAN NO (v3→v4 revision required — one design flip + one missed
constructor + honest arithmetic).** The v3 architecture is fundamentally
sound and every round-1/round-2 fold verified clean. But the no-baseline
fail-open rule re-admits the exact cluster-wide kill the plan exists to
close, in the one window the attacker can *time*; a third packet-derived
constructor (shared-hit materialize) was left ungated; and §2's attack-cost
arithmetic understates the union acceptance window by 2×.

## 1. BLOCKER — no-baseline fail-open re-admits the cluster kill, post-failover

End-to-end trace (every step verified):

1. Session born on node0 (RG owner), synced to node1
   (`SyncImport`/shared-map replica). Failover: node1 becomes owner.
2. Attacker fires a blind RST matching the tuple, landing as the **first
   locally-observed packet** of that flow on node1. Idle SSH/BGP/mgmt
   flows — the issue's named victims — have the widest first-packet
   windows; the failover itself is observable (VRRP priority-0 burst +
   GARP storm), so the window is *timable*.
3. `resolve_flow_session_decision` → shared hit →
   `materialize_shared_session_hit` (`session_glue/mod.rs:1092-1118`)
   installs the local copy — and **seeds `closing`/`reset` from the blind
   RST's own flags** via `upsert_synced_with_origin`
   (`install.rs:399-400`). Origin `SharedMaterialize` (peer-synced).
4. `enforce_session_ha_resolution` yields ForwardCandidate (node1 owns the
   RG) → `maybe_promote_synced_session` fires (`promote.rs:86-90`:
   promotable origin + ForwardCandidate) → `promote_synced_with_origin`
   → `update_session` (`mod.rs:1396-1432`): sets `origin = SharedPromote`,
   applies `closing |= is_closing(flags)`, `reset |= has_rst(flags)`,
   recomputes `expires_after_ns = TCP_RST_TIMEOUT_NS`.
5. Anchor: none (HA-imported, never locally observed) → v3 §5.4 rule 3
   **fails open** — validation never withholds the mark.
6. Reap 2 s later: `expire.rs:342-345` emits a Close delta iff
   `!is_reverse && !is_peer_synced() && !is_transient_local_seed()`.
   `SharedPromote` is **not** in `is_peer_synced` (`entry.rs:245-250`:
   only `SyncImport | SharedMaterialize | WorkerLocalImport`) and not
   transient (`:272`) → **Close delta emitted**.
7. Go decodes the close with no origin/generation protection; gen-zero
   deletes apply unconditionally (`sync_conn_gen.go:176-186`) → the
   shared-map copy and node0's standby copy are deleted. Cluster-wide
   kill, plus the SNAT pool-port re-seed teeth on the next real packet.

This is precisely the attack #6461 describes, surviving v3 in the
post-failover window. AGY's round-2 convergence pass independently
traced the same chain (its finding 1, VERIFIED). Note the failover case
is *worse* than the steady-state attack v3 does close: post-failover,
the residual applies to every synced flow whose next packet hasn't
arrived yet — for a busy flow milliseconds, for an idle management flow
minutes.

**Required v4 change:** flip rule 3 from fail-open to **refuse-demote**
(packet forwarded unchanged; no mark, no seed, no refresh, no wheel push;
entry ages on its ordinary timeout). This is not a new cost class — the
plan's own Option-A doctrine (§4) already declares a refused demote "as
if the RST were lost in transit — a condition #3046 already tolerates by
design." The no-baseline windows (post-failover, post-upgrade,
post-materialize, missing-forward) are exactly the windows an attacker
can time or engineer; they are where the gate must be strictest, not
where it gives up. Legit cost: a RST-first-after-failover flow (peer
died during failover) lingers to its ordinary timeout instead of the 2 s
fast reap — bounded table pressure during a churn window the bulk-sync
path already engineers for; never a broken connection (the RST is
delivered; endpoints tear down).

## 2. BLOCKER — the materialize seed is a third ungated packet-derived constructor

v3's constructor-gating inventory (§3 site table + §5.6) gates the
reverse-synth (site 2b) and the promote `update_session` (site 2), and
dismisses `UpsertSynced` (site 4) as "no packet exists." That dismissal
conflates two different callers of `upsert_synced_with_origin`:

- HA **wire** re-import (eventstream-driven) — genuinely packet-free.
- **`materialize_shared_session_hit`** (`session_glue/mod.rs:1100-1113`)
  — threads the *current shared-hit packet's* `tcp_flags` into
  `SessionInstall`, and `upsert_synced_with_origin` seeds
  `closing`/`reset` from those flags (`install.rs:399-400`).

The materialize path is packet-driven and ungated in v3. Consequence:
even after gating the promote's `update_session` per §5.5, the trace-1
kill survives — the materialize seed alone leaves `closing=true,
reset=true` on the fresh local copy, promote flips the origin to
`SharedPromote`, the entry reaps in 2 s, and the Close delta fires.
Gating site 2 without gating the materialize seed fixes nothing for the
failover case.

**Required v4 change:** enumerate materialize as packet-derived
constructor site 2c with the same rule as the reverse-synth: validate
the close against the best available anchor (none for a fresh import →
refuse under the §1 flip) and, on refuse, install the copy **alive**
(`closing=false, reset=false` — unlike the reverse-synth, the materialize
install cannot be skipped: the packet needs its forwarding decision and
the entry owns the flow going forward). The entry then tracks normally
from the first observed packets.

## 3. HIGH — the 2-packet seed race on invalid anchor sides (residual; accept + follow-up)

The `!valid` seed clause (§5.2 gating rule) adopts the first observed
sample of a direction unconditionally. For an entry with an invalid
anchor side — post-upgrade (zeroed struct on pre-existing entries),
post-import, post-materialize — an attacker who wins the
first-observation race:

1. sends a spoofed **non-close** data packet in direction D, seq=X
   (passes #4400, session hit, seeds `seq_hi(D)=X+len`);
2. sends the RST at seq=X — inside `[X+len−64KiB, X+len+FWD_SLACK]` →
   rule 1 accepts.

Two packets, zero sequence knowledge. AGY verified the trace (its
finding 2). The §1 rule-3 flip does **not** close this: after packet 1
seeds, a baseline *exists*, so rule 1 — not rule 3 — governs packet 2.

What bounds it:

- On the RG **owner**, entries installed from local traffic seed their
  anchor at install (§5.2(c)) — the invalid state never exists for
  locally-born flows. It exists only for (a) HA-imported entries on a
  node that has not yet observed the flow (the failover window), and
  (b) pre-upgrade entries on a running system until first observation.
- The permanently-unobserved asymmetric direction is **not** attacker-
  seedable: an off-path attacker's spoofed direction-D packet follows
  the same routing as real direction-D traffic; if that path never
  transits the firewall, neither does the attacker's seed. The race is
  real only where the firewall *will* see the flow but hasn't *yet*.
- K-observation or cross-leg-corroboration ("proven") bits were weighed
  and rejected: the attacker fabricates both legs self-consistently at
  K+1 packets; the bit adds per-entry state and update-path branches for
  no closed window (a determined fabricator always passes once no wire
  truth exists). With zero wire-truth, any firewall policy is arbitrary;
  refuse-demote is the safe arbitrary choice, and the residual is a
  *race*, not a standing capability.

Honest accounting vs master: today the kill is 1 packet, anytime, no
window constraints. After v4: outside the race windows it is a
1-in-2^14-ish blind guess per packet (§4) with the endpoint's own
RFC 5961 handling as backstop; inside the race windows (failover/
upgrade/materialize, until the first real packet per direction) it is 2
packets — and the attacker must beat real traffic to them. Strictly
better on every axis, not infinitely better. **Accepted as a documented
residual.** The follow-up that closes the synced-flow half is an
additive HA-wire anchor field (§11 Q6 — v4 should name it a follow-up
issue, not this PR): post-failover entries then arrive *with* a
baseline and validate immediately.

## 4. MEDIUM — §2 arithmetic understates the union acceptance window 2×

§5.4 rule 1 accepts on `window(seq_hi(D)) ∪ window(ack_hi(O))`. When
both legs are valid and non-overlapping the total acceptance interval is
up to **two** windows, not one:

- floor (FWD_SLACK=64 KiB): 2 × 128 KiB = 256 KiB → **1/16384** per
  guess (§2 claims 1/32768); expected spray-to-kill at 1,000 pps ≈ **16 s**
  (§2 claims 33 s);
- cap (FWD_SLACK=512 KiB): 2 × 576 KiB ≈ 1.15 MiB → **~1/3728**
  (§2's "~1.1 MiB" sentence covers one window only).

AGY's arithmetic matches (its finding 3). The legs usually overlap
(seq and ack positions track within a window of each other), so the
true figure is between 1× and 2× the single-window claim — §2 must
state the worst case, not the best.

## 5. LOW — double anchor update on the slow-path forward build

A cache-miss ForwardCandidate packet transits `lookup_with_origin`
(site b) **and** `account_packet` (`poll_descriptor/mod.rs:3497`,
site a): the same sample applied twice. Idempotent (gated `max`), no
borrow hazard (sequential phases). v4 should note the deliberate
no-dedup choice (a packet-token dedup would cost more than the ~100 ns
it saves).

## 6. Verified safe (no change needed)

- **Non-owner reverse-synth fail-open:** the in-hand forward match can
  be a *shared* replica (`lookup_forward_nat_across_scopes` →
  `shared_nat_sessions`) with no anchor → fail-open install of a
  born-dying reverse on the non-owner. Safe: reverse entries never emit
  Close deltas (`expire.rs:342` `!is_reverse`), and
  `propagate_tcp_state_to_companion` (`mod.rs:1232-1278`) probes only
  the local table — the owner's authoritative entry is unreachable.
  (With the §1 flip this path refuse-demotes instead — equally safe.)
- **OPENING connection-refused at the synth:** fwd seed `isn+1` (TFO:
  `isn+SEG.LEN`), server RST|ACK carries `ack=isn+SEG.LEN` → accepted →
  born-dying reverse → 2 s reap preserved; blind RST needs a 1/2^32 ack
  guess → refused → skip-install. #3046 semantics intact.
- **Post-borrow marking:** single-threaded worker; between borrow end
  and the re-probe only `propagate_tcp_state_to_companion` and
  `push_to_wheel` run (`lookup.rs:204-218`), both table probes on the
  same thread — no observer of the interim un-marked state.
- **Stall analysis:** with both update sites live, every forwarded TCP
  packet is a sample; the anchor lags by reordering extent, not
  in-flight size. No re-anchor hatch — correct call (a hatch reopens
  the r1 B1 staging channel at K+1 packets).
- **AGY r2 folds:** B1 (LocalDelivery site b), B2 (stall precision),
  F3 (skip-install), F4 (wnd(O)), F6 (TFO SEG.LEN) all verified in text
  and code. F5's interim-state concern is answered by the
  single-threaded phase ordering.

## Bottom line

The architecture has converged — single forward-entry anchor, gated
slides, pre-packet union validation, constructor gating, never-drop
delivery. What has not converged is the *edge policy*: v3 fails open
exactly where the attacker has the most control (no-baseline windows)
and leaves the materialize constructor outside the gate. v4 = flip rule
3 to refuse-demote, gate the materialize seed (install-alive), restate
§2 arithmetic for the union window, accept+quantify the 2-packet
first-observation race with the wire-anchor follow-up named. Those are
edge changes to a sound core; expect convergence next round.
