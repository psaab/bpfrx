# #1881 implementation — Claude SMR hostile code review (round 1)

Scope: the engineer/1881-gre-frozen diff (mechanism + tests + docs
commits) against plan v3 (docs/research/1881-gre-frozen-state/plan.md).
I attacked my own implementation as domain SMR before dispatching the
external reviewers.

## Worked trace 1 (required): refresh during an in-flight local-origin send

Setup: thread T for endpoint id E (gr-0-0-0, spawned_ifindex I1) is
mid-iteration — it has loaded forwarding Arc F_old and HA map H_old,
read a packet from the TUN, and is inside
`build_local_origin_tunnel_tx_request`. Concurrently the control
socket applies a snapshot that edits E's destination (and, on the
real system, the Go side has recreated the TUN anchor → new ifindex
I2 in the snapshot).

1. Coordinator: preflight passes → R-D purge (ids whose interface
   owner changed; E unchanged-owner ⇒ not purged) →
   `self.forwarding = F_new` → `ha.forwarding.store(F_new)`.
2. T is still building against `&F_old`: resolution, zone, owner-RG,
   reverse entry, CoS, encap ALL read F_old + H_old — one coherent
   (old) world. The encap owner check compares F_old's endpoint row
   against F_old's resolution — consistent. The packet goes out
   encapsulated per the OLD config: wrong-but-well-formed, the same
   RCU semantics as a worker mid-tick. No torn state: nothing in the
   build path can observe F_new mid-packet because the Arc is loaded
   exactly once per iteration (`tunnel.rs` loop head) and passed by
   reference everywhere below.
3. Coordinator (same apply, after the store):
   `reconcile_local_tunnel_sources` — pass 2 sees E's row now at I2 ≠
   spawned I1 ⇒ stale. Store #1 publishes the delivery map WITHOUT
   E's sender ⇒ no new deliveries can reach T. stop(T) + join: T's
   next loop-head check (`stop` at while, or inside the drain) fires
   within one bounded iteration (≤1ms idle sleep / one packet build /
   one drain chunk / 50ms error sleep — all bounded). Join returns.
4. Pass 3 spawns T' with I2, fresh channel; store #2 publishes I2.
   T' `load_full()`s F_new at entry — it can never see F_old (the
   store happened-before the spawn on the same thread).
5. Suppose instead T survives to its next iteration before the join
   lands: `load_arc_if_changed` returns F_new ⇒ the rotation gate
   recomputes against F_new: E.logical_ifindex == I2 ≠ I1 ⇒
   `endpoint_attached = false` ⇒ T parks (drops, builds nothing).
   So even in the store-to-join window T cannot encap against F_new
   while attached to the I1 TUN — the Codex r1 MAJOR-1 window is
   closed at the thread, not just by prune timing.

No torn state, no stale encap beyond the single in-flight old-world
packet, which is the accepted RCU boundary everywhere in this
dataplane. PASS.

## Worked trace 2: liveness respawn racing a Go anchor recreate

Go's `tunnelManager.Apply` removes and recreates ALL tunnel anchors
on every tunnel commit (observed live; `pkg/routing/tunnel.go`). The
old thread's TUN fd dies (fatal read errno) → finished sweep
tombstones it → liveness wants to respawn. Can the respawn bake in a
stale attachment? The coherence gate compares the latest STORED
snapshot row (id, mode, ifindex, label) against the CURRENT
forwarding endpoint — both updated together by the same apply, and a
commit that recreated the anchor always publishes a snapshot carrying
the new ifindex. Worst case: liveness respawns from the PRE-commit
coherent pair (old ifindex) while `open_tun` by NAME attaches the NEW
netdev — the thread runs with `spawned_ifindex = I1` against state
that still says I1, so the gate holds and the system is internally
consistent; the very next snapshot (the commit's own publish) flips
the row to I2 ⇒ `attachment_changed` prune + respawn with I2.
Converges in one apply; bounded churn, no loop. Observed live on fw1:
`stopped ... reason=attachment_changed` + `spawning ...` in the same
second. PASS (with the churn-per-commit note below).

## Findings against my own diff

### SMR-C1 (NOTE, accepted): per-commit thread churn on tunnel commits

Because Go recreates every tunnel anchor on every tunnel Apply, ANY
tunnel commit restarts every GRE local-origin thread (fatal-read exit
+ attachment prune/respawn). This is correct (the netdev genuinely
changed) and bounded (one churn cycle per commit), but it makes the
plan's "destination-only edit preserves the thread" property
unobservable on the live system — it holds only when the attachment
is genuinely unchanged (which the unit test pins). Making Go reuse
anchors in-place is a Go-side optimization, out of scope here; the
live pins are therefore behavioral (encap follows the new
destination; convergence to quiet).

### SMR-C2 (checked, OK): `continue` in the park branch

The park branch `continue`s the outer `while` from inside the
`match tun.read` arm — no inner loop is active at that point (the
delivery drain is a function call now), so control returns to the
loop head as intended.

### SMR-C3 (checked, OK): drain refactor preserves error semantics

Original inline drain: non-fatal write error → `break` to the read;
fatal → return; Empty/Disconnected → break. The extracted helper maps
these to `Drained`/`FatalIo`/`Drained` and the caller returns only on
`Stopped|FatalIo` — byte-equivalent behavior plus the new stop check.

### SMR-C4 (checked, OK): no worker hot-path impact

Workers' only contact points are unchanged ArcSwap loads
(`local_tunnel_deliveries`, `shared_forwarding`). `load_arc_if_changed`
visibility widened, body untouched, still `#[inline]`.

### SMR-C5 (checked, OK): publication rule

Both stores go through `publish_local_tunnel_deliveries_excluding`
(live-handle-only + exclusion), so a tombstone/failed spawn can never
be published — including from the liveness path (republish on swept>0
or respawn). `stop_all` and `stop_inner` store the empty map.

## Verdict

MERGE-READY from the SMR seat — pending Codex + AGY + Copilot rounds
and live validation evidence.
