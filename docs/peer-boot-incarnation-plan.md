# Peer boot incarnation on the config-sync wire (#5480)

**Status: PLAN — converged design, no implementation.** This is the prerequisite
for #5084. It changes the HA session-sync wire format, so it is a rolling-upgrade
decision in the #1960 class and needs sign-off before any code exists.

## Why this is needed

#5084 asks the standby to refuse a config payload queued from a peer incarnation
that a reconnect has replaced. PR #6900 attempted this with a receiver-local
connection epoch (`configNamespaceConnID`, a floor over `syncConnID`) and the
attempt failed across seven review rounds. The full post-mortem is on #5084; the
one-line version:

> `syncConnID` is a total **ORDER** over connections. The predicate the guard
> needs is an **EQUIVALENCE** — *were these two payloads produced by the same
> peer boot?* — because config generations are comparable only within one sender
> incarnation. A ranking cannot express an equivalence, and the floor has no
> correct setting: never descending locks out a live same-incarnation sibling
> that merely connected earlier, while descending re-admits departed
> older-incarnation connections and makes the floor a mutable target an in-flight
> `resetRecvGen` can reclaim.

The invariant that makes every symptom collapse at once:

> Fence on the peer's **boot incarnation** (an equivalence class), never on
> connection establishment order (a ranking). A payload applies iff it belongs to
> the CURRENT incarnation and its generation exceeds THAT incarnation's
> high-water. A payload from any other incarnation is dead permanently — never
> dropped-then-re-admitted.

Because incarnation membership is an equivalence, no connection ever needs
re-admitting, so the floor never descends. With no descent there is no window in
which the high-water is missing information, no re-admission of a departed
connection's stale generation, no mutable target for an in-flight reset, and no
live sibling fenced out in the first place.

## §1 — Where the incarnation comes from

**The granularity is not a free choice.** `initGenState` seeds `configGenCounter`
from a monotonic base (`pkg/cluster/sync.go`), and its own comment states the
purpose: *"so the sender's config-gen never regresses below a value the peer may
hold across this node's restarts **within a boot**"*. That gives a precise rule:

| event | `CLOCK_MONOTONIC` | generations | new incarnation? |
|---|---|---|---|
| daemon restart, same boot | keeps climbing | new seed is **higher** — still comparable | **no** |
| OS reboot | resets to ~0 | new seed is **lower** — incomparable | **yes** |

The incarnation must change *exactly* when `CLOCK_MONOTONIC` restarts — that is,
exactly on OS boot. Not per process, not per connection.

**Use `/proc/sys/kernel/random/boot_id`.** It is a 128-bit random UUID the kernel
regenerates at each boot, stable for the life of that boot, readable unprivileged,
and unchanged by a daemon restart. It matches the required granularity exactly.

Rejected alternatives:

- **A process-start monotonic seed** (what `syncEpoch` already is, `sync.go`).
  Wrong granularity: it changes on every daemon restart, which would force a
  namespace switch and a full re-prime for restarts whose generations are
  perfectly comparable. It is also an *order*, which is the mistake #6900 made.
- **A persisted counter on disk.** Adds a write to the boot path, a corruption
  mode, and a failure mode on a read-only or freshly-imaged root. `boot_id` is
  free and cannot disagree with the clock it exists to track.
- **The existing `syncMsgBulkStart` epoch.** It is `bulkSendNext.Add(1)`
  (`sync_bulk.go`), a per-process counter for bulk-ack matching that restarts at
  0 on process restart. It identifies a transfer, not a boot.
- **Hostname / node-id / MAC.** Constant across boots. Identifies the *node*, not
  the *incarnation*.

**Compare for equality only.** The field is opaque. Never order two `boot_id`s —
ordering is precisely the property we established cannot carry the meaning. "Which
incarnation is current" is answered by *which one primed*, not by comparing ids.

## §2 — Where it goes on the wire

**Extend the `syncMsgBulkStart` payload from 8 to 24 bytes: the existing
little-endian `uint64` epoch, then 16 bytes of `boot_id`.**

The alternative — putting it in the auth `HELLO` (`sync_auth.go`, which already
carries a `syncAuthVersion` byte) — must be **rejected**, and the reason is
decisive: `performSyncHandshake` returns immediately with
`syncAuthUnauthenticated` when `len(key) == 0`. An **unkeyed cluster performs no
handshake at all**, so a HELLO-carried incarnation simply would not exist there.
That would make the #5084 guard silently absent on unkeyed clusters — a
configuration-dependent security property, which is exactly the kind of thing
that gets missed.

`BulkStart` is also where the value is *consumed*: the prime is the claim event.
The incarnation arrives in the same frame that declares it current, so there is no
window where a connection is installed but its incarnation is unknown.

**This is the protocol's established extension pattern, not a new one.** Frames
are length-prefixed with an explicit `uint32` payload length, and every prior
field addition used a tolerant length gate:

- `syncMsgBulkStart`: `if len(payload) >= 8` (`sync_conn_read.go`)
- `syncMsgDeleteV4`: `if len(payload) >= 24` for the #2170 trailing generation
- `syncMsgDeleteV6`: `if len(payload) >= 48` for the same
- `encodeSessionV4Payload`: *"All length-gated: an old decoder stops after the…"*

An old receiver reads `payload[:8]` and ignores the rest. A new receiver reads
`payload[8:24]` when present. The HMAC trailer covers the whole payload, so the
authenticated path needs no change.

## §3 — A peer that sends no incarnation

`len(payload) < 24` ⇒ no incarnation ⇒ **treat the peer as un-incarnated and fall
back to exactly today's generation-only ordering.** Fail **open**.

This is the right call, and not merely the convenient one:

1. **The fallback is `origin/master`'s current behaviour**, not a weakened
   version of it. An upgraded node talking to an old peer is exactly as correct
   as the whole fleet is today. It does not gain the #5084 fix against that peer;
   it does not regress either.
2. **It is the convention this package already uses** for every legacy sentinel:
   `shouldApplyConfigGen` accepts `gen == 0` unconditionally; `configEpochStale`
   is disabled by `epoch == 0`; `fullSetSeqGuard.admit` accepts
   `incarnation == 0 || seq == 0`. A new field that failed closed would be the
   only one of its kind.
3. **Failing closed is an outage.** During a rolling upgrade the upgraded node
   would refuse *all* config from the not-yet-upgraded peer, stranding the
   standby on stale config for the whole window — and, because a refused config
   never raises `lastRecvConfigGen`, readiness could still read clean. That is
   strictly worse than the bug being fixed.
4. **This is not a security decision.** The incarnation is not an authorisation
   token and grants nothing. A peer that omits it gets the ordering behaviour it
   gets on master today. The authentication boundary is the PSK handshake and
   frame HMAC, which are untouched. A hostile peer cannot use omission to obtain
   anything it could not obtain by simply being an old build.

**Observability is mandatory here**, because a silent fallback is how a
half-upgraded cluster hides. The plan requires: a counter for primes received
without an incarnation, the peer's incarnation (or `none`) in
`show chassis cluster` status, and a one-time `slog.Warn` per connection when a
peer primes without one — one-time, not per-frame, per the logging rules.

## §4 — First connection after an upgrade

**There is no capability negotiation, and that is the point.** Presence is decided
per-frame by payload length, so there is no handshake round to get wrong and no
state in which one side believes the other is capable and is wrong.

| receiver | sender | outcome |
|---|---|---|
| old | old | today's behaviour |
| old | new | 24-byte `BulkStart`; old receiver reads `payload[:8]`, ignores the tail |
| new | old | 8-byte `BulkStart`; no incarnation; falls back to today's behaviour |
| new | new | full #5084 guard |

The mixed states are the two middle rows and both are stable indefinitely — there
is no "both sides upgraded but not yet agreed" state to traverse, because the
first `BulkStart` after both are new carries the field and is self-describing.

**Upgrade ordering does not matter.** Either node may be upgraded first.

## §5 — Does the mixed-version window need a flag day?

**No — but the answer is contingent, and the contingency is the whole decision.**

No flag day is needed *given* §3's fail-open. The change is a pure length-gated
payload extension whose absent-field behaviour is byte-for-byte today's
behaviour, so no state exists in which a node is worse off than before the
upgrade.

**A flag day would be unavoidable if the guard had to fail closed.** An upgraded
receiver cannot distinguish "old peer that cannot send the field" from "peer
suppressing the field", because the only thing that could tell them apart is a
negotiated capability — and a negotiated capability has nowhere to live on the
unkeyed path (§2). So *if* a future requirement demands that an un-incarnated
peer be refused, that requirement forces either a flag day or making the keyed
handshake mandatory. Both are decisions well outside #5084 and should not be
taken as a side effect of it.

**Recommendation: accept fail-open, no flag day, and record the contingency
above in the code comment** so a later reviewer who wants to tighten it
understands what they would be signing up for.

## §6 — Receiver-side design sketch

State replaces the `configNamespaceConnID` floor with:

- `peerIncarnation [16]byte` — the boot id of the incarnation that most recently
  primed; zero means "un-incarnated peer" (§3 fallback active).
- Each connection records the incarnation from the `BulkStart` that primed it.
- A queued config payload carries the incarnation it arrived under.

Rules:

1. A `BulkStart` carrying an incarnation **different** from `peerIncarnation`
   switches the namespace: clear the generation high-waters (as
   `resetRecvGen` already does) and set `peerIncarnation`.
2. A `BulkStart` carrying the **same** incarnation is a mid-connection re-prime
   (the #5450 forced resync) and must **not** clear queued payloads — same
   incarnation, comparable generations. This is the case #6900's equal-id
   exemption was approximating.
3. A payload whose incarnation ≠ `peerIncarnation` is dropped, permanently, and
   is never re-admitted. There is no descent and no release.
4. An un-incarnated payload (§3) is never dropped on incarnation grounds.

Note rule 3 removes the `continue`-skips-the-generation-gate hazard that killed
#6900: a dropped payload is from a *dead* incarnation whose generations are
incomparable with the current one, so its generation carries no information the
current high-water needs. That is only true because membership is an equivalence.

## §7 — Known residual

A pre-reboot socket that is half-open and has not yet errored can still hold a
buffered `BulkStart` from the dead incarnation. If it lands after the new
incarnation primed, rule 1 would switch the namespace *back*. This is bounded:
`receiveLoop` arms a 10s read deadline and returns at `missedHeartbeats >= 2`, so
such a socket self-evicts within ~20s of silence, and an OS reboot outlasts that
window — so the frame is hard to produce at all.

If it must be closed rather than bounded, the fix is a receiver-local
strictly-increasing "namespace claim ordinal" bumped on each switch, with a
switch refused from a connection whose slot is no longer installed. **That is
deliberately out of scope for the first implementation**: it is the same
add-an-ordering instinct that produced #6900, and it should only be added against
a demonstrated failure, not pre-emptively.

## §8 — What implementation would need to prove

Non-negotiable for the eventual PR:

- A binder that REDs as an **assertion** when the incarnation comparison is
  removed, showing a prior-incarnation config applying.
- An over-reach guard that stays GREEN under that revert: a **same-incarnation**
  re-prime must NOT drop queued payloads (rule 2) — the #5450 case.
- A **two-fabric** fixture in which the surviving fabric holds the lower
  `syncConnID` but the **same** incarnation, asserting it is never fenced out.
  This is the exact case that defeated #6900 and it must be green by
  construction, not by a descent.
- A **mixed-version** cell: an 8-byte `BulkStart` from an old peer must produce
  byte-identical behaviour to `origin/master`.
- Confirmation that an old decoder tolerates the 24-byte payload — assert against
  the actual decode path, not by inspection.

## Open questions for sign-off

1. Is fail-open during the mixed-version window (§3, §5) accepted? Everything
   else follows from it.
2. Is the ~20s residual (§7) acceptable to ship bounded rather than closed?
3. Should the un-incarnated-peer state raise a cluster health annotation, or is a
   status field plus a counter enough?
