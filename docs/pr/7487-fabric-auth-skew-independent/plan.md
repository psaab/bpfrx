# #7487 — make fabric RPC authentication skew-independent (D2)

Measured at `c72b844e7`. The issue BODY is history: its own recommendation was
rejected in comment 2. **Comment 3 is the spec** and selects D2.

## What is being changed, in one sentence

The fabric-auth CLIENT signs at `now + offset`, where `offset` is the peer's
wall-clock offset learned from the PSK-authenticated heartbeat. **The verifier's
accept band and replay horizon are untouched.**

## Verified at head (the spec's cites are from `8bd87fcbe`)

| fact | at `c72b844e7` |
|---|---|
| the window | `fabricAuthWindow(t) = t.Unix() / 30`, `fabric_auth.go:114` |
| the accept band | literally `{now, now-1, now+1}`, `fabric_auth.go:152` — **not touched by this change** |
| the ONE client signing site | `fabric_auth.go:351` — `fabricAuthTokenHex(c.keyFn(), time.Now())` |
| fabric auth lives in | `pkg/grpcapi/`, **not** `pkg/cluster` (the spec says `pkg/cluster`; that is wrong, and a grep aimed there returns empty with no error) |

## The precedent that makes this tractable — and the trap inside it

The heartbeat already carries an **additive, MAC-covered, version-bump-free
optional section**: the boot-epoch section (#6169/#6711). Its own doc states the
compatibility argument this change needs:

> *"UnmarshalHeartbeat stops after the version section and ignores the rest, so a
> v1 receiver simply never sees the epoch. Bidirectional compatibility with no
> HAProtocolVersion bump."*

Its shape, which the clock field should mirror:

- placed immediately **before** the auth trailer, so it is inside the MAC-covered
  span and therefore unforgeable;
- located by working **backwards** from the end: `bodyEnd = len - authTrailerSize`,
  `markerAt = bodyEnd - sectionSize`;
- disambiguated from a legacy body by a **PRF marker** derived from the PSK
  (`heartbeatEpochMarker(authKey)`), not a plaintext magic — an attacker cannot
  compute it, and a legacy body collides at ~2^-64;
- **read only from an already-MAC-verified frame.** `heartbeatFrameEpoch`'s
  comment is explicit: *"the keyless / unverified path must never consult the
  marker, or an attacker could steer the epoch by appending bytes."*

### THE TRAP, and it is the main design decision

The epoch section is **optional** (`epoch != 0`) and is located by counting
backwards a fixed size from the end of the signed body. A second optional
section located the same way **occupies the same bytes**. Naively appending a
clock section makes the two indistinguishable: with only one present, each
parser reads the other's bytes and its marker check is the only thing standing
between it and a wrong value.

Two candidate shapes:

- **(A) chained sections.** Each section carries its own PRF marker; the parser
  walks backwards consuming whichever marker matches, repeating until none does.
  Order-independent, each section stays independently optional, and adding a
  third later costs nothing. Cost: the walk must bound its iterations and must
  not treat a marker match inside an unrelated legacy body as a section (the
  ~2^-64 argument already covers this, per marker).
- **(B) one combined "extensions" section** carrying both fields with a presence
  bitmap. Fewer moving parts to parse, but it **changes the epoch section's
  on-wire shape**, which is exactly the redefinition the spec forbids: an old
  node reading a combined section would mis-parse the epoch it currently reads
  correctly.

**Choose (A).** (B) fails the additive requirement against the field that
already exists.

## The wire field

`ClockNanos` — the sender's wall clock, little-endian `uint64` nanoseconds,
inside its own section with its own PRF marker, immediately before the auth
trailer, chained per (A).

**Additive in both directions, and the mixed-version behaviour is stated rather
than discovered:**

- an **old** node emits no clock section; a new node must see **absent**, not
  zero-meaning-1970 — hence a presence flag, never a sentinel value;
- a **new** node's section is ignored by an old decoder, because
  `UnmarshalHeartbeat` stops after the version section;
- **a cluster with one upgraded node RETAINS today's bug until both sides carry
  the field.** The no-offset fallback is *exactly* today's behaviour — sign at
  local `now` — because any other fallback ships new behaviour to the
  half-upgraded state.

No `HAProtocolVersion` bump, matching the epoch section's precedent.

## Trust bound on the learned offset

The heartbeat is PSK-authenticated, so an on-segment attacker cannot steer the
offset without the key — the whole reason to prefer it over the #6708 scan,
whose value is steerable by token replay.

A **key-holding** peer can declare an arbitrary clock. It gains nothing against
this node's verifier (it could already forge tokens directly), but it could make
this node sign at an arbitrary time. So: **clamp** — accept a learned offset only
within a bound, and fall back to local `now` beyond it.

### The clamp gets its OWN constant, and a derived value

`fabricAuthMaxLearnedSkew`, new, in `pkg/grpcapi`. **Not** `bootEpochMaxSkew`,
and the reason is not the value: reusing it couples two unrelated bounds through
one symbol, so someone later tuning it for a boot-epoch reason silently moves the
fabric-auth signing window, with nothing at that call site saying they did. That
is a shared resolver named for one of its two jobs — the second consumer is
invisible at the point of change.

**Value: 5 minutes.** Derived, not inherited:

- the fault it must cover is **measured, not hypothetical** — 141 s of real field
  skew on the loss userspace cluster, cited at `fabric_auth_skew_6708.go:19` and
  `fabric_auth.go:76`, and pinned by a test case literally named
  `the_measured_141s_case`. I verified that rather than taking the spec's word;
- 5 min is ~2.1x the observed fault, which is margin for a worse one without
  being open-ended;
- the bound is also the amount of control a key-holding peer has over **when this
  node signs**, so smaller is strictly safer and the only pressure upward is
  operational tolerance;
- `bootEpochMaxSkew`'s **1 hour is two orders of magnitude above the observed
  fault** against a 30 s token window, and buys nothing nameable here.

The PR states what the number covers and what sized it, so the next person argues
with the reasoning rather than the constant.

The offset is read **only from a frame whose MAC has already verified**, per the
epoch precedent.

## Guards that must stay green

| cell | guards |
|---|---|
| `TestSkewScanDoesNotWidenTheAcceptBand6708` | the accept band IS the replay horizon. Anything that reds this has widened the horizon instead of moving the client's clock |
| the #6711 boot-epoch cells | the backward-clock-step shape the acceptance criteria name by reference. The new clamp must not reintroduce it |
| heartbeat encode/decode round-trip cells | the additive property, in **both** directions |

## New cells owed

- old→new and new→old frames decode correctly, with the clock section **absent**
  distinguishable from **zero**;
- an epoch section and a clock section present **together**, and each present
  **alone** — the chained-parser case (A) exists for, and the one a single-section
  fixture cannot see;
- a learned offset beyond the clamp falls back to local `now`;
- with no offset learned, the signed token is **byte-identical** to today's;
- a token signed at `now + offset` verifies against a peer whose clock is skewed
  by that offset — the actual failure the issue is about;
- **mutation**: reverting the client to `time.Now()` must red the skew cell, and
  removing the clamp must red the clamp cell.

## Gate

`make test-failover` **and** `make test-ha-crash` on the loss userspace cluster,
plus a run with deliberate skew injected on one node — the issue's own criterion
and the only one that exercises the real failure. Cluster smokes launched
**DETACHED**: a ~30-minute run against a 10-minute tool cap is killed mid-failover,
which leaves shared state odd even when the lock is clean.

## What I am least sure of, and want attacked

1. **The chained-section parser (A).** Two optional sections located by walking
   backwards is the whole risk of this change. Is there an ordering or
   marker-collision case where the epoch parser consumes the clock section's
   bytes, or vice versa? A wrong epoch is a #6711 regression.
2. **Whether the offset belongs on the heartbeat at all**, versus the sender
   simply stamping the window it used. Comment 3 chose the offset; I have not
   re-derived that choice and would rather it be attacked than inherited.
3. **The clamp value.** Reusing `bootEpochMaxSkew` (1h) is convenient; a fabric
   token window is 30s, so an hour may be far too generous for this use.
