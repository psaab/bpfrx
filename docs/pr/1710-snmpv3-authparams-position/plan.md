# #1710 — SNMPv3 USM: zero authParams by position, not by length heuristic

Status: v2 — Codex PLAN-NEEDS-MINOR (4 minors addressed below) + AGY
PLAN-READY. Core positional design ratified by both; no KILL
counterexample found.

## Adversarial review resolution (round 1)

- **Codex** (task-mpta4cny-05mmyf): PLAN-NEEDS-MINOR. Core design immune
  to the collision; no KILL counterexample. 4 minors, all resolved below.
- **AGY** (adversarial-review-mpta4okq-75xv55): PLAN-READY, with a
  bounds-checking hardening note (same as Codex minor #1).

Resolutions:

1. **Bounded parse invariant (Codex #1 / AGY hardening).** The locator
   MUST decode every child TLV from its **parent value slice**, never from
   `pkt[cursor:]`, so a nested length cannot escape its enclosing
   SEQUENCE/OCTET-STRING. `berEncodedLen` returns the *advertised* size
   without bounds-checking it fits (agent.go:988-996); the safety comes
   from `berDecodeHeader`/`berDecodeOctetString` decoding against the
   bounded container slice (agent.go:812-815, 882-885). Implementation:
   the locator descends by slicing the parent's value (returned by
   `berDecodeHeader`) and accumulates the absolute offset as
   `base += headerBytes` on descent / `base += berEncodedLen(field)` on
   sibling-skip, where each step first decodes from the bounded slice (so
   an over-run returns err → ok=false). Every cursor advance is also
   guarded by an explicit `start >= 0 && end <= len(pkt)` check before the
   range is returned.
2. **`ok` semantics (Codex #2).** The locator parses through the **sixth**
   USM field (privParams) before returning `ok=true`, matching
   `handleV3Packet`'s requirement that privParams decode (v3.go:208-212).
   `ok=true` therefore means "the USM sequence is well-formed through
   privParams and authParams is locatable." Documented on the helper.
3. **Long-form length test (Codex #3).** Test 7 added: a packet whose
   `msgSecurityParameters` OCTET STRING (and outer SEQUENCE) carry a
   long-form (>127) BER length, exercising the multi-byte
   `headerBytes = 1 + lenBytes` path (`berDecodeLength` long-form,
   agent.go:824-838).
4. **authParams-length wording (Codex #4).** Corrected: `verifyAuth`
   rejects `len(receivedMAC) != truncLen` *before* calling
   `zeroAuthParams` (v3.go:376-379), so a non-truncLen authParams never
   reaches the zeroing path. The locator zeroes the on-wire authParams
   value range regardless of its length, but for any packet that gets that
   far the length already equals `truncLen`. The earlier "zero
   unexpected-length authParams as received" rationale is withdrawn.

## Issue framing

`pkg/snmp/v3.go` `zeroAuthParams(pkt, truncLen)` blanks the
`msgAuthenticationParameters` OCTET STRING before HMAC recomputation by
scanning the raw packet for the **first non-zero OCTET STRING whose BER
length == truncLen** and zeroing it. In the USM security-parameters
SEQUENCE (RFC 3414) the field order is:

```
msgAuthoritativeEngineID   OCTET STRING
msgAuthoritativeEngineBoots INTEGER
msgAuthoritativeEngineTime  INTEGER
msgUserName                 OCTET STRING   <-- precedes authParams
msgAuthenticationParameters OCTET STRING   <-- the field we must zero
msgPrivacyParameters        OCTET STRING
```

`truncLen` is 12 (HMAC-MD5-96 / HMAC-SHA-96) or 24 (HMAC-SHA-256, 192-bit
truncation). A user whose username is exactly 12 chars (MD5/SHA-1) or 24
chars (SHA-256) makes the scan hit `msgUserName` first (lower index,
matching length, non-zero) and zero the username instead of authParams.
HMAC then runs over a packet with the username blanked but authParams
intact, the computed MAC never matches the received MAC, and that user is
**locked out of SNMPv3**. A `msgAuthoritativeEngineID` of exactly
`truncLen` bytes (e.g. a 12-byte engine ID, which is a legal length) is
also scanned before authParams and would be zeroed first — second trigger
of the same class.

## Honest scope/value framing

This is a management-plane correctness bug, not a perf change. The win is
that SNMPv3 auth works for the (specific but entirely plausible) set of
usernames/engine-IDs whose byte length collides with the HMAC truncation
length. There is no throughput or cycle dimension. The blast radius is one
helper (`zeroAuthParams`) plus its single caller (`verifyAuth`) plus the
parse site in `handleV3Packet` that must surface the field offset. If
reviewers conclude the fix is wrong or unneeded, PLAN-KILL is an acceptable
verdict.

## What's already in place

- `handleV3Packet` (v3.go:125) already **fully parses** the USM sequence in
  field order: engineID, boots, time, `userNameBytes`, `authParams`,
  `privParams` — each via `berDecodeOctetString`/`berDecodeInteger`
  (v3.go:183-212). The positional information the fix needs is already
  computed; it is simply discarded.
- All `berDecode*` helpers return **subslices of the original backing
  array** (`data[headerLen : headerLen+length]`), not copies
  (agent.go:815, 885). `data` passed into `handlePacket` is the source the
  agent copies into `a.lastPacket` (agent.go:240-241). Therefore
  `authParams` (a subslice reached through msgBody→afterHeader→secParamsRaw)
  shares the same backing array as the packet `a.lastPacket` is copied
  from; the value's byte offset within that array is well-defined.
- `verifyAuth` (v3.go:371) copies `a.lastPacket` into a fresh `pkt`, calls
  `zeroAuthParams(pkt, truncLen)`, then HMACs `pkt`.

## Concrete design

### 1. Compute the authParams byte offset at parse time

`authParams` is a subslice of the same backing array as the slice handed to
`handlePacket`. We do NOT have that original slice inside
`handleV3Packet` (it receives `rest`, the post-version remainder). Two
candidate offset sources:

- **(A) pointer arithmetic against `a.lastPacket`'s source.** Fragile:
  `a.lastPacket` is a *copy*, so its backing array differs from
  `authParams`'s. We would need the pre-copy slice. Rejected.

- **(B) pointer arithmetic against the slice the parse chain descends
  from.** `handlePacket` has `data` (the original). It computes
  `a.lastPacket` as a copy of `data`, then decodes `data` into `msgBody`,
  passes `rest` to `handleV3Packet`. `authParams` is a subslice of `data`'s
  backing array. The offset of `authParams` within `data` equals the offset
  within `a.lastPacket` (same length, index-for-index copy). Compute it as
  `offset = int(uintptr(unsafe.Pointer(&authParams[0])) -
  uintptr(unsafe.Pointer(&data[0])))`. **Rejected** — introduces `unsafe`,
  and `authParams` may be zero-length (empty authParams on a noAuth probe),
  making `&authParams[0]` invalid.

- **(C) Track offsets explicitly through the decode, no unsafe.** The clean
  approach: replace the offset-free `berDecodeOctetString` calls in the USM
  parse with offset-aware decoding **relative to `secParamsRaw`**, then
  translate `secParamsRaw`'s base offset within `a.lastPacket`. But
  `secParamsRaw` is also a subslice — its base offset must be tracked from
  the top. This means threading a running offset from `handlePacket` down.

  Cleanest no-unsafe form: have `handlePacket` pass `data` (the original
  full packet) into the v3 handler and compute the offset using a helper
  that walks the USM sequence **on `a.lastPacket` directly** to the
  authParams field, returning its `(start, len)` — i.e. a *positional*
  locator that decodes engineID, boots, time, userName, then authParams,
  returning the byte range of the 5th field. This decodes structure, not
  "first match of length L", so it is immune to the username/engineID
  length collision.

**Chosen design = (C) positional locator.** Add:

```go
// usmAuthParamsRange parses the USM security-parameters SEQUENCE that lives
// inside the SNMPv3 message `pkt` and returns the [start,end) byte range of
// the msgAuthenticationParameters OCTET STRING *value* (not its TLV header),
// located by RFC 3414 field position. Returns ok=false if `pkt` is not a
// well-formed v3 message with a USM sequence.
func usmAuthParamsRange(pkt []byte) (start, end int, ok bool)
```

It re-walks the outer SEQUENCE → version INTEGER → header SEQUENCE →
msgSecurityParameters OCTET STRING → USM SEQUENCE → engineID, boots, time,
userName, then authParams, computing a running absolute offset into `pkt`
via the consumed-byte counts of each TLV (header bytes + value bytes). No
`unsafe`, no pointer arithmetic. Because it walks to the **fifth USM field
by position**, a username or engineID of length `truncLen` cannot be
mistaken for authParams.

`zeroAuthParams` becomes:

```go
func zeroAuthParams(pkt []byte) {
    start, end, ok := usmAuthParamsRange(pkt)
    if !ok {
        return
    }
    for j := start; j < end; j++ {
        pkt[j] = 0
    }
}
```

`verifyAuth` drops the `truncLen` argument to `zeroAuthParams` (the range
is determined by parse, not by the caller's expected length) but still uses
`truncLen` for the `len(receivedMAC)` check and HMAC truncation. The
zeroed range is exactly the authParams value as encoded on the wire — if a
non-conformant peer sent an authParams of unexpected length, we zero what
is actually there, which is the correct input to the HMAC recomputation
per RFC 3414 §6.3.1 (blank the field as received).

### Why re-walk instead of plumbing the offset from handleV3Packet

`handleV3Packet` already parses the same fields, so re-walking duplicates
work. But threading an absolute offset out of `handleV3Packet` requires
`handlePacket` to compute `rest`'s offset within `data`, pass it down, and
`handleV3Packet` to accumulate offsets across `berDecodeHeader` /
`berEncodedLen` boundaries — touching the hot decode path and several call
sites for a once-per-auth-packet operation. A self-contained
`usmAuthParamsRange(a.lastPacket)` called only from `verifyAuth` keeps the
change to one helper + its caller, is independently testable, and runs only
on the auth path (never per-PDU). The duplicate parse is negligible
(management plane, one SNMP request).

### Offset accounting detail

`berDecodeHeader` returns `(tag, value, err)` but not bytes consumed. I will
use `berEncodedLen(slice)` (agent.go:988, returns total TLV length =
header+value) and `berDecodeLength` to advance an absolute cursor. The
locator computes, at each step, `cursor += headerBytes` before reading a
value and `cursor += valueLen` after, so when it reaches the authParams
value the cursor is its absolute start. I will assert in tests that
`start..end` lands exactly on the authParams bytes for both 12- and
24-char usernames and for a 12-byte engineID.

## Public API preservation

- `zeroAuthParams` is unexported, single caller (`verifyAuth`). Signature
  changes from `(pkt []byte, truncLen int)` to `(pkt []byte)`. No external
  consumer.
- `verifyAuth` signature unchanged.
- `handleV3Packet` / `handlePacket` signatures unchanged.
- New unexported helper `usmAuthParamsRange`.
- `insertAuthMAC` (the response-build mirror, v3.go:691) is **out of
  scope** — see below.

## Hidden invariants the change must preserve

- **HMAC input identity (RFC 3414 §6.3.1):** the packet handed to HMAC must
  be byte-identical to the received packet except authParams blanked to
  zeros. Zeroing exactly the parsed authParams value range preserves this
  (same as before for the non-colliding case; corrects the colliding case).
- **Copy isolation:** `verifyAuth` still HMACs a *copy* of `lastPacket`, so
  the original packet (used downstream for decrypt) is untouched. The
  locator runs read-only on the copy.
- **Empty / malformed packets:** locator returns `ok=false` →
  `zeroAuthParams` no-ops → HMAC over the unmodified copy → mismatch →
  auth fails closed. Same fail-closed posture as today (today's loop simply
  finds nothing and returns). No new panic path: all indexing is guarded by
  `berDecode*` truncation checks and an explicit `start/end <= len(pkt)`
  guard.
- **truncLen still gates `len(receivedMAC)`** in `verifyAuth` — unchanged.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Positional locator is a strict superset of correctness vs the heuristic; non-colliding packets get the identical authParams range zeroed. New tests pin both paths. |
| Lifetime / borrow | N/A (Go) | No `unsafe`, no aliasing; operates on the local copy. |
| Performance | NONE | Management plane, one re-parse per auth packet; never per-PDU/per-packet on the dataplane. |
| Architectural mismatch | LOW | Self-contained helper; does not re-plumb the decode hot path. Matches existing `berDecode*` walk style. |

## Test plan

New tests in `pkg/snmp` (table-driven, build a real v3 USM packet, run the
verify path):

1. **Regression — 12-char username, SHA-1 (truncLen 12):** construct a
   v3 authNoPriv message for a user with a 12-byte name, real HMAC-SHA-96
   authParams. Assert `verifyAuth` returns true. With the old heuristic this
   fails (username zeroed). Also assert with MD5 (truncLen 12).
2. **Regression — 24-char username, SHA-256 (truncLen 24):** same, name 24
   bytes. Assert auth succeeds.
3. **Negative-collision — 12-byte engineID:** username short (e.g. 4 chars),
   engineID exactly 12 bytes, SHA-1. Assert auth succeeds (engineID must NOT
   be zeroed).
4. **Locator unit test:** `usmAuthParamsRange` returns the exact
   `[start,end)` of authParams for a hand-built packet; cross-check by
   confirming `pkt[start:end]` equals the known authParams bytes and that
   the username/engineID bytes are at different offsets.
5. **Non-colliding control:** ordinary 5-char username, SHA-1 — auth
   succeeds (proves no regression for the common case the old code handled).
6. **Malformed packet:** truncated USM sequence → `usmAuthParamsRange`
   returns ok=false, `verifyAuth` returns false (fail closed), no panic.

To exercise `verifyAuth` end-to-end the test must set `a.lastPacket` and a
`usmUser` with `authKey`/`authProto`, then call the unexported `verifyAuth`
(same package). I will build the packet with the existing `berEncodeTLV`
helpers so the encoding matches what the agent emits, compute the real
HMAC over the zeroed-placeholder form, splice it in, then verify.

Gates:

- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/snmp/...` — green.
- New auth tests run 5× (flake check).
- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — full Go suite.
  Pre-existing `pkg/dataplane/userspace` sandbox unix-socket failures are
  known artifacts; reproduce on clean master and document.
- `make audit-check` (regen only if a file crosses the size threshold —
  unlikely for a ~40-line helper).
- **No cluster smoke** — this is a control-plane (SNMP management) change
  with no dataplane/CoS/HA surface. The gate is the Go suite plus the new
  auth tests.

## Out of scope (explicitly)

- **`insertAuthMAC` (v3.go:691)** uses the same first-OCTET-STRING-of-length
  heuristic on the **response-build** path. There the authParams placeholder
  is `make([]byte, truncLen)` (all-zero) and the locator requires the match
  to be all-zero, so a non-zero username of length `truncLen` is skipped.
  The residual risk is a username of exactly `truncLen` **zero** bytes
  (implausible) or a privParams placeholder collision. The response path
  builds the packet itself and knows the placeholder offset directly, so the
  correct fix there is to thread the offset from the builder, not re-walk —
  a different change. Tracked separately; not in this PR. I will note it in
  a code comment so it is not forgotten.
- Any change to BER decode helpers, the v2c path, or trap emission.
- DES/AES privacy paths.

## Open questions for adversarial review (each may justify PLAN-KILL)

1. **Is positional re-walk actually immune?** Confirm that decoding to the
   5th USM field by position cannot be fooled by a malformed sequence where
   an earlier field's declared length over/under-runs. (My read: `berDecode*`
   truncation checks make an over-run return err → ok=false → fail closed.
   Is there a length-confusion variant that lands the cursor on the wrong
   field while still returning ok=true?)
2. **Offset accounting correctness.** Does using `berEncodedLen` +
   `berDecodeLength` to advance an absolute cursor through nested
   SEQUENCE/OCTET-STRING wrappers (outer SEQ → version → header SEQ →
   secParams OCTET STRING → USM SEQ) correctly arrive at the authParams
   value start, accounting for multi-byte BER length encodings on the outer
   wrappers? Worked example requested.
3. **Should the fix instead plumb the offset out of `handleV3Packet`** (no
   duplicate parse) rather than re-walk in a standalone locator? Trade-off:
   touches the decode path + several call sites vs a once-per-auth re-parse.
   Is the re-walk's duplication a real defect or acceptable?
4. **Fail-closed posture:** is no-op-on-unparseable the right behavior, or
   should a parse failure in the locator be distinguishable from "authParams
   legitimately absent"? Today both fall through to mismatch. Acceptable?
5. **Is the bug even reachable in this codebase's config surface?** Does the
   SNMP config allow a 12/24-char username (no length cap that would prevent
   it)? If usernames are hard-capped below 12 the bug is latent-only — but
   the engineID-collision trigger remains, and Junos/standard USM allows
   long usernames. Verify the config path imposes no cap that makes this
   purely theoretical (which would weaken but not eliminate the fix's value
   via the engineID path).
