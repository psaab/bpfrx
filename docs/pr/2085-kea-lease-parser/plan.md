# #2085 — Display lease parser returns stale/expired and duplicate Kea memfile rows

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

`parseLeaseCSV` (`pkg/dhcpserver/dhcpserver.go:377-430`) — the
display-only Kea memfile lease parser consumed by `GetLeases4`/`GetLeases6`
(`:368`/`:374`) and rendered by `show dhcp server leases` (CLI
`pkg/cli/cli_show_services.go`, gRPC
`pkg/grpcapi/server_show_dhcp_lldp_snmp.go`) — returns EVERY data row
whose `address` field is non-empty. It applies:

- **no expire-vs-now filter** — a row whose `expire` epoch is in the
  past is still shown; and
- **no per-address dedup** — Kea's memfile is **append-only**, so a
  lease that has been renewed, re-allocated, or had a state change
  appears as MULTIPLE rows, all of which are returned.

Result: `show dhcp server leases` lists stale/expired leases and
duplicate rows for the same address. This is purely a control-plane
**display** bug — it does not affect forwarding, Kea's own lease
authority, or DDNS (which has its own parser, see below).

## Honest scope / value framing

The win is correctness of an operator display command, not
throughput. At absolute scale the cost is a per-call O(rows) map +
slice build (display path, called at most ~1/s by an operator typing
`show dhcp server leases` — never on the packet path, never on the
config-apply path). The blast radius is one function plus its two
test-only consumers. If reviewers conclude the fix is wrong-shaped or
the existing behaviour is somehow load-bearing, PLAN-KILL is an
acceptable verdict.

## What's already shipped / partially batched

`pkg/dhcpserver/ddns_leases.go` already implements a **state-aware**
parser — `parseActiveLeases(path, family, now)` — for the #1387 DDNS
reconciler. It ALREADY does expire-filter + per-address
last-write-wins dedup + state-column filtering + DUID/IAID identity +
fail-safe header validation, with `now time.Time` injected for tests.

That parser is deliberately SEPARATE from the display parser and the
plan keeps it that way: DDNS is a **destructive** consumer (an empty
or wrongly-keyed result deletes owned DNS records), so it must
hard-error on a mangled header and must read the `state`/identity
columns. The display path is **non-destructive** and **lenient** — a
mangled or short row should degrade to showing what it can, never
abort the whole `show`. Merging the two parsers would force the
display path to adopt DDNS's hard-fail semantics (a single corrupt row
would blank the entire lease display) or force DDNS to adopt the
display path's lenient semantics (re-opening the mass-delete bug
#1387 spent six review rounds closing). They stay separate; this plan
brings ONLY the two missing behaviours (expire filter + dedup) to the
display parser, in the display parser's own lenient style.

## Concrete design

Change `parseLeaseCSV` to take an injected clock and apply expire
filtering + last-write-wins dedup. Keep it lenient.

### Signature

```go
// before
func parseLeaseCSV(path string) ([]Lease, error)

// after
func parseLeaseCSV(path string, now time.Time) ([]Lease, error)
```

`GetLeases4`/`GetLeases6` pass `time.Now()`:

```go
func (m *Manager) GetLeases4() ([]Lease, error) {
	return parseLeaseCSV("/var/lib/kea/kea-leases4.csv", time.Now())
}
func (m *Manager) GetLeases6() ([]Lease, error) {
	return parseLeaseCSV("/var/lib/kea/kea-leases6.csv", time.Now())
}
```

This mirrors the `now time.Time` injection already used by
`parseActiveLeases` — a real seam, not an untestable `time.Now()`
buried in the parser.

### Body (replaces the `for _, fields := range records[1:]` accumulate)

Keep the existing header-map build and per-field extraction. Replace
the final `if l.Address != "" { leases = append(...) }` block with:

1. Skip rows with empty `address` (unchanged — empty address is not a
   displayable lease).
2. **Expire filter (lenient):** parse the `expire` field as a Unix
   epoch (`strconv.ParseInt(.., 10, 64)`). If it parses AND
   `expire > 0` AND `now.Unix() >= expire`, the row is expired — record
   it as a TOMBSTONE for that address (so a later append for the same
   address can supersede it) and do not emit. If `expire` is absent or
   unparseable, treat the row as live (lenient — display path must not
   hide a lease just because Kea wrote an exotic/blank expire).
3. **Dedup (last-write-wins):** keep a `map[string]Lease` keyed by
   address, overwriting on each row so the LAST row for an address wins
   (append-only memfile ⇒ chronological ⇒ newest last), plus a
   first-appearance `order []string` slice so display order is stable
   and deterministic. An expired row writes a zero `Lease{}` tombstone;
   a live row writes the populated `Lease`.
4. **Emit:** walk `order`, skip tombstones (`l.Address == ""`), append
   the rest. This is the exact emit pattern `parseActiveLeases`
   already uses — proven over six #1387 review rounds.

Crucially the tombstone-and-reclaim shape (an expired row tombstones
the address; a later live append for the same address re-populates it)
matches the DDNS parser so a re-allocated address that Kea appended a
fresh live row for is shown live, not hidden by an earlier expired row.

### now boundary semantics

`now.Unix() >= expire` ⇒ a lease expiring exactly at `now` is treated
expired (matches `parseActiveLeases` line 284: `now.Unix() >= expire`).
Consistent with the DDNS parser; the one-second boundary is
display-only and immaterial.

## Public API preservation

- `GetLeases4() ([]Lease, error)` — unchanged signature.
- `GetLeases6() ([]Lease, error)` — unchanged signature.
- `Lease` struct — unchanged (all six fields preserved).
- `parseLeaseCSV` is **package-private**; its only callers are
  `GetLeases4`/`GetLeases6` and the package's own tests. Adding the
  `now time.Time` param touches exactly those call sites. Confirmed by
  `grep -rn parseLeaseCSV` — no consumer outside the package.

## Hidden invariants the change must preserve

- **Lenient display semantics:** a corrupt/short/exotic row must
  degrade to showing what it can, NEVER abort the whole `show`. The
  display parser must NOT inherit DDNS's hard-error-on-mangled-header
  behaviour. (A blanked lease display on one bad row is a regression.)
- **Missing file ⇒ `(nil, nil)`** — unchanged (`os.IsNotExist`).
- **Header-only / <2 record file ⇒ `(nil, nil)`** — unchanged.
- **Quoted-field column integrity (#1778)** — unchanged (still
  `encoding/csv`, `FieldsPerRecord=-1`, `Comment='#'`). The dedup map
  keys on the already-parsed `address` value, so quoting is irrelevant
  to dedup.
- **DDNS parser untouched** — `parseActiveLeases` and its consumers are
  not modified; the destructive-path invariants from #1387 are
  unaffected.
- **No new error paths from the lenient filter** — an unparseable
  `expire` does not error; it falls through to "live". The function's
  error contract (only file-open and csv-read errors) is unchanged.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Only the display set shrinks (expired + duplicate rows removed). Live, unique rows are unchanged. Two test-only call sites updated for the new param. |
| Lifetime / borrow (Go: aliasing) | LOW | Pure value copies into a `map[string]Lease`; `Lease` has no pointers/slices. No aliasing hazard. |
| Performance regression | LOW | Display path, ~1/s operator-driven, never hot. O(rows) map+slice replaces O(rows) slice append. |
| Architectural mismatch | LOW | Reuses the proven `parseActiveLeases` tombstone/order/emit shape in-place; does NOT merge the two parsers (which would be the mismatch). |

## Test plan

Control-plane display bug — **NO smoke** (no dataplane change; the
loss-cluster CoS matrix is irrelevant here). Coverage is a focused
`pkg/dhcpserver` unit test, non-tautological (fails against pre-fix code):

1. New `TestParseLeaseCSV_ExpiredAndDuplicate`: synthetic append-only
   CSV with (a) the SAME address appearing twice with different
   `expire`/hostname (newer row last) and (b) a separate expired
   address (`expire` well in the past). Assert:
   - the duplicate address appears EXACTLY once, carrying the NEWEST
     row's fields;
   - the expired address is ABSENT;
   - a normal live address is present unchanged;
   - injects a fixed `now` (e.g. `time.Unix(1707900000, 0)`) so the
     test is deterministic and the boundary is explicit. Fails pre-fix
     (pre-fix returns 4 rows incl. the dup + expired).
2. Edge: absent/blank/garbage `expire` ⇒ row kept (lenient).
3. Edge: expired row for an address SUPERSEDED by a later live append
   ⇒ address shown live (tombstone-reclaim).
4. Update the three existing `parseLeaseCSV` call sites in
   `dhcpserver_test.go` to pass a `now` (use a fixed time past the
   1707955200 expiries in the existing fixtures so those rows stay live
   — preserves the existing assertions). The existing fixture expires
   (1707868800 / 1707955200 = 2024-02) need a `now` BEFORE them, or the
   existing 2-lease test would now correctly drop them; pick a `now`
   that keeps the existing fixtures live so those tests still assert the
   pre-existing behaviour.
5. Gates: `go build ./...`, `go vet ./pkg/dhcpserver/...`,
   `go test ./pkg/dhcpserver/...` (named test 5x for flake), full
   `go test ./...`.

## Out of scope (explicitly)

- The Kea `state` column (declined/expired-reclaimed) — the display
  path stays lenient and address+expire-based. Adding state filtering
  to the display is a separate enhancement; DDNS already handles state
  for the destructive path. (Open question 4 invites a reviewer to
  argue this should be in scope.)
- Merging the display and DDNS parsers — explicitly rejected above.
- Any change to how `expire`/`valid_lifetime` are RENDERED (epoch vs
  human time) — out of scope; only the row SET changes.

## Open questions for adversarial review

1. **Time seam vs. param:** is adding `now time.Time` to a
   package-private function the right seam, or should the clock be a
   `Manager` field? (The function is package-private with two trivial
   callers and the sibling `parseActiveLeases` already uses the param
   form — but argue if a `Manager` clock field is cleaner.)
2. **Lenient expire:** is "unparseable/absent expire ⇒ keep" correct
   for a display, or should an unparseable expire DROP the row
   (fail-safe)? DDNS keeps such a row too (line 275-280: expire stays
   0, no drop). Argue if display should differ.
3. **Boundary `>=` vs `>`:** `now.Unix() >= expire` treats expiring-now
   as expired (matches DDNS). Is `>` (still valid at the instant of
   expiry) more correct for a display? PLAN-KILL-adjacent if the
   boundary matters operationally.
4. **State column:** should the display ALSO drop declined /
   expired-reclaimed (state != 0) rows, not just past-`expire` rows? A
   reclaimed lease can have a future `expire` but a non-default state.
   Is expire-only filtering an incomplete fix?
5. **Dedup key:** is `address` the right dedup key for v6 (where the
   same address is effectively unique per lease) and v4? Could two
   genuinely-distinct live leases ever share an address in a healthy
   memfile such that last-write-wins hides a real lease?
6. **Should this fix instead just call `parseActiveLeases`?** Argue the
   merge case if you believe the two-parser split is wrong — the plan
   rejects it (destructive vs lenient semantics) but invites the
   counter-argument.
