# #2085 — Display lease parser returns stale/expired and duplicate Kea memfile rows

**Status:** v2 — folds in adversarial plan-review round 1 (two hostile
Claude reviewers: PLAN-NEEDS-MAJOR + PLAN-NEEDS-MINOR). Changes from v1:
(1) state-column filtering pulled IN scope — expire-only is incomplete
because released (state=2) and declined (state=1) Kea leases carry
FUTURE expire epochs and would still display as live; (2) test-fixture
`now` contradiction fixed (legacy call sites use a `now` BEFORE the
2024-02 fixture expiries); (3) call-site count corrected to FOUR;
(4) README update added.

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
the final `if l.Address != "" { leases = append(...) }` block with, per
row, in this order:

1. Skip rows with empty `address` (unchanged — empty address is not a
   displayable lease). Otherwise note the address into the
   first-appearance `order` slice (tombstone or not) so a later live
   append can reclaim it.
2. **State filter (lenient) — FOLDED IN per review:** read the `state`
   column. If it parses to a non-default value (`state != 0` — Kea
   `state=1` declined, `state=2` expired-reclaimed), the lease is NOT
   active — record a TOMBSTONE for the address and do not emit. A
   released or declined Kea lease is written with a non-default state
   but often a FUTURE `expire` epoch, so the expire filter alone would
   leave it visible — exactly the "stale row shown" symptom the issue
   is about. An absent/unparseable state is treated as active (Kea's
   default; lenient — matches the DDNS parser ddns_leases.go:264-273).
3. **Expire filter (lenient):** parse the `expire` field as a Unix
   epoch (`strconv.ParseInt(.., 10, 64)`). If it parses AND
   `expire > 0` AND `now.Unix() >= expire`, the row is expired — record
   it as a TOMBSTONE for that address (so a later append for the same
   address can supersede it) and do not emit. If `expire` is absent or
   unparseable, treat the row as live (lenient — display path must not
   hide a lease just because Kea wrote an exotic/blank expire).
4. **Dedup (last-write-wins):** keep a `map[string]Lease` keyed by
   address, overwriting on each row so the LAST row for an address wins
   (append-only memfile ⇒ chronological ⇒ newest last), plus the
   first-appearance `order []string` slice so display order is stable
   and deterministic. A non-active or expired row writes a zero
   `Lease{}` tombstone; a live row writes the populated `Lease`.
5. **Emit:** walk `order`, skip tombstones (`l.Address == ""`), append
   the rest. This is the exact emit pattern `parseActiveLeases`
   already uses — proven over six #1387 review rounds.

Crucially the tombstone-and-reclaim shape (a non-active/expired row
tombstones the address; a later live append for the same address
re-populates it) matches the DDNS parser so a re-allocated address that
Kea appended a fresh live row for is shown live, not hidden by an
earlier expired/reclaimed row. State is filtered BEFORE expire so a
declined lease with a future expire is correctly tombstoned.

### Why state filtering is lenient, not the DDNS hard-fail

The DDNS parser hard-errors on a mangled header because its empty
result authorizes a destructive DNS-record delete. The display path
copies ONLY the per-row lenient state/expire tombstone logic
(ddns_leases.go:255-287) — NOT the required-column header validation,
the duplicate-column rejection, or the ragged-row error. An absent
`state` column (older Kea, exotic header) therefore degrades to
"treat all rows as active" (today's behaviour), never blanks the
`show`. This keeps display leniency intact while closing the
state-stale gap.

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
| Behavioral regression | LOW | Only the display set shrinks (expired + non-active state + duplicate rows removed). Live, unique, state=0 rows are unchanged. Four test-only call sites updated for the new param. Absent state/expire columns ⇒ today's behaviour (lenient). |
| Lifetime / borrow (Go: aliasing) | LOW | Pure value copies into a `map[string]Lease`; `Lease` has no pointers/slices. No aliasing hazard. |
| Performance regression | LOW | Display path, ~1/s operator-driven, never hot. O(rows) map+slice replaces O(rows) slice append. |
| Architectural mismatch | LOW | Reuses the proven `parseActiveLeases` tombstone/order/emit shape in-place; does NOT merge the two parsers (which would be the mismatch). |

## Test plan

Control-plane display bug — **NO smoke** (no dataplane change; the
loss-cluster CoS matrix is irrelevant here). Coverage is a focused
`pkg/dhcpserver` unit test, non-tautological (fails against pre-fix code).

**Existing call sites (FOUR, corrected from v1):** `dhcpserver_test.go`
lines 265 (`TestParseLeaseCSV`), 292 (`TestParseLeaseCSV_NoFile`), 308
(`TestParseLeaseCSV_Empty`), 329 (`TestParseLeaseCSV_QuotedHostname`).
The existing fixtures (`TestParseLeaseCSV`, `TestParseLeaseCSV_QuotedHostname`)
use expire epochs `1707868800` / `1707955200` (2024-02) with `state=0`,
so the legacy call sites MUST pass a `now` BEFORE `1707868800` (use a
named constant, e.g. `time.Unix(1707800000, 0)`) so those rows stay live
and the pre-existing assertions still hold. `NoFile` and `Empty` take any
`now`. This is the F1/F2 fix: a `now` past the fixtures would silently
drop them and neuter the existing assertions.

1. New `TestParseLeaseCSV_ExpiredAndDuplicate`: synthetic append-only
   CSV (its OWN `now`, e.g. `time.Unix(1707900000, 0)`, with fixtures
   built relative to it) covering:
   - the SAME address appearing twice (state=0) with different
     `expire`/hostname (newer row last, future expire) ⇒ appears
     EXACTLY once, carrying the NEWEST row's fields;
   - a separate address whose only row has a PAST `expire` ⇒ ABSENT;
   - a normal live address (state=0, future expire) ⇒ present unchanged.
   - Assert `len(leases)` is the post-fix count and that against pre-fix
     code it would have returned MORE rows (comment the pre-fix vs
     post-fix expectation so the non-tautology is explicit).
2. New `TestParseLeaseCSV_StateFiltered`: a declined (`state=1`) and an
   expired-reclaimed (`state=2`) row, BOTH with a FUTURE `expire` (the
   gap expire-only misses), ⇒ both ABSENT; plus a state=2 row for an
   address SUPERSEDED by a later state=0 live append ⇒ shown live
   (state tombstone-reclaim). Fails an expire-only fix.
3. Edge: absent/blank/garbage `expire` with state=0 ⇒ row kept
   (lenient); absent/garbage `state` ⇒ row kept (lenient, default
   active). Optionally a header with NO `state` column ⇒ all rows kept
   (proves the lenient degrade-to-today path).
4. Edge: expired row for an address SUPERSEDED by a later live append
   ⇒ address shown live (expire tombstone-reclaim).
5. Update the FOUR existing call sites per the note above.
6. Gates: `go build ./...`, `go vet ./pkg/dhcpserver/...`,
   `go test ./pkg/dhcpserver/...` (named tests 5x for flake), full
   `go test ./...`.

## Docs

`pkg/dhcpserver/README.md` must be updated (CLAUDE.md mandates module
docs in the same work item):

- Lines 78-92 currently contrast the state-aware DDNS parser against
  "the display-only `parseLeaseCSV`" and assert reusing the display
  parser "would publish/retain stale records." Post-fix the display
  parser ALSO filters expired + non-active + dedups, so the rationale
  for keeping them separate shifts from "display has no filtering" to
  "display is lenient/non-destructive (never blanks the `show` on a bad
  row) vs DDNS is hard-fail/destructive (must error on a mangled
  header)." Update that paragraph.
- The lease-queries paragraph (lines 318-322) should note that the
  display now returns only active, non-expired leases, deduplicated
  per-address to the newest memfile row.

## Out of scope (explicitly)

- Merging the display and DDNS parsers — explicitly rejected above.
  The per-row lenient state/expire/dedup logic is COPIED, not shared,
  so the destructive DDNS header-validation invariants are untouched.
- Any change to how `expire`/`valid_lifetime` are RENDERED (epoch vs
  human time) — out of scope; only the row SET changes.
- DDNS-grade header/duplicate-column/ragged-row validation — the
  display path stays lenient by design (a bad row degrades, never
  aborts the `show`).

## Plan-review round 1 — resolutions

Two hostile Claude reviewers (PLAN-NEEDS-MAJOR + PLAN-NEEDS-MINOR):

1. **Time seam vs. param** — RESOLVED: param. Both reviewers confirmed
   `now time.Time` mirrors the sibling `parseActiveLeases` and a
   `Manager` field would be inconsistent over-engineering for a
   package-private two-caller function.
2. **Lenient expire** — RESOLVED: keep (unparseable/absent ⇒ live),
   matches DDNS. Display must not hide a lease over an exotic expire.
3. **Boundary `>=` vs `>`** — RESOLVED: keep `>=`, matches DDNS
   (ddns_leases.go:284); immaterial for a 1/s display, consistency
   between the two parsers is the tie-breaker.
4. **State column** — RESOLVED **IN SCOPE** (both reviewers, MAJOR/MINOR):
   released (state=2) and declined (state=1) Kea leases carry FUTURE
   `expire`, so expire-only leaves them visible — the issue's own
   symptom. State filter folded in (lenient, copied from
   ddns_leases.go:265-273).
5. **Dedup key** — RESOLVED: `address` is sound for v4 and v6 (IA_NA
   address is the row identity; IA_PD delegated prefix is unique per
   row). Kea never double-allocates one address concurrently in a
   healthy memfile, so last-write-wins only collapses genuine
   duplicates. v4/v6 are separate files/calls, no cross-family
   collision.
6. **Merge with `parseActiveLeases`** — RESOLVED: NO. Both reviewers
   confirmed the destructive-vs-lenient split is correct; merging would
   either re-open the #1387 mass-delete or blank the display on one bad
   row. Copy the lenient per-row logic, not the header-validation.

Also fixed: F1 test-fixture `now` contradiction, F2 call-site count
(FOUR), F5 README update.

## Open questions for round 2

- Is the lenient state filter correctly placed BEFORE the expire filter
  (so a declined lease with future expire is tombstoned by state, not
  missed)? Verify the order in the implementation.
- Does the new `TestParseLeaseCSV_StateFiltered` genuinely fail an
  expire-only fix (non-tautological against the half-fix)?
- Any remaining inaccuracy in the README rewrite of the two-parser
  rationale?
