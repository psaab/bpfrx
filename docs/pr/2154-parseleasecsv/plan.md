# #2154 — parseLeaseCSV must skip malformed lines, not abort whole file

**Status:** IMPLEMENTED — pending adversarial code review

## Issue framing

`pkg/dhcpserver/dhcpserver.go::parseLeaseCSV` backs `show dhcp server
leases` and the REST/gRPC lease endpoints. It reads Kea's append-only
memfile with a single `csv.Reader.ReadAll()`. Kea appends a new row on
every renewal / re-allocation / release / decline / expiry-reclaim,
concurrently with xpf reading. If xpf reads while Kea is mid-append, the
file ends on a partial/torn line. `ReadAll()` aborts on the FIRST
malformed record and returns `(nil, err)`, so a single torn last line
fails the ENTIRE `GetLeases4`/`GetLeases6` call and `show ... leases`
shows nothing even though most rows are valid — exactly when the network
is busiest.

#2085 already made the *semantics* lenient (per-record dedup/expire/state
filtering rather than blanking on one odd row) but left the *I/O* layer
all-or-nothing. This change makes the read robust ON TOP of #2085's
dedup/expire logic without regressing it.

## What's already shipped (#2085) that this must compose with

Inside the per-record loop (current lines 446-488):
- **Dedup**: one row per address, newest (last chronological) wins.
- **Tombstone**: a non-active row records an empty `Lease{}` for the
  address; a later active append can RECLAIM it.
- **State filter**: `state != 0` (declined/expired-reclaimed) tombstones.
- **Expire filter**: `expire <= now` tombstones.
- **Leniency**: absent/unparseable state/expire ⇒ treat row as active.
- **Stable order**: first-appearance order preserved via `order`/`seen`.
- Header column-index map built from the FIRST record.

This change touches ONLY the I/O layer (how records are obtained). The
dedup/expire/state/tombstone/order/leniency loop body is copied verbatim.

## Empirical csv.Reader.Read() semantics (verified, not assumed)

A standalone probe (5 torn-line shapes) against the project Go toolchain
confirmed:

1. After a `*csv.ParseError`, the next `Read()` recovers — it returns the
   next valid record or `io.EOF`. **It does NOT loop forever.** So a
   "log + skip + continue" loop terminates naturally.
2. A torn quoted field that spans to EOF (append in progress on a
   `"`-quoted column) consumes the remainder of the file as field content
   — but this is identical to `ReadAll()`'s behavior and the realistic
   Kea case is a torn LAST line, which after the error yields `io.EOF`.
3. Short lines (fewer fields) with `FieldsPerRecord = -1` produce NO
   error at all — already tolerated; the issue's "field-count mismatch"
   concern is a non-event with `-1`.
4. `io.EOF` terminates cleanly and MUST break the loop.
5. `csv.ErrFieldCount` cannot fire while `FieldsPerRecord = -1`, but the
   skip branch handles it generically anyway.

## Concrete design

Replace the `ReadAll()` block (lines 412-421) and the `records[0]`/
`records[1:]` indexing with a single streaming loop:

```go
r := csv.NewReader(f)
r.FieldsPerRecord = -1 // memfile rows vary across Kea versions / torn appends
r.Comment = '#'
r.ReuseRecord = false  // we keep header `cols` indices across iterations;
                       // ReuseRecord aliasing would not corrupt cols (we
                       // copy nothing by reference), but leave default false
                       // to avoid any shared-slice surprise.

var (
    cols   map[string]int // header column indices; nil until header read
    latest = make(map[string]Lease)
    order  = make([]string, 0)
    seen   = make(map[string]struct{})
)
nowUnix := now.Unix()
field := func(fields []string, name string) string {
    if idx, ok := cols[name]; ok && idx >= 0 && idx < len(fields) {
        return fields[idx]
    }
    return ""
}

for {
    fields, err := r.Read()
    if errors.Is(err, io.EOF) {
        break
    }
    if err != nil {
        // Torn/concurrent Kea append or exotic row: skip this record,
        // keep the rest. #2154 — one bad line must not blank the show.
        slog.Debug("dhcpserver: skipping malformed lease row",
            "path", path, "err", err)
        continue
    }
    if cols == nil { // first successful record is the header
        cols = make(map[string]int, len(fields))
        for i, h := range fields {
            cols[h] = i
        }
        continue
    }
    // ---- #2085 loop body, verbatim ----
    addr := field(fields, "address")
    ...dedup / state / expire / tombstone / order ...
}

if cols == nil { // no header at all (empty/comment-only file)
    return nil, nil
}
// ---- #2085 emit phase, verbatim ----
```

### Behavioral equivalences to preserve

| Old (`ReadAll`)                       | New (`Read` loop)                         |
|---------------------------------------|-------------------------------------------|
| `len(records) < 2` ⇒ `nil,nil`        | `cols==nil` (no header) ⇒ `nil,nil`; header-only ⇒ empty `order` ⇒ `nil,nil` |
| header = `records[0]`                 | header = first successful `Read()` record |
| data = `records[1:]`                  | every successful `Read()` after header    |
| any parse error ⇒ `(nil, err)`        | per-record parse error ⇒ skip+debug, continue |
| `os.IsNotExist` ⇒ `nil,nil`           | unchanged (open path untouched)           |
| other `os.Open` error ⇒ `err`         | unchanged                                 |

The function still returns a non-nil `error` ONLY for an `os.Open`
failure that is not `IsNotExist` — the same contract as before, minus the
now-removed `ReadAll` parse-error path (which was the bug).

## Hidden invariants preserved

- **Side-effect ordering**: state-filter precedes expire-filter precedes
  emit — copied verbatim, unchanged.
- **Tombstone/reclaim ordering**: chronological append order is preserved
  because `Read()` yields records in file order, identical to `ReadAll`.
- **Stable display order**: `order`/`seen` first-appearance logic
  unchanged.
- **Leniency**: absent/garbage state/expire still keeps the row.
- **No new allocations on the hot path** — this is a slow display path
  (1/`show`), allocation rules N/A, but the map/slice pre-sizing hint
  `len(records)-1` is simply dropped (we no longer have the count up
  front); maps grow as needed. Negligible.

## Risk assessment

| Class                          | Level | Rationale |
|--------------------------------|-------|-----------|
| Behavioral regression          | LOW   | Loop body byte-identical to #2085; only record acquisition changes. Equivalence table above. |
| Lifetime / aliasing            | LOW   | `ReuseRecord=false` (default); `field()` reads strings by value into `Lease`. No retained slice aliases the reader buffer. |
| Performance                    | NONE  | Slow path; loses one pre-size hint, gains nothing-loses-nothing. |
| Architectural mismatch         | NONE  | Localized to one function; no new abstraction. |
| Infinite loop on parse error   | NONE  | Empirically verified `Read()` recovers/EOFs after `ParseError`. |

## Test plan

`go test ./pkg/dhcpserver/` — all existing tests must pass unchanged
(they prove #2085 dedup/expire/state/leniency is not regressed), PLUS a
new non-tautological test:

- **`TestParseLeaseCSV_SkipsMalformedLine`**: a fixture with valid rows
  surrounding/followed by a torn line (short line, then a bad-quote line
  at EOF) must return the VALID leases, not `(nil, err)`. Asserts the
  count and that a specific valid address survives. This FAILS against
  the pre-fix `ReadAll` code (which returns `(nil, err)` on the torn
  quote), so it is non-tautological.
- Also assert the torn line at the very END (the canonical Kea
  mid-append case) still returns the leading valid rows.

No HA/cluster smoke: control-plane display path only (per issue
disposition: "Smoke-class: standard (display path), no HA smoke
required").

## Out of scope

- Changing what columns are displayed or the dedup/expire policy (#2085
  owns that).
- The destructive DDNS reconciler `parseActiveLeases` (intentionally
  hard-errors on a mangled header — different contract, not touched).
- Atomic-snapshot reads of the memfile (Kea owns the file; we only read).

## Open questions for adversarial review

1. Is the header-detection change (`cols == nil` ⇒ first successful
   record is header) equivalent to `records[0]` in ALL cases, including a
   file whose FIRST line is malformed? (Then the header would be the
   first *valid* line — is that a regression vs. ReadAll, which would
   have errored out entirely? Arguably better: ReadAll returned nothing.)
2. Could a torn quote on a NON-last line silently swallow trailing valid
   rows (verified case `bad-mid-then-good`)? Is that acceptable given it
   matches `ReadAll` behavior and the realistic case is a torn last line?
3. Is `slog.Debug` the right level (vs. Warn)? The issue says debug;
   per CLAUDE.md logging rules a 1/`show` event is not high-frequency,
   but Debug matches the issue's explicit instruction and avoids log
   spam if a persistently-corrupt file is polled.
4. Does dropping the `len(records)-1` pre-size hint matter? (No — slow
   path, maps grow.)
5. Should the function ever return an error for a partially-corrupt file
   (telemetry), or is silent-skip+nil-error correct for a display path?
   The issue mandates skip+continue → silent success is correct.
