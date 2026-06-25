# pkg/feeds

Dynamic-address feed fetcher. Periodically pulls CIDR prefixes from HTTP
feed servers and triggers config recompile when the resolved set changes
**by content** (not merely by count).

## Entry points

- `Manager` — `feeds.go`.
- `New(updateFn)` — `feeds.go`.
- `Apply(ctx context.Context, daCfg *config.DynamicAddressConfig)` — `feeds.go`. Starts/stops per-feed refresh goroutines.
- `GetPrefixes(name)` — `feeds.go`. Returns the current enforced (last-good) snapshot.
- `StopAll()`, `FeedInfo`, `AllFeeds()` — surfaced to `show security dynamic-address`.

## Refresh correctness & fail-safe behavior (#2050)

A fetch is treated as **successful** only when the transport read completes
without error **and** the parsed set is non-empty. On any failure the manager
applies a *retain-last-good* policy rather than installing a partial/empty set:

- **scanner errors fail the fetch.** The body is scanned with a raised
  per-line cap (`maxLineBytes`, 1 MiB); an overlong line (`bufio.ErrTooLong`)
  or a mid-stream read error returns an error. The whole read fails — a
  truncated set is never installed. `scanner.Err()` is checked after the loop.
- **content-based change detection.** Prefixes are canonicalized (parsed to
  masked CIDR / `/32` / `/128`), deduped, sorted, and SHA-256 hashed. The
  `onUpdate` recompile callback fires only when the hash changes — a same-count
  content swap (`192.0.2.0/24` -> `198.51.100.0/24`) fires; a reordered but
  identical set does not.
- **no success stamp on a partial/errored read.** `LastFetch`/`LastSuccess`
  are stamped, and the active snapshot replaced, only on a complete successful
  fetch. A failed fetch records `LastError` and leaves the snapshot untouched.
- **zero-prefix HTTP 200 is suspect.** An HTTP-200 body that parses to zero
  usable prefixes is treated as a failure (retain last-good), so a hijacked or
  misconfigured endpoint serving an empty file cannot silently fail-open an
  enforced denylist.
- **`hold-interval` is the opt-in timed drop (default: retain forever).**
  On a fetch failure the last-good snapshot is retained from `StaleSince`.
  By default (`hold-interval` unset) it is retained **indefinitely** — it is
  never auto-dropped to empty — so a stale denylist cannot silently
  fail-open. This is the operator-chosen posture and deliberately diverges
  from Junos hold-interval-then-drop. Only when `hold-interval` is explicitly
  configured > 0 does the snapshot drop to empty after that interval elapses
  (clearing `StaleSince`/`Hash`), firing an `onUpdate` so enforcement sees
  the now-empty set — an explicit operator opt-in to fail-open-on-stale.
- **startup is fail-closed.** Before the first successful fetch there is no
  snapshot; `GetPrefixes` returns empty. A policy referencing a feed-backed
  address resolves to nothing until the first good fetch (bounded to seconds).

`FeedInfo` carries additive status fields (`LastSuccess`, `LastError`,
`StaleSince`, `Hash`) alongside the legacy `URL`/`Prefixes`/`LastFetch`.

## Callers

`pkg/daemon` (compile-cycle integration), `pkg/grpcapi` (status queries).

## Dependencies

`pkg/config` only.

## Gotchas

- HTTP client timeout is 30 s. Timeouts log a warning but do not stop the
  manager — the next refresh tick retries.
- Multiple feeds can share a server; each feed's path is appended to the
  base URL.
- Default refresh interval is 1 hour; the Junos config can override via
  `update-interval`.
- Feed bodies are parsed line-by-line, one CIDR per line. Invalid lines
  are skipped silently — by design, since feed providers occasionally
  emit comments. A *scanner-level* error (overlong line / read error) is
  NOT skipped: it fails the whole fetch (retain last-good).
- A successful fetch always replaces the snapshot and stamps success, but
  the `onUpdate` recompile fires only when the canonical content hash
  changes — not on every fetch and not merely on a count change.
- **Feed size vs. the dataplane control-socket cap (#2744):** feed prefixes
  are carried inline as CIDR text in the userspace-dp `apply_snapshot`
  (`buildAddressBookTableWithFeeds`, `pkg/dataplane/userspace/policies.go`).
  Feeds are bounded only by the per-line scanner cap above, NOT by a
  total-entry cap, so a very large feed dominates the serialized snapshot
  size. The control socket caps a single request at `MaxControlRequestBytes`
  (64 MiB, in lockstep with the Rust `MAX_CONTROL_REQUEST_BYTES`); at
  ~45 B per IPv6 CIDR that covers ~1.4M prefixes. A snapshot past the cap is
  surfaced as a config error at apply time (Go pre-flight in
  `pkg/dataplane/userspace/process.go`) rather than silently rejected by the
  helper after commit.
