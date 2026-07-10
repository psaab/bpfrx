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

## Day-2 reconcile (#5036)

`Manager.Apply` is destructive (`StopAll` first) and is driven by the daemon,
not called once at boot. The daemon constructs the manager **unconditionally**
at startup (`ensureFeedManager`, even with no feed servers) and calls
`reconcileFeeds` on every applied config generation (wired into
`applyConfigLocked`, before the feed-overlay push). `reconcileFeeds` is gated
on a hash of the feed-**server** configuration (`feedsConfigHash`, which
excludes address bindings), so `Apply` re-runs only when the server set
actually changes — a feed **content** refresh (which re-enters `applyConfig`
via the `onUpdate` callback) leaves the hash unchanged and does not restart the
fetchers. Before #5036 the manager was built only if boot-time feed servers
existed and `Apply` was never re-invoked, so a feed server added/removed/edited
after boot was silently ignored until restart (a deny policy bound to a
day-2-added feed armed with zero prefixes — fail-open).

## Refresh correctness & fail-safe behavior (#2050)

A fetch is treated as **successful** only when the transport read completes
without error **and** the parsed set is non-empty. On any failure the manager
applies a *retain-last-good* policy rather than installing a partial/empty set:

- **scanner errors fail the fetch.** The body is scanned with a raised
  per-line cap (`maxLineBytes`, 1 MiB); an overlong line (`bufio.ErrTooLong`)
  or a mid-stream read error returns an error. The whole read fails — a
  truncated set is never installed. `scanner.Err()` is checked after the loop.
- **body-size + entry caps bound the fetch (#3934).** The response body is
  read through an `io.LimitReader` capped at `maxFeedBodyBytes` (32 MiB) and the
  parsed set is capped at `maxFeedPrefixes` (1,048,576 entries). A body larger
  than the size cap, or one producing more than the entry cap, fails the whole
  fetch (retain last-good) rather than buffering an arbitrarily large body into
  memory or installing a partial-but-huge set. This closes a remote OOM DoS: a
  feed server (or a MITM on a plaintext-http feed) returning a huge/infinite
  body cannot exhaust daemon memory. The size cap sits well under the 64 MiB
  userspace-dp control-request cap (`MaxControlRequestBytes`, #2744) so a single
  feed cannot dominate the apply snapshot. The 30 s client timeout
  (`httpClientTimeout`) bounds a slow-loris server that dribbles bytes.
- **plaintext-http feeds are warned (#3934).** A feed URL using `http://`
  (no transport integrity — a MITM can substitute the body) logs a one-time
  `slog.Warn` at `Apply`. `https` is strongly preferred for any feed source.
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
- **mixed valid/invalid bodies are observably degraded (#2993).** A body that
  mixes valid prefixes with malformed lines still installs the valid prefixes
  (a clean body is bit-identical to before), but the skipped invalid lines are
  no longer *silent*: `parseFeed` counts every malformed (non-comment, non-CIDR,
  non-IP) line and keeps a bounded verbatim sample (`maxInvalidSample`, 5).
  `FeedInfo` surfaces `InvalidLines`, `InvalidSample`, and `Degraded`
  (`InvalidLines > 0`); `show security dynamic-address` prints a `DEGRADED`
  line. A degraded install logs one `slog.Warn` on the content change (not every
  tick). This is **skip-with-count + degraded status**, not all-or-nothing: a
  provider bug that mangles one line of a denylist still enforces the rest, but
  the operator can see (and alarm on) that the installed set differs from the
  published feed instead of it reporting a clean success. The markers are
  cleared when a later clean body installs, and on a `hold-interval`
  drop-to-empty.

`FeedInfo` carries additive status fields (`LastSuccess`, `LastError`,
`StaleSince`, `Hash`) alongside the legacy `URL`/`Prefixes`/`LastFetch`.

## Callers

`pkg/daemon` (compile-cycle integration), `pkg/grpcapi` (status queries).

## Dependencies

`pkg/config` only.

## Gotchas

- HTTP client timeout is 30 s (`httpClientTimeout`, slow-loris protection).
  Timeouts log a warning but do not stop the manager — the next refresh tick
  retries.
- Multiple feeds can share a server; each feed's path is appended to the
  base URL.
- Default refresh interval is 1 hour; the Junos config can override via
  `update-interval`.
- Feed bodies are parsed line-by-line, one CIDR per line. Comment lines
  (`#`, `//`) and blanks are skipped silently. A malformed non-comment line
  is skipped but **counted** (`InvalidLines`/`InvalidSample`, marks the feed
  `Degraded`, #2993) — it is no longer a silent drop. A *scanner-level* error
  (overlong line / read error) is NOT skipped: it fails the whole fetch
  (retain last-good).
- A successful fetch always replaces the snapshot and stamps success, but
  the `onUpdate` recompile fires only when the canonical content hash
  changes — not on every fetch and not merely on a count change.
- **Feed size vs. the dataplane control-socket cap (#2744 / #3934):** feed
  prefixes are carried inline as CIDR text in the userspace-dp `apply_snapshot`
  (`buildAddressBookTableWithFeeds`, `pkg/dataplane/userspace/policies.go`).
  Each feed is now bounded at fetch time by BOTH a total body-size cap
  (`maxFeedBodyBytes`, 32 MiB) and a total-entry cap (`maxFeedPrefixes`,
  1,048,576) (#3934), so a single feed can no longer buffer an unbounded body
  or dominate the serialized snapshot. The control socket separately caps a
  single request at `MaxControlRequestBytes` (64 MiB, in lockstep with the Rust
  `MAX_CONTROL_REQUEST_BYTES`); at ~45 B per IPv6 CIDR that covers ~1.4M
  prefixes. The per-feed 32 MiB body cap keeps a single feed's serialized
  contribution comfortably under that ceiling. A snapshot past the control cap
  is still surfaced as a config error at apply time (Go pre-flight in
  `pkg/dataplane/userspace/process.go`) rather than silently rejected by the
  helper after commit.
