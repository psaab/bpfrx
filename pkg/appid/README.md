# pkg/appid

Application identification runtime. Maps Junos `applications` /
`application-set` definitions to protocol+port tuples for BPF compilation,
and resolves session display names from the dataplane's assigned `app_id`.

## Entry points

- `CatalogNames(cfg *config.Config, includeAll bool) ([]string, error)` — `runtime.go`.
  Returns the list of application names the compiler must lower
  into the `app_id` catalog. `includeAll=false` returns only
  apps referenced by policies; `true` returns every defined app.
  Returns an error if application-set expansion fails — callers must
  handle it.
- `BuildCatalog(cfg *config.Config) (Catalog, error)` — `catalog.go`.
  Returns the ordered application catalog: `Entries` (each carrying
  `AppID` + `(protocol, dst-port-range, src-port-range)` match rule)
  plus `AppNames` (`app_id → name`). The id assignment is in
  lock-step with `pkg/dataplane.compileApplications` (sorted-name
  order, ids from 1), so an `app_id` stamped on a session by the
  dataplane resolves through `ResolveSessionName` to the same name.
  `pkg/dataplane/userspace` ships `Entries` to the Rust dataplane as
  the snapshot `app_catalog` field (#2008 M5); the dataplane stamps
  the matched `app_id` on each new session.
- `ResolveSessionName(appNames map[uint16]string, cfg *config.Config, proto uint8, dstPort uint16, appID uint16) string` —
  `runtime.go`. Lookup order: dataplane `app_id` (authoritative from
  BPF) → exact `(proto, dstPort)` match → narrow built-in fallback
  (`junos-http`, `junos-ssh`, …). When AppID is **enabled** in
  `services.application-identification` and the dataplane has not
  assigned an `app_id` for the session (`appID == 0`), the function
  returns `UNKNOWN` rather than guessing from port heuristics. Used
  for session display in the CLI and gRPC paths. (`pkg/logging`
  resolves app names through its own `EventReader.resolveAppName`,
  and `pkg/flowexport` does not call this function — the wiring
  isn't shared with NetFlow / syslog.)

## Callers

`pkg/cli`, `pkg/dataplane` (compilation), `pkg/dataplane/userspace`
(catalog ship via `BuildCatalog`), `pkg/grpcapi`, `pkg/daemon`.

## Dependencies

`pkg/config` only.

## Gotchas

- The built-in fallback table is intentionally narrow. There is no L7 DPI
  in this package — real identifications come from the dataplane's
  `app_id` field on the session. See PR #1196 for the operator-facing
  contract (`show services application-identification status` plus a
  commit warning that flags policies relying on AppID matches that the
  runtime won't actually evaluate).
- `CatalogNames` calls `config.ExpandApplicationSet` internally to
  flatten `application-set` aliases. Callers don't need to pre-expand.
