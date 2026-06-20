# Application Identification (AppID) on xpf

This is the authoritative reference for what
`set services application-identification` actually does on
xpf today, and what it explicitly does NOT do, vs the Junos
vSRX feature of the same name. (#653)

## TL;DR

- xpf parses `services application-identification` as a
  Junos-compatible config knob.
- The runtime does **port + protocol matching only** against
  the configured `applications` catalog — *not* L7 deep packet
  inspection, *not* signature-based identification, *not*
  payload heuristics.
- The knob's only runtime effect is to switch the "session app
  name when no port match exists" behaviour from "guess from
  built-in port heuristic" to **"`UNKNOWN` (honest)"**.
- L7 features that depend on real AppID — dynamic-application
  policies, AppTrack, AppFW, AppQoS — are **not implemented**.

## Live status surface

```
> show services application-identification status
```

That command surfaces the contract documented here at runtime
so an operator looking at a session that says `junos-http`
knows it came from a `(proto=6, dst-port=80)` lookup, not L7
inspection.

A commit-time warning fires if `services
application-identification` is enabled, telling the operator
upfront what they're getting and not getting.

## How session app names are assigned today

1. **Compile time**: `pkg/appid/runtime.go:CatalogNames` builds
   the application catalog name set from policies + the
   predefined junos-* application list + user-defined
   applications. Each name is assigned a `u16 app_id`
   sequentially (from 1, in sorted-name order) — done in
   `pkg/dataplane/compiler.go:compileApplications`
   (`CompileResult.AppNames`, the `app_id → name` map the show
   path consumes) and, in lock-step, in
   `pkg/appid/catalog.go:BuildCatalog`, which also carries each
   application's `(protocol, dst-port-range, src-port-range)`
   match rule. A Go test
   (`pkg/dataplane/appid_catalog_parity_test.go`) pins that the
   two id assignments are identical, so an id stamped by the
   dataplane always resolves to the right name.
2. **Snapshot ship**: `buildAppCatalogSnapshot`
   (`pkg/dataplane/userspace/flow.go`) emits the catalog as the
   `app_catalog` field of the config snapshot — an ordered list
   of `(app_id u16, protocol u8, dst_port_low/high u16,
   src_port_low/high u16)`. It is an additive wire field with
   `omitempty` on the Go side and `#[serde(default)]` on the
   Rust side (`AppCatalogEntry` in
   `userspace-dp/src/protocol/security.rs`), so an old snapshot
   without it decodes to an empty catalog (HA/upgrade-safe).
3. **Session create (userspace dataplane)**: the snapshot
   catalog is compiled into `ForwardingState.app_catalog`
   (`AppCatalog` in `userspace-dp/src/policy.rs`). When a worker
   creates a new session (`poll_descriptor`), it calls
   `AppCatalog::lookup(protocol, src_port, dst_port)` and the
   resolved `app_id` (0 = no match) is stamped on the conntrack
   session value in `publish_conntrack.rs` (previously hardcoded
   to 0). The well-known service port is probed on both the src
   and dst slot so the forward and reverse conntrack entries
   resolve to the same `app_id`. **Note**: only the local
   session-owner stamps `app_id` in the conntrack map (the same
   property as `alg_type`); an HA-synced session on the standby
   peer is not mirrored into the conntrack map, and a session
   re-created locally after failover is re-stamped from the
   catalog (the catalog is shipped to both nodes), so `app_id`
   is re-derived rather than carried on the session-sync wire.
4. **Show output**:
   `pkg/appid/runtime.go:ResolveSessionName` resolves the
   `app_id` back to a name via the `compiler.go` `AppNames`
   map. If `app_id == 0`:
   - When `services application-identification` is **enabled**,
     return `UNKNOWN`.
   - When **disabled**, return a built-in port→name guess
     (`junos-http=80`, `junos-https=443`, `junos-ssh=22`,
     `junos-ftp=21`, etc. — the 15-entry `builtinFallbacks`
     map).

## What's parsed but not implemented

These config paths are accepted at commit time and their
runtime effect is the L3/L4 catalog classification above
(catalog ship + per-session `app_id` stamp + name resolution):

- `services application-identification` — enables catalog
  classification and toggles the show-output `UNKNOWN` vs
  port-guess behaviour for no-match sessions.
- `applications application <name>` — populates the catalog
  for port-based matching; a session matching it is stamped
  with this application's `app_id`.
- `applications application-set` — expands into individual
  applications at compile time. Members may be either
  `application <name>` references or nested
  `application-set <name>` references; `ExpandApplicationSet`
  recurses into nested sets (max depth 3) so a policy matching a
  parent set also matches applications defined only in a nested
  child set. (Before #2068 the compiler silently dropped nested
  `application-set` members, so such a policy under-matched.)

These config paths are accepted with NO runtime effect today
(parse-only):

- `services application-identification application-system-cache`
- `services application-identification download`
- `services application-identification global-offload`
- `services application-identification statistics`
- `applications application <name> signature ...` (custom
  L7 signatures — config schema present, runtime is port-only)

## What is missing vs Junos vSRX

The vSRX feature set under `services
application-identification` includes a full Junos AppID engine:

| Feature | xpf today | Junos vSRX |
|---|---|---|
| Port + protocol matching | ✅ implemented | ✅ |
| L7 DPI signature engine | ❌ not implemented | ✅ identifies 4000+ apps |
| Signature package download | ❌ not supported | ✅ `request services application-identification download` |
| Application System Cache | ❌ not supported | ✅ caches per-flow-tuple results |
| Custom L7 signatures | ❌ not supported (parse-only) | ✅ user-defined byte-pattern matching |
| Dynamic-application policy match | ❌ not implemented | ✅ `match dynamic-application` |
| AppTrack logging | ❌ not implemented | ✅ |
| Application Firewall (AppFW) | ❌ not implemented | ✅ |
| Application QoS (AppQoS) | ❌ not implemented | ✅ |
| Application Policy-Based Routing (APBR) | ❌ not implemented | ✅ |

These are tracked in `docs/feature-gaps.md` under "AppSecure
suite". A real L7 DPI engine is a multi-month effort
(signature compiler, packet-payload state machine, signature
package format, on-the-fly download/auto-update).

## Future direction

If full L7 AppID parity is required, the implementation path
would be:

1. **L7 DPI signature engine** — a packet-payload state
   machine driven by signature definitions. Either home-grown
   or via integration of an existing library (e.g.
   `nDPI`, `libprotoident`).
2. **Signature package format** — Junos uses a binary
   signature package downloaded from a server URL. xpf would
   need a compatible packaging format AND a compiler from
   per-application signature definitions to runtime byte
   patterns.
3. **Application System Cache** — a `(5-tuple, app_id)` cache
   that bypasses L7 inspection for already-classified flows.
4. **Dynamic-application policy match** — wire L7 app_id back
   into the policy lookup path, allowing policies to filter
   on the L7 result (currently policy app match resolves to
   the catalog port-based app_id at session-create time).
5. **AppTrack / AppFW / AppQoS** — per-feature runtime hooks
   that consume the L7 app_id.

This is out of scope for #653; #653 is purely the
contract-clarification piece. If/when this work is taken up,
file a fresh issue with the L7 engine architecture as the
starting point.
