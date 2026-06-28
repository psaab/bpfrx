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

### ICMP type/code constraint in policy matching (#3020)

`junos-ping` and `junos-pingv6` are **echo-request only** — Junos
parity is ICMP type 8 (`junos-ping`) and ICMPv6 type 128
(`junos-pingv6`), each with no code constraint. They are NOT the same
as the all-ICMP aliases `junos-icmp-all` / `junos-icmp6-all`, which
stay unconstrained and match every ICMP/ICMPv6 type/code. Before
#3020 every predefined ICMP application carried only a protocol with
no type/code, so `application junos-ping` matched all ICMP (identical
to `junos-icmp-all`) — a `permit junos-ping` rule also admitted
destination-unreachable, time-exceeded, redirect, neighbor-discovery,
etc.

The constraint is modeled as an optional `(ICMPType, ICMPCode)` on the
predefined application (`pkg/config/predefined.go`), carried on the
policy snapshot's application term (`PolicyApplicationSnapshot.ICMPType`
/ `.ICMPCode`, `pkg/dataplane/userspace/protocol.go`) and the Rust
matcher (`ApplicationMatch.icmp_type` / `.icmp_code`,
`userspace-dp/src/policy.rs`). `nil`/`None` means "no constraint"
(match all of the protocol — what the all-ICMP aliases keep). The wire
field is additive: a pointer + `omitempty` on the Go side and
`#[serde(default, skip_serializing_if = "Option::is_none")]` on the
Rust side, so an old helper missing the field — or an old Go snapshot
omitting it — decodes to `None` and ignores the constraint (match-all,
the pre-#3020 behavior); version skew degrades safely rather than
failing to decode.

The Rust matcher reads the packet's ICMP type/code from the live frame
at policy-evaluation time (`policy_packet_icmp` in
`poll_descriptor`, reusing the fragment/truncation-safe
`term_match_extra_from_frame`). When the type/code is unknown (a
truncated frame or a non-first fragment) an icmp-type-constrained term
fails closed (does not match). Policy evaluation is on the cold path
(session miss), so the per-packet extraction cost is incurred once per
session.

This affects **policy matching** only. The app-identification catalog
(`app_id` session stamping, above) does NOT carry ICMP type/code, so
`junos-ping` and `junos-icmp-all` can still resolve to the same
`app_id` for `show security flow session` display — that is cosmetic
naming, not enforcement.

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
  - **#2142 commit-time validation (fail-closed):** an application
    whose `destination-port` / `source-port` is malformed
    (not a valid numeric port, port range, or known service
    name, out of `1..65535`, or an inverted `low>high`
    range) or whose `protocol` is not a known name, a `junos-*`
    alias, or a `0..255` number is **rejected at commit** —
    *but only when the application is referenced by a security
    policy or a source/destination-NAT rule's `match application`
    (#2187), or when `services application-identification` is
    enabled* (every user application then compiles into the
    catalog). Such a spec was previously only WARNED: commit
    succeeded, the app-id compiler recorded the AppID name and
    then skipped the unparsable port (a never-match AppID), and a
    policy referencing it failed CLOSED on a `permit` rule or fell
    through OPEN on a `deny` rule (`validateApplicationSpecsStrict`,
    `pkg/config/compiler.go`). A source/destination-NAT rule's
    `match application` consumes the same port/proto
    (`appPortsFromSpec`, `pkg/dataplane/userspace/nat.go`), so a
    malformed app referenced only by a NAT rule used to escape both
    this commit gate and the #2124 runtime gate, silently
    never-matching (or over-matching) the NAT term; #2187 closes that
    by collecting NAT-rule references into the same strict walk
    (static NAT carries no `match application`, so only source and
    destination NAT rule-sets are walked). An **unreferenced** application with
    app-id disabled is not matchable by anything, so its malformed
    spec stays a *warning* (the operator can iterate on a
    not-yet-wired application library). This is the
    application-DEFINITION sibling of #2124's policy-app-term
    fail-closed gate. On the tolerant LOAD / peer-sync path the
    error is downgraded to a warning (no-brick, #1960/#2008
    doctrine): an already-persisted/synced config carrying a bad
    referenced app still BOOTS — the dataplane independently skips
    the bad port and the #2124 runtime capability gate
    (`expandUserspacePolicyApplications`) fails the snapshot closed
    (`ForwardingSupported=false`) for a referenced app it cannot
    represent, so the leniently-loaded bad app is inert rather than
    silently mis-matching.
  - **#3109 protocol-less application (fail-closed):** a custom
    application with a port (or any spec) but **no `protocol`** is
    likewise **rejected at commit** under the same referenced-only
    scope. Junos requires `protocol` for a usable application, and the
    userspace matcher keys every term on a protocol *number*
    (`appid.ProtocolNumber`) plus the port — a port is meaningless
    without a protocol. `compileApplications` defaults a protocol-less
    application to the empty protocol (`protocols = []string{""}`),
    which is unrepresentable on **both** sides: the Go capability gate
    (`normalizeUserspaceApplicationProtocol("")` →
    `expandUserspacePolicyApplications` `ok=false`) trips #2124's
    refuse-to-arm and sets `ForwardingSupported=false` for the **whole**
    userspace dataplane — so *one* protocol-less app used to silently
    disable security-policy enforcement for the entire config (a
    system-level fail-OPEN, traffic falling to the kernel slow path) —
    and the Rust snapshot builder hard-errors
    `SnapshotIntegrityError::UnrepresentableApplicationProtocol`
    (`parse_protocol("") => None`). The commit gate
    (`validateApplicationSpecsStrict`) now names the one offending
    application, so a NEW config can no longer reach the dataplane and
    disable everything at apply time. **Caveat — the lenient/HA-sync path
    is NOT yet isolated (#3261):** on the tolerant LOAD / peer-sync path
    the error is downgraded to a warning (no-brick) so an
    already-persisted / older-peer-synced config still BOOTS, but the
    #2124 runtime gate is COARSE — an unrepresentable application still
    makes `deriveUserspaceCapabilities` set `ForwardingSupported=false`
    for the **whole** userspace dataplane, disarming userspace forwarding
    and falling back to the kernel slow path (a system-level fail-OPEN).
    So one protocol-less app on the lenient path STILL disables
    enforcement globally; the strict commit gate is the real fix (it
    stops such an app from ever being committed). Per-policy fail-closed
    isolation of the lenient path is design-sensitive — a clean
    per-policy *drop* is fail-open for deny rules, conflicting with the
    deliberate #2124 whole-snapshot-reject fail-closed family — and is
    tracked in #3261.
  - **#3320 malformed inactivity-timeout / timeout (fail-closed):** an
    application's `inactivity-timeout` / `timeout` leaf used to be an
    untyped schema leaf with no integer validation. A malformed value (a
    unit suffix like `30s`, a non-numeric like `thirty`, a negative, or an
    out-of-range integer) **committed cleanly** and was then **silently
    dropped** by `compileApplications` (the `strconv.Atoi` error was
    ignored), leaving `InactivityTimeout` at its zero default — which the
    userspace serializer (`clampNonNegU32`,
    `pkg/dataplane/userspace/capabilities.go`) treats as "use the global
    per-protocol timeout". The operator's intent to age a sensitive
    application early was silently lost (the per-application #3227 timeout
    above never engaged). It is now **typed and validated** at two layers,
    each with the #1960 strict-commit / lenient-load downgrade: (1) the
    schema typed leaf (`schema_security.go`, `ValueInteger` +
    `ValidateInteger(0, 86400)`) rejects a malformed **top-level** value at
    commit-check for every application via the `SchemaValidate` gate; (2)
    `validateApplicationSpecsStrict` rejects a malformed top-level **or
    inline-`term`** timeout of a **referenced** application (the inline-term
    shape is opaque to the schema walk) using the raw token
    `compileApplications` records in `Application.UnknownTimeouts` (mirroring
    `UnknownActions` / `UnknownFlexMatch`). On the tolerant LOAD / peer-sync
    path both layers downgrade to a warning (no-brick) so an
    already-persisted / older-peer-synced config carrying a bad timeout
    still BOOTS — the dataplane already falls back to the global timeout for
    it. The accepted range is **`0..86400`** seconds, where **`0` is the
    pre-existing inherit-global sentinel** (the dataplane treats
    `InactivityTimeout <= 0` as "use the global per-protocol timeout",
    `clampNonNegU32` / `capabilities.go`; `types_security.go` documents `0 =
    default`), so `inactivity-timeout 0` keeps committing cleanly. Only
    non-numeric, negative, and `>86400` values are rejected.
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
