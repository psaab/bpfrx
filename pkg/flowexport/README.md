# pkg/flowexport

NetFlow v9 and IPFIX (NetFlow v10) exporters. Both ship session-close
events to remote collectors with per-zone direction filters and 1-in-N
session sampling. Wired off `pkg/logging.EventReader` SESSION_CLOSE
events in `pkg/daemon/daemon_flowexport.go`, not the conntrack GC
delete callback. No per-packet sampling path.

Flow record *assembly* is **entirely control-plane**: the userspace
dataplane does NOT build/format NetFlow/IPFIX records — flow records are
assembled in this package from SESSION_CLOSE `logging.EventRecord`s. The
Rust dataplane carried a dead `FlowExporter` and a write-only
`flow_export_config` field that emitted nothing; both were removed in
#2130. (The Go→Rust `flow_export` snapshot wire field is retained as
reserved/ignored to preserve the #1977 decode-safety tests.)

**#2460 — the SESSION_CLOSE events ARE now produced in userspace mode.**
Before #2460, the userspace dataplane emitted a session close ONLY as a
minimal `MSG_SESSION_CLOSE` (type 2) HA session-sync delta on the
SessionDeltaInfo channel (`handleEventStreamDelta`), never as an RT_FLOW
`SESSION_CLOSE` event on the raw dataplane-event channel that these
exporters consume — so the NetFlow/IPFIX session-close callbacks never
fired and userspace session-close export was silently non-functional
(per-packet deny/screen/filter RT_FLOW export already worked). The helper
now emits, on every session close, an ADDITIONAL RT_FLOW SESSION_CLOSE
frame (`EventFrameTypeSessionClose`, type 14) carrying the canonical
136-byte `dataplane.Event` payload on the raw channel. The daemon decodes
it into a `Type:"SESSION_CLOSE"` `EventRecord` via
`eventReader.ProcessRawEvent`, which fires the callbacks below. The type-2
HA delta is unchanged and emitted as a 1:1 pair with the type-14 frame —
the RT_FLOW frame is additive, not a replacement, so HA session sync is
unaffected. The record carries the real 5-tuple, NAT translated tuple,
zones, and protocol; the byte/packet volume counters are 0 because the
AF_XDP forwarding path does not yet maintain per-session accounting — that
is the follow-up tracked in **#2501**.

**#2465 — the exported flow StartTime is now the real session-creation
time, not a packet-count guess.** Before #2465 the NetFlow v9 / IPFIX
session-close exporters set the flow `StartTime` to
`EndTime - estimateSessionDuration(packet_count)` — a heuristic
(100ms·pkts for TCP, 50ms·pkts otherwise) that systematically mis-timed
flows (long idle sessions exported as very short; high-rate bursts
exported as long), degrading billing / audit / DDoS-reconstruction /
duration analytics. The SESSION_CLOSE RT_FLOW frame now carries the
session's real creation instant in the `created` wire field (offset 108,
absolute Unix **seconds**, little-endian u32) and the close instant in
`timestamp_ns` (offset 0, absolute Unix **nanoseconds**, little-endian
u64). The dataplane stamps the creation instant once at session install
(monotonic `CLOCK_MONOTONIC`), and the helper converts it to wall-clock
at emit time. The Go decoder surfaces `created` as
`logging.EventRecord.Created`; `flowStartTime` (manager.go) sets
`StartTime = time.Unix(Created, 0)` directly when it is non-zero (clamped
to the EndTime on clock skew). `estimateSessionDuration` is retained ONLY
as the fallback when `Created == 0` — an old-format frame, or a
synthesized close from a path that carried no creation instant (the
explicit clear-session / NAT-remap delete glue and the HA tunnel-remap
purge, which do not have the originating entry in hand). Each fallback
bumps a per-exporter `EstimatedDurations()` counter so operators can see
how often the heuristic is still in play. The byte/packet **volume**
counters remain 0 pending #2501 — only the timing is now real.

**#2853 — the flow StartTime keeps MILLISECOND resolution.** #2465's
`created` field is integer Unix **seconds** (offset 108, u32), so every
flow opened in the same wall-clock second exported the same StartTime —
up to ~1000ms of error for short flows (DNS, single HTTP requests),
flattening IPFIX `flowStartMilliseconds` / `flowStartMicroseconds` and
making the data unusable for micro-burst analysis or sub-second billing.
The SESSION_CLOSE RT_FLOW frame now ALSO carries the creation instant's
sub-second **nanosecond** remainder (0..=999,999,999) in the
close-unused `policy_id` slot (offset 44, little-endian u32). The Go
decoder surfaces it as `logging.EventRecord.CreatedNanos` (and zeroes
`PolicyID`, since a close never carried a real policy id, so the
close-record policy-name resolution is unchanged); `flowStartTime`
combines both as `time.Unix(Created, CreatedNanos)`. The exported
`flowStartMilliseconds` (`StartTime.UnixMilli()`) and NetFlow
`uptimeMs` now reflect the true sub-second start. The fallback path
(`Created == 0`) is unchanged.

**#2526 — the exporters now carry the post-NAT (translated) tuple.**
Before #2526 both the NetFlow v9 and IPFIX templates/encoders exported
only the pre-NAT 5-tuple, so a collector saw the private endpoint of a
NAT'd flow but never the public translated address/port — no NAT
correlation for security audit / compliance / forensics. The
SESSION_CLOSE `logging.EventRecord` already carried the translated tuple
(`NATSrcAddr`/`NATDstAddr`); the daemon callbacks
(`daemon_flowexport.go`) now parse it into `SessionCloseData.NAT{Src,Dst}{IP,Port}`
and `ExportSessionClose` resolves the post-NAT tuple (`resolvePostNAT`,
`manager.go`) onto `FlowRecord.NAT{Src,Dst}{IP,Port}`.

The exported elements (IANA "IPFIX Entities" registry, RFC 5103 /
RFC 8158) are appended LAST in every template:

| Element | ID | Type | Bytes | Family |
|---|---|---|---|---|
| postNATSourceIPv4Address | 225 | ipv4Address | 4 | v4 |
| postNATDestinationIPv4Address | 226 | ipv4Address | 4 | v4 |
| postNAPTSourceTransportPort | 227 | unsigned16 | 2 | both |
| postNAPTDestinationTransportPort | 228 | unsigned16 | 2 | both |
| postNATSourceIPv6Address | 281 | ipv6Address | 16 | v6 |
| postNATDestinationIPv6Address | 282 | ipv6Address | 16 | v6 |

NetFlow v9 reuses the same IANA element type IDs in its template
FlowSet. With the #2613 drop and the #2749 re-add of `ingressInterface`
(IE 10, 4B, below) the IPv4 IPFIX record is 61 bytes (45 pre-NAT body +
4 ingressInterface + 12 post-NAT) and the IPv6 record is 109 bytes (69 +
4 + 36); the NetFlow v9 record sizes derive from the template via
`recordSize` (4-byte padded), so they track the template automatically.
An init-time
assertion in `ipfix.go` pins `ipfixRecordSizeV4/V6` to the sum of their
template field lengths so a template/encoder length drift fails the
process at startup (a mismatch would corrupt every record). Golden
byte-level encoder tests (`postnat_test.go`) pin the field offsets/values
and the template/encoder length agreement for v4 and v6 on both exporters.

**Zero-NAT decision: post == pre (Junos/vSRX behaviour).** The post-NAT
elements are non-optional template fields, so every record of a template
MUST carry them — they cannot be conditionally omitted per-record without
a second template. When a flow was not translated (the dataplane reports
the unspecified address `0.0.0.0` / `::` and port 0 for that half), the
converter copies the pre-NAT value into the post-NAT field so the
collector always receives a usable tuple, matching Junos/vSRX (which
always emits the post-NAT fields). The address and port halves fall back
independently, so an address-only or port-only translation reports the
translated half and the pre-NAT other half. A collector distinguishes a
NAT'd flow from a non-NAT'd flow by post != pre. Volume counters remain 0
pending #2501.

**#2613 — stop advertising fields the close path cannot populate.** The
templates previously advertised `ipClassOfService`/SrcTos (5),
`tcpControlBits`/TCPFlags (6), `flowDirection`/Direction (61),
`ingressInterface`/InputSNMP (10) and `egressInterface`/OutputSNMP (14),
but the SESSION_CLOSE builder (`ExportSessionClose`) never set
`FlowRecord.{TOS,TCPFlags,Direction,InIf,OutIf}` — and there is nowhere
to set them from. The dataplane→Go SESSION_CLOSE RT_FLOW frame is a fixed
136-byte wire shape (`pkg/logging/ringbuf.go`) that carries no DSCP/TOS,
no observed TCP flags, no per-flow direction and no egress ifindex, and
the Rust encoder hardcodes the ingress-ifindex slot to 0 on close frames
(`userspace-dp/.../codec.rs::encode_session_close_rt_flow`). So every one
of those IEs reached collectors as an authoritative zero. The five fields
were removed from both NetFlow v9 templates and the IPFIX v4/v6 templates
(and their record encoders / size constants).

**#2749 — `ingressInterface` (IE 10 / IN_SNMP) re-introduced with a real
value.** The remaining four — SrcTos (5), TCPFlags (6), Direction (61)
and `egressInterface`/OutputSNMP (14) — still have no SESSION_CLOSE wire
source and stay dropped (their absence is still pinned by
`dropped_fields_test.go`). But the ingress ifindex IS on the wire: #2615
stamps the closing binding's ifindex into the [128:132] slot of the
136-byte RT_FLOW close frame (the Rust encoder no longer hardcodes 0).
`pkg/logging/ringbuf.go` already read that slot to resolve a human-facing
interface NAME; #2749 also retains the raw numeric value
(`EventRecord.IngressIfindex`), the daemon flow-export callbacks copy it
into `SessionCloseData.InIf`, and `ExportSessionClose` threads it into
`FlowRecord.InIf`. Both exporters re-advertise IE 10 (4 bytes, placed
before the post-NAT trailing block so #2526 offsets are unchanged) and
write the value. This is a **Go-only** change — no wire-format change was
needed because the ifindex was already carried since #2615. Presence
with a real value is pinned by `ingress_interface_test.go`
(`TestNetflowIngressInterfacePopulated` / `TestIPFIXIngressInterfacePopulated`:
template advertises IE 10 AND the encoded record carries the session's
ifindex, not zero). Populating SrcTos/TCPFlags/Direction/`egressInterface`
for real still needs the Rust↔Go wire-format extension (re-lay/extend the
close frame + conntrack-side TCP-flag/TOS stamping + egress-ifindex
tracking on the forwarding path), which remains the deferred scope of
#2749. The `export-extension flow-dir` config knob is still accepted but
no longer adds `flowDirection`; the compiler warns when it is configured
(`compiler_validate_warn.go`), mirroring the `app-id` warn-not-lie
precedent. The remaining fail-on-revert pins live in
`dropped_fields_test.go` (template-absence walk + record-layout golden
that proves the bytes after `protocol` are the real counters, not a
sentinel TOS/flags block).

**#2866 — `srcMask` / `dstMask` populated from the FIB.** The NetFlow v9
templates advertised `srcMask` (IE 9) / `dstMask` (IE 13) and the IPv6
variants (IE 29 / IE 30) and the v9 encoder wrote `FlowRecord.SrcMask` /
`.DstMask`, but `ExportSessionClose` never assigned those members, so
every flow reached collectors with a `/0` mask. (IPFIX did not advertise
the mask IEs at all.) The mask fields are the prefix length of the
routing-table entry that matches the flow's source / destination address
— the same FIB-longest-prefix-match semantics Junos/vSRX export. That
prefix length is NOT on the SESSION_CLOSE wire frame (unlike the deferred
#2749 fields, which need a dataplane wire extension), but it IS cheaply
derivable from the local FIB at export time. `routemask.go` resolves it
with `netlink.RouteGetWithOptions(ip, {FIBMatch:true})` (RTM_F_FIB_MATCH
makes the kernel report the matched FIB entry's prefix, so a default-route
match returns the real `/0` rather than echoing the queried host as a
`/32`), behind a short-TTL cache (`routeMaskCache`, default 10s) so the
per-flow close path does not issue an RTM_GETROUTE syscall per record.
The cache is also size-bounded at `routeMaskCacheMax` (8192) entries: the
TTL bounds the syscall *rate* but not the footprint, and on an
internet-facing firewall the destination-IP cardinality is effectively
unbounded, so an uncapped map would grow for the daemon's lifetime (a
slow leak). On insert at the cap, `evictLocked` first purges expired
entries (cheap, usually recovers headroom because TTLs are short) and, if
still at the cap, clears the map — a simple hard ceiling rather than
per-entry LRU bookkeeping for a syscall-amortization cache. The bound is
pinned by `TestRouteMaskCacheBounded` (inserting >cap distinct keys keeps
`len(entries)` <= cap; removing the bound flips it RED).
`Exporter` / `IPFIXExporter` carry a `MaskResolver` func (defaulted by
`NewExporter`/`NewIPFIXExporter` to `NewRouteMaskResolver`; nil on a
zero-value exporter → masks stay 0, the pre-#2866 behaviour and the test
seam). `ExportSessionClose` calls it for the pre-NAT src/dst IP. IPFIX
also gains the four mask IEs (9/13/29/30, 1 byte each), placed in the same
record slot as the v9 masks (after `flowEnd`, before `ingressInterface`)
so the two protocols keep a parallel layout; the IPFIX record sizes grow
by 2 bytes (v4 61→63, v6 109→111). Presence-with-real-value is pinned by
`srcmask_dstmask_test.go` (`TestNetflowSrcDstMaskPopulated` /
`TestIPFIXSrcDstMaskPopulated`: the template advertises the mask IE AND
the encoded record carries the resolved prefix length, not zero — a
deterministic injected resolver keeps the test free of a kernel-FIB
dependency).

## File layout

The package is split by responsibility (#1988):

- `manager.go` — resolved export config (`ExportConfig`,
  `CollectorConfig`, `SamplingDir`), the sampling scheduler
  (`ShouldExport`), the shared `FlowRecord`/`SessionCloseData` shapes,
  and the `BuildExportConfig` / `BuildIPFIXExportConfig` /
  `BuildSamplingZones` config resolvers.
- `netflow.go` — NetFlow v9 template/record encoding and the `Exporter`
  that drives it.
- `ipfix.go` — IPFIX (v10) template/record encoding and the
  `IPFIXExporter` that drives it.
- `routemask.go` — the `MaskResolver` func type and
  `NewRouteMaskResolver` (#2866): a TTL-cached FIB longest-prefix-match
  lookup that resolves a flow's `srcMask`/`dstMask` (route prefix length)
  at export time, plus the `resolveMasks` helper both exporters call.
- `transport.go` — shared collector connection management
  (`collectorConns`: dial / fan-out write / close) and the per-family
  batch accumulator (`flowBatch`) used by both exporters. `dialCollectors`
  surfaces any `SourceAddress`/destination resolve error (a misconfigured
  source-address is never silently dropped to an OS-chosen bind) and, on
  any mid-loop resolve or dial failure, closes the connections opened
  earlier in the loop before returning — no descriptor leak on partial
  failure.

## Header sequence number — v9 vs IPFIX (#2609)

The two protocols define the header sequence number differently, and the
exporters MUST NOT share the same rule:

- **NetFlow v9 (RFC 3954)** — the header `SeqNumber` counts **export
  packets**. Every datagram, *including* a template-only refresh,
  advances the counter. `Exporter.sendTemplates()` therefore reads and
  post-increments `e.seq` exactly like a data send.
- **IPFIX / NetFlow v10 (RFC 7011 §3.1, §10.3.2)** — the header
  `SequenceNumber` is the **cumulative count of Data Records** sent in
  all prior Messages for this Observation Domain (the sequence of the
  *next* Data Record). A Message that carries only (Options) Template
  Sets contains no Data Records, so `IPFIXExporter.sendTemplates()`
  carries the **current** cumulative value WITHOUT advancing it. Emitting
  a hardcoded `0` on every periodic refresh (the pre-#2609 bug) rewound
  the header sequence, which loss/sequence-tracking collectors (pmacct,
  Elastiflow) read as packet loss or an exporter restart. Pinned by
  `TestIPFIXTemplateRefreshPreservesSequenceNumber` (fail-on-revert).

## Per-collector write-health (#2464)

Flow export is forensics/compliance data; a collector going unreachable
used to be invisible — every failed UDP write in `writeAll` was
`slog.Debug`-logged and dropped while the exporter kept counting
"exported", so an operator got no warning that records were being lost.
Each `collectorConn` now tracks `WriteAttempts`, `WriteFailures`,
`LastError`/`LastErrorTime`, `LastFailureTime`, `LastSuccessTime`, and a
`Healthy` flag (atomic counters + a mutex-guarded snapshot, race-safe
against a concurrent status reader). The export DATA path is unchanged:
writes are still attempted to every collector and failures are still
non-fatal — this is additive observability.

`writeAll` emits a state-change log ONLY on the
unhealthy↔healthy edge (a `slog.Warn` when a healthy collector first
fails, a `slog.Info` when it recovers), never once per failed write —
`writeAll` runs on the 100ms batch ticker plus each template refresh, so
a per-write warn would flood the journal (project logging rule: no
Warn/Info in a per-tick loop). The per-write `slog.Debug` line is kept
for deep tracing.

The snapshot is surfaced through `Exporter.CollectorHealth()` /
`IPFIXExporter.CollectorHealth()` → `Daemon.FlowCollectorHealth()`
(annotated with protocol / instance / template via
`ExporterCollectorHealth`) on four surfaces:
- **Prometheus** — `xpf_flow_export_collector_{write_attempts_total,
  write_failures_total,healthy,last_success_timestamp_seconds,
  last_failure_timestamp_seconds}`, labeled `{protocol,collector}`
  (emitted before the dataplane gate — exporters are control-plane).
- **REST** — `GET /api/v1/services/flow-exporters`.
- **gRPC / CLI show** — `show flow-monitoring statistics` (gRPC ShowText
  topic `flow-monitoring-statistics`; both the remote `cli` binary and
  the in-daemon interactive CLI).

## Entry points

NetFlow v9:
- `Exporter` — `netflow.go`.
- `NewExporter(cfg *ExportConfig) (*Exporter, error)` — `netflow.go`.
  Takes `*ExportConfig` (never a value copy): `ExportConfig` embeds the
  live 1-in-N `sampleCounter` (`atomic.Uint64`), and copying it would
  fork the counter (a go-vet "copies lock value" failure) — see #2224.
- `Run(ctx context.Context)` — `netflow.go`. Main export loop.
- `Exporter.ExportSessionClose(rec, evt)` — emit one record.

IPFIX:
- `IPFIXExporter` — `ipfix.go`.
- `NewIPFIXExporter(cfg *ExportConfig) (*IPFIXExporter, error)` — `ipfix.go`.
  Also takes `*ExportConfig` (never a value copy) for the same #2224
  reason as `NewExporter`.
- `IPFIXExporter.Run(ctx context.Context)` — `ipfix.go`.
- `IPFIXExporter.ExportSessionClose(rec, evt)` — emit one record.

Shared:
- `ExportConfig` — `manager.go`. Resolved per-template-group config: the
  collectors that referenced one template, that template's timeouts /
  field options, plus the family-shared sampling state (#2461 — see
  "Per-flow-server template binding" below).
- `ResolveV9TemplateGroups(...) []*ExportConfig` /
  `ResolveIPFIXTemplateGroups(...)` — `manager.go`. The per-template-group
  resolvers the daemon uses (#2461).
- `BuildExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig` — `manager.go`.
  Returns nil (no v9 exporter) unless BOTH `forwarding-options sampling`
  has a flow-server AND `services flow-monitoring version9` is configured
  (#2129). This mirrors the `BuildIPFIXExportConfig` `version-ipfix` gate.
  Before #2129 the v9 exporter started on sampling alone, emitting an
  unrequested v9 stream to an IPFIX-only operator's collector. Its
  collector set now contains ONLY the flow-servers bound to v9 (#2136 —
  see "Per-flow-server export-version binding" below).
- `BuildIPFIXExportConfig(...)` / `BuildSamplingZones(...)` — `manager.go`.
- `SamplingDir` — `manager.go`. Direction enum.
- `SessionCloseData` — `manager.go`. Wire shape built from
  `logging.EventReader` SESSION_CLOSE records (in
  `pkg/daemon/daemon_flow.go`).

## Per-flow-server export-version binding (#2136)

Junos binds each `flow-server` to exactly one export version + template.
`BuildExportConfig` (v9) and `BuildIPFIXExportConfig` (IPFIX) therefore
no longer flatten every flow-server into both collector sets — they each
take only the flow-servers resolved to their own version, via the shared
`collectVersionCollectors` / `resolveFlowServerVersion` helpers in
`manager.go`. A given collector address:port appears in at most one of
the two sets, so it never receives both a NetFlow v9 (version 9) AND an
IPFIX (v10) datagram for the same flow.

Before #2136 both builders returned every flow-server, and the daemon
started both exporters against the same collector socket — each with its
own SESSION_CLOSE callback and its own independent 1-in-N counter — so a
flow-server reachable under both global version stanzas was exported
twice with mismatched sampling.

Resolution order for one flow-server (`resolveFlowServerVersion`):

1. **Explicit per-server selector wins.** A flow-server configured with
   `version9 { template … }` / `version9-template …` binds to v9; one
   configured with `version-ipfix { template … }` /
   `version-ipfix-template …` binds to IPFIX (parsed by
   `compiler_services.go` into `FlowServer.Version`). It is then bound to
   that version *only if* the matching global `services flow-monitoring`
   stanza exists (the global stanza supplies template timeouts/fields); a
   server bound to a version whose global stanza is absent exports
   nothing and does NOT silently fall back to the other version.
2. **Unbound server inherits the single configured global version.**
3. **Unbound server with BOTH global versions configured → IPFIX**
   (documented precedence). IPFIX (v10) is the IETF-standard superset of
   NetFlow v9, so an operator who enabled both but did not pin the
   collector gets the modern protocol — and, critically, exactly ONE
   datagram stream rather than the pre-#2136 double-export. To send v9 to
   such a collector, pin it explicitly with a per-server `version9`
   selector.

## Per-flow-server template binding (#2461)

After #2136 routes each flow-server to the right *version*, #2461 routes
it to the right *template*. Junos binds each flow-server to one template
under its version; before #2461 the resolver ignored that reference
entirely — it built ONE export config from the FIRST Go-map-iteration
template and broadcast it (timeouts, `flow-dir` export-extension) to every
collector of the version. A collector that asked for a specific template
silently received whichever the map yielded first, and that choice flipped
across process restarts (map order is not an operator contract).

The resolver now groups collectors by the template they referenced and
emits one `*ExportConfig` per group:

- **`ResolveV9TemplateGroups` / `ResolveIPFIXTemplateGroups`** (`manager.go`)
  return `[]*ExportConfig`, one per referenced template. The group key is
  `(version, template_name)`; **source-address is a deterministic sort
  tiebreak, NOT part of the grouping key** — collectors that share a
  template but pin different source-addresses share ONE group and each
  still receives its own source-pinned UDP connection (via
  `dialCollectors`). Each group carries the timeouts / `V9TemplateOpts` of
  the template its collectors referenced. A collector that referenced no
  template lands in the default (`TemplateName == ""`) group, which inherits
  the lone template's parameters when exactly one is configured (the common
  single-template case — unchanged) and otherwise the built-in defaults.
- **Determinism.** Groups are sorted by template name and each group's
  collectors by address, so process restarts produce identical exporter
  wiring — the map-iteration nondeterminism is gone.
- **Validation.** A flow-server referencing an UNDEFINED template is
  hard-rejected at commit / commit-check by
  `validateFlowServerTemplateReferencesStrict` (`pkg/config`). The tolerant
  load / peer-sync path downgrades it to a warning (#1960) and the resolver
  DROPS that group, so a leniently-loaded bad config exports nothing for
  that collector rather than the wrong template.
- **Per-instance sampling.** 1-in-N sampling is a sampling-INSTANCE
  property (#2462). The template groups of ONE instance share that
  instance's `sampleCounter` (a pointer); two different instances each get
  their own counter. The daemon evaluates `ShouldExport` exactly once per
  instance per SESSION_CLOSE and fans the record out to that instance's
  groups.
- `BuildExportConfig` / `BuildIPFIXExportConfig` (singular) are retained
  for single-aggregate callers and now return the first resolved group.

## Multi-sampling-instance isolation (#2462)

`forwarding-options` can define several `sampling instance <name>` blocks,
each with its own input rate, families, and flow-servers. Before #2462 the
resolver flattened EVERY instance into one global export policy:
`collectVersionCollectors` merged all instances' flow-servers into one
collector set, `samplingRate()` returned the first-nonzero `InputRate` in
Go map order, and one `sampleCounter` was shared by the whole family. Flows
from instance A exported to instance B's collectors and the effective rate
depended on map-iteration order.

The resolver now treats each instance as a first-class export policy. The
grouping key is `(instance, version, template)`:

- **Own collectors.** `collectInstanceVersionCollectors` walks ONE
  instance's flow-servers, so instance A's collectors never receive
  instance B's flows.
- **Own rate.** Each instance's `ExportConfig.SamplingRate` is its own
  `InputRate` — the first-nonzero map-order global rate is gone.
- **Own 1-in-N counter.** Each instance gets a distinct `sampleCounter`, so
  1-in-N is independent per instance (and still shared across that
  instance's template groups, the #2461 invariant scoped to one instance).
- **Attribution by family.** The only per-flow instance selector available
  is the address family: the interface `family inet { sampling { input; } }`
  stanza is a plain boolean and there is **no per-interface
  sampling-instance selector** in the config model. So `ServesInet` /
  `ServesInet6` record which families an instance configured a collector
  for, and `ExportConfig.ServesFamily(isIPv6)` gates a record — an
  inet-only instance never exports an IPv6 flow. The daemon callback walks
  the contiguous per-instance run of groups, applies the family gate + the
  single per-instance sampling decision, then fans to that instance's
  groups.
- **Determinism.** Instances are resolved in lexical name order
  (`sortedInstanceNames`), so restarts produce identical wiring.

### Supported vs rejected matrix

| Configuration | Result |
|---|---|
| Single sampling instance (any rate / families / collectors) | **Supported** — unchanged from pre-#2462 (the common case) |
| Two instances, different families (A: inet, B: inet6) | **Supported** — attributed by flow family |
| Two instances, different export versions (A: version9, B: version-ipfix) on the same family | **Supported** — distinct datagram streams |
| Two instances both exporting the same `(version, family)` pair | **Rejected at commit** — no per-flow instance selector exists, so the runtime cannot attribute a flow to one instance |

The reject is `validateSamplingInstanceConflictsStrict` (`pkg/config`):
strict on commit / commit-check (hard reject so the operator sees it),
lenient on load / peer-sync (downgraded to a warning via
`opts.lenientSamplingInstanceConflicts` so an already-persisted or
peer-synced config still boots — #1960; the resolver still emits both
instances' independent `ExportConfig`s, duplicating eligible flows to both
rather than bricking the load).

### Daemon wiring (one exporter per (instance, template) group)

`reconcileFlowExporters` starts **N exporters per family** — one per
`(instance, template)` group — instead of a single exporter.
`d.flowExporters` / `d.ipfixExporters` are slices; the atomic `flowBundle`
/ `ipfixBundlePtr` carry the group set; the once-registered session-close
callback walks each contiguous per-instance run, applies the family gate +
the single per-instance sampling decision, and exports to that instance's
groups. The per-family config-hash gate, transient-create-failure retry (no
hash recorded), and shutdown teardown all operate over the slice.

## Callers

`pkg/daemon/daemon_flowexport.go::reconcileFlowExporters` owns the
exporter lifecycle (#2075). It runs at boot (after the EventReader
exists) AND on every config commit from `applyConfigLocked`, and is
config-hash-gated per family so an unrelated commit never bounces a
healthy exporter (preserving its template-refresh cadence and 1-in-N
sampling counter). A commit that changes `forwarding-options sampling`
/ `services flow-monitoring` — or that ADDS / REMOVES flow export
entirely — therefore takes effect immediately, without a daemon
restart (before #2075 the exporters were started only at boot and
stopped only at shutdown).

Because the `EventReader` callback list is append-only (clear-all only,
no per-callback removal), the reconcile registers ONE stable
indirection callback per family exactly once
(`flowCBOnce`/`ipfixCBOnce`) that reads the live `(exporter, config)`
pair lock-free from an `atomic.Pointer` bundle; reconcile swaps the
bundle atomically. The callback calls `Exporter.ExportSessionClose()`
(NetFlow v9) / `IPFIXExporter.ExportSessionClose()` (IPFIX) from the
`logging.EventReader` SESSION_CLOSE event. The resolved `*ExportConfig`
is shared by pointer everywhere — in the bundle, by the callback's
`ShouldExport`, AND inside the exporter — so there is exactly ONE live
1-in-N `sampleCounter` (`atomic.Uint64`) per sampling INSTANCE (#2462;
shared across that instance's template groups, distinct between
instances). `ExportConfig` is
never copied by value: doing so would fork the atomic counter (a go-vet
"copies lock value" failure) and silently re-seed the modulo cadence the
moment any caller sampled off the copy (#2224).
`stopFlowExporter`/`stopIPFIXExporter` drain the exporter at shutdown.

## Dependencies

`pkg/config`, `pkg/logging`.

## Gotchas

- 1-in-N sampling uses a monotonic counter on `ExportConfig`. With small
  N a burst of close events can sample several consecutive flows; that's
  expected.
- NetFlow v9 templates refresh every 60 s. If a collector restarts and
  misses a refresh it sees opaque records until the next cycle —
  configure the collector to handle template re-resolution.
- Two batches are maintained inside `flowBatch` (`v4` and `v6`, split
  by family, not by zone — `transport.go`). Both flush on a 100 ms
  ticker or on shutdown.
- `BuildSamplingZones` resolves a zone's interface references
  (`parseIfaceRef`, `manager.go`) into (physical-name, unit) pairs to
  decide which zones have sampling enabled. The unit suffix is parsed
  strictly (#2463): a bare reference with no dot is the implicit unit 0
  (a legitimate config form), but a reference WITH a dot must carry a
  clean unsigned decimal unit after the FINAL dot — `strconv.Atoi`, no
  sign, space, empty suffix, or trailing junk. A malformed reference
  (`ge-0/0/0.1abc2`, `ge-0/0/0.foo`, `ge-0/0/0.-1`, `ge-0/0/0.`) is
  WARNED once and SKIPPED, not silently coerced. The previous
  digit-accumulation scan accepted them all — `1abc2` became unit 12,
  `foo` and an empty suffix became unit 0, `-1` became unit 1 — so
  sampling could be enabled on the wrong unit or silently on unit 0,
  diverging from the operator's interface list.
- `ExportSessionClose` builds the flow record synchronously from the
  event-reader callback. The export goroutine (started in `Run(ctx)`)
  is what actually transmits and refreshes templates; record assembly
  itself isn't offloaded.
- Collector destination and source-bind addresses are built with
  `net.JoinHostPort` (`manager.go` / `transport.go`), so an IPv6
  flow-server or `source-address` is bracketed (`[2001:db8::9]:4739`)
  and parses under `net.ResolveUDPAddr` / `net.Dial`. A plain
  `"%s:%d"` / `addr+":0"` left an IPv6 literal unbracketed and
  unparseable, so IPv6 collectors silently never dialed (#2183). IPv4
  addresses are unaffected.
