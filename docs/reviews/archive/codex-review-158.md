# codex review 158 - flowexport NetFlow/IPFIX quota campaign

Date: 2026-07-01
Checkout: /home/ps/git/codex-bpfrx
Base commit: fc6049c057d7
Focus: pkg/flowexport, flow-export daemon lifecycle, collector health, sampling/source-address config, and route-mask attribution.

## Instruction compliance

- Ran `git pull --rebase`: repository was already up to date before this pass.
- Read `/home/ps/git/agy-do-review-audit.txt`.
- Suppressed duplicates by scanning prior `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, and repo issue/history docs for flowexport, NetFlow, IPFIX, collector, template, sampling, source-address, route-mask, and reverse-counter terms.
- Existing duplicate classes intentionally not repeated:
  - #2129/#2136: unintended v9/IPFIX double export.
  - #2461: per-flow-server template grouping.
  - #2462: multi-instance flattening.
  - #2464: collector health visibility exists.
  - #2609: IPFIX template refresh sequence number.
  - #2749/#3270/#2866: ingress/egress ifindex, CoS/TCP flags, flowDirection, and src/dst masks populated.
  - #2526/#2853/#3056: post-NAT tuple, sub-second start time, close policy ID.
- Temporary verification probe added and removed:
  - `pkg/flowexport/codex_audit_158_test.go`
  - Command: `go test ./pkg/flowexport -run TestCodexAudit158FixedExporterIdentityCollidesAcrossTemplateGroups -count=1`
  - Result: passed, proving two distinct template groups can still share source/observation identity and template IDs.
- Worktree returned clean after probe removal.

## Module checklist

1. `pkg/flowexport/manager.go`:
   - Collector/template/version resolvers.
   - Sampling-zone mapping and `ShouldExport`.
   - `FlowRecord` / `SessionCloseData` assembly helpers.
2. `pkg/flowexport/netflow.go`:
   - v9 template IDs, source ID, sequence, batching, counters.
3. `pkg/flowexport/ipfix.go`:
   - IPFIX observation domain ID, template IDs, sequence, batching, counters.
4. `pkg/flowexport/transport.go`:
   - Collector dial, write fan-out, health, batch queue.
5. `pkg/flowexport/routemask.go`:
   - FIB longest-prefix-match cache and netlink lookup.
6. `pkg/daemon/daemon_flowexport.go`:
   - Reconcile stop/start, atomic bundles, callbacks.
7. `pkg/config/compiler_services.go` and `types_system.go`:
   - Sampling source-address representation and compiler precedence.
8. `pkg/config/compiler_validate_strict.go`:
   - Template-reference and sampling-instance conflict gates.
9. `pkg/logging/eventbuf.go` / `ringbuf.go`:
   - SESSION_CLOSE event fields used by exporters.
10. `pkg/api`, `pkg/cli`:
   - REST, CLI, and Prometheus collector health surfaces.

## Module inspection log

- Resolver/template grouping:
  - Positive: current code is deterministic and per-template/per-instance; I did not repeat closed #2461/#2462 findings.
  - New issue: protocol identity was not made per-template/per-instance, so the collector cannot distinguish those now-separated exporters.
- NetFlow encoder:
  - Positive: sequence behavior for v9 matches the package docs.
  - New issue: fixed `SourceID=1` and fixed template IDs survive all grouping.
- IPFIX encoder:
  - Positive: template-only refresh does not advance the sequence.
  - New issue: fixed Observation Domain ID and template IDs collide across exporter groups.
- Daemon lifecycle:
  - Positive: one stable callback avoids callback leaks.
  - New issues: stop/start and create-failure windows can drop records or tear down a healthy old exporter.
- Transport/batching:
  - Positive: failures are surfaced through health.
  - New issues: writes are synchronous without deadlines; queue is unbounded; stats count attempted exports as exported.
- Route masks:
  - Positive: cache exists and is bounded.
  - New issues: lookup is VRF/table blind and synchronous in the event callback.
- Logging/session close:
  - Positive: reverse counters are decoded.
  - New issue: exporter ignores reverse counters for exported volume.
- Operator surfaces:
  - Positive: REST/CLI expose protocol/instance/template.
  - New issue: Prometheus drops instance/template/source labels and can collide.
- Config source-address:
  - Positive: output-level source-address is parsed.
  - New issue: flow-server-nested source-address is collapsed to a family-wide value.

## High confidence findings

### H01 - NetFlow v9 template groups collide on fixed SourceID and fixed template IDs

Severity: High
Confidence: High

Evidence:
- `pkg/daemon/daemon_flowexport.go:205-245` starts one v9 exporter per template group.
- `pkg/flowexport/netflow.go:49-53` hardcodes `templateIDv4 = 256` and `templateIDv6 = 257`.
- `pkg/flowexport/netflow.go:517-528` hardcodes `sourceID: 1` for every exporter and encodes templates from that group's options.
- `pkg/flowexport/netflow.go:637-657` sends templates with `SourceID: e.sourceID`.
- `pkg/flowexport/netflow.go:670-725` sends data with the same fixed template IDs and source ID.

Runtime trace:
1. Operator configures two flow-monitoring v9 templates, one base and one with `export-extension flow-dir`, both pointing to the same collector.
2. Resolver correctly emits two template groups.
3. Daemon starts two v9 exporters.
4. Both exporters send templates from source ID `1`; both define template `256` and `257`.
5. The template bodies differ when flow-dir is enabled, but the collector's `(exporter source, SourceID, templateID)` identity is identical.
6. Collector can parse later data using the wrong schema, or treat the second template refresh as a template redefinition for the first group.

Why this matters:
The grouping fix moved xpf closer to vSRX semantics, but the protocol identity did not follow. Multiple templates to the same collector are an explicitly supported configuration shape in the resolver, yet the wire protocol still looks like one exporter redefining the same template IDs.

Suggested issue:
Allocate stable per-exporter SourceID/template ID space derived from `(protocol, instance, template, family, source-address)` or collapse groups into one protocol exporter that owns a single sequence/source ID and globally unique template IDs.

### H02 - IPFIX template groups collide on fixed Observation Domain ID and fixed template IDs

Severity: High
Confidence: High

Evidence:
- `pkg/daemon/daemon_flowexport.go:289-323` starts one IPFIX exporter per template group.
- `pkg/flowexport/ipfix.go:61-65` hardcodes `ipfixTemplateIDv4 = 256`, `ipfixTemplateIDv6 = 257`.
- `pkg/flowexport/ipfix.go:539-545` hardcodes `sourceID: 1` for every IPFIX exporter.
- `pkg/flowexport/ipfix.go:651-678` sends template sets with `ObservationID: e.sourceID`.
- `pkg/flowexport/ipfix.go:691-736` sends data sets using the fixed template IDs and the same observation ID.

Runtime trace:
1. Two IPFIX template groups differ by `flow-dir` or future extension.
2. Both exporters dial the same collector.
3. Both advertise template ID `256` and `257` under Observation Domain ID `1`.
4. RFC 7011 scoping is violated operationally: the collector sees one Observation Domain redefining the same template IDs.
5. Data records from one exporter can be decoded with the other exporter template.

Suggested issue:
Make IPFIX Observation Domain IDs and/or template IDs unique per active template group, or use a single exporter instance per collector that emits all templates under one consistent sequence and ID namespace.

### H03 - Allowed family-disjoint sampling instances can still collide sequence spaces at one collector

Severity: High
Confidence: High

Evidence:
- `pkg/config/compiler_validate_strict.go:739-774` documents that multiple instances are allowed when disambiguated by family or version.
- `pkg/flowexport/manager.go:473-507` creates separate `ExportConfig`s with separate counters per instance.
- `pkg/daemon/daemon_flowexport.go:317-323` starts a separate exporter goroutine per IPFIX group.
- `pkg/flowexport/ipfix.go:517-519` keeps a separate `seq` per exporter.
- `pkg/flowexport/ipfix.go:542` uses `sourceID: 1` for each exporter.

Runtime trace:
1. Instance A serves inet/IPFIX to collector C.
2. Instance B serves inet6/IPFIX to the same collector C.
3. Strict validator allows this because families are distinct.
4. Daemon starts two IPFIX exporters, each with sequence starting at 0 and Observation Domain ID 1.
5. Collector receives interleaved messages from the same observation domain with independent sequence streams.
6. Sequence-tracking collectors can report loss/restarts or discard records.

Suggested issue:
Pin a unique source/observation identity per instance/template group, and add tests for same collector with family-disjoint instances.

### H04 - Prometheus flow-export metrics can emit duplicate labelsets and hide the failing group

Severity: High
Confidence: High

Evidence:
- `pkg/daemon/daemon_flowexport.go:461-483` annotates health rows with protocol, instance, and template.
- `pkg/api/metrics_descriptors.go:1701-1726` defines labels only as `{protocol, collector}`.
- `pkg/api/metrics_system.go:134-156` emits metrics using only `h.Protocol` and `h.Address`.
- `pkg/flowexport/transport.go:137` sets `CollectorHealth.Address` to only `c.Address`, not source address.

Runtime trace:
1. Two template groups or two family-disjoint instances use the same collector address.
2. `FlowCollectorHealth()` returns two rows with different instance/template.
3. Prometheus collector emits two samples with identical metric name and identical `{protocol,collector}` labels.
4. Depending on scrape path, this is either a duplicate series error or the operator sees only one collapsed health stream.
5. A partial failure of one template group is not attributable.

Suggested issue:
Prometheus labels need at least `protocol`, `collector`, `source_address`, `instance`, and `template`, or the daemon must aggregate rows intentionally with explicit semantics.

### H05 - Reconcile stop/start publishes a stale bundle while the old exporter is already stopped

Severity: High
Confidence: High

Evidence:
- `pkg/daemon/daemon_flowexport.go:180-191` cancels the old context, waits for the exporter goroutine, closes old exporters, and sets `d.flowExporters = nil`.
- `pkg/daemon/daemon_flowexport.go:232-245` stores the new bundle only after all new exporters are built.
- `pkg/daemon/daemon_flowexport.go:356-399` callback reads `d.flowBundle` lock-free and calls `ExportSessionClose`.
- `pkg/flowexport/netflow.go:565-610` `ExportSessionClose` only appends to the batch.

Runtime trace:
1. Commit changes flow export config.
2. Reconcile cancels and waits for the old exporter loop.
3. The old bundle is still published until line 234 stores the new bundle.
4. A SESSION_CLOSE callback in that interval reads the old bundle and queues into the old exporter's batch.
5. The old Run loop is already stopped, so no ticker will flush that batch.
6. Record is silently lost.

Suggested issue:
Publish an empty/draining bundle before stopping, or publish the replacement before cancelling the old group with a generation/drain handoff. Add a race test with a callback between cancel and bundle swap.

### H06 - A transient create failure tears down healthy exporters and leaves flow export disabled until another apply

Severity: High
Confidence: High

Evidence:
- `pkg/daemon/daemon_flowexport.go:180-191` stops old v9 exporters before creating new ones.
- `pkg/daemon/daemon_flowexport.go:205-226` returns on `NewExporter` error, stores an empty bundle, and sets `flowHashSet=false`.
- `pkg/daemon/daemon_flowexport.go:269-303` has the same IPFIX ordering.

Runtime trace:
1. Existing exporter is healthy and sending records.
2. Operator changes config, or DNS/source-address availability is transient during apply.
3. Reconcile stops old exporters first.
4. New exporter creation fails on one group.
5. Daemon publishes an empty bundle and leaves hash unset.
6. No automatic retry exists except a later commit/apply, so observability is down even though the old config could have continued exporting.

Suggested issue:
Construct and validate all replacement exporters first. Only after the full replacement set succeeds should the daemon atomically swap bundles and stop old exporters.

### H07 - One blocking collector write can stall all collectors, template refreshes, shutdown drain, and batch flushing

Severity: High
Confidence: High

Evidence:
- `pkg/flowexport/transport.go:158-191` loops collectors and calls `c.conn.Write(pkt)` synchronously.
- No write deadline is set in `dialCollectors` or `writeAll`.
- `pkg/flowexport/netflow.go:540-560` uses the same Run goroutine for template refresh and batch flush.
- `pkg/flowexport/ipfix.go:558-576` has the same structure.

Runtime trace:
1. Exporter has collector A and collector B.
2. Collector A's `net.Conn.Write` blocks due to OS/socket/pathology/fake connector.
3. `writeAll` never reaches collector B.
4. The Run goroutine cannot service the next batch tick or template refresh.
5. On shutdown, `flushBatches` can also block on the same write.

Suggested issue:
Use UDP sockets with bounded write deadlines, per-collector nonblocking goroutines, or drop-after-deadline semantics. Add a fake blocking `net.Conn` regression test.

### H08 - Flow-export batch queue is unbounded and can grow without backpressure

Severity: High
Confidence: High

Evidence:
- `pkg/flowexport/transport.go:230-244` appends to `flowBatch.v4/v6` with no cap.
- `pkg/flowexport/netflow.go:565-610` queues every exported close.
- `pkg/flowexport/netflow.go:659-667` drains only from the Run goroutine.
- H05/H07 show credible paths where the Run goroutine is stopped or blocked.

Runtime trace:
1. SESSION_CLOSE rate spikes during a scan or failover.
2. Collector write stalls or the callback queues into a stopped exporter during reconcile.
3. `ExportSessionClose` keeps appending records.
4. No cap, drop counter, or backpressure exists.
5. Memory grows with event rate.

Suggested issue:
Bound `flowBatch` by records/bytes, drop with counters when full, and expose queue depth/drops. Use a ring or channel with explicit backpressure semantics.

### H09 - Route-mask lookup is VRF/routing-instance/table blind

Severity: High
Confidence: High

Evidence:
- `pkg/logging/eventbuf.go:9-62` `EventRecord` carries zones, interfaces, counters, policy, and NAT fields, but no routing table/VRF/routing-instance.
- `pkg/flowexport/manager.go:739-779` `SessionCloseData` also has no routing table/VRF field.
- `pkg/flowexport/routemask.go:151-153` calls `netlink.RouteGetWithOptions(ip, &netlink.RouteGetOptions{FIBMatch: true})` without table, VRF link, mark, namespace, or source interface.

Runtime trace:
1. Flow is routed in a forwarding instance/VRF, PBR-selected table, or non-main routing domain.
2. SESSION_CLOSE contains only IPs/zones/ifindexes.
3. Exporter asks Linux for the route to src/dst in the default lookup context.
4. Kernel returns the main table match, not the table that forwarded the flow.
5. NetFlow/IPFIX `srcMask`/`dstMask` are wrong while appearing authoritative.

Suggested issue:
Carry the forwarding table/routing-instance or matched route prefix on the close event, or derive masks from xpf's own routing resolution rather than a global kernel query.

### H10 - Route-mask netlink lookup runs synchronously inside the session-close callback path

Severity: High
Confidence: High

Evidence:
- `pkg/daemon/daemon_flowexport.go:397-399` calls `ExportSessionClose` directly from the EventReader callback.
- `pkg/flowexport/netflow.go:579-581` resolves masks while building the record.
- `pkg/flowexport/ipfix.go:594-596` does the same for IPFIX.
- `pkg/flowexport/routemask.go:96` calls `c.lookup(ip)` on cache miss.
- `pkg/flowexport/routemask.go:151-153` implements that lookup as a netlink route query.

Runtime trace:
1. Event reader decodes a close event and runs callbacks.
2. Cache miss for source or destination mask.
3. Callback performs netlink RTM_GETROUTE synchronously.
4. Kernel/netlink latency directly delays the event reader and all callbacks behind this one.
5. High-cardinality destination churn can turn close-event handling into a netlink-bound path.

Suggested issue:
Move route-mask resolution to the exporter goroutine, pre-resolve asynchronously with bounded work, or carry matched route prefix from dataplane resolution.

### H11 - Flow-server-nested source-address is stored as a family-wide override

Severity: High
Confidence: High

Evidence:
- `pkg/config/types_system.go:881-887` `SamplingFamily` has one `SourceAddress` for the whole family.
- `pkg/config/types_system.go:906-912` `FlowServer` has no `SourceAddress`.
- `pkg/config/compiler_services.go:1394-1403` comments admit the family carries one source address and manager applies it to every collector.
- `pkg/config/compiler_services.go:1459-1462` captures a flow-server-nested `source-address` into a single `flowServerSrc` variable.
- `pkg/config/compiler_services.go:1481-1487` assigns that single value to `sf.SourceAddress`.
- `pkg/flowexport/manager.go:208-218` applies `fam.SourceAddress` to every collector.

Runtime trace:
1. Collector A configures a nested source-address.
2. Collector B in the same family has no nested source-address or has a different desired bind.
3. Compiler stores only one family-wide source address.
4. Flowexport applies that address to every collector in the family.
5. Collector B dials with collector A's source bind, which can fail or use the wrong routing/ACL path.

Suggested issue:
Add `FlowServer.SourceAddress` and keep output-level source-address as a default. Dedupe and health labels should include the effective source per collector.

### H12 - Exported volume ignores server-to-client counters

Severity: High
Confidence: High

Evidence:
- `pkg/logging/eventbuf.go:26-37` has `SessionPkts/Bytes` and `RevSessionPkts/RevSessionBytes`.
- `pkg/logging/ringbuf.go:584-585` decodes reverse counters from the SESSION_CLOSE frame.
- `pkg/flowexport/netflow.go:588-589` exports only `rec.SessionPkts` and `rec.SessionBytes`.
- `pkg/flowexport/ipfix.go:603-604` exports only `rec.SessionPkts` and `rec.SessionBytes`.

Runtime trace:
1. Client downloads a large file.
2. Close event carries small client-to-server request bytes and large server-to-client response bytes.
3. Event log can display both directions.
4. NetFlow/IPFIX record writes only the client-to-server half into packet/octet delta counts.
5. Collector underreports traffic volume for normal asymmetric flows.

Suggested issue:
Decide and document vSRX parity semantics: export initiator-to-responder only, responder-to-initiator as a second reverse record, or total bidirectional counters. If the expected appliance behavior is total session volume, encode `Session + RevSession` with overflow-safe add and tests.

## Medium confidence findings

### M01 - Exporter Stats count records as exported even when every collector write failed

Severity: Medium
Confidence: High

Evidence:
- `pkg/flowexport/transport.go:158-191` `writeAll` records per-collector failures but returns no success/failure aggregate.
- `pkg/flowexport/netflow.go:725-728` increments `exportedFlows` and `exportedPkts` after `writeAll`.
- `pkg/flowexport/ipfix.go:736-739` does the same.
- README says pre-health behavior kept counting "exported" while writes failed; current Stats still does for aggregate exporter counters.

Runtime trace:
1. All collectors are unreachable.
2. `writeAll` records failures.
3. `sendRecords` increments exported flow/packet counters anyway.
4. Any future status surface using `Stats()` can show successful export volume despite total delivery failure.

Suggested issue:
Rename counters to attempted, or have `writeAll` return attempted/succeeded/failed counts and expose delivered vs dropped records.

### M02 - Collector health identity omits source address even though source address is part of the collector key

Severity: Medium
Confidence: High

Evidence:
- `pkg/flowexport/manager.go:869-870` dedupes by address + source address + template.
- `pkg/flowexport/transport.go:137` stores health `addr: c.Address` only.
- `pkg/flowexport/transport.go:63-71` `CollectorHealth` has no source-address field.
- CLI prints only `Collector %s (%s)` at `pkg/cli/cli_show_flow.go:1208`.

Runtime trace:
1. Same collector destination is configured twice with different source binds.
2. Runtime correctly opens distinct UDP connections.
3. Health snapshots show identical `Address`.
4. CLI/REST/Prometheus cannot tell which source-bound connection failed.

Suggested issue:
Add `SourceAddress` to `CollectorHealth`, CLI, REST, and Prometheus labels.

### M03 - Multiple nested flow-server source-address values are last-writer-wins by AST order

Severity: Medium
Confidence: High

Evidence:
- `pkg/config/compiler_services.go:1404` declares one `flowServerSrc`.
- `pkg/config/compiler_services.go:1459-1462` overwrites it for each nested source-address.
- `pkg/config/compiler_services.go:1484-1485` stores only the final non-empty value.

Runtime trace:
1. Collector A nested source-address is `10.0.0.1`.
2. Collector B nested source-address is `10.0.0.2`.
3. Compiler walks children and overwrites `flowServerSrc`.
4. All collectors inherit the last seen nested value.
5. Behavior depends on AST/set command ordering, not per-collector configuration.

Suggested issue:
Same as H11: represent source-address on `FlowServer`, then compute effective source per collector.

### M04 - No-source collector dial bypasses test seams and custom resolver path

Severity: Medium
Confidence: High

Evidence:
- `pkg/flowexport/transport.go:82-93` defines `dialUDP` and `resolveUDPAddr` seams.
- `pkg/flowexport/transport.go:113-128` uses those seams only when `SourceAddress` is set.
- `pkg/flowexport/transport.go:129-131` uses `net.Dial("udp", c.Address)` directly when no source address is set.

Runtime trace:
1. Most collectors have no explicit source-address.
2. Tests cannot inject dial behavior for that branch via the package seams.
3. Resolve/dial error behavior is not as directly unit-testable as the source-address branch.
4. Future changes can drift between branches.

Suggested issue:
Always resolve remote with `resolveUDPAddr` and dial with `dialUDP`, passing nil local address when no source bind is configured.

### M05 - `resolveMasks` discards the resolver `ok` bit, conflating unresolved with real default route

Severity: Medium
Confidence: High

Evidence:
- `pkg/flowexport/routemask.go:22-25` documents that `ok` distinguishes `/0` from unresolved.
- `pkg/flowexport/routemask.go:137-143` ignores the bool and returns only mask bytes.
- Exporters have no counter or field to surface resolver misses.

Runtime trace:
1. FIB lookup fails for a flow.
2. Resolver returns `(0,false)`.
3. Exporter writes `srcMask=0` or `dstMask=0`.
4. Collector cannot distinguish an actual default-route match from unresolved attribution.

Suggested issue:
Track route-mask resolve failures as counters and optionally avoid populating mask fields when unresolved if protocol/template strategy allows it.

### M06 - Cache cap eviction clears the entire route-mask cache under high-cardinality scans

Severity: Medium
Confidence: High

Evidence:
- `pkg/flowexport/routemask.go:34` sets max 8192.
- `pkg/flowexport/routemask.go:122-129` clears the entire cache if no expired entries can be reclaimed.

Runtime trace:
1. Internet-facing firewall sees more than 8192 distinct destination IPs within 10 seconds.
2. Cache reaches cap with mostly live entries.
3. Insert of one more IP clears all entries.
4. Hot prefixes become cold and trigger fresh netlink lookups.
5. Under scans, this can oscillate into repeated full-cache cold starts.

Suggested issue:
Use a small LRU/clock eviction or shard by prefix/family so one high-cardinality burst does not evict the entire hot set.

### M07 - Created-after-close clock skew clamp is not counted as an estimated/invalid duration

Severity: Medium
Confidence: High

Evidence:
- `pkg/flowexport/manager.go:802-809` clamps `created.After(rec.Time)` to `rec.Time` and returns `usedEstimate=false`.
- `pkg/flowexport/netflow.go:569-572` increments `estimatedDurations` only when `usedEstimate` is true.
- `pkg/flowexport/ipfix.go:584-587` mirrors that behavior.

Runtime trace:
1. Dataplane/helper conversion emits a created timestamp after close time.
2. Exporter clamps start to end.
3. Flow duration becomes zero.
4. No counter increments, so operators cannot detect clock-skew corruption.

Suggested issue:
Add a separate `clamped_duration` counter and include it in CLI/REST/Prometheus health.

### M08 - IPFIX export has no sampler/options metadata for sampling interval

Severity: Medium
Confidence: Medium

Evidence:
- `pkg/flowexport/ipfix.go:54-58` defines Options Template set ID but no options template is built.
- `pkg/flowexport/ipfix.go:267-310` only emits data templates.
- `pkg/flowexport/manager.go:77` has `SamplingRate`, but it is not encoded into IPFIX.

Runtime trace:
1. Operator configures 1-in-N sampling.
2. Exporter emits only sampled flow records.
3. Collector receives no IPFIX sampler/options record identifying sampling interval.
4. Collector cannot correctly scale sampled counts without out-of-band config.

Suggested issue:
Add IPFIX Options Templates for sampling interval/algorithm and observation metadata, or document that collector-side scaling must be manually configured.

### M09 - Public `BuildExportConfig` helpers silently drop all but the first template group

Severity: Medium
Confidence: High

Evidence:
- `pkg/flowexport/manager.go:513-524` returns `groups[0]`.
- `pkg/flowexport/manager.go:527-533` does the same for IPFIX.
- `rg` shows current production daemon uses `Resolve*TemplateGroups`, but tests and future callers still use `Build*ExportConfig`.

Runtime trace:
1. Future internal caller uses the simple helper in a multi-template config.
2. Helper returns only first deterministic group.
3. Caller sees an apparently valid config but misses other collectors/templates.

Suggested issue:
Deprecate or rename to `BuildFirstExportConfigForTests`, or return an error when more than one group exists.

### M10 - Template refresh ticker can panic for hand-built configs with zero refresh rate

Severity: Medium
Confidence: Medium

Evidence:
- Default context sets refresh to 60s at `pkg/flowexport/manager.go:263-271`.
- `pkg/flowexport/netflow.go:544` calls `time.NewTicker(e.cfg.TemplateRefreshRate)`.
- `pkg/flowexport/ipfix.go:561` does the same.
- `NewExporter` and `NewIPFIXExporter` do not normalize a zero value.

Runtime trace:
1. Test or future caller constructs `ExportConfig` directly with zero `TemplateRefreshRate`.
2. `NewExporter` succeeds.
3. `Run` panics on `time.NewTicker(0)`.

Suggested issue:
Normalize in constructors, not only in resolver-produced configs.

### M11 - `ShouldExport` exports all sessions when no sampling zones are configured

Severity: Medium
Confidence: Medium

Evidence:
- `pkg/flowexport/manager.go:589-594` documents "If no SamplingZones are configured, all sessions are eligible."
- `pkg/flowexport/manager.go:595-607` enforces zone eligibility only when the map is non-empty.

Runtime trace:
1. Operator configures collectors and input rate but no interface `sampling input/output`.
2. SamplingZones is empty.
3. Every session becomes eligible and is sampled by rate.
4. A missing interface sampling stanza changes scope from "no observation point" to global observation.

Suggested issue:
Re-check Junos/vSRX semantics. If interface sampling is required for active flow monitoring, make empty SamplingZones export nothing or commit-warn/fail.

### M12 - FlowDirection defaults to ingress for globally-sampled flows

Severity: Medium
Confidence: Medium

Evidence:
- `pkg/flowexport/manager.go:636-643` returns 0 when no ingress input or egress output match.
- `pkg/flowexport/manager.go:627` documents default ingress.
- `pkg/config/compiler_validate_warn.go:570-578` warns only when flow-dir is configured but no interface has sampling input/output.

Runtime trace:
1. Flow-dir extension is enabled.
2. No per-zone sampling direction selects the record, or the record is exported via the global empty-zone fallback.
3. Exporter encodes `flowDirection=0`.
4. Collector sees authoritative ingress for a record that did not have an ingress observation point.

Suggested issue:
If global export remains supported, either omit flowDirection for such groups or add an explicit unknown/sentinel strategy if collector-compatible.

### M13 - NetFlow v9 SysUptime truncates pre-exporter sessions to boot time after daemon restart

Severity: Medium
Confidence: Medium

Evidence:
- `pkg/flowexport/netflow.go:466-471` returns 0 when flow time is before exporter boot.
- `pkg/flowexport/netflow.go:517-521` sets exporter `bootTime` at constructor time.
- Long-lived sessions can close after daemon restart while their `Created` predates exporter construction.

Runtime trace:
1. Daemon restarts while sessions remain in dataplane.
2. Session closes after exporter restarts.
3. Start time is before exporter boot.
4. v9 `FirstSwitched` becomes 0.
5. Collector sees session start at exporter boot, not actual start.

Suggested issue:
Document NetFlow v9 limitation and prefer IPFIX for absolute timestamps, or preserve exporter boot epoch across restarts if protocol-compatible.

### M14 - Route-mask lookup ignores source interface and source address

Severity: Medium
Confidence: High

Evidence:
- `pkg/flowexport/routemask.go:151-153` queries only by destination IP.
- `SessionCloseData` has `InIf` and `OutIf` at `pkg/flowexport/manager.go:756-772`, but no source interface/table is passed to the resolver.

Runtime trace:
1. Linux policy routing chooses different prefixes based on source address or fwmark.
2. RouteGet without source/mark can pick a different route than forwarding used.
3. Exported prefix masks become misleading even outside full VRF cases.

Suggested issue:
Carry enough forwarding-resolution context to choose the same route table/path used by the dataplane.

### M15 - Collector health has no queue-depth/drop visibility

Severity: Medium
Confidence: Medium

Evidence:
- `pkg/flowexport/transport.go:60-72` health includes write counters and last timestamps only.
- `pkg/flowexport/transport.go:230-257` batch queue has no exported depth/drop counters.
- REST and Prometheus surfaces mirror only collector write health.

Runtime trace:
1. Exporter queues records faster than it flushes.
2. Collector writes may still be healthy when the queue grows.
3. Operator sees no queue pressure until memory pressure or record loss.

Suggested issue:
Expose per-exporter queue length, max queue length, dropped records, and flush latency.

## Low confidence / triage findings

### L01 - Per-family batch split prevents mixed v4/v6 coalescing and may increase packet rate

Severity: Low
Confidence: Medium

Evidence:
- `pkg/flowexport/transport.go:230-244` keeps separate v4/v6 slices.
- `pkg/flowexport/netflow.go:659-667` flushes v4 and v6 as separate sends.
- `pkg/flowexport/ipfix.go:680-688` mirrors this.

Trace:
Mixed-family close bursts become at least two datagrams per flush interval even if a collector could ingest multiple data sets in one IPFIX message.

Suggested issue:
Consider IPFIX multi-set messages and v9 multi-FlowSet packing to reduce packet rate under dual-stack bursts.

### L02 - Batch drain discards slice capacity every 100ms

Severity: Low
Confidence: High

Evidence:
- `pkg/flowexport/transport.go:249-255` returns current slices and sets both to nil.

Trace:
At steady export rates, every flush causes future appends to allocate again instead of reusing capacity. For high-rate close storms this adds allocator churn.

Suggested issue:
Use a double-buffer or bounded ring that reuses backing arrays.

### L03 - No active/inactive timeout logic exists despite config fields in `ExportConfig`

Severity: Low
Confidence: Medium

Evidence:
- `pkg/flowexport/manager.go:73-75` stores active/inactive/template refresh timeouts.
- Exporters only emit on session close from callbacks; no active timeout emission is visible in `netflow.go` or `ipfix.go`.

Trace:
Long-lived sessions produce no periodic active records, so collectors lack interim accounting until close. This may diverge from vSRX active flow monitoring expectations for long-lived flows.

Suggested issue:
Validate vSRX active-timeout parity. If required, add periodic active export fed by session snapshots, not only close events.

### L04 - No collector DNS refresh after constructor-time dial

Severity: Low
Confidence: Medium

Evidence:
- `pkg/flowexport/transport.go:100-139` dials collectors at construction.
- Reconcile is config-hash gated at `pkg/daemon/daemon_flowexport.go:172-176` and `261-265`.

Trace:
Collector hostname DNS changes while config is unchanged. Existing UDP connection keeps old resolved address until an exporter restart or config change.

Suggested issue:
Add periodic collector re-resolution or document that collector hostnames are resolved only at apply time.

### L05 - Collector write health starts optimistic, so never-written collectors are "healthy"

Severity: Low
Confidence: High

Evidence:
- `pkg/flowexport/transport.go:135-137` initializes `healthy: true`.
- LastSuccessTime is zero until first successful write.

Trace:
Immediately after boot or before first template write failure, health can show up even though no successful datagram has been sent.

Suggested issue:
Use explicit state: unknown/up/down, or mark healthy only after first successful write.

### L06 - REST health endpoint returns empty collectors for both unconfigured and callback-unwired states

Severity: Low
Confidence: High

Evidence:
- `pkg/api/health.go:66-71` returns `{"collectors": collectors}` where collectors is nil/empty if callback absent or no config.

Trace:
API clients cannot distinguish "flow export not configured" from "daemon failed to wire health callback".

Suggested issue:
Return configured/wired booleans or an explicit status object.

### L07 - Flow-export package remains too monolithic for protocol correctness work

Severity: Low
Confidence: High

Evidence:
- `pkg/flowexport/README.md:259-278` layout still groups manager, protocol encoders, transport, and batch in one package.
- `netflow.go` and `ipfix.go` each combine template definitions, record encoders, run loop, stats, batching, and transport calls.

Trace:
Fixing protocol identity will need coordinated changes across resolver, daemon grouping, transport, and both encoders. Current shape encourages duplicating fixes between v9 and IPFIX.

Suggested issue:
Refactor into `flowexport/{config,transport,batch,netflow,ipfix,health}` packages or subdirectories, with a shared exporter runner that owns identity, sequencing, and batching.

### L08 - Tests overuse package-internal helpers and under-cover real daemon multi-group wire collisions

Severity: Low
Confidence: High

Evidence:
- Many `pkg/flowexport/*_test.go` tests call encoders/constructors directly.
- Existing tests validate field offsets and sequence behavior but not same-collector multi-template identity.
- Temporary probe for this audit passed and should become a permanent fail-on-revert test.

Trace:
Unit tests can prove one template encodes correctly while missing collector-visible interactions between multiple exporters.

Suggested issue:
Add loopback UDP integration tests that start daemon-resolved multiple template groups to the same collector and assert unique protocol identities.

## Suggested issue list

1. flowexport: allocate unique NetFlow/IPFIX exporter identity per template group / instance.
2. flowexport: prevent IPFIX/NetFlow sequence collisions across family-disjoint instances to the same collector.
3. flowexport: fix Prometheus collector-health labels to include instance/template/source.
4. flowexport: close reconcile stop/start callback loss window.
5. flowexport: preserve old exporters until replacement construction succeeds.
6. flowexport: add write deadlines or per-collector nonblocking fanout.
7. flowexport: bound batch queue and expose drops/depth.
8. flowexport: make route-mask attribution routing-instance/table aware.
9. flowexport: move route-mask netlink lookup off EventReader callback path.
10. config/flowexport: represent flow-server-nested source-address per collector.
11. flowexport: export bidirectional close volume or document/encode directional records.
12. flowexport: split attempted vs delivered export counters.
13. flowexport: expose source-address in health/CLI/REST/metrics.
14. flowexport: preserve resolver ok bit / expose route-mask miss counter.
15. flowexport: replace route-mask clear-all eviction with LRU/clock.
16. flowexport: add sampler/options metadata for IPFIX sampling interval.
17. flowexport: deprecate first-group-only BuildExportConfig helpers.
18. flowexport: normalize TemplateRefreshRate in constructors.
19. flowexport: decide empty SamplingZones semantics against vSRX.
20. flowexport: add active-timeout/interim export parity check.
21. flowexport: collector DNS refresh or documented apply-time-only resolution.
22. flowexport: unknown/up/down health state instead of optimistic healthy.
23. api: distinguish no flow-export config from health callback absent.
24. flowexport: modularize protocol/transport/batch/health responsibilities.
25. flowexport: add loopback multi-group collector wire identity tests.
