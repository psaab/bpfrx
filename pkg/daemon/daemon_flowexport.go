// daemon_flowexport.go — NetFlow v9 / IPFIX exporter lifecycle wiring
// (#2075).
//
// Before #2075 the flow exporters were started once at daemon boot and
// stopped only at shutdown: the apply path (daemon_apply.go) had zero
// flowexport references, so a runtime commit that changed
// forwarding-options sampling (collector address/port, source-address,
// 1-in-N input-rate, which zones sample, a v9 export-extension) was
// silently ignored until a daemon restart — and flow export ADDED in a
// later commit never started at all.
//
// reconcileFlowExporters runs on every apply (and at boot, after the
// EventReader exists) but is CONFIG-HASH-GATED per family: it
// (re)starts or stops an exporter only when the rendered v9 / IPFIX
// stanza actually changed, so an unrelated commit never bounces a
// healthy exporter (preserving its template-refresh cadence and the
// 1-in-N sampling counter).
//
// The EventReader callback list is append-only with only a clear-ALL
// primitive (no per-callback removal), and the same EventReader carries
// callbacks for the trace writer too. A naive stop/start reconcile
// would therefore leak a closure (closed over a now-closed exporter) on
// every commit. Instead we register a single stable indirection
// callback per family exactly once (flowCBOnce / ipfixCBOnce) that
// reads the live (exporter, config) pair from an atomic.Pointer bundle;
// reconcile swaps the bundle atomically. The resolved *ExportConfig is
// held by pointer everywhere — in the bundle, by the session-close
// callback's ShouldExport, AND inside the exporter (#2224) — so there is
// exactly ONE live 1-in-N sampleCounter per family. ExportConfig embeds
// that counter as an atomic.Uint64; passing it by value would copy the
// atomic (a go-vet "copies lock value" failure) and fork the counter,
// silently re-seeding the modulo cadence the moment any caller sampled
// off the copy.
package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/logging"
)

// v9Group is one running NetFlow v9 template-group exporter and its
// resolved config (#2461). One flow-server template => one group => one
// exporter, so a collector receives exactly the template it referenced.
type v9Group struct {
	exp *flowexport.Exporter
	ec  *flowexport.ExportConfig
}

// ipfixGroup is the IPFIX equivalent of v9Group.
type ipfixGroup struct {
	exp *flowexport.IPFIXExporter
	ec  *flowexport.ExportConfig
}

// exporterBundle is the immutable per-family set of NetFlow v9 template-
// group exporters the session-close callback reads via d.flowBundle. An
// empty groups slice means "no v9 exporter configured". The groups share
// one ExportConfig.sampleCounter, so the callback evaluates ShouldExport
// (the shared 1-in-N counter + sampling zones) EXACTLY ONCE and fans the
// record out to every group (#2461).
type exporterBundle struct {
	groups []v9Group
}

// ipfixBundle is the IPFIX equivalent of exporterBundle.
type ipfixBundle struct {
	groups []ipfixGroup
}

// firstExp returns the first running v9 group exporter, or nil when no v9
// exporter is configured. A test/inspection convenience over b.groups.
func (b *exporterBundle) firstExp() *flowexport.Exporter {
	if b == nil || len(b.groups) == 0 {
		return nil
	}
	return b.groups[0].exp
}

// firstExp returns the first running IPFIX group exporter, or nil.
func (b *ipfixBundle) firstExp() *flowexport.IPFIXExporter {
	if b == nil || len(b.groups) == 0 {
		return nil
	}
	return b.groups[0].exp
}

// flowExportConfigHash hashes the resolved per-family template groups
// ([]*ExportConfig: Collectors, TemplateName, timeouts, SamplingZones,
// SamplingRate, V9TemplateOpts). The unexported atomic.Uint64 sampleCounter
// is invisible to json.Marshal, and Go marshals map[uint16]SamplingDir keys
// in sorted numeric order, so the encoding is deterministic — provided the
// resolver returns the groups in a stable order (it sorts by template name;
// #2461). An empty slice hashes to a distinct sentinel so "configured ->
// removed" registers as a real change.
func flowExportConfigHash(ecs []*flowexport.ExportConfig) [32]byte {
	if len(ecs) == 0 {
		// Distinct, stable sentinel for the unconfigured state.
		return sha256.Sum256([]byte("flowexport:nil"))
	}
	data, err := json.Marshal(ecs)
	if err != nil {
		// Marshal of plain structs cannot realistically fail; fall back
		// to a zero hash (forces re-apply) rather than silently skip.
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

// buildFlowExportConfigs resolves the NetFlow v9 export config from the
// committed config into one ExportConfig per per-flow-server template group
// (#2461), filling per-zone sampling directions on each. Returns nil when
// flow export is not configured.
func (d *Daemon) buildFlowExportConfigs(cfg *config.Config) []*flowexport.ExportConfig {
	ecs := flowexport.ResolveV9TemplateGroups(&cfg.Services, &cfg.ForwardingOptions)
	if len(ecs) == 0 {
		return nil
	}
	zoneIDs := buildZoneIDs(cfg)
	zones := flowexport.BuildSamplingZones(cfg, zoneIDs)
	for _, ec := range ecs {
		ec.SamplingZones = zones
	}
	return ecs
}

// buildIPFIXExportConfigs resolves the IPFIX export config from the
// committed config into one ExportConfig per template group. Returns nil
// when IPFIX export is not configured.
func (d *Daemon) buildIPFIXExportConfigs(cfg *config.Config) []*flowexport.ExportConfig {
	ecs := flowexport.ResolveIPFIXTemplateGroups(&cfg.Services, &cfg.ForwardingOptions)
	if len(ecs) == 0 {
		return nil
	}
	zoneIDs := buildZoneIDs(cfg)
	zones := flowexport.BuildSamplingZones(cfg, zoneIDs)
	for _, ec := range ecs {
		ec.SamplingZones = zones
	}
	return ecs
}

// reconcileFlowExporters reconciles BOTH the NetFlow v9 and IPFIX
// exporters against the committed config. Safe to call from boot (after
// the EventReader exists) and from applyConfigLocked. Returns true when
// either family actually (re)started or stopped.
//
// No-ops (returns false) when the EventReader does not yet exist — the
// boot apply runs before the EventReader is created, so the
// post-EventReader boot block is what first starts the exporters; the
// apply-path call handles every later commit.
func (d *Daemon) reconcileFlowExporters(cfg *config.Config) bool {
	if cfg == nil || d.eventReader == nil || d.daemonCtx == nil {
		return false
	}
	v9 := d.reconcileV9Exporter(cfg)
	ipfix := d.reconcileIPFIXExporter(cfg)
	return v9 || ipfix
}

// reconcileV9Exporter reconciles the NetFlow v9 template-group exporters
// (one per per-flow-server template, #2461).
func (d *Daemon) reconcileV9Exporter(cfg *config.Config) bool {
	d.flowReconMu.Lock()
	defer d.flowReconMu.Unlock()

	ecs := d.buildFlowExportConfigs(cfg)
	h := flowExportConfigHash(ecs)
	if d.flowHashSet && h == d.flowHash {
		return false // gated: healthy exporters keep running
	}

	wasRunning := len(d.flowExporters) > 0

	// Stop the old exporters (if any). The session-close callback reads
	// the bundle lock-free; we publish the new bundle as one atomic
	// pointer, so a concurrent read sees either the old or new set.
	if d.flowCancel != nil {
		d.flowCancel()
		d.flowWg.Wait()
		for _, exp := range d.flowExporters {
			exp.Close()
		}
		d.flowExporters = nil
		d.flowCancel = nil
	}

	if len(ecs) == 0 {
		d.flowBundle.Store(&exporterBundle{})
		d.flowHash, d.flowHashSet = h, true
		if !wasRunning {
			// Nothing was running and nothing starts: record the hash so
			// later identical commits gate, but report no change.
			return false
		}
		slog.Info("NetFlow v9 exporter stopped (flow export removed)")
		return true
	}

	flowCtx, cancel := context.WithCancel(d.daemonCtx)
	groups := make([]v9Group, 0, len(ecs))
	exps := make([]*flowexport.Exporter, 0, len(ecs))
	for _, ec := range ecs {
		exp, err := flowexport.NewExporter(ec)
		if err != nil {
			slog.Warn("failed to create flow exporter", "template", ec.TemplateName, "err", err)
			// Roll back the group exporters started so far and do NOT
			// record the hash: NewExporter -> dialCollectors can fail
			// transiently (a pinned source-address bind before the source
			// interface is up, transient collector DNS). Leaving
			// flowHashSet false means the NEXT commit (even an identical
			// one) retries instead of being hash-gated into a permanently-
			// dead family. NewExporter is cheap, so the retry is safe; the
			// gate re-arms on the first fully-successful start.
			cancel()
			for _, e := range exps {
				e.Close()
			}
			d.flowBundle.Store(&exporterBundle{})
			d.flowHashSet = false
			return true
		}
		exps = append(exps, exp)
		groups = append(groups, v9Group{exp: exp, ec: ec})
	}

	d.flowExporters = exps
	d.flowCancel = cancel
	d.flowBundle.Store(&exporterBundle{groups: groups})

	d.flowCBOnce.Do(func() {
		d.eventReader.AddCallback(d.flowExportCallback)
	})

	for _, exp := range exps {
		d.flowWg.Add(1)
		go func(e *flowexport.Exporter) {
			defer d.flowWg.Done()
			e.Run(flowCtx)
		}(exp)
	}

	d.flowHash, d.flowHashSet = h, true
	slog.Info("NetFlow v9 exporter reconciled",
		"template_groups", len(ecs),
		"sampling_zones", len(ecs[0].SamplingZones),
		"sampling_rate", ecs[0].SamplingRate)
	return true
}

// reconcileIPFIXExporter reconciles the IPFIX template-group exporters.
func (d *Daemon) reconcileIPFIXExporter(cfg *config.Config) bool {
	d.ipfixReconMu.Lock()
	defer d.ipfixReconMu.Unlock()

	ecs := d.buildIPFIXExportConfigs(cfg)
	h := flowExportConfigHash(ecs)
	if d.ipfixHashSet && h == d.ipfixHash {
		return false
	}

	wasRunning := len(d.ipfixExporters) > 0

	if d.ipfixCancel != nil {
		d.ipfixCancel()
		d.ipfixWg.Wait()
		for _, exp := range d.ipfixExporters {
			exp.Close()
		}
		d.ipfixExporters = nil
		d.ipfixCancel = nil
	}

	if len(ecs) == 0 {
		d.ipfixBundlePtr.Store(&ipfixBundle{})
		d.ipfixHash, d.ipfixHashSet = h, true
		if !wasRunning {
			return false
		}
		slog.Info("IPFIX exporter stopped (flow export removed)")
		return true
	}

	ipfixCtx, cancel := context.WithCancel(d.daemonCtx)
	groups := make([]ipfixGroup, 0, len(ecs))
	exps := make([]*flowexport.IPFIXExporter, 0, len(ecs))
	for _, ec := range ecs {
		exp, err := flowexport.NewIPFIXExporter(ec)
		if err != nil {
			slog.Warn("failed to create IPFIX exporter", "template", ec.TemplateName, "err", err)
			// Roll back and do NOT record the hash (see the v9 path).
			cancel()
			for _, e := range exps {
				e.Close()
			}
			d.ipfixBundlePtr.Store(&ipfixBundle{})
			d.ipfixHashSet = false
			return true
		}
		exps = append(exps, exp)
		groups = append(groups, ipfixGroup{exp: exp, ec: ec})
	}

	d.ipfixExporters = exps
	d.ipfixCancel = cancel
	d.ipfixBundlePtr.Store(&ipfixBundle{groups: groups})

	d.ipfixCBOnce.Do(func() {
		d.eventReader.AddCallback(d.ipfixExportCallback)
	})

	for _, exp := range exps {
		d.ipfixWg.Add(1)
		go func(e *flowexport.IPFIXExporter) {
			defer d.ipfixWg.Done()
			e.Run(ipfixCtx)
		}(exp)
	}

	d.ipfixHash, d.ipfixHashSet = h, true
	slog.Info("IPFIX exporter reconciled",
		"template_groups", len(ecs),
		"sampling_zones", len(ecs[0].SamplingZones),
		"sampling_rate", ecs[0].SamplingRate)
	return true
}

// flowExportCallback is the single, stable NetFlow v9 session-close
// handler registered on the EventReader exactly once. It reads the live
// set of template-group exporters lock-free from the atomic bundle, so
// reconcile can swap the exporters without ever touching the callback list.
//
// #2461: the template groups of ONE instance share one ShouldExport state
// (the 1-in-N counter + sampling zones), so the sampling decision is made
// EXACTLY ONCE per instance and fanned to that instance's groups — each
// group encodes with the template its collectors referenced. Deciding per
// template group would over-increment the shared counter and corrupt 1-in-N.
//
// #2462: sampling instances are independent export policies. A flow is
// attributed to an instance by address family (ServesFamily) and then
// sampled at THAT instance's own rate via THAT instance's own counter, so a
// flow eligible for instance A exports only to A's collectors at A's rate and
// never crosses to instance B. The per-instance decision is made once
// (groupedByInstance walks contiguous same-instance runs — the resolver
// emits an instance's groups consecutively) so the shared per-instance
// counter advances exactly once per eligible flow.
func (d *Daemon) flowExportCallback(rec logging.EventRecord, raw []byte) {
	if rec.Type != "SESSION_CLOSE" {
		return
	}
	b := d.flowBundle.Load()
	if b == nil || len(b.groups) == 0 {
		return
	}
	sd := flowexport.SessionCloseData{
		SrcPort:  parseSrcPort(rec.SrcAddr),
		DstPort:  parseSrcPort(rec.DstAddr),
		Protocol: parseProtocol(rec.Protocol),
	}
	sd.SrcIP, sd.DstIP, sd.IsIPv6 = parseAddrPair(rec.SrcAddr, rec.DstAddr)

	i := 0
	for i < len(b.groups) {
		inst := b.groups[i].ec.InstanceName
		// First group of this instance carries the shared per-instance state.
		lead := b.groups[i].ec
		// Determine the contiguous run of groups for this instance.
		j := i
		for j < len(b.groups) && b.groups[j].ec.InstanceName == inst {
			j++
		}
		// Family attribution then the single per-instance sampling decision.
		if lead.ServesFamily(sd.IsIPv6) && lead.ShouldExport(rec.InZone, rec.OutZone) {
			for k := i; k < j; k++ {
				b.groups[k].exp.ExportSessionClose(rec, sd)
			}
		}
		i = j
	}
}

// ipfixExportCallback is the IPFIX equivalent of flowExportCallback.
func (d *Daemon) ipfixExportCallback(rec logging.EventRecord, raw []byte) {
	if rec.Type != "SESSION_CLOSE" {
		return
	}
	b := d.ipfixBundlePtr.Load()
	if b == nil || len(b.groups) == 0 {
		return
	}
	sd := flowexport.SessionCloseData{
		SrcPort:  parseSrcPort(rec.SrcAddr),
		DstPort:  parseSrcPort(rec.DstAddr),
		Protocol: parseProtocol(rec.Protocol),
	}
	sd.SrcIP, sd.DstIP, sd.IsIPv6 = parseAddrPair(rec.SrcAddr, rec.DstAddr)

	i := 0
	for i < len(b.groups) {
		inst := b.groups[i].ec.InstanceName
		lead := b.groups[i].ec
		j := i
		for j < len(b.groups) && b.groups[j].ec.InstanceName == inst {
			j++
		}
		if lead.ServesFamily(sd.IsIPv6) && lead.ShouldExport(rec.InZone, rec.OutZone) {
			for k := i; k < j; k++ {
				b.groups[k].exp.ExportSessionClose(rec, sd)
			}
		}
		i = j
	}
}

// FlowCollectorHealth returns the per-collector write-health for every
// running NetFlow v9 and IPFIX exporter group (#2464). The slice is
// empty when no flow export is configured. Safe to call concurrently
// with reconcile and the export-flush goroutines: it reads the live
// bundles lock-free and each exporter's health() snapshot is mutex/atomic
// guarded. The returned type lives in pkg/flowexport so pkg/api and
// pkg/grpcapi (which cannot import pkg/daemon) can name it.
func (d *Daemon) FlowCollectorHealth() []flowexport.ExporterCollectorHealth {
	var out []flowexport.ExporterCollectorHealth
	if b := d.flowBundle.Load(); b != nil {
		for _, g := range b.groups {
			for _, h := range g.exp.CollectorHealth() {
				out = append(out, flowexport.ExporterCollectorHealth{
					Protocol:        "netflow-v9",
					Instance:        g.ec.InstanceName,
					Template:        g.ec.TemplateName,
					CollectorHealth: h,
				})
			}
		}
	}
	if b := d.ipfixBundlePtr.Load(); b != nil {
		for _, g := range b.groups {
			for _, h := range g.exp.CollectorHealth() {
				out = append(out, flowexport.ExporterCollectorHealth{
					Protocol:        "ipfix",
					Instance:        g.ec.InstanceName,
					Template:        g.ec.TemplateName,
					CollectorHealth: h,
				})
			}
		}
	}
	return out
}
