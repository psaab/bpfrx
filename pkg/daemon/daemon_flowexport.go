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
// reconcile swaps the bundle atomically. The exporter never reads the
// config's 1-in-N sampleCounter (only the callback's ShouldExport
// does), so the daemon-held *ExportConfig is the sole counter owner and
// is held by pointer in the bundle.
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

// exporterBundle is the immutable (exporter, resolved-config) pair the
// NetFlow v9 session-close callback reads via d.flowBundle. A nil exp
// means "no v9 exporter configured".
type exporterBundle struct {
	exp *flowexport.Exporter
	ec  *flowexport.ExportConfig
}

// ipfixBundle is the IPFIX equivalent of exporterBundle.
type ipfixBundle struct {
	exp *flowexport.IPFIXExporter
	ec  *flowexport.ExportConfig
}

// flowExportConfigHash hashes the resolved *ExportConfig (Collectors,
// timeouts, SamplingZones, SamplingRate, V9TemplateOpts). The
// unexported atomic.Uint64 sampleCounter is invisible to json.Marshal,
// and Go marshals map[uint16]SamplingDir keys in sorted numeric order,
// so the encoding is deterministic. A nil ec hashes to a distinct
// sentinel so "configured -> removed" registers as a real change.
func flowExportConfigHash(ec *flowexport.ExportConfig) [32]byte {
	if ec == nil {
		// Distinct, stable sentinel for the unconfigured state.
		return sha256.Sum256([]byte("flowexport:nil"))
	}
	data, err := json.Marshal(ec)
	if err != nil {
		// Marshal of plain structs cannot realistically fail; fall back
		// to a zero hash (forces re-apply) rather than silently skip.
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

// buildFlowExportConfig resolves the NetFlow v9 export config from the
// committed config, filling per-zone sampling directions. Returns nil
// when flow export is not configured.
func (d *Daemon) buildFlowExportConfig(cfg *config.Config) *flowexport.ExportConfig {
	ec := flowexport.BuildExportConfig(&cfg.Services, &cfg.ForwardingOptions)
	if ec == nil {
		return nil
	}
	zoneIDs := buildZoneIDs(cfg)
	ec.SamplingZones = flowexport.BuildSamplingZones(cfg, zoneIDs)
	return ec
}

// buildIPFIXExportConfig resolves the IPFIX export config from the
// committed config. Returns nil when IPFIX export is not configured.
func (d *Daemon) buildIPFIXExportConfig(cfg *config.Config) *flowexport.ExportConfig {
	ec := flowexport.BuildIPFIXExportConfig(&cfg.Services, &cfg.ForwardingOptions)
	if ec == nil {
		return nil
	}
	zoneIDs := buildZoneIDs(cfg)
	ec.SamplingZones = flowexport.BuildSamplingZones(cfg, zoneIDs)
	return ec
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

// reconcileV9Exporter reconciles only the NetFlow v9 exporter.
func (d *Daemon) reconcileV9Exporter(cfg *config.Config) bool {
	d.flowReconMu.Lock()
	defer d.flowReconMu.Unlock()

	ec := d.buildFlowExportConfig(cfg)
	h := flowExportConfigHash(ec)
	if d.flowHashSet && h == d.flowHash {
		return false // gated: healthy exporter keeps running
	}

	wasRunning := d.flowExporter != nil

	// Stop the old exporter (if any). The session-close callback reads
	// the bundle lock-free; we publish the new bundle as one atomic
	// pointer, so a concurrent read sees either the old or new pair.
	if d.flowCancel != nil {
		d.flowCancel()
		d.flowWg.Wait()
		if d.flowExporter != nil {
			d.flowExporter.Close()
		}
		d.flowExporter = nil
		d.flowCancel = nil
	}

	if ec == nil {
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

	exp, err := flowexport.NewExporter(*ec)
	if err != nil {
		slog.Warn("failed to create flow exporter", "err", err)
		// Do NOT record the hash on a create failure: NewExporter ->
		// dialCollectors can fail transiently (a pinned source-address
		// bind before the source interface is up, transient collector
		// DNS). Leaving flowHashSet false means the NEXT commit (even an
		// identical one) retries instead of being hash-gated into a
		// permanently-dead exporter. NewExporter is cheap, so the retry
		// is safe; the gate re-arms on the first successful start.
		d.flowBundle.Store(&exporterBundle{})
		d.flowHashSet = false
		return true
	}

	flowCtx, cancel := context.WithCancel(d.daemonCtx)
	d.flowExporter = exp
	d.flowCancel = cancel
	d.flowBundle.Store(&exporterBundle{exp: exp, ec: ec})

	d.flowCBOnce.Do(func() {
		d.eventReader.AddCallback(d.flowExportCallback)
	})

	d.flowWg.Add(1)
	go func() {
		defer d.flowWg.Done()
		exp.Run(flowCtx)
	}()

	d.flowHash, d.flowHashSet = h, true
	slog.Info("NetFlow v9 exporter reconciled",
		"collectors", len(ec.Collectors),
		"active_timeout", ec.FlowActiveTimeout,
		"inactive_timeout", ec.FlowInactiveTimeout,
		"sampling_zones", len(ec.SamplingZones),
		"sampling_rate", ec.SamplingRate)
	return true
}

// reconcileIPFIXExporter reconciles only the IPFIX exporter.
func (d *Daemon) reconcileIPFIXExporter(cfg *config.Config) bool {
	d.ipfixReconMu.Lock()
	defer d.ipfixReconMu.Unlock()

	ec := d.buildIPFIXExportConfig(cfg)
	h := flowExportConfigHash(ec)
	if d.ipfixHashSet && h == d.ipfixHash {
		return false
	}

	wasRunning := d.ipfixExporter != nil

	if d.ipfixCancel != nil {
		d.ipfixCancel()
		d.ipfixWg.Wait()
		if d.ipfixExporter != nil {
			d.ipfixExporter.Close()
		}
		d.ipfixExporter = nil
		d.ipfixCancel = nil
	}

	if ec == nil {
		d.ipfixBundlePtr.Store(&ipfixBundle{})
		d.ipfixHash, d.ipfixHashSet = h, true
		if !wasRunning {
			return false
		}
		slog.Info("IPFIX exporter stopped (flow export removed)")
		return true
	}

	exp, err := flowexport.NewIPFIXExporter(*ec)
	if err != nil {
		slog.Warn("failed to create IPFIX exporter", "err", err)
		// Do NOT record the hash on a create failure (see the v9 path):
		// leaving ipfixHashSet false lets the next commit retry instead
		// of being gated into a permanently-dead exporter.
		d.ipfixBundlePtr.Store(&ipfixBundle{})
		d.ipfixHashSet = false
		return true
	}

	ipfixCtx, cancel := context.WithCancel(d.daemonCtx)
	d.ipfixExporter = exp
	d.ipfixCancel = cancel
	d.ipfixBundlePtr.Store(&ipfixBundle{exp: exp, ec: ec})

	d.ipfixCBOnce.Do(func() {
		d.eventReader.AddCallback(d.ipfixExportCallback)
	})

	d.ipfixWg.Add(1)
	go func() {
		defer d.ipfixWg.Done()
		exp.Run(ipfixCtx)
	}()

	d.ipfixHash, d.ipfixHashSet = h, true
	slog.Info("IPFIX exporter reconciled",
		"collectors", len(ec.Collectors),
		"active_timeout", ec.FlowActiveTimeout,
		"inactive_timeout", ec.FlowInactiveTimeout,
		"sampling_zones", len(ec.SamplingZones),
		"sampling_rate", ec.SamplingRate)
	return true
}

// flowExportCallback is the single, stable NetFlow v9 session-close
// handler registered on the EventReader exactly once. It reads the live
// (exporter, config) pair lock-free from the atomic bundle, so reconcile
// can swap the exporter without ever touching the callback list.
func (d *Daemon) flowExportCallback(rec logging.EventRecord, raw []byte) {
	if rec.Type != "SESSION_CLOSE" {
		return
	}
	b := d.flowBundle.Load()
	if b == nil || b.exp == nil || b.ec == nil {
		return
	}
	if !b.ec.ShouldExport(rec.InZone, rec.OutZone) {
		return
	}
	sd := flowexport.SessionCloseData{
		SrcPort:  parseSrcPort(rec.SrcAddr),
		DstPort:  parseSrcPort(rec.DstAddr),
		Protocol: parseProtocol(rec.Protocol),
	}
	sd.SrcIP, sd.DstIP, sd.IsIPv6 = parseAddrPair(rec.SrcAddr, rec.DstAddr)
	b.exp.ExportSessionClose(rec, sd)
}

// ipfixExportCallback is the IPFIX equivalent of flowExportCallback.
func (d *Daemon) ipfixExportCallback(rec logging.EventRecord, raw []byte) {
	if rec.Type != "SESSION_CLOSE" {
		return
	}
	b := d.ipfixBundlePtr.Load()
	if b == nil || b.exp == nil || b.ec == nil {
		return
	}
	if !b.ec.ShouldExport(rec.InZone, rec.OutZone) {
		return
	}
	sd := flowexport.SessionCloseData{
		SrcPort:  parseSrcPort(rec.SrcAddr),
		DstPort:  parseSrcPort(rec.DstAddr),
		Protocol: parseProtocol(rec.Protocol),
	}
	sd.SrcIP, sd.DstIP, sd.IsIPv6 = parseAddrPair(rec.SrcAddr, rec.DstAddr)
	b.exp.ExportSessionClose(rec, sd)
}
