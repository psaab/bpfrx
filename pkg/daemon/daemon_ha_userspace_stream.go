package daemon

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/logging"
)

type userspaceSessionDeltaDrainer interface {
	DrainSessionDeltas(max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error)
}

type userspaceEventStreamProvider interface {
	EventStream() *dpuserspace.EventStream
}

// shouldSyncUserspaceDelta decides whether a userspace session delta should be
// synced to the peer. ss is the caller's captured session-sync object (#4958):
// the per-delta hot path takes the snapshot once in queueUserspaceSessionDeltas
// rather than re-reading the shared field under lock for every delta.
func (d *Daemon) shouldSyncUserspaceDelta(ss *cluster.SessionSync, delta dpuserspace.SessionDeltaInfo, ingressZone uint16) bool {
	// Local-delivery sessions are traffic destined TO the firewall itself
	// (management SSH, BGP peering, DHCP, NDP, ICMP echo, etc.).  These are
	// intentionally excluded from HA session sync because:
	//  1. Each cluster node handles its own host-bound traffic independently;
	//     the peer's kernel stack processes its own local-delivery sessions
	//     after failover with no need for synced state.
	//  2. Local-delivery sessions reference node-local ifindexes and addresses
	//     that are meaningless on the peer.
	//  3. The userspace dataplane already sets track_in_userspace=false for
	//     these (afxdp.rs), so they are not in the session sweep; this guard
	//     covers the helper event-stream path.
	// See #315 for discussion.
	if strings.EqualFold(delta.Disposition, "local_delivery") {
		slog.Debug("userspace delta: filtered (local_delivery)", "src", delta.SrcIP, "dst", delta.DstIP)
		return false
	}
	if strings.EqualFold(delta.Origin, "missing_neighbor_seed") {
		slog.Debug("userspace delta: filtered (missing_neighbor_seed)", "src", delta.SrcIP, "dst", delta.DstIP)
		return false
	}
	if delta.FabricRedirect && !delta.FabricIngress {
		return ss != nil
	}
	if delta.OwnerRGID > 0 && ss != nil && ss.IsPrimaryForRGFn != nil {
		ok := ss.IsPrimaryForRGFn(delta.OwnerRGID)
		if !ok {
			slog.Debug("userspace delta: filtered (not primary for owner RG)", "rg", delta.OwnerRGID, "src", delta.SrcIP, "dst", delta.DstIP)
		}
		return ok
	}
	ok := ss != nil && ss.ShouldSyncZone(ingressZone)
	if !ok {
		slog.Debug("userspace delta: filtered (zone not synced)", "zone", ingressZone, "src", delta.SrcIP, "dst", delta.DstIP)
	}
	return ok
}

func (d *Daemon) syncUserspaceSessionDeltas(ctx context.Context) {
	drainer, ok := d.dataplane().(userspaceSessionDeltaDrainer)
	if !ok || d.cluster == nil || d.getSessionSync() == nil {
		return
	}

	const (
		fastInterval      = 100 * time.Millisecond // event stream disconnected
		reconcileInterval = 5 * time.Second        // event stream connected
	)
	ticker := time.NewTicker(fastInterval)
	defer ticker.Stop()
	wasConnected := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Adjust cadence based on event stream state.
		connected := d.eventStreamConnected.Load()
		if connected != wasConnected {
			wasConnected = connected
			if connected {
				ticker.Reset(reconcileInterval)
			} else {
				ticker.Reset(fastInterval)
			}
		}

		ss := d.getSessionSync()
		if d.cluster == nil || ss == nil {
			return
		}
		if !d.cluster.IsLocalPrimaryAny() || !ss.IsConnected() {
			continue
		}
		cfg := d.store.ActiveConfig()
		if cfg == nil {
			continue
		}
		d.userspaceDeltaSyncMu.Lock()
		_, err := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
		d.userspaceDeltaSyncMu.Unlock()
		if err != nil {
			slog.Debug("userspace session delta drain failed", "err", err)
		}
	}
}

// runUserspaceEventStream attempts to consume session events from the helper's
// binary event stream. Falls back to the existing polling loop when the stream
// is unavailable or disconnected.
func (d *Daemon) runUserspaceEventStream(ctx context.Context) {
	if _, ok := d.dataplane().(userspaceEventStreamProvider); !ok {
		// Manager doesn't support event stream — fall back to polling.
		d.syncUserspaceSessionDeltas(ctx)
		return
	}
	wired := d.wireUserspaceEventStreamCallbacks(ctx)
	if wired == nil {
		return
	}
	if d.cluster == nil || d.getSessionSync() == nil {
		return
	}

	slog.Info("userspace: event stream consumer started, polling is primary until stream connects")

	// Monitor connection. When the stream is connected, events arrive via
	// callback and polling drops to 5s reconciliation. When disconnected,
	// polling resumes at 100ms.
	d.eventStreamFallbackLoop(ctx, wired)
}

// currentEventStreamProvider re-resolves the event-stream provider from the
// #2114 cell.
//
// Codex PR #6743 r6-F4: this loop used to CAPTURE the provider once, at
// Phase 5 (daemon_run.go), from the constructed-but-unarmed bootstrap
// backend — before any helper socket existed. If the bootstrap arm then
// failed and cleared the cell (daemon_run_naming.go), nothing cancelled
// this goroutine: it kept polling the STALE, disowned backend every 500ms
// for the daemon's lifetime, which is exactly the escape #2114 exists to
// close. Re-resolving per tick means an emptied cell yields no provider
// and a REPLACED backend yields the new one.
func (d *Daemon) currentEventStreamProvider() (userspaceEventStreamProvider, bool) {
	p, ok := d.dataplane().(userspaceEventStreamProvider)
	return p, ok
}

// wireUserspaceEventStreamCallbacks waits for a stream to exist on the
// CURRENTLY published backend and installs the callbacks on it. It returns
// the stream it wired, or nil if ctx ended first.
func (d *Daemon) wireUserspaceEventStreamCallbacks(ctx context.Context) *dpuserspace.EventStream {
	// Wait for the event stream to become available (helper may not have started yet).
	for {
		if provider, ok := d.currentEventStreamProvider(); ok {
			if es := provider.EventStream(); es != nil {
				d.installEventStreamCallbacks(es)
				return es
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// installEventStreamCallbacks binds the daemon's handlers onto es.
//
// Split out for r6-F4's rewire: the commit-confirmed rollback CLOSES the
// armed backend's stream (pkg/dataplane/userspace/process.go) and a
// corrected re-arm constructs a NEW one. Before r6 the wiring ran once, at
// startup, on a goroutine that had already returned — so the replacement
// stream had no callbacks and its events accumulated in the
// callback-not-ready queue instead of reaching session sync. The fallback
// loop now re-installs whenever it observes a different stream instance.
func (d *Daemon) installEventStreamCallbacks(es *dpuserspace.EventStream) {
	es.SetOnEvent(func(eventType uint8, seq uint64, delta dpuserspace.SessionDeltaInfo) bool {
		return d.handleEventStreamDelta(eventType, delta)
	})
	es.SetOnFullResync(func() bool {
		return d.handleEventStreamFullResync()
	})
	if d.eventReader != nil {
		es.SetOnRawDataplaneEvent(func(seq uint64, payload []byte) {
			if !d.eventReader.ProcessRawEvent(payload) {
				slog.Debug("userspace event stream: dropped undecodable dataplane event", "seq", seq)
			}
		})
	} else {
		es.SetOnDataplaneEvent(func(seq uint64, rec logging.EventRecord) {
			if d.eventBuf != nil {
				d.eventBuf.Add(rec)
			}
		})
	}
}

// handleEventStreamDelta processes a single session event from the event
// stream. It returns true when the delta has been handled, including permanent
// non-owner no-op handling on HA backups. It returns false only for transient
// readiness gaps where EventStream should withhold ACK so the helper can replay.
func (d *Daemon) handleEventStreamDelta(eventType uint8, delta dpuserspace.SessionDeltaInfo) bool {
	ss := d.getSessionSync()
	if d.cluster == nil || ss == nil {
		slog.Debug("userspace delta: ignored (no cluster/sync)", "type", eventType)
		return true
	}
	if !d.cluster.IsLocalPrimaryAny() {
		slog.Debug("userspace delta: ignored (not primary for any RG)", "type", eventType)
		return true
	}
	if !ss.IsConnected() {
		slog.Debug("userspace delta: dropped (sync not connected)", "type", eventType)
		return false
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return false
	}
	zoneIDs := buildZoneIDs(cfg)

	// Map binary event type to the string event expected by queueUserspaceSessionDeltas.
	switch eventType {
	case dpuserspace.EventTypeSessionOpen, dpuserspace.EventTypeSessionUpdate:
		delta.Event = "open"
	case dpuserspace.EventTypeSessionClose:
		delta.Event = "close"
	}

	d.queueUserspaceSessionDeltas(zoneIDs, []dpuserspace.SessionDeltaInfo{delta})
	return true
}

// handleEventStreamFullResync handles a FullResync frame from the helper.
// This means the helper's replay buffer was trimmed past our last ack; we need
// a one-shot bulk export to catch up.
func (d *Daemon) handleEventStreamFullResync() bool {
	slog.Warn("userspace event stream: full resync requested, triggering bulk export")
	ss := d.getSessionSync()
	if d.cluster == nil || ss == nil {
		slog.Debug("userspace event stream: full resync ignored (no cluster/sync)")
		return true
	}
	if !d.cluster.IsLocalPrimaryAny() {
		slog.Debug("userspace event stream: full resync ignored (not primary for any RG)")
		return true
	}
	if !ss.IsConnected() {
		slog.Debug("userspace event stream: full resync deferred (sync not connected)")
		return false
	}
	exporter, ok := d.dataplane().(userspaceSessionExporter)
	if !ok {
		return false
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return false
	}
	rgIDs := d.primaryOwnerRGIDs(cfg)
	if len(rgIDs) == 0 {
		return false
	}
	if _, err := d.exportUserspaceOwnerRGSessionsWithConfig(exporter, cfg, rgIDs); err != nil {
		slog.Warn("userspace event stream: full resync export failed", "err", err)
		return false
	}
	return true
}

// eventStreamFallbackLoop monitors the event stream connection and falls back
// to polling via DrainSessionDeltas when the stream is disconnected.
// When the event stream is live, polling slows to 5s reconciliation;
// when disconnected, it runs at 100ms to compensate for the lost stream.
// wired is the stream whose callbacks are already installed; a different
// instance observed on a later tick is re-wired in place (r6-F4).
func (d *Daemon) eventStreamFallbackLoop(ctx context.Context, wired *dpuserspace.EventStream) {
	drainer, hasDrainer := d.dataplane().(userspaceSessionDeltaDrainer)
	if d.cluster == nil || d.getSessionSync() == nil {
		return
	}

	const (
		fastInterval      = 100 * time.Millisecond // event stream disconnected
		reconcileInterval = 5 * time.Second        // event stream connected
	)
	ticker := time.NewTicker(fastInterval)
	defer ticker.Stop()
	wasConnected := false

	defer d.eventStreamConnected.Store(false)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// r6-F4: re-resolve BOTH the provider and the stream each tick.
		// The provider must come from the cell (a captured one can be a
		// backend the daemon disowned), and a stream instance that is not
		// the one we wired is a post-rollback replacement whose callbacks
		// were never installed.
		var es *dpuserspace.EventStream
		if provider, ok := d.currentEventStreamProvider(); ok {
			es = provider.EventStream()
		}
		if es != nil && es != wired {
			d.installEventStreamCallbacks(es)
			wired = es
			slog.Info("userspace: event stream replaced (rollback/re-arm), callbacks re-installed")
		}
		connected := es != nil && es.IsConnected()

		// Track transitions and adjust cadence.
		if connected != wasConnected {
			wasConnected = connected
			d.eventStreamConnected.Store(connected)
			if connected {
				ticker.Reset(reconcileInterval)
				slog.Info("userspace: event stream connected, polling reduced to reconciliation (5s)")
			} else {
				ticker.Reset(fastInterval)
				slog.Info("userspace: event stream disconnected, polling resumed at 100ms")
			}
		}

		if connected {
			// Stream is live — run reconciliation drain to catch any
			// missed events, but at the slow 5s cadence.
			if !hasDrainer {
				continue
			}
			ss := d.getSessionSync()
			if d.cluster == nil || ss == nil {
				return
			}
			if !d.cluster.IsLocalPrimaryAny() || !ss.IsConnected() {
				continue
			}
			cfg := d.store.ActiveConfig()
			if cfg == nil {
				continue
			}
			d.userspaceDeltaSyncMu.Lock()
			n, _ := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
			d.userspaceDeltaSyncMu.Unlock()
			if n > 0 {
				slog.Info("userspace: reconciliation drain caught missed deltas", "count", n)
			}
			continue
		}

		// Stream disconnected — fall back to fast polling.
		if !hasDrainer {
			continue
		}
		ss := d.getSessionSync()
		if d.cluster == nil || ss == nil {
			return
		}
		if !d.cluster.IsLocalPrimaryAny() || !ss.IsConnected() {
			continue
		}
		cfg := d.store.ActiveConfig()
		if cfg == nil {
			continue
		}
		d.userspaceDeltaSyncMu.Lock()
		_, _ = d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
		d.userspaceDeltaSyncMu.Unlock()
	}
}

func (d *Daemon) queueUserspaceSessionDeltas(
	zoneIDs map[string]uint16,
	deltas []dpuserspace.SessionDeltaInfo,
) int {
	// Snapshot the live session-sync object once for the whole batch (#4958):
	// the per-delta filter and queue calls all operate on this pointer instead
	// of re-reading the shared field, so the hot path never locks per delta and
	// a concurrent stopClusterComms cannot nil the field mid-batch.
	ss := d.getSessionSync()
	if ss == nil {
		return 0
	}
	queued := 0
	for _, delta := range deltas {
		switch strings.ToLower(delta.Event) {
		case "open":
			switch delta.AddrFamily {
			case dataplane.AFInet:
				key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
				if !ok {
					slog.Debug("userspace delta: V4 conversion failed", "src", delta.SrcIP, "dst", delta.DstIP, "disposition", delta.Disposition)
					continue
				}
				if !d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
					continue
				}
				ss.QueueSessionV4(key, val)
				slog.Debug("userspace delta: queued V4", "src", delta.SrcIP, "dst", delta.DstIP, "ownerRG", delta.OwnerRGID)
				queued++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasV4(key, val, delta); ok {
						ss.QueueSessionV4(wireKey, wireVal)
						queued++
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if !ok || !d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
					continue
				}
				ss.QueueSessionV6(key, val)
				queued++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasV6(key, val, delta); ok {
						ss.QueueSessionV6(wireKey, wireVal)
						queued++
					}
				}
			}
		case "close":
			switch delta.AddrFamily {
			case dataplane.AFInet:
				key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
					ss.QueueDeleteV4(key)
					queued++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV4(key, delta)
						if wireKey != key {
							ss.QueueDeleteV4(wireKey)
							queued++
						}
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
					ss.QueueDeleteV6(key)
					queued++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV6(key, delta)
						if wireKey != key {
							ss.QueueDeleteV6(wireKey)
							queued++
						}
					}
				}
			}
		}
	}
	return queued
}

func (d *Daemon) drainUserspaceSessionDeltasWithConfig(
	drainer userspaceSessionDeltaDrainer,
	cfg *config.Config,
	maxBatches int,
) (int, error) {
	if drainer == nil || cfg == nil || maxBatches <= 0 {
		return 0, nil
	}
	zoneIDs := buildZoneIDs(cfg)
	total := 0
	for batch := 0; batch < maxBatches; batch++ {
		deltas, _, err := drainer.DrainSessionDeltas(256)
		if err != nil {
			return total, err
		}
		if len(deltas) == 0 {
			break
		}
		total += d.queueUserspaceSessionDeltas(zoneIDs, deltas)
		if len(deltas) < 256 {
			break
		}
	}
	return total, nil
}
