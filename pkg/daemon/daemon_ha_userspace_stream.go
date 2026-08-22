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

// runUserspaceEventStream consumes session events from the helper's binary
// event stream, falling back to DrainSessionDeltas polling whenever the
// stream is unavailable or disconnected.
//
// Codex PR #6743 r7-F1b: this used to open with a ONE-SHOT probe —
// `if _, ok := d.dataplane().(userspaceEventStreamProvider); !ok` — and, on
// a miss, hand off permanently to a separate polling loop that had no
// wiring logic at all. An empty cell at that instant (the daemon has not
// armed the helper yet, or a bootstrap-arm failure cleared it) therefore
// LATCHED the daemon into pure polling: a corrected commit could publish a
// perfectly healthy provider afterwards and its callbacks were never
// installed, so every helper event sat in the callback-not-ready queue for
// the rest of the process's life. The per-tick drainer resolution (r7-F1)
// does not reach this one — the decision was already made, and on the
// standalone path the goroutine had already returned.
//
// eventStreamFallbackLoop is now the single loop for both roles: it
// re-resolves the provider, the stream and the drainer from the #2114 cell
// every tick, installs callbacks the first time it sees a stream (passing
// nil for `wired` means "nothing wired yet"), and polls at 100 ms while
// disconnected — which is exactly what the deleted polling loop did. So a
// backend published after entry is picked up on the next tick instead of
// being missed forever.
func (d *Daemon) runUserspaceEventStream(ctx context.Context) {
	if d.cluster == nil || d.getSessionSync() == nil {
		// Standalone: no session sync, so nothing to poll or drain — but
		// the helper's DATAPLANE events (RT_FLOW records into the event
		// buffer) still arrive through these callbacks, so they must be
		// installed. wireUserspaceEventStreamCallbacks re-reads the cell
		// every 500 ms until a provider with a stream appears, so an empty
		// cell here is a retry, not a latch.
		//
		// KNOWN GAP (#6743 r2-N5), stated because the sentence above is
		// true of the FIRST wiring only and reads as if the whole path were
		// self-correcting. wireUserspaceEventStreamCallbacks RETURNS once
		// it installs, and this arm returns with it. The re-install on a
		// REPLACED stream instance — the `es != wired` block r6-F4 added —
		// lives in eventStreamFallbackLoop, which this path never runs. So
		// on a standalone (no-cluster) daemon, a commit-confirmed rollback
		// that closes the armed backend's stream followed by a corrected
		// re-arm that constructs a new one leaves the replacement stream
		// with no callbacks: its dataplane events accumulate in the
		// callback-not-ready queue instead of reaching the event buffer,
		// until the daemon restarts.
		//
		// This is PRE-EXISTING in shape — the clustered path had the same
		// hole before r6-F4 and this arm was never converted — and is left
		// alone here rather than fixed blind: the fix is either to run a
		// stream-watch loop on this path too or to hoist the re-install
		// into the wiring helper, and both want their own binder.
		d.wireUserspaceEventStreamCallbacks(ctx)
		return
	}

	slog.Info("userspace: event stream consumer started, polling is primary until stream connects")

	// Monitor connection. When the stream is connected, events arrive via
	// callback and polling drops to 5s reconciliation. When disconnected,
	// polling resumes at 100ms.
	d.eventStreamFallbackLoop(ctx, nil)
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

// currentSessionDeltaDrainer re-resolves the session-delta drainer from the
// #2114 cell. Every tick of the two polling loops must call this immediately
// before the drain, for the SAME reason currentEventStreamProvider exists.
//
// Codex PR #6743 r7-F1: r6-F4 made the provider and the stream per-tick but
// left the drainer captured once, at loop entry, in eventStreamFallbackLoop
// and in the (since removed, see runUserspaceEventStream) sibling polling
// loop. The loop is launched with commsCtx (daemon_ha_sync.go), which only
// stopClusterComms cancels — a dataplane disown does not. So after a
// commit-confirmed
// rollback + a failed corrected re-arm cleared the cell
// (daemon_run_naming.go), the provider correctly resolved to nothing, the
// stream reported disconnected, and the loop dropped to its FAST 100 ms
// branch — where the captured `hasDrainer` was still true and it kept
// calling DrainSessionDeltas on the torn-down, disowned backend (taking
// userspaceDeltaSyncMu each time) for the daemon's lifetime. That is the
// escape #2114 exists to close, at 10 Hz.
//
// The reverse arm matters just as much: a cell that is momentarily empty at
// loop entry used to latch hasDrainer=false (and, in the sibling polling
// loop, RETURN outright), so the reconciliation drain stayed dead for the
// goroutine's life even after a healthy backend was republished. Resolving
// per tick makes both directions self-correcting.
func (d *Daemon) currentSessionDeltaDrainer() (userspaceSessionDeltaDrainer, bool) {
	dr, ok := d.dataplane().(userspaceSessionDeltaDrainer)
	return dr, ok
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

		// r6-F4 / r7-F1: re-resolve the provider, the stream AND the
		// drainer each tick. The provider must come from the cell (a
		// captured one can be a backend the daemon disowned), a stream
		// instance that is not the one we wired is a post-rollback
		// replacement whose callbacks were never installed, and the
		// drainer resolves at each of its two use sites below (see
		// currentSessionDeltaDrainer — a captured one kept draining a
		// disowned backend at 10 Hz).
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
			drainer, hasDrainer := d.currentSessionDeltaDrainer()
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
		drainer, hasDrainer := d.currentSessionDeltaDrainer()
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
	emitV4 := func(key dataplane.SessionKey, val dataplane.SessionValue) {
		ss.QueueSessionV4(key, val)
		queued++
	}
	emitV6 := func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
		ss.QueueSessionV6(key, val)
		queued++
	}
	for _, delta := range deltas {
		switch strings.ToLower(delta.Event) {
		case "open":
			d.forEachUserspaceOpenWireSession(ss, zoneIDs, delta, emitV4, emitV6)
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

// forEachUserspaceOpenWireSession expands ONE "open" session delta into the
// (key, value) pairs that represent it on the cluster session-sync wire, after
// applying the sync filter, and hands each to the family-appropriate callback.
//
// It is the SINGLE definition of "what does this delta look like on the wire" —
// the conversion, the owner-RG/zone filter, and the #4090 fabric forward wire
// alias. Both producers use it: the incremental event-stream path
// (queueUserspaceSessionDeltas, which queues each pair onto sendCh) and the
// #6031 authoritative bulk snapshot (userspaceBulkSessionSnapshot, which
// collects them into the window). A divergence between those two is always a
// bug — the bulk window is meant to be exactly the set the incremental stream
// would have delivered — so they share one walk instead of two copies that can
// drift.
//
// Callback-shaped rather than slice-returning so the incremental path, which
// runs once per session event, allocates nothing per delta: each caller builds
// its closures once per batch.
func (d *Daemon) forEachUserspaceOpenWireSession(
	ss *cluster.SessionSync,
	zoneIDs map[string]uint16,
	delta dpuserspace.SessionDeltaInfo,
	v4 func(dataplane.SessionKey, dataplane.SessionValue),
	v6 func(dataplane.SessionKeyV6, dataplane.SessionValueV6),
) {
	switch delta.AddrFamily {
	case dataplane.AFInet:
		key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
		if !ok {
			slog.Debug("userspace delta: V4 conversion failed", "src", delta.SrcIP, "dst", delta.DstIP, "disposition", delta.Disposition)
			return
		}
		if !d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
			return
		}
		v4(key, val)
		slog.Debug("userspace delta: queued V4", "src", delta.SrcIP, "dst", delta.DstIP, "ownerRG", delta.OwnerRGID)
		if delta.FabricRedirect && !delta.FabricIngress {
			if wireKey, wireVal, ok := userspaceForwardWireAliasV4(key, val, delta); ok {
				v4(wireKey, wireVal)
			}
		}
	case dataplane.AFInet6:
		key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
		if !ok || !d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
			return
		}
		v6(key, val)
		if delta.FabricRedirect && !delta.FabricIngress {
			if wireKey, wireVal, ok := userspaceForwardWireAliasV6(key, val, delta); ok {
				v6(wireKey, wireVal)
			}
		}
	}
}

// userspaceBulkSessionSnapshot builds the AUTHORITATIVE session set for one
// cluster bulk window from the userspace dataplane's TABLE-TRUTH export
// (#6031), and is installed as SessionSync.BulkSessionSource.
//
// Before this, BulkSync sourced the window from s.sessions.ForEachV4/V6 — which
// on the userspace dataplane walks the BPF conntrack maps the Rust helper
// publishes as a best-effort DISPLAY MIRROR (publish_bpf_conntrack_entry, so
// `show security flow session` can render zone/interface info), not the helper's
// authoritative in-process SessionTable. The mirror can drift: publication is
// gated at table cap and on install_failed, the periodic refresh lags, and the
// mirror carries no per-session ORIGIN, so it also echoes peer-owned imports
// back at their owner. Since #5085 removed the empty-bulk reconcile skip, a
// transiently under-populated mirror at cold-prime reconciles away LIVE
// peer-owned sessions on the standby.
//
// ExportOwnerRGSessions is the table-truth walk (control verb
// `export_owner_rg_sessions`), filtered to the redundancy groups this node is
// primary for and skipping locally-demoted entries — so the window is both
// complete and owner-RG accurate, which the zone-level ShouldSyncZone
// approximation could not be.
//
// Return contract (SessionSync.BulkSessionSource):
//
//   - (nil, nil) when there is no authoritative source to consult — no
//     published runtime, a runtime that is not the userspace exporter, or no
//     committed config. BulkSync then falls back to the store walk, exactly as
//     before, so nothing regresses where no table-truth exists.
//   - (empty, nil) when this node is primary for NO redundancy group. That is
//     an authoritative "I own nothing to sync", NOT an absent source: the peer
//     must reconcile away sessions it still holds on our behalf. Returning
//     (nil, nil) here would silently fall back to the mirror and re-push the
//     peer's own imports back at it.
//   - (nil, err) when the export itself failed. BulkSync ABORTS rather than
//     falling back — see the field doc for why an incomplete window is the
//     unrecoverable direction.
func (d *Daemon) userspaceBulkSessionSnapshot() (*cluster.BulkSessionSnapshot, error) {
	if d.getSessionSync() == nil {
		return nil, nil
	}
	rt := d.dataplane()
	if rt == nil {
		return nil, nil
	}
	exporter, ok := rt.(userspaceSessionExporter)
	if !ok {
		return nil, nil
	}
	if d.store == nil {
		return nil, nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return nil, nil
	}
	// Read the CURRENT active config's RG set on every call, never a startup
	// snapshot: a day-2 commit can add a redundancy group (#3917) and its
	// sessions must ride the very next bulk window.
	return d.buildUserspaceBulkSnapshotWithConfig(exporter, cfg, d.primaryOwnerRGIDs(cfg))
}

// buildUserspaceBulkSnapshotWithConfig is the config-taking half of
// userspaceBulkSessionSnapshot, split out so the export -> convert -> filter
// pipeline is drivable in a unit test without a published runtime. It mirrors
// exportUserspaceOwnerRGSessionsWithConfig, which does the same walk for the
// full-resync path but QUEUES onto the lossy sendCh instead of collecting.
//
// An empty rgIDs set returns an EMPTY, non-nil snapshot: this node owns no
// syncable sessions, which is an authoritative statement the peer must
// reconcile against, not an absent source.
func (d *Daemon) buildUserspaceBulkSnapshotWithConfig(
	exporter userspaceSessionExporter,
	cfg *config.Config,
	rgIDs []int,
) (*cluster.BulkSessionSnapshot, error) {
	snapshot := &cluster.BulkSessionSnapshot{}
	if exporter == nil || cfg == nil || len(rgIDs) == 0 {
		return snapshot, nil
	}
	deltas, _, err := exporter.ExportOwnerRGSessions(rgIDs, 0)
	if err != nil {
		return nil, err
	}
	ss := d.getSessionSync()
	zoneIDs := buildZoneIDs(cfg)
	appendV4 := func(key dataplane.SessionKey, val dataplane.SessionValue) {
		snapshot.V4 = append(snapshot.V4, dataplane.SessionEntryV4{Key: key, Value: val})
	}
	appendV6 := func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
		snapshot.V6 = append(snapshot.V6, dataplane.SessionEntryV6{Key: key, Value: val})
	}
	for _, delta := range deltas {
		// The export yields the live table, so every record is an "open".
		// Anything else would be a helper bug; skipping it keeps a stray
		// close-shaped record from being framed as a live session.
		if delta.Event != "" && !strings.EqualFold(delta.Event, "open") {
			continue
		}
		d.forEachUserspaceOpenWireSession(ss, zoneIDs, delta, appendV4, appendV6)
	}
	return snapshot, nil
}
