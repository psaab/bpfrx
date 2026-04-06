package daemon

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/bpfrx/pkg/cluster"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/dataplane"
	dpuserspace "github.com/psaab/bpfrx/pkg/dataplane/userspace"
	"github.com/psaab/bpfrx/pkg/vrrp"
)

func (d *Daemon) stopSyncReadyTimer() {
	d.syncReadyTimerMu.Lock()
	defer d.syncReadyTimerMu.Unlock()
	d.syncReadyTimerGen.Add(1)
	if d.syncReadyTimer != nil {
		d.syncReadyTimer.Stop()
		d.syncReadyTimer = nil
	}
}

func (d *Daemon) armSyncReadyTimer() {
	if d.cluster == nil || d.syncReadyTimeout <= 0 {
		return
	}
	timerGen := d.syncReadyTimerGen.Add(1)
	d.syncReadyTimerMu.Lock()
	defer d.syncReadyTimerMu.Unlock()
	if d.syncReadyTimer != nil {
		d.syncReadyTimer.Stop()
	}
	timeout := d.syncReadyTimeout
	d.syncReadyTimer = time.AfterFunc(timeout, func() {
		if d.syncReadyTimerGen.Load() != timerGen || !d.syncPeerConnected.Load() {
			return
		}
		if d.cluster != nil && !d.cluster.IsSyncReady() {
			slog.Info("cluster: sync readiness timeout, releasing hold")
			d.cluster.SetSyncReady(true)
		}
	})
}

func (d *Daemon) onSessionSyncPeerConnected() {
	d.syncPeerConnected.Store(true)
	d.hbSuppressStart.Store(0) // fresh connection → reset suppression cap

	// Determine whether this is a true cold start or a routine reconnect.
	// A cold start means no bulk sync has ever completed during this
	// daemon's lifetime — the peer (or we) genuinely started from scratch.
	// On a routine reconnect after a brief network blip, the sessions are
	// already synced; preserve the primed state and sync readiness (#466).
	coldStart := d.sessionSync == nil || !d.sessionSync.BulkEverCompleted()

	if coldStart {
		d.syncBulkPrimed.Store(false)
		d.syncPeerBulkPrimed.Store(false)
	}

	gen := d.syncPrimeRetryGen.Add(1)
	slog.Info("cluster: session sync peer connected",
		"retry_gen", gen,
		"cold_start", coldStart,
		"bulk_primed", d.syncBulkPrimed.Load(),
		"peer_bulk_primed", d.syncPeerBulkPrimed.Load(),
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())

	if coldStart {
		if d.cluster != nil {
			d.cluster.SetSyncReady(false)
		}
		d.armSyncReadyTimer()
		d.startSessionSyncPrimeRetry(gen)
	}
}

func (d *Daemon) onSessionSyncBulkReceived() {
	d.syncBulkPrimed.Store(true)
	slog.Info("cluster: session sync bulk received",
		"retry_gen", d.syncPrimeRetryGen.Load())
	d.stopSyncReadyTimer()
	if d.vrrpMgr != nil {
		d.vrrpMgr.ReleaseSyncHold()
	}
	if d.cluster != nil {
		d.cluster.SetSyncReady(true)
	}
}

func (d *Daemon) onSessionSyncBulkAckReceived() {
	d.syncPeerBulkPrimed.Store(true)
	slog.Info("cluster: session sync bulk ack received",
		"retry_gen", d.syncPrimeRetryGen.Load())
}

func (d *Daemon) onSessionSyncPeerDisconnected() {
	d.syncPeerConnected.Store(false)
	gen := d.syncPrimeRetryGen.Add(1)

	// On disconnect after a completed bulk exchange, preserve primed state
	// and sync readiness. The sessions are still in the BPF maps — a
	// subsequent reconnect will resume incremental sync without needing a
	// full bulk transfer (#466).
	wasEverPrimed := d.sessionSync != nil && d.sessionSync.BulkEverCompleted()
	if !wasEverPrimed {
		d.syncBulkPrimed.Store(false)
		d.syncPeerBulkPrimed.Store(false)
	}

	slog.Info("cluster: session sync peer disconnected",
		"retry_gen", gen,
		"was_ever_primed", wasEverPrimed,
		"bulk_primed", d.syncBulkPrimed.Load(),
		"peer_bulk_primed", d.syncPeerBulkPrimed.Load(),
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())
	d.stopSyncReadyTimer()

	if !wasEverPrimed {
		if d.cluster != nil {
			d.cluster.SetSyncReady(false)
		}
	}
}

func (d *Daemon) shouldSuppressPeerHeartbeatTimeout() (bool, string) {
	ss := d.sessionSync
	if ss == nil || !ss.IsConnected() {
		d.hbSuppressStart.Store(0) // reset when sync disconnected
		return false, ""
	}
	const maxPeerSyncSilence = 2 * time.Second
	age, ok := ss.LastPeerReceiveAge()
	if !ok || age > maxPeerSyncSilence {
		d.hbSuppressStart.Store(0) // reset when sync goes quiet
		return false, ""
	}

	// Cap total suppression duration. During graceful shutdown the peer
	// may send a bulk sync that keeps LastPeerReceiveAge() fresh for tens
	// of seconds while heartbeats have already stopped. After 5s of
	// continuous suppression, stop suppressing so the heartbeat timeout
	// can fire and trigger failover.
	const maxSuppressDuration = 5 * time.Second
	now := time.Now().UnixNano()
	start := d.hbSuppressStart.Load()
	if start == 0 {
		d.hbSuppressStart.Store(now)
		start = now
	}
	if time.Duration(now-start) > maxSuppressDuration {
		return false, ""
	}

	return true, fmt.Sprintf("session sync connected with recent peer traffic age=%s", age.Truncate(10*time.Millisecond))
}

func syncPrimeProgressObserved(current, baseline cluster.SyncStatsSnapshot) bool {
	return current.SessionsReceived > baseline.SessionsReceived ||
		current.SessionsInstalled > baseline.SessionsInstalled ||
		current.DeletesReceived > baseline.DeletesReceived
}

func (d *Daemon) startSessionSyncPrimeRetry(gen uint64) {
	ss := d.sessionSync
	if ss == nil || d.dp == nil {
		return
	}
	go func() {
		intervals := []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
		const retryWhileAckPendingAfter = 35 * time.Second
		maxAttempts := len(intervals)
		baseline := ss.Stats()
		slog.Info("cluster: starting session sync bulk-prime retry loop",
			"retry_gen", gen,
			"max_attempts", maxAttempts,
			"intervals", intervals)
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if wait := intervals[attempt-1]; wait > 0 {
				time.Sleep(wait)
			}
			if d.syncPrimeRetryGen.Load() != gen {
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "generation advanced")
				return
			}
			if d.syncPeerBulkPrimed.Load() {
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "peer bulk ack received")
				return
			}
			if d.sessionSync != ss || !ss.IsConnected() {
				reason := "session sync replaced"
				if d.sessionSync == ss && !ss.IsConnected() {
					reason = "session sync disconnected"
				}
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", reason)
				return
			}
			if pendingEpoch, pendingAge, ok := ss.PendingBulkAck(); ok && pendingAge < retryWhileAckPendingAfter {
				slog.Info("cluster: deferring session sync bulk-prime retry",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "outbound bulk still awaiting ack",
					"pending_epoch", pendingEpoch,
					"pending_age", pendingAge.Round(10*time.Millisecond),
					"retry_after", retryWhileAckPendingAfter)
				continue
			}
			current := ss.Stats()
			if syncPrimeProgressObserved(current, baseline) {
				slog.Info("cluster: deferring session sync bulk-prime retry",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "peer sync progress observed",
					"sessions_received", current.SessionsReceived,
					"sessions_installed", current.SessionsInstalled,
					"deletes_received", current.DeletesReceived,
					"baseline_sessions_received", baseline.SessionsReceived,
					"baseline_sessions_installed", baseline.SessionsInstalled,
					"baseline_deletes_received", baseline.DeletesReceived)
				baseline = current
				continue
			}
			slog.Info("cluster: retrying session sync bulk prime",
				"retry_gen", gen,
				"attempt", attempt,
				"connected", ss.IsConnected(),
				"sessions_received", current.SessionsReceived,
				"sessions_installed", current.SessionsInstalled,
				"deletes_received", current.DeletesReceived,
				"baseline_sessions_received", baseline.SessionsReceived,
				"baseline_sessions_installed", baseline.SessionsInstalled,
				"baseline_deletes_received", baseline.DeletesReceived)
			if err := d.bulkSyncViaEventStreamOrFallback(ss); err != nil {
				slog.Warn("cluster: session sync bulk prime retry failed",
					"retry_gen", gen,
					"attempt", attempt,
					"err", err)
				continue
			}
			if d.syncPeerBulkPrimed.Load() {
				slog.Info("cluster: session sync bulk prime retry loop observed bulk ack",
					"retry_gen", gen,
					"attempt", attempt)
				return
			}
		}
		slog.Warn("cluster: session sync bulk-prime retry loop exhausted",
			"retry_gen", gen,
			"attempts", maxAttempts)
	}()
}

// bulkSyncViaEventStreamOrFallback attempts to export all sessions via the
// event stream (fast path — sessions flow through the existing event stream
// callback into QueueSessionV4/V6). Falls back to the old BulkSync path
// (iterating BPF maps from Go) when the event stream isn't available.
func (d *Daemon) bulkSyncViaEventStreamOrFallback(ss *cluster.SessionSync) error {
	if exporter, ok := d.dp.(userspaceEventStreamExporter); ok {
		slog.Info("cluster: using event stream export for bulk sync")
		if err := exporter.ExportAllSessionsViaEventStream(); err != nil {
			slog.Warn("cluster: event stream bulk export failed, falling back to BulkSync", "err", err)
		} else {
			slog.Info("cluster: exported sessions via event stream for bulk sync")
			return nil
		}
	}
	slog.Info("cluster: event stream export not available, falling back to BulkSync",
		"dp_type", fmt.Sprintf("%T", d.dp))
	if ss == nil {
		return fmt.Errorf("session sync not initialized")
	}
	return ss.BulkSync()
}

// buildZoneIDs replicates the deterministic zone ID assignment from the
// dataplane compiler (sorted zone names, 1-based sequential IDs).
func buildZoneIDs(cfg *config.Config) map[string]uint16 {
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	ids := make(map[string]uint16, len(names))
	for i, name := range names {
		ids[name] = uint16(i + 1)
	}
	return ids
}

type userspaceSessionDeltaDrainer interface {
	DrainSessionDeltas(max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error)
}

type userspaceSessionExporter interface {
	ExportOwnerRGSessions(rgIDs []int, max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error)
}

type userspaceEventStreamProvider interface {
	EventStream() *dpuserspace.EventStream
}

type userspaceEventStreamExporter interface {
	ExportAllSessionsViaEventStream() error
}

func daemonMonotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

func userspaceSessionTimeout(proto uint8) uint32 {
	switch proto {
	case 6:
		return 300
	case 17:
		return 60
	case 1, 58:
		return 15
	default:
		return 30
	}
}

func userspaceHostToNetwork16(v uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	return binary.NativeEndian.Uint16(raw[:])
}

func userspaceNetworkToHost16(v uint16) uint16 {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], v)
	return binary.BigEndian.Uint16(raw[:])
}

func userspaceReverseKeyV4(key dataplane.SessionKey, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKey {
	rev := dataplane.SessionKey{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		copy(rev.SrcIP[:], ip)
	}
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		copy(rev.DstIP[:], ip)
	}
	if delta.NATDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(delta.NATDstPort)
	}
	if delta.NATSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(delta.NATSrcPort)
	}
	return rev
}

func userspaceForwardWireKeyV4(key dataplane.SessionKey, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKey {
	wire := key
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		copy(wire.SrcIP[:], ip)
		wire.SrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		copy(wire.DstIP[:], ip)
		wire.DstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	return wire
}

func effectiveUserspaceNATSrcPort(delta dpuserspace.SessionDeltaInfo) uint16 {
	if delta.NATSrcPort != 0 {
		return delta.NATSrcPort
	}
	if delta.NATSrcIP != "" {
		return delta.SrcPort
	}
	return 0
}

func effectiveUserspaceNATDstPort(delta dpuserspace.SessionDeltaInfo) uint16 {
	if delta.NATDstPort != 0 {
		return delta.NATDstPort
	}
	if delta.NATDstIP != "" {
		return delta.DstPort
	}
	return 0
}

func userspaceReverseKeyV6(key dataplane.SessionKeyV6, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKeyV6 {
	rev := dataplane.SessionKeyV6{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		copy(rev.SrcIP[:], ip)
	}
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		copy(rev.DstIP[:], ip)
	}
	if delta.NATDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(delta.NATDstPort)
	}
	if delta.NATSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(delta.NATSrcPort)
	}
	return rev
}

func userspaceParseSyncMAC(raw string) [6]byte {
	var out [6]byte
	if raw == "" {
		return out
	}
	mac, err := net.ParseMAC(raw)
	if err != nil || len(mac) != len(out) {
		return out
	}
	copy(out[:], mac)
	return out
}

func userspaceSessionFromDeltaV4(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	src := net.ParseIP(delta.SrcIP).To4()
	dst := net.ParseIP(delta.DstIP).To4()
	if src == nil || dst == nil {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	var key dataplane.SessionKey
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	ingressZone := zoneIDs[delta.IngressZone]
	egressZone := zoneIDs[delta.EgressZone]
	if ingressZone == 0 || egressZone == 0 {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValue{
		State:       4, // SESS_STATE_ESTABLISHED
		SessionID:   uint64(now)<<16 | uint64(delta.Slot&0xffff),
		Created:     now,
		LastSeen:    now,
		Timeout:     userspaceSessionTimeout(delta.Protocol),
		IngressZone: ingressZone,
		EgressZone:  egressZone,
		ReverseKey:  userspaceReverseKeyV4(key, delta),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = userspaceParseSyncMAC(delta.NeighborMAC)
	val.FibSmac = userspaceParseSyncMAC(delta.SrcMAC)
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		val.Flags |= dataplane.SessFlagSNAT
		val.NATSrcIP = binary.NativeEndian.Uint32(ip)
		val.NATSrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		val.Flags |= dataplane.SessFlagDNAT
		val.NATDstIP = binary.NativeEndian.Uint32(ip)
		val.NATDstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	return key, val, true
}

func userspaceForwardWireAliasFromDeltaV4(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	wireKey := userspaceForwardWireKeyV4(key, delta)
	if wireKey == key {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	return wireKey, val, true
}

func userspaceSessionFromDeltaV6(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	src := net.ParseIP(delta.SrcIP).To16()
	dst := net.ParseIP(delta.DstIP).To16()
	if src == nil || dst == nil {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	var key dataplane.SessionKeyV6
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	ingressZone := zoneIDs[delta.IngressZone]
	egressZone := zoneIDs[delta.EgressZone]
	if ingressZone == 0 || egressZone == 0 {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValueV6{
		State:       4, // SESS_STATE_ESTABLISHED
		SessionID:   uint64(now)<<16 | uint64(delta.Slot&0xffff),
		Created:     now,
		LastSeen:    now,
		Timeout:     userspaceSessionTimeout(delta.Protocol),
		IngressZone: ingressZone,
		EgressZone:  egressZone,
		ReverseKey:  userspaceReverseKeyV6(key, delta),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = userspaceParseSyncMAC(delta.NeighborMAC)
	val.FibSmac = userspaceParseSyncMAC(delta.SrcMAC)
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		val.Flags |= dataplane.SessFlagSNAT
		copy(val.NATSrcIP[:], ip)
		val.NATSrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		val.Flags |= dataplane.SessFlagDNAT
		copy(val.NATDstIP[:], ip)
		val.NATDstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	return key, val, true
}

func userspaceForwardWireKeyV6(key dataplane.SessionKeyV6, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKeyV6 {
	wire := key
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		copy(wire.SrcIP[:], ip)
		wire.SrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		copy(wire.DstIP[:], ip)
		wire.DstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	return wire
}

func userspaceForwardWireAliasFromDeltaV6(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	wireKey := userspaceForwardWireKeyV6(key, delta)
	if wireKey == key {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	return wireKey, val, true
}

func (d *Daemon) shouldSyncUserspaceDelta(delta dpuserspace.SessionDeltaInfo, ingressZone uint16) bool {
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
	if delta.FabricRedirect && !delta.FabricIngress {
		return d.sessionSync != nil
	}
	if delta.OwnerRGID > 0 && d.sessionSync != nil && d.sessionSync.IsPrimaryForRGFn != nil {
		ok := d.sessionSync.IsPrimaryForRGFn(delta.OwnerRGID)
		if !ok {
			slog.Debug("userspace delta: filtered (not primary for owner RG)", "rg", delta.OwnerRGID, "src", delta.SrcIP, "dst", delta.DstIP)
		}
		return ok
	}
	ok := d.sessionSync != nil && d.sessionSync.ShouldSyncZone(ingressZone)
	if !ok {
		slog.Debug("userspace delta: filtered (zone not synced)", "zone", ingressZone, "src", delta.SrcIP, "dst", delta.DstIP)
	}
	return ok
}

// buildZoneRGMap builds a zone_id→RG mapping by looking up which interfaces
// belong to each zone, then checking those interfaces' RedundancyGroup.
// Zones with RETH interfaces inherit the RETH's RG; non-RETH zones are not
// included (they fall back to global IsPrimaryFn in session sync).
func buildZoneRGMap(cfg *config.Config, zoneIDs map[string]uint16) map[uint16]int {
	result := make(map[uint16]int)
	for zoneName, zone := range cfg.Security.Zones {
		zid, ok := zoneIDs[zoneName]
		if !ok {
			continue
		}
		rgSeen := -1
		for _, ifName := range zone.Interfaces {
			// Strip unit suffix (e.g. "reth0.0" → "reth0") for config lookup.
			baseName := ifName
			if idx := strings.IndexByte(ifName, '.'); idx >= 0 {
				baseName = ifName[:idx]
			}
			if ifc, ok := cfg.Interfaces.Interfaces[baseName]; ok && ifc.RedundancyGroup > 0 {
				if rgSeen >= 0 && rgSeen != ifc.RedundancyGroup {
					slog.Warn("zone spans multiple redundancy groups; "+
						"active/active session sync ownership is ambiguous",
						"zone", zoneName,
						"rg1", rgSeen, "rg2", ifc.RedundancyGroup)
				}
				if rgSeen < 0 {
					result[zid] = ifc.RedundancyGroup
					rgSeen = ifc.RedundancyGroup
				}
			}
		}
	}
	return result
}

// rgHasRETH returns whether the given redundancy group has any RETH interfaces.
func rgHasRETH(cfg *config.Config, rgID int) bool {
	if cfg == nil {
		return false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}

func (d *Daemon) syncUserspaceSessionDeltas(ctx context.Context) {
	drainer, ok := d.dp.(userspaceSessionDeltaDrainer)
	if !ok || d.cluster == nil || d.sessionSync == nil {
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

		if d.cluster == nil || d.sessionSync == nil {
			return
		}
		if !d.cluster.IsLocalPrimaryAny() || !d.sessionSync.IsConnected() {
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
	provider, ok := d.dp.(userspaceEventStreamProvider)
	if !ok || d.cluster == nil || d.sessionSync == nil {
		// Manager doesn't support event stream — fall back to polling.
		d.syncUserspaceSessionDeltas(ctx)
		return
	}

	// Wait for the event stream to become available (helper may not have started yet).
	var es *dpuserspace.EventStream
	for {
		es = provider.EventStream()
		if es != nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Wire callbacks.
	es.SetOnEvent(func(eventType uint8, seq uint64, delta dpuserspace.SessionDeltaInfo) {
		d.handleEventStreamDelta(eventType, delta)
	})
	es.SetOnFullResync(func() {
		d.handleEventStreamFullResync()
	})

	slog.Info("userspace: event stream consumer started, polling is primary until stream connects")

	// Monitor connection. When the stream is connected, events arrive via
	// callback and polling drops to 5s reconciliation. When disconnected,
	// polling resumes at 100ms.
	d.eventStreamFallbackLoop(ctx, provider)
}

// handleEventStreamDelta processes a single session event from the event stream.
func (d *Daemon) handleEventStreamDelta(eventType uint8, delta dpuserspace.SessionDeltaInfo) {
	if d.cluster == nil || d.sessionSync == nil {
		slog.Debug("userspace delta: dropped (no cluster/sync)", "type", eventType)
		return
	}
	if !d.cluster.IsLocalPrimaryAny() {
		slog.Debug("userspace delta: dropped (not primary for any RG)", "type", eventType)
		return
	}
	if !d.sessionSync.IsConnected() {
		slog.Debug("userspace delta: dropped (sync not connected)", "type", eventType)
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
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
}

// handleEventStreamFullResync handles a FullResync frame from the helper.
// This means the helper's replay buffer was trimmed past our last ack; we need
// a one-shot bulk export to catch up.
func (d *Daemon) handleEventStreamFullResync() {
	slog.Warn("userspace event stream: full resync requested, triggering bulk export")
	exporter, ok := d.dp.(userspaceSessionExporter)
	if !ok {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// Export sessions for all RGs we're primary for.
	var rgIDs []int
	if d.cluster != nil {
		for rgID := 0; rgID < 16; rgID++ {
			if d.cluster.IsLocalPrimary(rgID) {
				rgIDs = append(rgIDs, rgID)
			}
		}
	}
	if len(rgIDs) == 0 {
		return
	}
	if _, err := d.exportUserspaceOwnerRGSessionsWithConfig(exporter, cfg, rgIDs); err != nil {
		slog.Warn("userspace event stream: full resync export failed", "err", err)
	}
}

// eventStreamFallbackLoop monitors the event stream connection and falls back
// to polling via DrainSessionDeltas when the stream is disconnected.
// When the event stream is live, polling slows to 5s reconciliation;
// when disconnected, it runs at 100ms to compensate for the lost stream.
func (d *Daemon) eventStreamFallbackLoop(ctx context.Context, provider userspaceEventStreamProvider) {
	drainer, hasDrainer := d.dp.(userspaceSessionDeltaDrainer)

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

		es := provider.EventStream()
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
			if d.cluster == nil || d.sessionSync == nil {
				return
			}
			if !d.cluster.IsLocalPrimaryAny() || !d.sessionSync.IsConnected() {
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
		if d.cluster == nil || d.sessionSync == nil {
			return
		}
		if !d.cluster.IsLocalPrimaryAny() || !d.sessionSync.IsConnected() {
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
	if d.sessionSync == nil {
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
				if !d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					continue
				}
				d.sessionSync.QueueSessionV4(key, val)
				slog.Debug("userspace delta: queued V4", "src", delta.SrcIP, "dst", delta.DstIP, "ownerRG", delta.OwnerRGID)
				queued++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasFromDeltaV4(delta, zoneIDs); ok {
						d.sessionSync.QueueSessionV4(wireKey, wireVal)
						queued++
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if !ok || !d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					continue
				}
				d.sessionSync.QueueSessionV6(key, val)
				queued++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasFromDeltaV6(delta, zoneIDs); ok {
						d.sessionSync.QueueSessionV6(wireKey, wireVal)
						queued++
					}
				}
			}
		case "close":
			switch delta.AddrFamily {
			case dataplane.AFInet:
				key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					d.sessionSync.QueueDeleteV4(key)
					queued++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV4(key, delta)
						if wireKey != key {
							d.sessionSync.QueueDeleteV4(wireKey)
							queued++
						}
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					d.sessionSync.QueueDeleteV6(key)
					queued++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV6(key, delta)
						if wireKey != key {
							d.sessionSync.QueueDeleteV6(wireKey)
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

func (d *Daemon) exportUserspaceOwnerRGSessionsWithConfig(
	exporter userspaceSessionExporter,
	cfg *config.Config,
	rgIDs []int,
) (int, error) {
	if exporter == nil || cfg == nil || len(rgIDs) == 0 {
		return 0, nil
	}
	deltas, _, err := exporter.ExportOwnerRGSessions(rgIDs, 0)
	if err != nil {
		return 0, err
	}
	return d.queueUserspaceSessionDeltas(buildZoneIDs(cfg), deltas), nil
}

func (d *Daemon) tryPrepareUserspaceRGDemotion(rgID int) {
	if err := d.prepareUserspaceRGDemotionWithTimeout(rgID, 5*time.Second); err != nil {
		slog.Warn("userspace: prepare rg demotion failed", "rg", rgID, "err", err)
	}
}

func (d *Daemon) acquireUserspaceRGDemotionPrep(rgID int, hold time.Duration) bool {
	d.userspaceDemotionPrepMu.Lock()
	defer d.userspaceDemotionPrepMu.Unlock()
	now := time.Now()
	if until, ok := d.userspaceDemotionPrepUntil[rgID]; ok && now.Before(until) {
		return false
	}
	if hold < 10*time.Second {
		hold = 10 * time.Second
	}
	d.userspaceDemotionPrepUntil[rgID] = now.Add(hold)
	return true
}

// releaseUserspaceRGDemotionPrep clears the suppression window so retries
// (e.g. manual failover admission) can re-attempt demotion prep immediately.
func (d *Daemon) releaseUserspaceRGDemotionPrep(rgID int) {
	d.userspaceDemotionPrepMu.Lock()
	defer d.userspaceDemotionPrepMu.Unlock()
	delete(d.userspaceDemotionPrepUntil, rgID)
}

func (d *Daemon) prepareUserspaceRGDemotion(rgID int) error {
	return d.prepareUserspaceRGDemotionWithTimeout(rgID, 30*time.Second)
}

func wrapUserspaceManualFailoverPrepareError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "previous demotion barrier still pending") ||
		strings.Contains(msg, "session sync not ready before demotion") ||
		strings.Contains(msg, "session sync peer not quiescent before demotion") ||
		strings.Contains(msg, "demotion peer barrier failed") {
		return &cluster.RetryablePreFailoverError{Err: err}
	}
	return err
}

func userspaceManualFailoverTransferReadinessError(state cluster.TransferReadinessSnapshot) error {
	if state.ReadyForManualFailover() {
		return nil
	}
	if reason := state.Reason(); reason != "" {
		return fmt.Errorf("session sync transfer not ready before demotion: %s", reason)
	}
	return nil
}

func (d *Daemon) userspaceTransferReadiness(rgID int) (bool, []string) {
	if d.sessionSync == nil || !d.sessionSync.IsConnected() || !d.syncPeerConnected.Load() {
		return false, []string{"session sync disconnected"}
	}
	state := d.sessionSync.TransferReadiness()
	if state.ReadyForManualFailover() {
		return true, nil
	}
	if reason := state.Reason(); reason != "" {
		return false, []string{reason}
	}
	return true, nil
}

func (d *Daemon) prepareUserspaceManualFailover(rgID int) error {
	return wrapUserspaceManualFailoverPrepareError(
		d.prepareUserspaceRGDemotionWithTimeout(rgID, 60*time.Second),
	)
}

func (d *Daemon) prepareUserspaceRGDemotionWithTimeout(rgID int, barrierTimeout time.Duration) error {
	if !d.acquireUserspaceRGDemotionPrep(rgID, barrierTimeout) {
		slog.Info("userspace: skipping duplicate rg demotion prepare", "rg", rgID)
		return nil
	}
	success := false
	defer func() {
		if !success {
			d.releaseUserspaceRGDemotionPrep(rgID)
		}
	}()
	if d.sessionSync == nil || !d.sessionSync.IsConnected() {
		// Release suppression window so a reconnect + retry can re-run
		// the barrier check before the actual demotion proceeds.
		d.releaseUserspaceRGDemotionPrep(rgID)
		success = true
		return nil
	}
	// Transfer readiness (bulk sync state) is NOT checked here.
	// The barrier at the end of this function proves the peer has all
	// sessions. Planned failover should not depend on bulk sync state —
	// both nodes have full session state from continuous real-time sync.

	// Stop the bulk sync retry loop — it floods the sync TCP connection
	// with session data, delaying the barrier write/ack by 30+ seconds.
	// Advancing the retry generation causes the goroutine to exit.
	retryGen := d.syncPrimeRetryGen.Add(1)

	// If the barrier fails, restart the retry loop so the peer can still
	// receive its cold-start bootstrap. Only suppress the restart when
	// the barrier succeeds and the demotion completes (success=true).
	defer func() {
		if success {
			return
		}
		if d.syncPeerBulkPrimed.Load() {
			return // peer already primed, no retry needed
		}
		ss := d.sessionSync
		if ss == nil || !ss.IsConnected() {
			return // peer disconnected, retry would be pointless
		}
		if d.syncPrimeRetryGen.Load() != retryGen {
			return // a newer retry generation is already active
		}
		slog.Info("cluster: restarting bulk-prime retry loop after failed demotion prep",
			"retry_gen", retryGen, "rg", rgID)
		d.startSessionSyncPrimeRetry(retryGen)
	}()

	// Single barrier — peer ack means it has processed all queued deltas.
	// The actual demotion happens atomically in UpdateRGActive(false).
	if err := d.sessionSync.WaitForPeerBarrier(barrierTimeout); err != nil {
		return fmt.Errorf("demotion peer barrier failed: %w", err)
	}

	success = true
	slog.Info("userspace: peer barrier ready for rg demotion", "rg", rgID)
	return nil
}

// syncConfigToPeer sends the active config to the cluster peer if this node
// is primary and config sync is enabled.
func (d *Daemon) syncConfigToPeer() {
	if d.cluster == nil || d.sessionSync == nil {
		return
	}
	// Only sync if this node is primary for RG0 (config ownership group).
	if !d.cluster.IsLocalPrimary(0) {
		return
	}
	d.pushConfigToPeer()
}

// pushConfigToPeer sends the active config to the cluster peer unconditionally
// (does not check primary/secondary status). Used both by normal commit sync
// and by the peer-reconnect path where the stable node pushes its config
// regardless of whether it was preempted.
func (d *Daemon) pushConfigToPeer() {
	if d.sessionSync == nil {
		return
	}
	// Check if config sync is enabled.
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
		return
	}
	// Get the active config tree as text.
	configText := d.store.ShowActive()
	if configText == "" {
		return
	}
	d.sessionSync.QueueConfig(configText)
}

// handleConfigSync processes a config received from the cluster peer.
// Config sync is unidirectional: primary → secondary only. If this node
// is the RG0 primary (config authority), incoming config is rejected to
// prevent a reconnecting secondary from overwriting the authoritative config.
func (d *Daemon) handleConfigSync(configText string) {
	if d.cluster != nil && d.cluster.IsLocalPrimary(0) {
		slog.Warn("cluster: rejecting config sync (this node is RG0 primary)")
		return
	}
	slog.Info("cluster: accepting config sync from peer", "size", len(configText))

	compiled, err := d.store.SyncApply(configText, nil)
	if err != nil {
		slog.Error("cluster: config sync apply failed", "err", err)
		return
	}

	// Apply the compiled config to the dataplane.
	if compiled != nil {
		d.applyConfig(compiled)
	}
	slog.Info("cluster: config sync applied successfully")
}

// watchClusterEvents monitors cluster state transitions and toggles
// config store read-only mode based on primary/secondary state.
// startClusterComms starts heartbeat and session sync after VRFs are created.
// Called after applyConfig so that control/fabric interfaces are already in
// the management VRF (if configured).
func (d *Daemon) startClusterComms(ctx context.Context) {
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	cc := cfg.Chassis.Cluster

	// Create an independently-cancellable sub-context so cluster comms can
	// be restarted on config change (#87) without cancelling the daemon ctx.
	commsCtx, commsCancel := context.WithCancel(ctx)
	d.clusterCommsCancel = commsCancel
	d.activeClusterTransport = clusterTransportFromConfig(cfg)

	// Determine VRF device if control/fabric interfaces are in mgmt VRF.
	// Check mgmtVRFInterfaces first, then fall back to probing the control
	// interface directly (handles config-only mode where applyConfig may
	// have run but mgmtVRFInterfaces is empty due to VRF creation failure).
	vrfDevice := ""
	if len(d.mgmtVRFInterfaces) > 0 {
		vrfDevice = "vrf-mgmt"
	} else if cc.ControlInterface != "" {
		// Control/fabric interfaces (em*, fab*) are always placed in
		// vrf-mgmt by the compiler. Check if the VRF device exists.
		if _, err := net.InterfaceByName("vrf-mgmt"); err == nil {
			vrfDevice = "vrf-mgmt"
		}
	}

	// Start BPF watchdog heartbeat: write monotonic timestamp to ha_watchdog
	// map every 500ms for each configured RG. If the daemon is SIGKILL'd,
	// the timestamp goes stale and BPF stops forwarding within 2s.
	if d.dp != nil && len(cc.RedundancyGroups) > 0 {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-commsCtx.Done():
					return
				case <-ticker.C:
					var ts unix.Timespec
					_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
					now := uint64(ts.Sec)
					for _, rg := range cc.RedundancyGroups {
						if err := d.dp.UpdateHAWatchdog(rg.ID, now); err != nil {
							slog.Warn("ha watchdog write failed", "rg", rg.ID, "err", err)
						}
					}
				}
			}
		}()
		slog.Info("HA watchdog heartbeat started", "rgs", len(cc.RedundancyGroups))
	}

	// In VRRP mode, make strict VIP ownership the runtime default so
	// rg_active follows VIP/MAC ownership rather than cluster-primary
	// intent. Direct/no-reth-vrrp mode and private-rg-election mode
	// still use cluster state because there are no VRRP instances to
	// gate on.
	d.syncRGStrictVIPOwnershipMode(cc)

	// Start heartbeat if control-interface and peer-address are configured.
	// Retry on bind failure: the control interface address and VRF device
	// may not be ready during daemon startup (networkd race).
	if cc.ControlInterface != "" && cc.PeerAddress != "" {
		go func() {
			for i := 0; i < 30; i++ {
				localIP := resolveInterfaceAddr(cc.ControlInterface, "")
				if localIP == "" {
					if i == 0 {
						slog.Info("cluster: control interface has no IPv4 address yet, waiting",
							"interface", cc.ControlInterface)
					}
					time.Sleep(2 * time.Second)
					continue
				}
				if err := d.cluster.StartHeartbeat(localIP, cc.PeerAddress, vrfDevice); err != nil {
					if i < 5 {
						slog.Info("cluster: heartbeat bind not ready, retrying",
							"err", err, "attempt", i+1)
					} else {
						slog.Warn("failed to start cluster heartbeat, retrying",
							"err", err, "attempt", i+1)
					}
					time.Sleep(2 * time.Second)
					continue
				}
				return
			}
			slog.Error("cluster heartbeat failed after retries")
		}()
	}

	// Start session/config sync on the control link (same interface as
	// heartbeat, port 4785). Consolidates all control-plane traffic onto
	// the dedicated control path. Falls back to fabric if no control
	// interface is configured (legacy compatibility).
	syncIface := cc.ControlInterface
	syncPeerAddr := cc.PeerAddress
	syncTransport := "control-link"
	if syncIface == "" || syncPeerAddr == "" {
		syncIface = cc.FabricInterface
		syncPeerAddr = cc.FabricPeerAddress
		syncTransport = "fabric"
	}
	if syncIface != "" && syncPeerAddr != "" {
		go func() {
			var syncIP string
			for i := 0; i < 30; i++ {
				syncIP = resolveInterfaceAddr(syncIface, "")
				if syncIP != "" {
					break
				}
				if i == 0 {
					slog.Info("cluster: sync interface has no IPv4 address yet, waiting",
						"interface", syncIface, "transport", syncTransport)
				}
				select {
				case <-commsCtx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
			if syncIP == "" {
				slog.Error("cluster: sync interface address not available after retries",
					"interface", syncIface)
				return
			}

			syncLocal := fmt.Sprintf("%s:4785", syncIP)
			syncPeer := fmt.Sprintf("%s:4785", syncPeerAddr)
			slog.Info("cluster: session sync transport", "mode", syncTransport,
				"local", syncLocal, "peer", syncPeer)

			// Resolve secondary fabric (fab1) for dual transport failover.
			// Only applicable when using fabric transport (not control-link).
			var syncLocal1, syncPeer1 string
			if syncTransport == "fabric" && cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
				var fab1IP string
				for i := 0; i < 15; i++ {
					fab1IP = resolveInterfaceAddr(cc.Fabric1Interface, "")
					if fab1IP != "" {
						break
					}
					if i == 0 {
						slog.Info("cluster: fabric1 interface has no IPv4 address yet, waiting",
							"interface", cc.Fabric1Interface)
					}
					select {
					case <-commsCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
				}
				if fab1IP != "" {
					syncLocal1 = fmt.Sprintf("%s:4785", fab1IP)
					syncPeer1 = fmt.Sprintf("%s:4785", cc.Fabric1PeerAddress)
					slog.Info("cluster: dual fabric transport configured",
						"fab0_local", syncLocal, "fab1_local", syncLocal1)
				} else {
					slog.Warn("cluster: fabric1 address not available, using single fabric only",
						"interface", cc.Fabric1Interface)
				}
			}

			if syncLocal1 != "" {
				d.sessionSync = cluster.NewDualSessionSync(syncLocal, syncPeer, syncLocal1, syncPeer1, nil)
			} else {
				d.sessionSync = cluster.NewSessionSync(syncLocal, syncPeer, nil)
			}

			d.cluster.SetSyncTransport(syncTransport)

			// Store sync peer addresses for gRPC peer dialing (session queries etc).
			d.syncPeerAddr = syncPeerAddr
			if syncLocal1 != "" {
				d.syncPeerAddr1 = cc.Fabric1PeerAddress
			}

			// Start gRPC fabric listener(s) so peer can proxy monitor requests.
			// d.grpcSrv is set after startClusterComms returns, so we poll briefly.
			// Uses the sync interface address (fabric or control-link).
			// When dual-fabric is configured, listen on both fabric IPs.
			go func() {
				for i := 0; i < 30; i++ {
					if d.grpcSrv != nil {
						grpcAddr := fmt.Sprintf("%s:50051", syncIP)
						if syncLocal1 != "" {
							// Extract fab1 local IP (syncLocal1 is "ip:4785").
							fab1Host, _, _ := net.SplitHostPort(syncLocal1)
							grpcAddr1 := fmt.Sprintf("%s:50051", fab1Host)
							go d.grpcSrv.RunFabricListener(commsCtx, grpcAddr1, vrfDevice)
							slog.Info("gRPC dual fabric listeners", "fab0", grpcAddr, "fab1", grpcAddr1)
						}
						d.grpcSrv.RunFabricListener(commsCtx, grpcAddr, vrfDevice)
						return
					}
					time.Sleep(time.Second)
				}
			}()

			// Wire sync stats into cluster manager for CLI display.
			d.cluster.SetSyncStats(d.sessionSync)

			// Wire config sync callback: when secondary receives config from primary.
			d.sessionSync.OnConfigReceived = func(configText string) {
				d.cluster.RecordEvent(cluster.EventConfigSync, -1, fmt.Sprintf("Config received (%d bytes)", len(configText)))
				d.handleConfigSync(configText)
			}

			// Wire peer connected callback: push config to returning peer.
			// Only push if this node is RG0 primary (config authority) and
			// has been running >30s (stable node). A freshly started node
			// must NOT push stale config from disk.
			d.sessionSync.OnPeerConnected = func() {
				d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer connected")
				d.onSessionSyncPeerConnected()
				if d.cluster == nil || !d.cluster.IsLocalPrimary(0) {
					slog.Info("cluster: skipping config push (not RG0 primary)")
					return
				}
				if time.Since(d.startTime) < 30*time.Second {
					slog.Info("cluster: skipping config push (daemon just started)")
					return
				}
				slog.Info("cluster: pushing config to reconnected peer")
				d.pushConfigToPeer()
			}

			d.sessionSync.OnBulkSyncReceived = func() {
				d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync completed")
				slog.Info("cluster: session sync complete, releasing VRRP hold")
				d.onSessionSyncBulkReceived()
			}

			d.sessionSync.OnBulkSyncAckReceived = func() {
				d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync acknowledged by peer")
				d.onSessionSyncBulkAckReceived()
			}

			// Wire bulk sync override: use event stream export (fast path)
			// instead of BPF map iteration for initial bulk sync on connect.
			d.sessionSync.BulkSyncOverride = func() error {
				return d.bulkSyncViaEventStreamOrFallback(d.sessionSync)
			}

			d.sessionSync.OnPeerDisconnected = func() {
				d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer disconnected (all fabrics)")
				d.onSessionSyncPeerDisconnected()
			}

			// Wire remote failover: when the peer requests us to transfer an RG
			// out of primary and explicitly acknowledge the result.
			// Guard: only honor the request if we are actually primary for
			// this RG. Stale/delayed sync messages can arrive after we've
			// already transitioned to secondary — blindly calling
			// ManualFailover would cause dual-resign (both nodes secondary)
			// and a 30-second traffic blackhole.
			d.sessionSync.OnRemoteFailover = func(rgID int) error {
				if !d.cluster.IsLocalPrimary(rgID) {
					return fmt.Errorf("%w: redundancy group %d", cluster.ErrRemoteFailoverRejected, rgID)
				}
				slog.Info("cluster: remote failover request from peer", "rg", rgID)
				if err := d.cluster.ManualFailover(rgID); err != nil {
					slog.Warn("cluster: remote failover failed", "rg", rgID, "err", err)
					return err
				}
				return nil
			}
			d.sessionSync.OnRemoteFailoverCommit = func(rgID int) error {
				return d.cluster.FinalizePeerTransferOut(rgID)
			}

			// Wire peer failover sender so cluster Manager can send remote
			// failover requests via the fabric sync connection.
			d.cluster.SetPeerFailoverFunc(d.sessionSync.SendFailover)
			d.cluster.SetPeerFailoverCommitFunc(d.sessionSync.SendFailoverCommit)
			d.cluster.SetPreManualFailoverHook(d.prepareUserspaceManualFailover)
			d.cluster.SetTransferReadinessFunc(d.userspaceTransferReadiness)
			d.cluster.SetPeerTimeoutGuard(d.shouldSuppressPeerHeartbeatTimeout)

			// Wire peer fencing: on heartbeat timeout, cluster sends
			// fence via sync; on receive, disable all local RGs.
			d.cluster.SetPeerFenceFunc(d.sessionSync.SendFence)
			d.sessionSync.OnFenceReceived = func() {
				slog.Warn("cluster: fence received from peer, disabling all RGs")
				if cfg.Chassis.Cluster != nil {
					for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
						if err := d.dp.UpdateRGActive(rg.ID, false); err != nil {
							slog.Warn("cluster: fence: failed to disable rg_active",
								"rg", rg.ID, "err", err)
						}
					}
				}
			}

			d.sessionSync.SetVRFDevice(vrfDevice)
			// Retry sync start: the VRF device and address binding may not
			// be ready during daemon startup (networkd race).
			for i := 0; i < 30; i++ {
				if err := d.sessionSync.Start(commsCtx); err != nil {
					if i < 5 {
						slog.Info("cluster: sync bind not ready, retrying",
							"err", err, "attempt", i+1)
					} else {
						slog.Warn("failed to start session sync, retrying",
							"err", err, "attempt", i+1)
					}
					select {
					case <-commsCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}
				slog.Info("cluster session sync started",
					"local", syncLocal, "peer", syncPeer, "vrf", vrfDevice)

				// Wire dataplane into session sync and start the sweep.
				// Must happen here (not in Run) because d.sessionSync is
				// created asynchronously in this goroutine.
				if d.dp != nil {
					d.sessionSync.SetDataPlane(d.dp)
					d.sessionSync.IsPrimaryFn = func() bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(0)
					}
					d.sessionSync.IsPrimaryForRGFn = func(rgID int) bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(rgID)
					}
					d.sessionSync.StartSyncSweep(commsCtx)
					go d.runUserspaceEventStream(commsCtx)
				}

				break
			}

			// Start periodic IPsec SA sync if enabled.
			if cc.IPsecSASync && d.ipsec != nil {
				go d.syncIPsecSAPeriodic(commsCtx)
			}

			// Initialize fabric refresh channel for event-driven updates (#124).
			d.fabricRefreshCh = make(chan struct{}, 1)

			// Populate fabric_fwd BPF map for cross-chassis redirect,
			// then periodically refresh to correct neighbor drift.
			// Resolve to physical parent (ge-0-0-0) — BPF runs on
			// the parent, not the IPVLAN overlay. Neighbor resolution
			// uses the overlay (fab0/fab1) where the sync IP lives (#129).
			fabParent := d.resolveFabricParent(cc.FabricInterface)
			fabOverlay := config.LinuxIfName(cc.FabricInterface)
			if fabOverlay == fabParent {
				fabOverlay = "" // no overlay — legacy mode
			}
			go d.populateFabricFwd(commsCtx, fabParent, fabOverlay, cc.FabricPeerAddress)

			// Populate secondary fabric_fwd entry (key=1) if fab1 configured.
			if cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
				fab1Parent := d.resolveFabricParent(cc.Fabric1Interface)
				fab1Overlay := config.LinuxIfName(cc.Fabric1Interface)
				if fab1Overlay == fab1Parent {
					fab1Overlay = "" // no overlay
				}
				go d.populateFabricFwd1(commsCtx, fab1Parent, fab1Overlay, cc.Fabric1PeerAddress)
			}

			// Monitor fabric link/neighbor state via netlink (#124).
			go d.monitorFabricState(commsCtx)
		}()
	}
}

// stopClusterComms tears down heartbeat and session sync so they can be
// restarted with new transport settings (#87). Cancels the comms sub-context
// (which stops retry loops, fabric_fwd refresh, IPsec SA sync, sync sweep)
// and explicitly stops heartbeat + session sync listeners/connections.
func (d *Daemon) stopClusterComms() {
	if d.clusterCommsCancel != nil {
		d.clusterCommsCancel()
		d.clusterCommsCancel = nil
	}
	if d.cluster != nil {
		d.cluster.StopHeartbeat()
	}
	if d.sessionSync != nil {
		d.stopSyncReadyTimer()
		d.sessionSync.Stop()
		d.sessionSync = nil
	}
}

// clusterTransportKey extracts the four cluster transport fields that
// determine heartbeat and session sync endpoints. Used to detect config
// changes that require restarting cluster comms.
type clusterTransportKey struct {
	ControlInterface   string
	PeerAddress        string
	FabricInterface    string
	FabricPeerAddress  string
	Fabric1Interface   string
	Fabric1PeerAddress string
}

func clusterTransportFromConfig(cfg *config.Config) clusterTransportKey {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return clusterTransportKey{}
	}
	cc := cfg.Chassis.Cluster
	return clusterTransportKey{
		ControlInterface:   cc.ControlInterface,
		PeerAddress:        cc.PeerAddress,
		FabricInterface:    cc.FabricInterface,
		FabricPeerAddress:  cc.FabricPeerAddress,
		Fabric1Interface:   cc.Fabric1Interface,
		Fabric1PeerAddress: cc.Fabric1PeerAddress,
	}
}

// ensureFabricIPVLAN creates an IPVLAN L2 interface on top of parent for
// fabric IP addressing. The parent keeps its ge-X-0-Y name (XDP/TC attaches
// there); the IPVLAN carries the fabric IP used for session sync.
// Idempotent: skips creation if the IPVLAN already exists on the correct parent.
func ensureFabricIPVLAN(parent, name string, addrs []string) error {
	parentLink, err := netlink.LinkByName(parent)
	if err != nil {
		return fmt.Errorf("parent %s: %w", parent, err)
	}

	// Ensure parent is UP — IPVLAN inherits carrier from parent.
	netlink.LinkSetUp(parentLink)

	// Set jumbo MTU on parent for fabric throughput — IPVLAN inherits
	// parent MTU as upper bound, so parent must be set first.
	if parentLink.Attrs().MTU < 9000 {
		if err := netlink.LinkSetMTU(parentLink, 9000); err != nil {
			slog.Warn("fabric: failed to set parent MTU 9000",
				"parent", parent, "err", err)
		}
	}

	// Check if IPVLAN already exists on correct parent.
	if existing, err := netlink.LinkByName(name); err == nil {
		if existing.Attrs().ParentIndex == parentLink.Attrs().Index {
			// Already correct — reconcile addresses, MTU, and ensure UP (#127).
			if existing.Attrs().MTU < 9000 {
				netlink.LinkSetMTU(existing, 9000)
			}
			reconcileIPVLANAddrs(existing, name, addrs)
			netlink.LinkSetUp(existing)
			return nil
		}
		// Wrong parent — remove and recreate.
		netlink.LinkDel(existing)
	}

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name,
			ParentIndex: parentLink.Attrs().Index,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}
	if err := netlink.LinkAdd(ipvlan); err != nil {
		return fmt.Errorf("create IPVLAN %s on %s: %w", name, parent, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find created IPVLAN %s: %w", name, err)
	}

	// Set jumbo MTU on IPVLAN overlay (must not exceed parent MTU).
	if err := netlink.LinkSetMTU(link, 9000); err != nil {
		slog.Warn("fabric IPVLAN: failed to set MTU 9000",
			"name", name, "err", err)
	}

	// Add configured addresses.
	for _, addrStr := range addrs {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("fabric IPVLAN: invalid address", "addr", addrStr, "err", err)
			continue
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			slog.Warn("fabric IPVLAN: failed to add address",
				"name", name, "addr", addrStr, "err", err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	slog.Info("created fabric IPVLAN", "name", name, "parent", parent,
		"addrs", addrs)
	return nil
}

// reconcileIPVLANAddrs adds missing addresses and removes stale ones from an
// existing IPVLAN interface (#127). Called when ensureFabricIPVLAN finds the
// overlay already exists on the correct parent.
func reconcileIPVLANAddrs(link netlink.Link, name string, desired []string) {
	// Build set of desired addresses (normalized to CIDR strings).
	want := make(map[string]*netlink.Addr, len(desired))
	for _, addrStr := range desired {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("fabric IPVLAN: invalid address in config", "addr", addrStr, "err", err)
			continue
		}
		want[addr.IPNet.String()] = addr
	}

	// Get current addresses.
	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		slog.Warn("fabric IPVLAN: failed to list addresses", "name", name, "err", err)
		return
	}

	// Remove stale addresses not in desired set.
	have := make(map[string]bool, len(existing))
	for _, a := range existing {
		key := a.IPNet.String()
		have[key] = true
		if _, ok := want[key]; !ok {
			if err := netlink.AddrDel(link, &a); err != nil {
				slog.Warn("fabric IPVLAN: failed to remove stale address",
					"name", name, "addr", key, "err", err)
			} else {
				slog.Info("fabric IPVLAN: removed stale address",
					"name", name, "addr", key)
			}
		}
	}

	// Add missing addresses.
	for key, addr := range want {
		if !have[key] {
			if err := netlink.AddrReplace(link, addr); err != nil {
				slog.Warn("fabric IPVLAN: failed to add address",
					"name", name, "addr", key, "err", err)
			} else {
				slog.Info("fabric IPVLAN: added missing address",
					"name", name, "addr", key)
			}
		}
	}
}

// CleanupFabricIPVLANs removes all fabric IPVLAN interfaces (fab0, fab1).
func CleanupFabricIPVLANs() {
	for _, name := range []string{"fab0", "fab1"} {
		if link, err := netlink.LinkByName(name); err == nil {
			if _, ok := link.(*netlink.IPVlan); ok {
				netlink.LinkDel(link)
				slog.Info("removed fabric IPVLAN", "name", name)
			}
		}
	}
}

// resolveFabricParent returns the Linux name of the physical parent interface
// for a fabric interface (e.g. fab0 → ge-0-0-0). Falls back to fabName if
// no LocalFabricMember is configured (legacy mode).
func (d *Daemon) resolveFabricParent(fabName string) string {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return fabName
	}
	if ifCfg, ok := cfg.Interfaces.Interfaces[fabName]; ok && ifCfg.LocalFabricMember != "" {
		return config.LinuxIfName(ifCfg.LocalFabricMember)
	}
	return fabName
}

// populateFabricFwd resolves the fabric interface MACs and populates the
// fabric_fwd BPF map for cross-chassis packet redirect during failback.
// fabIface is the physical parent (XDP attachment point); overlay is the
// IPVLAN child where the sync IP lives (neighbor resolution target, #129).
// If overlay is empty, fabIface is used for both (legacy/no-IPVLAN mode).
// Attempts immediately on startup with fast 500ms retries (10 attempts),
// then falls back to 30s periodic refresh.
func (d *Daemon) populateFabricFwd(ctx context.Context, fabIface, overlay, peerAddr string) {
	peerIP := net.ParseIP(peerAddr)
	if peerIP == nil {
		slog.Warn("cluster: invalid fabric peer address", "addr", peerAddr)
		return
	}
	if overlay == "" {
		overlay = fabIface
	}

	// Store fabric config for RefreshFabricFwd.
	d.fabricMu.Lock()
	d.fabricIface = fabIface
	d.fabricOverlay = overlay
	d.fabricPeerIP = peerIP
	d.fabricMu.Unlock()

	// Fast initial population: attempt immediately, then 500ms retries.
	for i := 0; i < 10; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}

		// Actively probe for neighbor entry on the overlay (#129).
		d.probeFabricNeighbor(ctx, overlay, peerIP)

		if d.refreshFabricFwd(fabIface, overlay, peerIP, i == 0) {
			break
		}
		if i == 9 {
			slog.Warn("cluster: fabric_fwd not populated after fast retries, continuing with periodic refresh")
		}
	}

	// Periodic refresh every 30s as safety net, plus event-driven
	// refresh via fabricRefreshCh from netlink monitor (#124).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refreshFabricFwd(fabIface, overlay, peerIP, false)
		case <-d.fabricRefreshCh:
			d.refreshFabricFwd(fabIface, overlay, peerIP, false)
		}
	}
}

// probeFabricNeighbor triggers ARP/NDP resolution for the fabric peer
// if no neighbor entry exists. Uses ping (not arping) because arping's
// PF_PACKET raw sockets don't populate the kernel ARP table with XDP attached.
func (d *Daemon) probeFabricNeighbor(ctx context.Context, fabIface string, peerIP net.IP) {
	link, err := netlink.LinkByName(fabIface)
	if err != nil {
		return
	}

	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}
	neighs, _ := netlink.NeighList(link.Attrs().Index, neighFamily)
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
			(n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT|netlink.NUD_DELAY|netlink.NUD_PROBE)) != 0 {
			return // Entry exists, no probe needed.
		}
	}

	// No neighbor entry — trigger ARP/NDP resolution via raw ICMP probe.
	sendICMPProbe(fabIface, peerIP)

	// Also probe on the parent interface if this is an IPVLAN overlay.
	// After crash recovery, the IPVLAN overlay may not respond to ARP
	// (stale MAC, vrf-mgmt routing isolation). The parent (ge-X-0-0)
	// is a real NIC on the same L2 segment — ARP on it is more reliable.
	// Additionally, send IPv6 ff02::1 multicast on the parent to populate
	// the NDP table with the peer's MAC as a fallback.
	if parentIdx := link.Attrs().ParentIndex; parentIdx > 0 {
		if parent, err := netlink.LinkByIndex(parentIdx); err == nil {
			parentName := parent.Attrs().Name
			sendICMPProbe(parentName, peerIP)
			sendIPv6MulticastProbe(parentName, parentIdx)
		}
	}
}

// sendICMPProbe sends a single raw ICMP/ICMPv6 echo request bound to
// the given interface. This triggers kernel ARP/NDP resolution without
// shelling out to ping. Non-blocking: sendto MSG_DONTWAIT.
func sendICMPProbe(iface string, target net.IP) {
	if target.To4() != nil {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMP echo: type=8, code=0, checksum=0xf7ff, id=0, seq=0
		icmp := [8]byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}
		sa := &unix.SockaddrInet4{}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, icmp[:], unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMPv6 auto-checksum at offset 2
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
		// ICMPv6 echo: type=128, code=0, checksum=0 (kernel fills), id=0, seq=0
		icmp6 := [8]byte{128, 0, 0, 0, 0, 0, 0, 0}
		sa6 := &unix.SockaddrInet6{}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
	}
}

// sendIPv6MulticastProbe sends an ICMPv6 echo request to ff02::1 (all-nodes
// multicast) on the given interface. All link-local nodes respond, populating
// the IPv6 neighbor table with their MACs. This provides a reliable fallback
// for discovering the fabric peer's MAC when IPv4 ARP fails (e.g. after
// crash recovery with RETH MAC changes on IPVLAN overlays).
func sendIPv6MulticastProbe(iface string, ifindex int) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
	// ICMPv6 echo request: type=128, code=0, checksum=0 (kernel fills)
	icmp6 := [8]byte{128, 0, 0, 0, 0, 0, 0, 1}
	sa6 := &unix.SockaddrInet6{ZoneId: uint32(ifindex)}
	// ff02::1 — all-nodes link-local multicast
	copy(sa6.Addr[:], net.ParseIP("ff02::1").To16())
	_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
}

func (d *Daemon) logFabricRefreshFailure(slot int, msg string, args ...any) {
	d.fabricMu.Lock()
	now := time.Now()
	last := d.lastFabricLog0
	if slot == 1 {
		last = d.lastFabricLog1
	}
	if now.Sub(last) < 2*time.Second {
		d.fabricMu.Unlock()
		return
	}
	if slot == 0 {
		d.lastFabricLog0 = now
	} else {
		d.lastFabricLog1 = now
	}
	d.fabricMu.Unlock()
	slog.Info(msg, args...)
}

// refreshFabricFwd resolves fabric link/neighbor state and updates the
// fabric_fwd BPF map. Returns true on success. Called during initial
// population and periodic drift correction.
// fabIface is the physical parent (for ifindex/MAC); overlay is the IPVLAN
// child where the sync IP lives (for neighbor resolution, #129).
func (d *Daemon) refreshFabricFwd(fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	link, err := netlink.LinkByName(fabIface)
	if err != nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (link not found)",
			"interface", fabIface, "err", err)
		d.clearFabricFwd0()
		return false
	}
	localMAC := link.Attrs().HardwareAddr
	if len(localMAC) != 6 {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (invalid local mac)",
			"interface", fabIface, "local_mac", localMAC)
		d.clearFabricFwd0()
		return false
	}

	// Check oper-state: non-UP interfaces cannot forward (#122).
	operState := link.Attrs().OperState
	if operState != netlink.OperUp && operState != netlink.OperUnknown {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (link not operational)",
			"interface", fabIface, "oper_state", operState)
		d.clearFabricFwd0()
		return false
	}

	// Increase fabric txqueuelen for generic XDP.
	if link.Attrs().TxQLen < 10000 {
		if err := netlink.LinkSetTxQLen(link, 10000); err != nil {
			slog.Warn("cluster: failed to set fabric txqueuelen",
				"interface", fabIface, "err", err)
		}
	}

	// Resolve peer MAC from ARP/NDP table on the overlay interface (#129).
	// The sync IP lives on the overlay (fab0/fab1), so neighbor entries
	// are associated with the overlay's ifindex, not the parent's.
	neighLink := link
	if overlay != fabIface {
		if ol, err := netlink.LinkByName(overlay); err == nil {
			neighLink = ol
		}
	}
	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}

	validState := netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_PERMANENT | netlink.NUD_DELAY | netlink.NUD_PROBE

	neighs, err := netlink.NeighList(neighLink.Attrs().Index, neighFamily)
	if err != nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (neighbor list)",
			"overlay", neighLink.Attrs().Name, "peer", peerIP, "err", err)
		d.clearFabricFwd0()
		return false
	}
	var peerMAC net.HardwareAddr
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
			(n.State&validState) != 0 {
			peerMAC = n.HardwareAddr
			break
		}
	}

	// Fallback: if overlay ARP failed, try the parent interface's neighbor
	// tables (both IPv4 and IPv6). After crash recovery, the IPVLAN overlay
	// may not resolve ARP due to stale MAC or VRF isolation, but the parent
	// (ge-X-0-0) is a real NIC on the same L2 — its ARP/NDP is reliable.
	if peerMAC == nil {
		parentIdx := neighLink.Attrs().ParentIndex
		if parentIdx == 0 {
			parentIdx = link.Attrs().Index // use fabric parent directly
		}
		// Check parent IPv4 neighbors for the peer IP.
		parentNeighs, _ := netlink.NeighList(parentIdx, neighFamily)
		for _, n := range parentNeighs {
			if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
				(n.State&validState) != 0 {
				peerMAC = n.HardwareAddr
				slog.Info("cluster: fabric peer MAC resolved via parent ARP",
					"peer_mac", peerMAC, "overlay", overlay)
				break
			}
		}
		// Check parent IPv6 NDP neighbors (populated via ff02::1 probe).
		if peerMAC == nil {
			v6Neighs, _ := netlink.NeighList(parentIdx, netlink.FAMILY_V6)
			for _, n := range v6Neighs {
				if len(n.HardwareAddr) != 6 || (n.State&validState) == 0 {
					continue
				}
				if !n.IP.IsLinkLocalUnicast() {
					continue
				}
				if bytes.Equal(n.HardwareAddr, localMAC) {
					continue
				}
				peerMAC = n.HardwareAddr
				slog.Info("cluster: fabric peer MAC resolved via parent IPv6 NDP",
					"peer_mac", peerMAC, "peer_ll", n.IP, "overlay", overlay)
				break
			}
		}
	}

	if peerMAC == nil {
		if logWaiting {
			slog.Info("cluster: waiting for fabric peer neighbor entry",
				"peer", peerIP, "overlay", overlay)
		} else {
			d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (missing peer neighbor)",
				"peer", peerIP, "overlay", overlay)
		}
		d.clearFabricFwd0()
		return false
	}

	// Use parent's ifindex for redirect — XDP runs on the parent.
	info := dataplane.FabricFwdInfo{
		Ifindex: uint32(link.Attrs().Index),
	}
	copy(info.PeerMAC[:], peerMAC)
	copy(info.LocalMAC[:], localMAC)

	// Find a non-VRF interface for zone-decoded FIB lookups.
	// Prefer the fabric interface itself (known UP, non-VRF).
	// Fall back to loopback (ifindex 1): always present, always
	// UP, never a VRF member — deterministic across reboots.
	info.FIBIfindex = uint32(link.Attrs().Index)
	if link.Attrs().MasterIndex != 0 {
		// Fabric link is a VRF member — use loopback for
		// main-table FIB lookups (avoids l3mdev interference).
		info.FIBIfindex = 1
	}

	if d.dp == nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (dataplane not ready)")
		return false
	}
	if err := d.dp.UpdateFabricFwd(info); err != nil {
		slog.Warn("cluster: failed to update fabric_fwd map", "err", err)
		return false
	}

	d.fabricMu.Lock()
	d.fabricPopulated = true
	d.fabricMu.Unlock()

	slog.Info("cluster: fabric_fwd updated",
		"interface", fabIface, "ifindex", info.Ifindex,
		"fib_ifindex", info.FIBIfindex,
		"local_mac", localMAC, "peer_mac", peerMAC)

	// Push updated fabric MACs to userspace helper so it can do
	// cross-chassis fabric redirect. The initial snapshot may have
	// been built before the peer MAC was resolved.
	if d.dp != nil {
		d.dp.SyncFabricState()
	}

	return true
}

// clearFabricFwd0 writes a zeroed FabricFwdInfo to key=0 if a valid entry
// was previously written, ensuring the dataplane falls back (#121).
func (d *Daemon) clearFabricFwd0() {
	d.fabricMu.RLock()
	populated := d.fabricPopulated
	d.fabricMu.RUnlock()
	if !populated || d.dp == nil {
		return
	}
	if err := d.dp.UpdateFabricFwd(dataplane.FabricFwdInfo{}); err != nil {
		slog.Warn("cluster: failed to clear fabric_fwd[0]", "err", err)
		return
	}
	d.fabricMu.Lock()
	d.fabricPopulated = false
	d.fabricMu.Unlock()
	slog.Info("cluster: fabric_fwd[0] cleared (path down)")
}

// populateFabricFwd1 resolves the secondary fabric interface MACs and populates
// the fabric_fwd BPF map entry at key=1 for cross-chassis packet redirect.
// Mirrors populateFabricFwd but writes to key=1 via UpdateFabricFwd1.
func (d *Daemon) populateFabricFwd1(ctx context.Context, fabIface, overlay, peerAddr string) {
	peerIP := net.ParseIP(peerAddr)
	if peerIP == nil {
		slog.Warn("cluster: invalid fabric1 peer address", "addr", peerAddr)
		return
	}
	if overlay == "" {
		overlay = fabIface
	}

	// Store fabric1 config for RefreshFabricFwd.
	d.fabricMu.Lock()
	d.fabricIface1 = fabIface
	d.fabricOverlay1 = overlay
	d.fabricPeerIP1 = peerIP
	d.fabricMu.Unlock()

	// Fast initial population: attempt immediately, then 500ms retries.
	for i := 0; i < 10; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}

		// Probe on the overlay (#129).
		d.probeFabricNeighbor(ctx, overlay, peerIP)

		if d.refreshFabricFwd1(fabIface, overlay, peerIP, i == 0) {
			break
		}
		if i == 9 {
			slog.Warn("cluster: fabric1_fwd not populated after fast retries, continuing with periodic refresh")
		}
	}

	// Periodic refresh every 30s as safety net, plus event-driven
	// refresh via fabricRefreshCh from netlink monitor (#124).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refreshFabricFwd1(fabIface, overlay, peerIP, false)
		case <-d.fabricRefreshCh:
			d.refreshFabricFwd1(fabIface, overlay, peerIP, false)
		}
	}
}

// refreshFabricFwd1 resolves secondary fabric link/neighbor state and updates
// the fabric_fwd BPF map at key=1. Returns true on success.
// fabIface is the physical parent; overlay is the IPVLAN child (#129).
func (d *Daemon) refreshFabricFwd1(fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	link, err := netlink.LinkByName(fabIface)
	if err != nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (link not found)",
			"interface", fabIface, "err", err)
		d.clearFabricFwd1()
		return false
	}
	localMAC := link.Attrs().HardwareAddr
	if len(localMAC) != 6 {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (invalid local mac)",
			"interface", fabIface, "local_mac", localMAC)
		d.clearFabricFwd1()
		return false
	}

	// Check oper-state: non-UP interfaces cannot forward (#122).
	operState := link.Attrs().OperState
	if operState != netlink.OperUp && operState != netlink.OperUnknown {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (link not operational)",
			"interface", fabIface, "oper_state", operState)
		d.clearFabricFwd1()
		return false
	}

	// Increase fabric txqueuelen for generic XDP.
	if link.Attrs().TxQLen < 10000 {
		if err := netlink.LinkSetTxQLen(link, 10000); err != nil {
			slog.Warn("cluster: failed to set fabric1 txqueuelen",
				"interface", fabIface, "err", err)
		}
	}

	// Resolve peer MAC from overlay interface (#129).
	neighLink := link
	if overlay != fabIface {
		if ol, err := netlink.LinkByName(overlay); err == nil {
			neighLink = ol
		}
	}
	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}
	neighs, err := netlink.NeighList(neighLink.Attrs().Index, neighFamily)
	if err != nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (neighbor list)",
			"overlay", neighLink.Attrs().Name, "peer", peerIP, "err", err)
		d.clearFabricFwd1()
		return false
	}
	var peerMAC net.HardwareAddr
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
			(n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT|netlink.NUD_DELAY|netlink.NUD_PROBE)) != 0 {
			peerMAC = n.HardwareAddr
			break
		}
	}
	if peerMAC == nil {
		if logWaiting {
			slog.Info("cluster: waiting for fabric1 peer neighbor entry",
				"peer", peerIP, "overlay", overlay)
		} else {
			d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (missing peer neighbor)",
				"peer", peerIP, "overlay", overlay)
		}
		d.clearFabricFwd1()
		return false
	}

	info := dataplane.FabricFwdInfo{
		Ifindex: uint32(link.Attrs().Index),
	}
	copy(info.PeerMAC[:], peerMAC)
	copy(info.LocalMAC[:], localMAC)

	info.FIBIfindex = uint32(link.Attrs().Index)
	if link.Attrs().MasterIndex != 0 {
		info.FIBIfindex = 1
	}

	if d.dp == nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (dataplane not ready)")
		return false
	}
	if err := d.dp.UpdateFabricFwd1(info); err != nil {
		slog.Warn("cluster: failed to update fabric1_fwd map", "err", err)
		return false
	}

	d.fabricMu.Lock()
	d.fabric1Populated = true
	d.fabricMu.Unlock()

	slog.Info("cluster: fabric1_fwd updated",
		"interface", fabIface, "ifindex", info.Ifindex,
		"fib_ifindex", info.FIBIfindex,
		"local_mac", localMAC, "peer_mac", peerMAC)
	return true
}

// clearFabricFwd1 writes a zeroed FabricFwdInfo to key=1 if a valid entry
// was previously written, ensuring the dataplane falls back (#121).
func (d *Daemon) clearFabricFwd1() {
	d.fabricMu.RLock()
	populated := d.fabric1Populated
	d.fabricMu.RUnlock()
	if !populated || d.dp == nil {
		return
	}
	if err := d.dp.UpdateFabricFwd1(dataplane.FabricFwdInfo{}); err != nil {
		slog.Warn("cluster: failed to clear fabric_fwd[1]", "err", err)
		return
	}
	d.fabricMu.Lock()
	d.fabric1Populated = false
	d.fabricMu.Unlock()
	slog.Info("cluster: fabric_fwd[1] cleared (path down)")
}

// RefreshFabricFwd triggers an immediate refresh of the fabric_fwd BPF map.
// Call this on link state changes, neighbor changes, or failover transitions.
// Refreshes both fab0 (key=0) and fab1 (key=1) entries.
func (d *Daemon) RefreshFabricFwd() {
	d.fabricMu.RLock()
	fabIface := d.fabricIface
	overlay := d.fabricOverlay
	peerIP := d.fabricPeerIP
	fabIface1 := d.fabricIface1
	overlay1 := d.fabricOverlay1
	peerIP1 := d.fabricPeerIP1
	probeAt0 := d.lastFabricProbe
	probeAt1 := d.lastFabricProbe1
	d.fabricMu.RUnlock()
	if fabIface != "" && peerIP != nil {
		if time.Since(probeAt0) >= 2*time.Second {
			d.fabricMu.Lock()
			if time.Since(d.lastFabricProbe) >= 2*time.Second {
				d.lastFabricProbe = time.Now()
				go d.probeFabricNeighbor(context.Background(), overlayOrParent(overlay, fabIface), peerIP)
			}
			d.fabricMu.Unlock()
		}
		d.refreshFabricFwd(fabIface, overlay, peerIP, false)
	}
	if fabIface1 != "" && peerIP1 != nil {
		if time.Since(probeAt1) >= 2*time.Second {
			d.fabricMu.Lock()
			if time.Since(d.lastFabricProbe1) >= 2*time.Second {
				d.lastFabricProbe1 = time.Now()
				go d.probeFabricNeighbor(context.Background(), overlayOrParent(overlay1, fabIface1), peerIP1)
			}
			d.fabricMu.Unlock()
		}
		d.refreshFabricFwd1(fabIface1, overlay1, peerIP1, false)
	}
}

func overlayOrParent(overlay, parent string) string {
	if overlay != "" {
		return overlay
	}
	return parent
}

// monitorFabricState subscribes to netlink link and neighbor updates and
// triggers immediate fabric_fwd refresh when fabric interfaces or their
// neighbor entries change (#124). The 30s ticker in populateFabricFwd
// remains as a safety net.
func (d *Daemon) monitorFabricState(ctx context.Context) {
	linkUpdates := make(chan netlink.LinkUpdate, 64)
	linkDone := make(chan struct{})
	if err := netlink.LinkSubscribe(linkUpdates, linkDone); err != nil {
		slog.Warn("cluster: failed to subscribe to link updates for fabric monitor", "err", err)
		return
	}

	neighUpdates := make(chan netlink.NeighUpdate, 64)
	neighDone := make(chan struct{})
	if err := netlink.NeighSubscribe(neighUpdates, neighDone); err != nil {
		slog.Warn("cluster: failed to subscribe to neigh updates for fabric monitor", "err", err)
		close(linkDone)
		return
	}

	slog.Info("cluster: fabric state monitor started (link + neighbor)")

	for {
		select {
		case <-ctx.Done():
			close(linkDone)
			close(neighDone)
			return
		case update, ok := <-linkUpdates:
			if !ok {
				return
			}
			name := update.Attrs().Name
			d.fabricMu.RLock()
			isFabric := name == d.fabricIface || name == d.fabricIface1 ||
				name == d.fabricOverlay || name == d.fabricOverlay1
			d.fabricMu.RUnlock()
			if isFabric {
				slog.Debug("cluster: fabric link state change detected",
					"interface", name, "oper_state", update.Attrs().OperState)
				d.triggerFabricRefresh()
			}
		case update, ok := <-neighUpdates:
			if !ok {
				return
			}
			d.fabricMu.RLock()
			isPeer := (d.fabricPeerIP != nil && update.IP.Equal(d.fabricPeerIP)) ||
				(d.fabricPeerIP1 != nil && update.IP.Equal(d.fabricPeerIP1))
			d.fabricMu.RUnlock()
			if isPeer {
				slog.Debug("cluster: fabric peer neighbor change detected",
					"ip", update.IP, "type", update.Type)
				d.triggerFabricRefresh()
			}
		}
	}
}

// triggerFabricRefresh sends a non-blocking signal to the fabric refresh
// channel, waking populateFabricFwd/populateFabricFwd1 loops.
func (d *Daemon) triggerFabricRefresh() {
	select {
	case d.fabricRefreshCh <- struct{}{}:
	default:
		// Already pending — no need to queue another.
	}
}

// getOrCreateRGState returns the rgStateMachine for the given RG, creating
// one if it doesn't exist yet.
func (d *Daemon) getOrCreateRGState(rgID int) *rgStateMachine {
	d.rgStatesMu.RLock()
	s, ok := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	if ok {
		return s
	}
	d.rgStatesMu.Lock()
	defer d.rgStatesMu.Unlock()
	// Double-check after upgrading to write lock.
	if s, ok = d.rgStates[rgID]; ok {
		return s
	}
	s = newRGStateMachine()
	d.rgStates[rgID] = s
	return s
}

func (d *Daemon) syncRGStrictVIPOwnershipMode(cc *config.ClusterConfig) {
	if cc == nil {
		return
	}
	strictByDefault := !(cc.NoRethVRRP || cc.PrivateRGElection)
	for _, rg := range cc.RedundancyGroups {
		s := d.getOrCreateRGState(rg.ID)
		s.SetStrictVIPOwnership(strictByDefault)
	}
}

// isRethMasterState returns true when ALL VRRP instances for rgID are MASTER.
// Returns false if no instances exist for the RG.
func (d *Daemon) isRethMasterState(rgID int) bool {
	return d.getOrCreateRGState(rgID).AllVRRPMaster()
}

// isAnyRethInstanceMaster returns true if ANY VRRP instance for rgID is
// MASTER. Used by the cluster event handler to defer rg_active deactivation
// until all VRRP instances have transitioned to BACKUP.
func (d *Daemon) isAnyRethInstanceMaster(rgID int) bool {
	return d.getOrCreateRGState(rgID).AnyVRRPMaster()
}

// snapshotRethMasterState returns per-RG master state derived from all
// per-instance entries. An RG is MASTER only when ALL its instances are MASTER.
func (d *Daemon) snapshotRethMasterState() map[int]bool {
	d.rgStatesMu.RLock()
	defer d.rgStatesMu.RUnlock()
	out := make(map[int]bool, len(d.rgStates))
	for rgID, s := range d.rgStates {
		out[rgID] = s.IsActive()
	}
	return out
}

func (d *Daemon) watchClusterEvents(ctx context.Context) {
	// Debounce VRRP updates: coalesce rapid cluster events into a single
	// UpdateInstances call. Without this, every heartbeat-driven state change
	// triggers a separate update before priorities settle.
	var vrrpTimer *time.Timer
	defer func() {
		if vrrpTimer != nil {
			vrrpTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-d.cluster.Events():
			noRethVRRP := d.isNoRethVRRP()

			// Dual-active winner reaffirm: no state change but send
			// GARPs to refresh upstream ARP/NDP caches after split-brain.
			if ev.DualActiveWin && noRethVRRP {
				d.scheduleDirectAnnounce(ev.GroupID, "dual-active-win")
				continue
			}

			// Update rg_active through unified state machine.
			//
			// Both cluster and VRRP events funnel through rgStateMachine
			// which determines rg_active = clusterPri || anyVrrpMaster.
			// This prevents the dual-inactive window (both nodes
			// rg_active=false during failover) and eliminates the race
			// between the two independent goroutine writers.
			//
			// Transition ordering safety:
			// - Activation: set rg_active FIRST, then remove blackholes,
			//   then trigger VRRP MASTER (#485). Neighbor readiness is
			//   maintained continuously in the background.
			// - Deactivation: run preflight FIRST, then resign VRRP,
			//   add blackholes, then clear rg_active (#485)
			isPrimary := ev.NewState == cluster.StatePrimary
			clusterDemotionEdge := ev.OldState == cluster.StatePrimary && !isPrimary
			s := d.getOrCreateRGState(ev.GroupID)
			tr := s.SetCluster(isPrimary)
			if isPrimary {
				// Activation: enable forwarding first.
				// Re-read desired state to guard against a
				// concurrent VRRP goroutine that may have
				// already superseded this transition.
				if tr.Changed && d.dp != nil {
					cur, _ := s.CurrentDesired()
					if err := d.dp.UpdateRGActive(ev.GroupID, cur); err != nil {
						slog.Warn("failed to update rg_active from cluster event",
							"rg", ev.GroupID, "active", cur, "err", err)
					} else {
						s.ApplyIfCurrent(tr)
					}
				}
				// Then remove blackhole routes — steady-state neighbor
				// maintenance keeps next-hop resolution warm in the
				// background, so activation no longer depends on a
				// one-shot neighbor warmup here.
				d.removeBlackholeRoutes(ev.GroupID)

				// VRRP priority + ForceRGMaster AFTER rg_active and
				// blackhole removal (#485).
				if !noRethVRRP {
					d.vrrpMgr.UpdateRGPriority(ev.GroupID, 200)
					// With preempt=false, VRRP won't self-elect even at
					// higher priority. Force MASTER since cluster state
					// is authoritative (e.g. after failover reset).
					// Only do this for intentional promotions (Secondary →
					// Primary), NOT on initial boot (SecondaryHold → Primary)
					// where VRRP should follow its own election timer.
					if ev.OldState == cluster.StateSecondary {
						d.vrrpMgr.ForceRGMaster(ev.GroupID)
					}
				}

				// no-reth-vrrp direct mode: add VIPs + send GARPs +
				// start per-RG services on primary transition.
				if noRethVRRP {
					d.directAddVIPs(ev.GroupID)
					d.addStableRethLinkLocal(ev.GroupID)
					d.scheduleDirectAnnounce(ev.GroupID, "cluster-primary")
					d.applyRethServicesForRG(ev.GroupID)
					go d.RefreshFabricFwd()
				}
			} else {
				// Demotion: run preflight and resign VRRP BEFORE
				// clearing rg_active (#485). The preflight shifts
				// userspace flow cache entries to FabricRedirect so
				// the demoting node forwards via fabric during the
				// transition window. ResignRG must follow preflight
				// so traffic is already on the fabric path before
				// the VRRP BACKUP transition removes VIPs.
				if clusterDemotionEdge && d.dp != nil {
					d.tryPrepareUserspaceRGDemotion(ev.GroupID)
				}
				if !noRethVRRP {
					if ev.OldState == cluster.StatePrimary &&
						(ev.NewState == cluster.StateSecondary || ev.NewState == cluster.StateSecondaryHold) {
						d.vrrpMgr.ResignRG(ev.GroupID)
					}
				}
				// Deactivation: blackhole routes first (if transitioning
				// to inactive), then clear rg_active.
				if tr.Changed && !tr.Active {
					d.injectBlackholeRoutes(ev.GroupID)
				}
				if tr.Changed && d.dp != nil {
					cur, _ := s.CurrentDesired()
					if !cur && !clusterDemotionEdge {
						d.tryPrepareUserspaceRGDemotion(ev.GroupID)
					}
					if err := d.dp.UpdateRGActive(ev.GroupID, cur); err != nil {
						slog.Warn("failed to update rg_active from cluster event",
							"rg", ev.GroupID, "active", cur, "err", err)
					} else {
						s.ApplyIfCurrent(tr)
					}
				}

				// no-reth-vrrp direct mode: remove VIPs + stop services
				// on secondary transition.
				if noRethVRRP && tr.Changed && !tr.Active {
					d.cancelDirectAnnounce(ev.GroupID)
					d.directRemoveVIPs(ev.GroupID)
					d.removeStableRethLinkLocal(ev.GroupID)
					d.clearRethServicesForRG(ev.GroupID)
				}
			}

			// Strict VIP ownership: suppress GARP on secondary, allow on primary.
			// Not applicable with no-reth-vrrp (no VRRP instances).
			if !noRethVRRP && s.IsStrictVIPOwnership() {
				d.vrrpMgr.SetGARPSuppression(ev.GroupID, !isPrimary)
			}

			// Debounced VRRP priority update — 500ms coalesce window.
			// Skipped in no-reth-vrrp mode (no RETH VRRP instances to update).
			if !noRethVRRP {
				if vrrpTimer != nil {
					vrrpTimer.Stop()
				}
				vrrpTimer = time.AfterFunc(500*time.Millisecond, func() {
					if cfg := d.store.ActiveConfig(); cfg != nil {
						localPri := d.cluster.LocalPriorities()
						var all []*vrrp.Instance
						all = append(all, vrrp.CollectInstances(cfg)...)
						all = append(all, vrrp.CollectRethInstances(cfg, localPri)...)
						if err := d.vrrpMgr.UpdateInstances(all); err != nil {
							slog.Warn("cluster: failed to update VRRP instances", "err", err)
						}
					}
				})
			}

			// RG0-specific: config ownership and IPsec SA re-initiation.
			if ev.GroupID == 0 {
				switch ev.NewState {
				case cluster.StatePrimary:
					slog.Info("cluster: became primary for RG0, enabling config writes")
					d.store.SetClusterReadOnly(false)

					// On failover to primary: re-initiate synced IPsec SAs.
					if cc := d.clusterConfig(); cc != nil && cc.IPsecSASync && d.ipsec != nil && d.sessionSync != nil {
						go d.reinitiateIPsecSAs()
					}

				case cluster.StateSecondary, cluster.StateSecondaryHold:
					slog.Info("cluster: became secondary for RG0, disabling config writes")
					d.store.SetClusterReadOnly(true)
				}
			}
		}
	}
}

// rethVRIDBase is the VRRP GroupID offset for RETH instances.
// RETH instances use GroupID = rethVRIDBase + rgID (set in pkg/vrrp/vrrp.go).
// Standalone VRRP groups use GroupID < rethVRIDBase.
const rethVRIDBase = 100

// isRethVRID returns true if the VRRP GroupID belongs to a RETH instance.
func isRethVRID(vrid int) bool {
	return vrid >= rethVRIDBase
}

// rgIDFromVRID extracts the redundancy group ID from a VRRP group ID.
// VRID = rethVRIDBase + RG ID (set in pkg/vrrp/vrrp.go).
func rgIDFromVRID(vrid int) int {
	return vrid - rethVRIDBase
}

// watchVRRPEvents monitors VRRP state changes and logs transitions.
// On MASTER transition, updates rg_active, removes blackhole routes, and
// refreshes fabric forwarding. Neighbor readiness is maintained in the
// background by runPeriodicNeighborResolution / maintainClusterNeighborReadiness.
// Also starts/stops RA senders and Kea DHCP server per-RG — in
// active/active mode, a BACKUP event for RG1 must not clear services
// started for RG0.
func (d *Daemon) watchVRRPEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-d.vrrpMgr.Events():
			if !ok {
				return
			}
			// Standalone VRRP instances (GroupID < rethVRIDBase) do not
			// participate in HA redundancy group state. Skip the
			// rg_active/blackhole logic to avoid creating phantom RG entries.
			if !isRethVRID(ev.GroupID) {
				slog.Info("vrrp: standalone state change (non-RETH)",
					"interface", ev.Interface,
					"group", ev.GroupID,
					"state", ev.State.String())
				continue
			}
			rgID := rgIDFromVRID(ev.GroupID)
			slog.Info("vrrp: state change",
				"interface", ev.Interface,
				"group", ev.GroupID,
				"rg", rgID,
				"state", ev.State.String())
			if ev.State == vrrp.StateMaster {
				s := d.getOrCreateRGState(rgID)
				tr := s.SetVRRP(ev.Interface, true)
				if tr.Changed && tr.Active && d.dp != nil {
					// Activation order: set rg_active FIRST, then
					// remove blackhole routes. Re-read desired state
					// to guard against interleaved cluster goroutine.
					// Only activate when ALL VRRP instances in the RG
					// are MASTER — prevents partial ownership (#132).
					cur, _ := s.CurrentDesired()
					if err := d.dp.UpdateRGActive(rgID, cur); err != nil {
						slog.Warn("failed to update rg_active", "rg", rgID, "err", err)
					} else {
						s.ApplyIfCurrent(tr)
					}
					go d.RefreshFabricFwd()
				}
				// Only remove blackholes and apply services when ALL
				// VRRP instances in the RG are MASTER (#132).
				if tr.Changed && tr.Active {
					d.removeBlackholeRoutes(rgID)
					d.addStableRethLinkLocal(rgID)
					d.applyRethServicesForRG(rgID)
				}
			}
			if ev.State == vrrp.StateBackup {
				s := d.getOrCreateRGState(rgID)
				tr := s.SetVRRP(ev.Interface, false)
				if tr.Changed && !tr.Active {
					// Deactivation order: inject blackhole routes FIRST,
					// then clear rg_active. Re-read desired state to
					// guard against interleaved cluster goroutine.
					d.injectBlackholeRoutes(rgID)
					if d.dp != nil {
						cur, _ := s.CurrentDesired()
						if !cur {
							d.tryPrepareUserspaceRGDemotion(rgID)
						}
						if err := d.dp.UpdateRGActive(rgID, cur); err != nil {
							slog.Warn("failed to update rg_active", "rg", rgID, "err", err)
						} else {
							s.ApplyIfCurrent(tr)
						}
						go d.RefreshFabricFwd()
					}
					d.removeStableRethLinkLocal(rgID)
					d.clearRethServicesForRG(rgID)
				}
			}
		}
	}
}

// reconcileRGStateLoop periodically reads the authoritative cluster and VRRP
// states and reconciles rgStateMachine / rg_active BPF map / blackhole routes /
// VRRP posture / RA+DHCP services.
// This is the safety net for dropped events (non-blocking channel sends).
// Runs every 2s; also wakes immediately on event-drop notifications via
// reconcileNowCh. Skips if cluster or dataplane is nil.
func (d *Daemon) reconcileRGStateLoop(ctx context.Context) {
	// Run immediately on startup to correct stale rg_active from prior run.
	d.reconcileRGState()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.reconcileRGState()
		case <-d.reconcileNowCh:
			d.reconcileRGState()
		}
	}
}

// triggerReconcile requests an immediate RG state reconciliation pass.
// Non-blocking: if a reconcile is already pending, the request is coalesced.
func (d *Daemon) triggerReconcile() {
	select {
	case d.reconcileNowCh <- struct{}{}:
	default:
	}
}

func (d *Daemon) reconcileRGState() {
	if d.cluster == nil || d.vrrpMgr == nil {
		return
	}

	// Read authoritative VRRP instance states.
	vrrpStates := d.vrrpMgr.InstanceStates()

	// Build per-RG VRRP state map: rgID → { iface → isMaster }.
	// Skip standalone (non-RETH) VRRP instances.
	rgVRRP := make(map[int]map[string]bool)
	for _, ev := range vrrpStates {
		if !isRethVRID(ev.GroupID) {
			continue
		}
		rgID := rgIDFromVRID(ev.GroupID)
		if rgVRRP[rgID] == nil {
			rgVRRP[rgID] = make(map[string]bool)
		}
		rgVRRP[rgID][ev.Interface] = (ev.State == vrrp.StateMaster)
	}

	// Collect all known RG IDs from three sources:
	// 1) existing rgStates (event-driven)
	// 2) cluster-configured groups (may exist before VRRP fires)
	// 3) RETH VRRP instances (may exist before cluster events)
	seen := make(map[int]bool)
	d.rgStatesMu.RLock()
	for rgID := range d.rgStates {
		seen[rgID] = true
	}
	d.rgStatesMu.RUnlock()
	for _, gs := range d.cluster.GroupStates() {
		seen[gs.GroupID] = true
	}
	for rgID := range rgVRRP {
		seen[rgID] = true
	}
	rgIDs := make([]int, 0, len(seen))
	for rgID := range seen {
		rgIDs = append(rgIDs, rgID)
	}

	// Evaluate per-RG readiness for the takeover gate.
	noRethVRRP := d.isNoRethVRRP()

	// Check fabric readiness — only relevant when peer is alive.
	fabricReady := true
	if d.cluster.PeerAlive() {
		d.fabricMu.RLock()
		fp := d.fabricPopulated
		d.fabricMu.RUnlock()
		if !fp {
			d.triggerFabricRefresh()
			fabricReady = false
		}
	}

	if mon := d.cluster.Monitor(); mon != nil {
		for _, rgID := range rgIDs {
			ifReady, ifReasons := mon.RGInterfaceReady(rgID)
			var vrrpReady bool
			var vrrpReasons []string
			if noRethVRRP {
				// No RETH VRRP instances — check sync readiness instead.
				// Blocks promotion until bulk session sync completes (or
				// times out), equivalent to VRRP sync-hold in RETH mode.
				vrrpReady = d.cluster.IsSyncReady()
				if !vrrpReady {
					vrrpReasons = append(vrrpReasons, "session sync not ready")
				}
				// Also verify VIP ownership can be established: RETH
				// interfaces must exist and be UP before we allow promotion.
				vipOK, vipReasons := d.checkVIPReadiness(rgID)
				if !vipOK {
					vrrpReady = false
					vrrpReasons = append(vrrpReasons, vipReasons...)
				}
			} else if d.vrrpMgr != nil {
				hasRETH := rgHasRETH(d.store.ActiveConfig(), rgID)
				vrrpReady, vrrpReasons = d.vrrpMgr.RGVRRPReady(rgID, hasRETH)
			} else {
				vrrpReady = true // no VRRP = always ready
			}
			userspaceReady, userspaceReasons := d.checkUserspaceTakeoverReadiness(rgID)
			ready := ifReady && vrrpReady && fabricReady && userspaceReady
			var reasons []string
			reasons = append(reasons, ifReasons...)
			reasons = append(reasons, vrrpReasons...)
			if !fabricReady {
				reasons = append(reasons, "fabric forwarding path not ready")
			}
			reasons = append(reasons, userspaceReasons...)
			d.cluster.SetRGReady(rgID, ready, reasons)
		}
	}

	for _, rgID := range rgIDs {
		clusterPri := d.cluster.IsLocalPrimary(rgID)
		vrrp := rgVRRP[rgID] // may be nil if no VRRP instances for this RG
		if vrrp == nil {
			vrrp = make(map[string]bool)
		}

		s := d.getOrCreateRGState(rgID)
		tr := s.Reconcile(clusterPri, vrrp)

		// Desired-vs-applied retry: even if the state machine didn't
		// change this pass, a prior UpdateRGActive failure may have
		// left applied != desired. Retry unconditionally.
		needsApply := tr.Changed || s.NeedsApply()
		if needsApply && d.dp != nil {
			if tr.Changed {
				slog.Info("reconcile: correcting rg_active drift",
					"rg", rgID, "active", tr.Active, "epoch", tr.Epoch)
			} else {
				slog.Info("reconcile: retrying rg_active apply",
					"rg", rgID, "active", tr.Active)
			}
			if tr.Active {
				// Activation ordering: set rg_active FIRST, then
				// remove blackholes.
				if err := d.dp.UpdateRGActive(rgID, true); err != nil {
					slog.Warn("reconcile: failed to update rg_active",
						"rg", rgID, "active", true, "err", err)
				} else {
					s.MarkApplied(true)
				}
			} else {
				// Deactivation ordering: blackholes FIRST, then
				// clear rg_active.
				d.injectBlackholeRoutes(rgID)
				d.tryPrepareUserspaceRGDemotion(rgID)
				if err := d.dp.UpdateRGActive(rgID, false); err != nil {
					slog.Warn("reconcile: failed to update rg_active",
						"rg", rgID, "active", false, "err", err)
				} else {
					s.MarkApplied(false)
				}
			}
		}

		// Declarative blackhole route reconciliation: assert the route
		// set that should exist regardless of prior transition results.
		// Active RGs should NOT have blackholes; inactive RGs SHOULD.
		if tr.Active {
			d.removeBlackholeRoutes(rgID)
		} else {
			d.injectBlackholeRoutes(rgID)
		}

		// VRRP posture reconciliation (#86): detect sustained mismatch
		// between cluster state and VRRP state. Only act after 10s+
		// continuous mismatch to avoid fighting transient states (VRRP
		// sync-hold, election timers, hitless restart). Skip entirely
		// during sync-hold when VRRP is intentionally suppressing preempt.
		// Also skip when no-reth-vrrp is active (no RETH VRRP instances).
		//
		// NeedsMaster: only re-send priority update — do NOT call
		// ForceRGMaster here. ForceRGMaster overrides preempt=false,
		// which should only happen from explicit cluster operations
		// (Secondary→Primary in watchClusterEvents). After a reboot
		// the transition is SecondaryHold→Primary, which intentionally
		// skips ForceRGMaster so VRRP respects non-preempt config.
		// The priority update fixes the dropped-event case (#86) while
		// letting VRRP's preempt logic decide whether to transition.
		if d.vrrpMgr != nil && !d.vrrpMgr.InSyncHold() && !noRethVRRP {
			switch s.CheckVRRPPosture(time.Now()) {
			case vrrpPostureNeedsMaster:
				slog.Warn("reconcile: VRRP posture mismatch — cluster=primary but VRRP!=MASTER, re-sending priority",
					"rg", rgID)
				d.vrrpMgr.UpdateRGPriority(rgID, 200)
			case vrrpPostureNeedsResign:
				slog.Warn("reconcile: VRRP posture mismatch — cluster=secondary but VRRP=MASTER, resigning",
					"rg", rgID)
				d.vrrpMgr.ResignRG(rgID)
			}
		}

		// Direct-mode VIP safety net: idempotently add VIPs on active
		// RGs to recover from missed events or transient address removal
		// (e.g. networkd reload). VIP removal only on state change to
		// avoid racing with event-driven directAddVIPs during failover.
		if noRethVRRP {
			if tr.Active {
				if added := d.directAddVIPs(rgID); added > 0 {
					d.scheduleDirectAnnounce(rgID, "reconcile-vip-add")
				}
			} else if tr.Changed {
				d.cancelDirectAnnounce(rgID)
				d.directRemoveVIPs(rgID)
			}
		}

		// Startup active-side announce: after a daemon restart, an RG can
		// remain active without any ownership transition. In direct mode
		// that means no failover event fires to refresh downstream ARP/NDP
		// caches, so LAN hosts can keep a failed gateway entry until they
		// happen to relearn it. Re-announce once per daemon run.
		if noRethVRRP && tr.Active && !d.startupActiveAnnounce[rgID] {
			if d.startupActiveAnnounce == nil {
				d.startupActiveAnnounce = make(map[int]bool)
			}
			d.startupActiveAnnounce[rgID] = true
			d.scheduleDirectAnnounce(rgID, "startup-active")
			go func() {
				if cfg := d.store.ActiveConfig(); cfg != nil {
					d.resolveNeighbors(cfg)
				}
			}()
		}

		// RA/DHCP service reconciliation (#93): safety net for dropped
		// VRRP events that should have started or stopped per-RG services.
		// Services (RA/DHCP) only start/stop on actual state change to
		// avoid thrashing restarts every reconcile tick.
		if tr.Changed {
			if tr.Active {
				d.applyRethServicesForRG(rgID)
			} else {
				d.clearRethServicesForRG(rgID)
			}
		}
		// Stable link-local: ensure correct on EVERY reconcile tick.
		// The kernel preserves NODAD addresses across daemon restarts,
		// so stale addresses can exist without a state transition.
		// Primary: add (idempotent — AddrAdd returns EEXIST if present).
		// Secondary: remove (idempotent — AddrDel returns ENOENT if absent).
		if tr.Active {
			d.addStableRethLinkLocal(rgID)
		} else {
			d.removeStableRethLinkLocal(rgID)
		}

		// Startup goodbye RA: when an RG is inactive on the first
		// reconcile pass (node booted as secondary), send a one-shot
		// goodbye RA (lifetime=0) to clear stale routes from a
		// previous primary run. Each RETH node has a per-node virtual
		// MAC producing a distinct link-local, so hosts see each node
		// as a separate IPv6 router. Without this, hosts ECMP-split
		// traffic to BOTH nodes even though only one is active.
		if !tr.Active && d.ra != nil && !d.startupGoodbyeRA[rgID] {
			if d.startupGoodbyeRA == nil {
				d.startupGoodbyeRA = make(map[int]bool)
			}
			d.startupGoodbyeRA[rgID] = true
			cfg := d.store.ActiveConfig()
			if cfg != nil {
				rgIfaces := rethInterfacesForRG(cfg, rgID)
				rgIfaceSet := make(map[string]bool, len(rgIfaces))
				for _, n := range rgIfaces {
					rgIfaceSet[n] = true
				}
				allRA := d.buildRAConfigs(cfg)
				var rgRA []*config.RAInterfaceConfig
				for _, ra := range allRA {
					if rgIfaceSet[ra.Interface] {
						rgRA = append(rgRA, ra)
					}
				}
				if len(rgRA) > 0 {
					go d.ra.WithdrawOnce(rgRA)
				}
			}
		}
	}
}

// rethInterfacesForRG returns the Linux interface names of RETH interfaces
// belonging to the given redundancy group.
func rethInterfacesForRG(cfg *config.Config, rgID int) []string {
	var names []string
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup == rgID && strings.HasPrefix(name, "reth") {
			// Resolve RETH to physical member for Linux-level operations.
			resolved := config.LinuxIfName(cfg.ResolveReth(name))
			for _, unit := range ifc.Units {
				if unit.VlanID > 0 {
					names = append(names, resolved+"."+fmt.Sprintf("%d", unit.VlanID))
				} else {
					names = append(names, resolved)
				}
			}
		}
	}
	return names
}

// userspaceDataplaneActive returns true when the userspace dataplane is
// running in a mode that handles forwarding (not eBPF-only). Callers use
// this to skip eBPF-specific workarounds (blackhole routes) that the
// userspace pipeline doesn't need.
func (d *Daemon) userspaceDataplaneActive() bool {
	if um, ok := d.dp.(*dpuserspace.Manager); ok {
		return um.Mode() != dpuserspace.ModeEBPFOnly
	}
	return false
}

// injectBlackholeRoutes adds blackhole routes for RETH subnets of the given
// RG. Called on VRRP BACKUP transition — prevents bpf_fib_lookup from routing
// return traffic via the default route (which would escape via WAN). Instead,
// FIB returns BLACKHOLE and the BPF failure handler triggers fabric redirect.
func (d *Daemon) injectBlackholeRoutes(rgID int) {
	if d.userspaceDataplaneActive() {
		return
	}
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	var routes []netlink.Route
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup != rgID || !strings.HasPrefix(name, "reth") {
			continue
		}
		for _, unit := range ifc.Units {
			for _, addr := range unit.Addresses {
				_, ipNet, err := net.ParseCIDR(addr)
				if err != nil {
					slog.Warn("blackhole: failed to parse RETH address",
						"rg", rgID, "iface", name, "addr", addr, "err", err)
					continue
				}
				rt := netlink.Route{
					Dst:      ipNet,
					Type:     unix.RTN_BLACKHOLE,
					Priority: 4242,
				}
				if err := netlink.RouteAdd(&rt); err != nil {
					if errors.Is(err, unix.EEXIST) {
						// Idempotent transition: route already present
						// from a prior BACKUP event. Track it so MASTER
						// cleanup removes it deterministically.
						routes = append(routes, rt)
						slog.Debug("blackhole: route already exists",
							"rg", rgID, "dst", ipNet)
						continue
					}
					slog.Warn("blackhole: failed to add route",
						"rg", rgID, "dst", ipNet, "err", err)
					continue
				}
				routes = append(routes, rt)
				slog.Info("blackhole: injected route for inactive RG",
					"rg", rgID, "dst", ipNet)
			}
		}
	}
	d.blackholeRoutes[rgID] = routes
}

// removeBlackholeRoutes removes blackhole routes previously injected for the
// given RG. Called on VRRP MASTER transition — the connected route returns
// naturally when the VIP is added back.
func (d *Daemon) removeBlackholeRoutes(rgID int) {
	if d.userspaceDataplaneActive() {
		return
	}
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	for _, rt := range d.blackholeRoutes[rgID] {
		if err := netlink.RouteDel(&rt); err != nil {
			if errors.Is(err, unix.ESRCH) {
				// Idempotent transition: route already gone.
				slog.Debug("blackhole: route already removed",
					"rg", rgID, "dst", rt.Dst)
				continue
			}
			slog.Warn("blackhole: failed to remove route",
				"rg", rgID, "dst", rt.Dst, "err", err)
		} else {
			slog.Info("blackhole: removed route for active RG",
				"rg", rgID, "dst", rt.Dst)
		}
	}
	delete(d.blackholeRoutes, rgID)
}

// reconcileBlackholeRoutes removes stale blackhole routes left by a previous
// daemon run. The in-memory blackholeRoutes map is lost on restart, so any
// RTN_BLACKHOLE routes with priority 4242 (our sentinel) survive in the kernel.
// Called once at startup before cluster comms start.
func (d *Daemon) reconcileBlackholeRoutes() {
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	families := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
	for _, family := range families {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{
			Type: unix.RTN_BLACKHOLE,
		}, netlink.RT_FILTER_TYPE)
		if err != nil {
			slog.Warn("blackhole: failed to list routes for reconciliation",
				"family", family, "err", err)
			continue
		}
		for _, rt := range routes {
			if rt.Priority != 4242 {
				continue
			}
			if err := netlink.RouteDel(&rt); err != nil && !errors.Is(err, unix.ESRCH) {
				slog.Warn("blackhole: failed to remove stale route",
					"dst", rt.Dst, "err", err)
			} else {
				slog.Info("blackhole: removed stale route from previous run",
					"dst", rt.Dst)
			}
		}
	}
}

// applyRethServicesForRG starts RA senders and Kea DHCP server only for
// RETH interfaces belonging to the given RG. Called on VRRP MASTER
// transition — these services must only run on the primary to avoid
// dual-router / dual-DHCP issues.
func (d *Daemon) applyRethServicesForRG(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	rgIfaces := rethInterfacesForRG(cfg, rgID)
	rgIfaceSet := make(map[string]bool, len(rgIfaces))
	for _, n := range rgIfaces {
		rgIfaceSet[n] = true
	}

	if d.ra != nil {
		allRA := d.buildRAConfigs(cfg)
		var rgRA []*config.RAInterfaceConfig
		for _, ra := range allRA {
			if rgIfaceSet[ra.Interface] {
				rgRA = append(rgRA, ra)
			}
		}
		// Collect RA configs from ALL master RGs (not just this one).
		for otherRG, isMaster := range d.snapshotRethMasterState() {
			if !isMaster || otherRG == rgID {
				continue
			}
			otherIfaces := rethInterfacesForRG(cfg, otherRG)
			otherSet := make(map[string]bool, len(otherIfaces))
			for _, n := range otherIfaces {
				otherSet[n] = true
			}
			for _, ra := range allRA {
				if otherSet[ra.Interface] {
					rgRA = append(rgRA, ra)
				}
			}
		}
		if len(rgRA) > 0 {
			if err := d.ra.Apply(rgRA); err != nil {
				slog.Warn("vrrp: failed to apply RA on MASTER", "rg", rgID, "err", err)
			} else {
				slog.Info("vrrp: RA senders started (MASTER)", "rg", rgID)
			}
		}
	}
	if d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		dhcpCfg := d.filterDHCPConfigForMasterRGs(cfg)
		if dhcpCfg != nil {
			if err := d.dhcpServer.Apply(dhcpCfg); err != nil {
				slog.Warn("vrrp: failed to apply DHCP server on MASTER", "rg", rgID, "err", err)
			} else {
				slog.Info("vrrp: DHCP server started (MASTER)", "rg", rgID)
			}
		}
	}
}

// clearRethServicesForRG withdraws RA senders and stops DHCP server only
// for RETH interfaces belonging to the given RG. Called on VRRP BACKUP
// transition. If other RGs are still MASTER, their services remain active.
func (d *Daemon) clearRethServicesForRG(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	// Check if any other RG is still master — if so, reapply services for
	// those RGs only; otherwise clear everything.
	anyOtherMaster := false
	for otherRG, isMaster := range d.snapshotRethMasterState() {
		if otherRG != rgID && isMaster {
			anyOtherMaster = true
			break
		}
	}

	if d.ra != nil {
		if anyOtherMaster {
			// Withdraw only this RG's interfaces; reapply others.
			rgIfaces := rethInterfacesForRG(cfg, rgID)
			d.ra.WithdrawInterfaces(rgIfaces)
		} else {
			if err := d.ra.Withdraw(); err != nil {
				slog.Warn("vrrp: failed to withdraw RA on BACKUP", "rg", rgID, "err", err)
			} else {
				slog.Info("vrrp: RA withdrawn (BACKUP, goodbye RA sent)", "rg", rgID)
			}
		}
	}
	if d.dhcpServer != nil {
		if anyOtherMaster {
			// Reapply DHCP with only the remaining master RGs' interfaces.
			dhcpCfg := d.filterDHCPConfigForMasterRGs(cfg)
			if dhcpCfg != nil {
				if err := d.dhcpServer.Apply(dhcpCfg); err != nil {
					slog.Warn("vrrp: failed to reapply DHCP after RG BACKUP", "rg", rgID, "err", err)
				}
			} else {
				d.dhcpServer.Clear()
			}
		} else {
			d.dhcpServer.Clear()
			slog.Info("vrrp: DHCP server stopped (BACKUP)", "rg", rgID)
		}
	}
}

// filterDHCPConfigForMasterRGs returns a DHCP config containing only groups
// whose interfaces belong to RGs that are currently MASTER. Returns nil if
// no groups match.
func (d *Daemon) filterDHCPConfigForMasterRGs(cfg *config.Config) *config.DHCPServerConfig {
	// Collect all interfaces belonging to master RGs.
	masterIfaces := make(map[string]bool)
	for rgID, isMaster := range d.snapshotRethMasterState() {
		if !isMaster {
			continue
		}
		for _, n := range rethInterfacesForRG(cfg, rgID) {
			masterIfaces[n] = true
		}
	}

	dhcpCfg := cfg.System.DHCPServer
	resolveDHCPRethInterfaces(&dhcpCfg, cfg)

	filterGroups := func(groups map[string]*config.DHCPServerGroup) map[string]*config.DHCPServerGroup {
		if groups == nil {
			return nil
		}
		result := make(map[string]*config.DHCPServerGroup)
		for name, group := range groups {
			var kept []string
			for _, iface := range group.Interfaces {
				if masterIfaces[iface] {
					kept = append(kept, iface)
				}
			}
			if len(kept) > 0 {
				cp := *group
				cp.Interfaces = kept
				result[name] = &cp
			}
		}
		return result
	}

	var result config.DHCPServerConfig
	if dhcpCfg.DHCPLocalServer != nil {
		filtered := filterGroups(dhcpCfg.DHCPLocalServer.Groups)
		if len(filtered) > 0 {
			result.DHCPLocalServer = &config.DHCPLocalServerConfig{Groups: filtered}
		}
	}
	if dhcpCfg.DHCPv6LocalServer != nil {
		filtered := filterGroups(dhcpCfg.DHCPv6LocalServer.Groups)
		if len(filtered) > 0 {
			result.DHCPv6LocalServer = &config.DHCPLocalServerConfig{Groups: filtered}
		}
	}
	if result.DHCPLocalServer == nil && result.DHCPv6LocalServer == nil {
		return nil
	}
	return &result
}

// applyRethServices starts RA senders and Kea DHCP server. Called on VRRP
// MASTER transition — these services bind to RETH member interfaces
// and must only run on the primary node to avoid dual-RA / dual-DHCP.
// Deprecated: use applyRethServicesForRG for per-RG management.
func (d *Daemon) applyRethServices() {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if d.ra != nil {
		raConfigs := d.buildRAConfigs(cfg)
		if len(raConfigs) > 0 {
			if err := d.ra.Apply(raConfigs); err != nil {
				slog.Warn("vrrp: failed to apply RA on MASTER", "err", err)
			} else {
				slog.Info("vrrp: RA senders started (MASTER)")
			}
		}
	}
	if d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		dhcpCfg := cfg.System.DHCPServer
		resolveDHCPRethInterfaces(&dhcpCfg, cfg)
		if err := d.dhcpServer.Apply(&dhcpCfg); err != nil {
			slog.Warn("vrrp: failed to apply DHCP server on MASTER", "err", err)
		} else {
			slog.Info("vrrp: DHCP server started (MASTER)")
		}
	}
}

// clearRethServices sends goodbye RAs (lifetime=0) and stops Kea DHCP
// server. Called on VRRP BACKUP transition to prevent the secondary from
// advertising RAs or serving DHCP leases. The goodbye RA tells hosts to
// immediately remove this router as a default gateway.
// Deprecated: use clearRethServicesForRG for per-RG management.
func (d *Daemon) clearRethServices() {
	if d.ra != nil {
		if err := d.ra.Withdraw(); err != nil {
			slog.Warn("vrrp: failed to withdraw RA on BACKUP", "err", err)
		} else {
			slog.Info("vrrp: RA withdrawn (BACKUP, goodbye RA sent)")
		}
	}
	if d.dhcpServer != nil {
		d.dhcpServer.Clear()
		slog.Info("vrrp: DHCP server stopped (BACKUP)")
	}
}

// warmNeighborCache iterates synced sessions and sends ARP requests /
// ICMPv6 Neighbor Solicitations for unique destination IPs. This
// pre-populates the kernel neighbor cache so that bpf_fib_lookup
// returns SUCCESS (not NO_NEIGH) for the first packet after failover.
func (d *Daemon) warmNeighborCache() {
	if d.dp == nil {
		return
	}

	seen := make(map[[4]byte]bool)
	seenV6 := make(map[[16]byte]bool)

	// Iterate IPv4 sessions: collect unique dst IPs (forward entries
	// need ARP for the next-hop toward the destination) and unique src IPs
	// (return entries need ARP for the on-link client).
	_ = d.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !seen[key.DstIP] {
			seen[key.DstIP] = true
		}
		if !seen[key.SrcIP] {
			seen[key.SrcIP] = true
		}
		return true
	})

	// Iterate IPv6 sessions.
	_ = d.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !seenV6[key.DstIP] {
			seenV6[key.DstIP] = true
		}
		if !seenV6[key.SrcIP] {
			seenV6[key.SrcIP] = true
		}
		return true
	})

	// Resolve IPv4 neighbors by sending a UDP packet to trigger kernel ARP.
	// UDP connect() alone does NOT trigger ARP — only the route lookup is
	// performed. We must send at least one byte so the kernel actually
	// calls neigh_resolve_output() → arp_solicit().
	count := 0
	for ip4 := range seen {
		addr := netip.AddrFrom4(ip4)
		if !addr.IsGlobalUnicast() || addr.IsPrivate() && addr.IsLoopback() {
			continue
		}
		conn, err := net.DialTimeout("udp4", netip.AddrPortFrom(addr, 1).String(), 50*time.Millisecond)
		if err == nil {
			conn.Write([]byte{0}) // triggers ARP resolution
			conn.Close()
			count++
		}
	}

	// Resolve IPv6 neighbors.
	countV6 := 0
	for ip6 := range seenV6 {
		addr := netip.AddrFrom16(ip6)
		if !addr.IsGlobalUnicast() {
			continue
		}
		conn, err := net.DialTimeout("udp6", netip.AddrPortFrom(addr, 1).String(), 50*time.Millisecond)
		if err == nil {
			conn.Write([]byte{0}) // triggers NDP resolution
			conn.Close()
			countV6++
		}
	}

	if count > 0 || countV6 > 0 {
		slog.Info("cluster: neighbor cache warmup complete",
			"ipv4_hosts", count, "ipv6_hosts", countV6)
		// Brief pause to allow ARP/NDP responses before traffic arrives.
		time.Sleep(200 * time.Millisecond)
	}
}

// clusterConfig returns the current cluster config or nil.
func (d *Daemon) clusterConfig() *config.ClusterConfig {
	if d.store == nil {
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	return cfg.Chassis.Cluster
}

// checkVIPReadiness verifies that RETH interfaces for the given RG exist and
// are operationally UP, so that VIPs can actually be added. Used in
// private-rg-election mode where there are no VRRP instances to gate readiness.
func (d *Daemon) checkVIPReadiness(rgID int) (bool, []string) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return true, nil // no config = nothing to check
	}
	linkByName := d.linkByNameFn
	if linkByName == nil {
		linkByName = netlink.LinkByName
	}
	return checkVIPReadinessForConfig(cfg, rgID, linkByName)
}

// checkVIPReadinessForConfig verifies that RETH interfaces for the given RG
// exist and are operationally UP. Pure function for testability.
func checkVIPReadinessForConfig(cfg *config.Config, rgID int, linkByName func(string) (netlink.Link, error)) (bool, []string) {
	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	if len(vipMap) == 0 {
		return true, nil // no VIPs for this RG
	}
	var reasons []string
	for ifName := range vipMap {
		link, err := linkByName(ifName)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("vip interface %s not found", ifName))
			continue
		}
		up := link.Attrs().OperState == netlink.OperUp ||
			link.Attrs().Flags&net.FlagUp != 0
		if !up {
			reasons = append(reasons, fmt.Sprintf("vip interface %s down", ifName))
		}
	}
	return len(reasons) == 0, reasons
}

func userspaceRGConfigured(cfg *config.Config, rgID int) bool {
	if cfg == nil || cfg.System.DataplaneType != dataplane.TypeUserspace || rgID <= 0 {
		return false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}

// checkUserspaceTakeoverReadiness returns whether the userspace dataplane
// is ready to take over forwarding for the given RG. Returns (true, nil)
// for non-userspace RGs or when the dataplane is healthy.
func (d *Daemon) checkUserspaceTakeoverReadiness(rgID int) (bool, []string) {
	cfg := d.store.ActiveConfig()
	if !userspaceRGConfigured(cfg, rgID) {
		return true, nil
	}
	// Copilot fix: if dp is nil or wrong type but config says userspace,
	// the dataplane isn't ready — don't report takeover-ready.
	if d.dp == nil {
		return false, []string{fmt.Sprintf("userspace dataplane not initialized for RG %d", rgID)}
	}
	um, ok := d.dp.(*dpuserspace.Manager)
	if !ok {
		return false, []string{fmt.Sprintf("userspace dataplane manager not available for RG %d", rgID)}
	}
	return um.TakeoverReady()
}

// isNoRethVRRP returns true when no-reth-vrrp is explicitly configured,
// meaning the daemon directly manages VIPs/GARPs without VRRP instances.
// Default (no flag) uses VRRP for RETH failover.
func (d *Daemon) isNoRethVRRP() bool {
	cc := d.clusterConfig()
	return cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection)
}

// directAddVIPs adds VIPs for RETH interfaces in the given RG using netlink.
// IPv6 addresses are added with IFA_F_NODAD to avoid DAD delays.
// Idempotent — skips addresses that already exist. Returns the number of
// addresses actually added (non-EEXIST).
func (d *Daemon) directAddVIPs(rgID int) int {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return 0
	}
	var added int
	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			if d.vipWarnedIfaces == nil {
				d.vipWarnedIfaces = make(map[string]bool)
			}
			if !d.vipWarnedIfaces[ifName] {
				slog.Warn("directAddVIPs: interface not found", "iface", ifName, "err", err)
				d.vipWarnedIfaces[ifName] = true
			}
			continue
		}
		// Interface exists now — clear any previous warning suppression
		delete(d.vipWarnedIfaces, ifName)
		for _, cidr := range addrs {
			addr, err := netlink.ParseAddr(cidr)
			if err != nil {
				slog.Warn("directAddVIPs: bad address", "addr", cidr, "err", err)
				continue
			}
			if addr.IP.To4() == nil {
				addr.Flags = unix.IFA_F_NODAD
			}
			if err := netlink.AddrAdd(link, addr); err != nil {
				if !errors.Is(err, syscall.EEXIST) {
					slog.Warn("directAddVIPs: failed to add", "iface", ifName, "addr", cidr, "err", err)
				}
			} else {
				slog.Info("directAddVIPs: added VIP", "iface", ifName, "addr", cidr)
				added++
			}
		}
	}
	return added
}

// directRemoveVIPs removes VIPs for RETH interfaces in the given RG.
// Ignores "not found" errors for idempotency.
func (d *Daemon) directRemoveVIPs(rgID int) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			continue // interface may not exist yet
		}
		for _, cidr := range addrs {
			addr, err := netlink.ParseAddr(cidr)
			if err != nil {
				continue
			}
			if err := netlink.AddrDel(link, addr); err != nil {
				if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
					slog.Warn("directRemoveVIPs: failed to remove", "iface", ifName, "addr", cidr, "err", err)
				}
			} else {
				slog.Info("directRemoveVIPs: removed VIP", "iface", ifName, "addr", cidr)
			}
		}
	}
}

// addStableRethLinkLocal adds the stable router link-local address to all
// RETH interfaces for the given RG. This address is shared across cluster
// nodes (no nodeID component) so hosts see the same IPv6 router identity
// regardless of which node is primary. Managed like a VIP: only present
// on the MASTER node.
func (d *Daemon) addStableRethLinkLocal(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	clusterID := cfg.Chassis.Cluster.ClusterID
	stableLL := cluster.StableRethLinkLocal(clusterID, rgID)
	rethToPhys := cfg.RethToPhysical()

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup != rgID {
			continue
		}
		if !strings.HasPrefix(ifName, "reth") {
			continue
		}
		// Skip interfaces with an explicitly configured link-local address —
		// the user's configured LL replaces the auto-generated stable LL.
		if rethUnitHasConfiguredLinkLocal(ifc, 0) {
			slog.Debug("skipping stable LL (explicit LL configured)", "iface", ifName)
			continue
		}
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)
		addStableLLToInterface(linuxName, stableLL)
		for unitNum := range ifc.Units {
			if unitNum > 0 && rethUnitHasIPv6(ifc, unitNum) {
				unit := ifc.Units[unitNum]
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				addStableLLToInterface(subIface, stableLL)
			}
		}
	}
}

func addStableLLToInterface(ifName string, ll net.IP) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(128, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			slog.Warn("failed to add stable link-local", "iface", ifName, "addr", ll, "err", err)
		}
	} else {
		slog.Info("added stable router link-local", "iface", ifName, "addr", ll)
	}
}

// removeStableRethLinkLocal removes the stable router link-local address
// from all RETH interfaces for the given RG. Called on BACKUP transition.
func (d *Daemon) removeStableRethLinkLocal(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	clusterID := cfg.Chassis.Cluster.ClusterID
	stableLL := cluster.StableRethLinkLocal(clusterID, rgID)
	rethToPhys := cfg.RethToPhysical()

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup != rgID {
			continue
		}
		if !strings.HasPrefix(ifName, "reth") {
			continue
		}
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)
		removeStableLLFromInterface(linuxName, stableLL)
		for unitNum := range ifc.Units {
			if unitNum > 0 {
				unit := ifc.Units[unitNum]
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				removeStableLLFromInterface(subIface, stableLL)
			}
		}
	}
}

func removeStableLLFromInterface(ifName string, ll net.IP) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(128, 128)},
	}
	if err := netlink.AddrDel(link, addr); err != nil {
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
			slog.Warn("failed to remove stable link-local", "iface", ifName, "addr", ll, "err", err)
		}
	} else {
		slog.Info("removed stable router link-local", "iface", ifName, "addr", ll)
	}
}

func (d *Daemon) directAnnounceActive(rgID int, seq uint64) bool {
	d.directAnnounceMu.Lock()
	current := d.directAnnounceSeq[rgID]
	d.directAnnounceMu.Unlock()
	if current != seq {
		return false
	}
	d.rgStatesMu.RLock()
	s := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	return s != nil && s.IsActive()
}

func (d *Daemon) cancelDirectAnnounce(rgID int) {
	d.directAnnounceMu.Lock()
	defer d.directAnnounceMu.Unlock()
	if d.directAnnounceSeq == nil {
		d.directAnnounceSeq = make(map[int]uint64)
	}
	d.directAnnounceSeq[rgID]++
}

func (d *Daemon) scheduleDirectAnnounce(rgID int, reason string) {
	d.directAnnounceMu.Lock()
	if d.directAnnounceSeq == nil {
		d.directAnnounceSeq = make(map[int]uint64)
	}
	d.directAnnounceSeq[rgID]++
	seq := d.directAnnounceSeq[rgID]
	schedule := append([]time.Duration(nil), d.directAnnounceSchedule...)
	sendFn := d.directSendGARPsFn
	d.directAnnounceMu.Unlock()
	if len(schedule) == 0 {
		schedule = []time.Duration{0}
	}
	if sendFn == nil {
		sendFn = d.directSendGARPs
	}
	slog.Info("direct-mode re-announce scheduled", "rg", rgID, "reason", reason, "bursts", len(schedule))
	go func() {
		start := time.Now()
		for idx, at := range schedule {
			if wait := time.Until(start.Add(at)); wait > 0 {
				timer := time.NewTimer(wait)
				<-timer.C
			}
			if !d.directAnnounceActive(rgID, seq) {
				return
			}
			sendFn(rgID)
			slog.Info("direct-mode re-announce sent", "rg", rgID, "reason", reason, "burst", idx+1, "total", len(schedule))
		}
	}()
}

// directSendGARPs sends gratuitous ARP/IPv6 NA bursts for all VIPs in the
// given RG. Reads per-RG GratuitousARPCount (default 3).
func (d *Daemon) directSendGARPs(rgID int) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// Read per-RG GARP count.
	garpCount := 3
	if cc := cfg.Chassis.Cluster; cc != nil {
		for _, rg := range cc.RedundancyGroups {
			if rg.ID == rgID && rg.GratuitousARPCount > 0 {
				garpCount = rg.GratuitousARPCount
			}
		}
	}

	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		for _, cidr := range addrs {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				if err := cluster.SendGratuitousARPBurst(ifName, ip, garpCount); err != nil {
					slog.Warn("directSendGARPs: GARP failed", "iface", ifName, "ip", ip, "err", err)
				}
				// Send ARP probe to gateway (.1) to update upstream ARP caches.
				_, ipNet, _ := net.ParseCIDR(cidr)
				if ipNet != nil {
					gw := make(net.IP, len(ipNet.IP))
					copy(gw, ipNet.IP)
					gw[len(gw)-1] = 1
					if err := cluster.SendARPProbe(ifName, gw); err != nil {
						slog.Warn("directSendGARPs: ARP probe failed", "iface", ifName, "gw", gw, "err", err)
					}
				}
			} else {
				if err := cluster.SendGratuitousIPv6Burst(ifName, ip, garpCount); err != nil {
					slog.Warn("directSendGARPs: IPv6 NA failed", "iface", ifName, "ip", ip, "err", err)
				}
			}
		}
	}

	// Send NA burst for router link-local so hosts update neighbor cache for
	// the router identity (not just VIPs). Uses the explicitly configured
	// link-local if present, otherwise the auto-generated stable LL.
	// Send on base interface AND all VLAN sub-interfaces (separate L2 domains).
	if cfg.Chassis.Cluster != nil {
		stableLL := cluster.StableRethLinkLocal(cfg.Chassis.Cluster.ClusterID, rgID)
		rethToPhys := cfg.RethToPhysical()
		seen := make(map[string]bool)
		for ifName, ifc := range cfg.Interfaces.Interfaces {
			if ifc.RedundancyGroup != rgID || !strings.HasPrefix(ifName, "reth") {
				continue
			}
			// Use configured link-local if present, otherwise stable LL.
			routerLL := stableLL
			if unit, ok := ifc.Units[0]; ok {
				for _, addr := range unit.Addresses {
					ip, _, err := net.ParseCIDR(addr)
					if err == nil && ip.IsLinkLocalUnicast() && ip.To4() == nil {
						routerLL = ip
						break
					}
				}
			}
			physName := ifc.Name
			if phys, ok := rethToPhys[ifc.Name]; ok {
				physName = phys
			}
			linuxName := config.LinuxIfName(physName)
			// Send on base interface.
			if !seen[linuxName] {
				seen[linuxName] = true
				if err := cluster.SendGratuitousIPv6Burst(linuxName, routerLL, garpCount); err != nil {
					slog.Warn("directSendGARPs: router link-local NA failed",
						"iface", linuxName, "ip", routerLL, "err", err)
				}
			}
			// Send on each VLAN sub-interface.
			for _, unit := range ifc.Units {
				if unit.VlanID > 0 {
					subIface := fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
					if !seen[subIface] {
						seen[subIface] = true
						if err := cluster.SendGratuitousIPv6Burst(subIface, routerLL, garpCount); err != nil {
							slog.Warn("directSendGARPs: router link-local NA failed",
								"iface", subIface, "ip", routerLL, "err", err)
						}
					}
				}
			}
		}
	}
}

// syncIPsecSAPeriodic runs on the primary node, periodically syncing active IPsec
// connection names to the secondary via the session sync channel.
func (d *Daemon) syncIPsecSAPeriodic(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if d.cluster == nil || !d.cluster.IsLocalPrimary(0) {
				continue
			}
			cc := d.clusterConfig()
			if cc == nil || !cc.IPsecSASync {
				continue
			}
			names, err := d.ipsec.ActiveConnectionNames()
			if err != nil {
				slog.Debug("cluster: failed to get IPsec connection names", "err", err)
				continue
			}
			if len(names) > 0 && d.sessionSync != nil {
				d.sessionSync.QueueIPsecSA(names)
			}
		}
	}
}

// reinitiateIPsecSAs re-initiates all IPsec connections that were synced from the
// previous primary. Called when this node becomes primary after failover.
func (d *Daemon) reinitiateIPsecSAs() {
	names := d.sessionSync.PeerIPsecSAs()
	if len(names) == 0 {
		return
	}
	slog.Info("cluster: re-initiating IPsec SAs after failover", "count", len(names))
	for _, name := range names {
		if err := d.ipsec.InitiateConnection(name); err != nil {
			slog.Warn("cluster: failed to initiate IPsec SA", "name", name, "err", err)
		} else {
			slog.Info("cluster: IPsec SA initiated", "name", name)
		}
	}
}

// resolveDHCPRethInterfaces translates RETH interface names in DHCP server
// groups to their physical member Linux names (Kea needs real device names).
func resolveDHCPRethInterfaces(dhcpCfg *config.DHCPServerConfig, cfg *config.Config) {
	resolve := func(groups map[string]*config.DHCPServerGroup) {
		for _, group := range groups {
			for i, iface := range group.Interfaces {
				group.Interfaces[i] = config.LinuxIfName(cfg.ResolveReth(iface))
			}
		}
	}
	if dhcpCfg.DHCPLocalServer != nil {
		resolve(dhcpCfg.DHCPLocalServer.Groups)
	}
	if dhcpCfg.DHCPv6LocalServer != nil {
		resolve(dhcpCfg.DHCPv6LocalServer.Groups)
	}
}
