// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/vishvananda/netlink"
)

// collectDHCPRoutes builds FRR DHCPRoute entries from active DHCP leases.
// Interfaces bound to the management VRF are excluded — their routes are
// programmed directly via netlink into the VRF table by applyMgmtVRFRoutes.
func (d *Daemon) collectDHCPRoutes() []frr.DHCPRoute {
	if d.dhcp == nil {
		return nil
	}
	var routes []frr.DHCPRoute
	for _, lease := range d.dhcp.Leases() {
		if d.mgmtVRFInterfaces[lease.Interface] {
			continue
		}
		isIPv6 := lease.Family == dhcp.AFInet6
		// Default route (option-3 gateway, or option-121 0.0.0.0/0 entry).
		if lease.Gateway.IsValid() {
			routes = append(routes, frr.DHCPRoute{
				Gateway:   lease.Gateway.String(),
				Interface: lease.Interface,
				IsIPv6:    isIPv6,
			})
		}
		// RFC 3442 classless static routes (option 121 / legacy 249). A
		// lease may carry these with or without a default gateway.
		for _, cr := range lease.ClasslessRoutes {
			routes = append(routes, frr.DHCPRoute{
				Destination: cr.Destination.String(),
				Gateway:     cr.Gateway.String(),
				Interface:   lease.Interface,
				IsIPv6:      isIPv6,
			})
		}
	}
	return routes
}

// applyMgmtVRFRoutes programs default routes in the management VRF table
// for DHCP leases on management interfaces (fxp*, fab*). These routes are
// managed via netlink (not FRR) because FRR doesn't own the management VRF.
func (d *Daemon) applyMgmtVRFRoutes() {
	if d.dhcp == nil || len(d.mgmtVRFInterfaces) == 0 {
		return
	}
	const mgmtTableID = 999
	nlh, err := netlink.NewHandle()
	if err != nil {
		slog.Warn("mgmt VRF routes: failed to get netlink handle", "err", err)
		return
	}
	defer nlh.Close()

	for _, lease := range d.dhcp.Leases() {
		if !d.mgmtVRFInterfaces[lease.Interface] {
			continue
		}
		// A lease may carry a default gateway (option 3 or the option-121
		// 0.0.0.0/0 entry) and/or RFC 3442 classless static routes (option
		// 121 / legacy 249). Program each into the management VRF table.
		if !lease.Gateway.IsValid() && len(lease.ClasslessRoutes) == 0 {
			continue
		}
		link, err := nlh.LinkByName(lease.Interface)
		if err != nil {
			slog.Warn("mgmt VRF route: interface not found",
				"interface", lease.Interface, "err", err)
			continue
		}
		linkIndex := link.Attrs().Index

		if lease.Gateway.IsValid() {
			var dst *net.IPNet
			if lease.Family == dhcp.AFInet6 {
				dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
			} else {
				dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
			}
			gwSlice := lease.Gateway.AsSlice()
			route := &netlink.Route{
				LinkIndex: linkIndex,
				Dst:       dst,
				Gw:        net.IP(gwSlice),
				Table:     mgmtTableID,
			}
			if err := nlh.RouteReplace(route); err != nil {
				slog.Warn("mgmt VRF route: failed to add default route",
					"interface", lease.Interface, "gw", lease.Gateway, "table", mgmtTableID, "err", err)
			} else {
				slog.Info("mgmt VRF default route installed",
					"interface", lease.Interface, "gw", lease.Gateway, "table", mgmtTableID)
			}
		}

		// RFC 3442 classless static routes.
		for _, cr := range lease.ClasslessRoutes {
			dst := &net.IPNet{
				IP:   net.IP(cr.Destination.Addr().AsSlice()),
				Mask: net.CIDRMask(cr.Destination.Bits(), cr.Destination.Addr().BitLen()),
			}
			route := &netlink.Route{
				LinkIndex: linkIndex,
				Dst:       dst,
				Gw:        net.IP(cr.Gateway.AsSlice()),
				Table:     mgmtTableID,
			}
			if err := nlh.RouteReplace(route); err != nil {
				slog.Warn("mgmt VRF route: failed to add classless route",
					"interface", lease.Interface, "dst", cr.Destination, "gw", cr.Gateway,
					"table", mgmtTableID, "err", err)
			} else {
				slog.Info("mgmt VRF classless route installed",
					"interface", lease.Interface, "dst", cr.Destination, "gw", cr.Gateway,
					"table", mgmtTableID)
			}
		}
	}
}

// logFinalStats reads and logs global counter summary before shutdown.
//
// The signature uses the daemon-local dataplaneReadyProbe
// (runtime_probes.go) + dataplane.Telemetry runtime domain so the
// shutdown path no longer touches the legacy BPF-shaped DataPlane
// surface (#1519). Telemetry().GlobalCounter is structurally
// identical to the previous dp.ReadGlobalCounter call and routes
// to the same underlying BPF map read on both backends.
//
// Ordering invariant (see daemon_run.go shutdown sequence): this
// runs AFTER d.cluster.Stop() / d.sessionSync.Stop() and BEFORE
// d.dp.Close()/d.dp.Teardown(), so the Telemetry provider is
// still backed by a live bpfShim on the userspace path. AGY
// round-1 walked-trace confirmation: manager.bpfShim teardown
// only happens inside manager.Close()/Teardown().
func logFinalStats(ready dataplaneReadyProbe, telemetry dataplane.Telemetry) {
	if ready == nil || !ready.IsLoaded() {
		return
	}
	if telemetry == nil {
		return
	}
	indices := []struct {
		idx  uint32
		name string
	}{
		{dataplane.GlobalCtrRxPackets, "rx_packets"},
		{dataplane.GlobalCtrTxPackets, "tx_packets"},
		{dataplane.GlobalCtrDrops, "drops"},
		{dataplane.GlobalCtrSessionsNew, "sessions_created"},
		{dataplane.GlobalCtrSessionsClosed, "sessions_closed"},
		{dataplane.GlobalCtrScreenDrops, "screen_drops"},
		{dataplane.GlobalCtrPolicyDeny, "policy_denies"},
	}

	attrs := make([]any, 0, len(indices)*2)
	for _, n := range indices {
		v, err := telemetry.GlobalCounter(n.idx)
		if err != nil {
			continue
		}
		attrs = append(attrs, n.name, v)
	}

	slog.Info("final statistics", attrs...)
}

// stopFlowExporter stops the running NetFlow v9 exporter (shutdown).
//
// #2075: the exporter is now (re)started by reconcileFlowExporters, not
// startFlowExporter. This stop is called only at shutdown. It takes
// flowReconMu so it cannot race a concurrent reconcile swap, and it is
// nil-safe / idempotent (a reconcile that already stopped the exporter
// leaves flowCancel/flowExporter nil; context.CancelFunc is idempotent).
func (d *Daemon) stopFlowExporter() {
	d.flowReconMu.Lock()
	defer d.flowReconMu.Unlock()
	// Unpublish the bundle before teardown (#3742), then cancel + wait +
	// close via the shared helper (flowWg is now a nil-safe pointer).
	d.flowBundle.Store(&exporterBundle{})
	d.teardownV9Locked()
	d.flowExportErr = nil
}

// stopIPFIXExporter stops the running IPFIX exporter (shutdown).
func (d *Daemon) stopIPFIXExporter() {
	d.ipfixReconMu.Lock()
	defer d.ipfixReconMu.Unlock()
	d.ipfixBundlePtr.Store(&ipfixBundle{})
	d.teardownIPFIXLocked()
	d.ipfixExportErr = nil
}

// parseAddrPair parses "ip:port" or "[ip]:port" into net.IPs and IPv6 flag.
func parseAddrPair(src, dst string) (srcIP, dstIP net.IP, isV6 bool) {
	srcIP = parseHost(src)
	dstIP = parseHost(dst)
	isV6 = srcIP != nil && srcIP.To4() == nil
	return
}

func parseHost(addr string) net.IP {
	// Handle "[ipv6]:port" format
	if len(addr) > 0 && addr[0] == '[' {
		end := 0
		for i, c := range addr {
			if c == ']' {
				end = i
				break
			}
		}
		if end > 1 {
			return net.ParseIP(addr[1:end])
		}
	}
	// Handle "ipv4:port" format
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return net.ParseIP(addr[:i])
		}
	}
	return net.ParseIP(addr)
}

func parseSrcPort(addr string) uint16 {
	// Find last colon
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			var port uint16
			for _, c := range addr[i+1:] {
				if c >= '0' && c <= '9' {
					port = port*10 + uint16(c-'0')
				}
			}
			return port
		}
	}
	return 0
}

// archiveConfig transfers the active config to remote archive sites
// when system { archival { configuration { transfer-on-commit; } } } is set.
//
// #3867: the uploaded bytes are the CURRENT ACTIVE configuration serialized
// from the configstore — the same hierarchical text `show configuration`
// renders via Store.ShowActive() and the same source the local auto-archive
// (writeArchive) uses — NOT d.opts.ConfigFile. The boot file
// /etc/xpf/xpf.conf is written once at install and is never rewritten after
// the configstore became DB-canonical, so scp'ing it uploaded the day-0
// config on every commit: the DR/compliance archive silently diverged from
// the running config from the first commit onward while scp still logged
// success. We serialize the just-committed active config to a temp file and
// scp THAT, preserving the historical remote filename (the boot-file
// basename) and the scp transport.
func (d *Daemon) archiveConfig(cfg *config.Config) {
	if cfg.System.Archival == nil || !cfg.System.Archival.TransferOnCommit {
		return
	}
	if len(cfg.System.Archival.ArchiveSites) == 0 {
		return
	}
	d.archiveToSites(cfg.System.Archival.ArchiveSites)
}

// archiveToSites serializes the CURRENT active configuration (Store.ShowActive
// — the same hierarchical text `show configuration` renders) to a transient
// 0600 temp file and uploads it to every archive site via the archiveTransfer
// seam (default scpArchiveTransfer). It is the shared archive-to-site path used
// by BOTH transfer-on-commit (archiveConfig, invoked on each commit apply) and
// the periodic transfer-interval timer (runArchiveTimer, #4078) — the periodic
// path reuses this exact transport rather than reimplementing it. The uploaded
// remote filename preserves the historical basename (the boot-file basename,
// default xpf.conf).
func (d *Daemon) archiveToSites(sites []string) {
	if len(sites) == 0 {
		return
	}
	if d.store == nil {
		slog.Warn("config archival skipped: no configuration store")
		return
	}

	// Serialize the CURRENT active config (the just-committed tree) — the
	// same hierarchical text `show configuration` renders. This is the
	// config the operator expects the DR/compliance archive to reflect, not
	// the stale install-time boot file.
	active := d.store.ShowActive()
	if active == "" {
		slog.Warn("config archival skipped: active configuration is empty")
		return
	}

	// Write to a temp file whose basename matches the historical remote name
	// (the boot-file basename, default xpf.conf) so an archive-site directory
	// destination keeps the same archived filename as before this fix.
	base := filepath.Base(d.opts.ConfigFile)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "xpf.conf"
	}
	tmpDir, err := os.MkdirTemp("", "xpf-archive-")
	if err != nil {
		slog.Warn("config archival failed: create temp dir", "err", err)
		return
	}
	srcPath := filepath.Join(tmpDir, base)
	// 0600 — the active config may contain encrypted secrets; keep the
	// transient copy owner-only (MkdirTemp already made the dir 0700).
	if err := os.WriteFile(srcPath, []byte(active), 0600); err != nil {
		slog.Warn("config archival failed: write temp config", "err", err)
		os.RemoveAll(tmpDir)
		return
	}

	transfer := d.archiveTransfer
	if transfer == nil {
		transfer = scpArchiveTransfer
	}

	var wg sync.WaitGroup
	for _, site := range sites {
		wg.Add(1)
		go func(dest string) {
			defer wg.Done()
			slog.Info("archiving config", "destination", dest)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := transfer(ctx, srcPath, dest); err != nil {
				slog.Warn("config archival failed", "destination", dest, "err", err)
			} else {
				slog.Info("config archived successfully", "destination", dest)
			}
		}(site)
	}

	// Remove the temp file only after every upload finishes reading it.
	go func() {
		wg.Wait()
		os.RemoveAll(tmpDir)
	}()
}

// scpArchiveTransfer is the default transfer-on-commit transport: scp the
// serialized active-config file to one archive site. It is split out of
// archiveConfig behind the Daemon.archiveTransfer seam so tests can inject a
// capturing transfer and assert archiveConfig serializes the CURRENT active
// config rather than the stale boot file (#3867).
func scpArchiveTransfer(ctx context.Context, srcPath, dest string) error {
	// #4589 A7 F-02: `--` end-of-options separator before the positional
	// src/dest. `dest` is an operator-configured `archive-sites` URL taken
	// verbatim (compiler_system.go); without the separator a leading-dash
	// value (`-oProxyCommand=...`) is parsed by scp's getopt as an OPTION,
	// not a destination — CWE-88 argv injection running as the xpfd root
	// user. After `--`, getopt stops scanning so src/dest are always
	// positional. Belt-and-suspenders with the commit-time leading-dash
	// reject in compiler_system.go.
	out, err := exec.CommandContext(ctx, "scp",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"--",
		srcPath, dest,
	).CombinedOutput()
	if err != nil {
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			return fmt.Errorf("%w: %s", err, trimmed)
		}
		return err
	}
	return nil
}

// flowTraceCallback is the single, stable flow-traceoptions handler
// registered on the EventReader exactly ONCE (traceCBOnce). It reads the live
// TraceWriter lock-free from the atomic pointer, so a config commit can swap
// the writer — or clear it to nil on disable — without ever registering a
// second callback. This is the #3932 fix: the previous applyFlowTrace /
// updateFlowTrace called er.AddCallback on every commit touching traceoptions,
// so a long-lived daemon leaked one callback (and one TraceWriter) per commit,
// and every event was then dispatched to all N — a growing per-event cost plus
// a stale-writer drop storm. A nil pointer (traceoptions disabled) makes this a
// no-op.
func (d *Daemon) flowTraceCallback(rec logging.EventRecord, raw []byte) {
	tw := d.traceWriterPtr.Load()
	if tw == nil {
		return
	}
	tw.HandleEvent(rec, raw)
}

// applyFlowTrace sets up the initial flow trace writer from config at boot.
func (d *Daemon) applyFlowTrace(cfg *config.Config, er *logging.EventReader) {
	d.reconcileFlowTrace(cfg, er)
}

// updateFlowTrace reconciles the trace writer when config changes.
func (d *Daemon) updateFlowTrace(cfg *config.Config) {
	d.reconcileFlowTrace(cfg, d.eventReader)
}

// reconcileFlowTrace installs the flow trace writer described by cfg as the
// SINGLE live writer. The stable indirection callback (flowTraceCallback) is
// registered on er exactly once — the first time a writer is installed — and
// every later call only SWAPS the underlying writer, closing the one it
// replaced. So N commits touching traceoptions leave exactly one registered
// callback and one live TraceWriter (#3932). Closing the old writer on swap
// releases its file handle so it can no longer rotate the trace file (no
// double-rotation, no drop storm from a stale closed writer). Disabling
// traceoptions clears the writer to nil; the stable callback stays but becomes
// a no-op. er may be nil (no event reader yet) — then this is a no-op.
func (d *Daemon) reconcileFlowTrace(cfg *config.Config, er *logging.EventReader) {
	if er == nil {
		return
	}

	to := cfg.Security.Flow.Traceoptions
	enabled := to != nil && to.File != ""

	var tw *logging.TraceWriter
	if enabled {
		w, err := logging.NewTraceWriter(to)
		if err != nil {
			// Keep the current writer running rather than dropping tracing on a
			// bad reconcile (mirrors the flowexport #3742 keep-old-on-build-
			// failure posture). Nothing is swapped, so no callback/writer leak.
			slog.Warn("failed to create trace writer", "err", err)
			return
		}
		tw = w
		// Register the single stable callback exactly once, the first time a
		// writer exists. A boot with traceoptions disabled registers nothing;
		// the first enable arms it.
		d.traceCBOnce.Do(func() {
			er.AddCallback(d.flowTraceCallback)
		})
	}

	// Swap the live writer (possibly nil) and close the one it replaced. The
	// callback reads the pointer lock-free; traceReconMu only serializes
	// concurrent reconciles so exactly one writer is closed per swap.
	d.traceReconMu.Lock()
	old := d.traceWriterPtr.Swap(tw)
	if old != nil {
		old.Close()
	}
	d.traceReconMu.Unlock()

	switch {
	case enabled:
		slog.Info("flow traceoptions active",
			"file", to.File,
			"filters", len(to.PacketFilters))
	case old != nil:
		slog.Info("flow traceoptions disabled")
	}
}

// linkStateResubBackoffDefault is the delay between a link-update
// subscription closing (e.g. on a recoverable ENOBUFS) and the
// resubscribe attempt. Matches the neighbor listener's 2s backoff.
const linkStateResubBackoffDefault = 2 * time.Second

// monitorLinkState subscribes to netlink link updates and emits SNMP
// linkUp/linkDown traps on interface state changes.
//
// Resilience (#3950): a netlink multicast receive can fail with ENOBUFS
// when a burst of link events overflows the socket receive buffer — many
// interfaces flapping at once, precisely when link-state monitoring
// matters most for HA (RETH member link-down tracking, DHCP-on-link-up).
// ENOBUFS is RECOVERABLE: the kernel dropped some notifications but the
// socket stays usable. The vishvananda/netlink subscribe goroutine,
// however, treats ANY receive error as terminal — it reports the error to
// the ErrorCallback and closes the update channel. The pre-#3950 loop
// returned on that channel close, so a single transient ENOBUFS
// permanently disabled link-state traps for the daemon's lifetime.
//
// The loop now RESUBSCRIBES on channel close (mirroring the neighbor
// listener's runOneSubscription pattern) and, because messages were
// dropped during the overflow, RE-SYNCS via LinkList to catch up on any
// up/down transitions missed while unsubscribed — feeding the same emit
// path a streamed event would. It exits only on context cancellation.
func (d *Daemon) monitorLinkState(ctx context.Context) {
	// prevOper persists ACROSS resubscribes so the post-ENOBUFS re-sync
	// only emits traps for interfaces whose state genuinely changed.
	prevOper := make(map[int]bool) // ifindex -> up
	seeded := false
	slog.Info("SNMP link state monitor started")

	for {
		if !d.runLinkStateSubscription(ctx, prevOper, &seeded) {
			return // context cancelled — clean exit
		}
		// Subscription closed on a recoverable receive error (ENOBUFS or
		// similar). Back off briefly, then loop to resubscribe. The
		// catch-up re-sync runs inside runLinkStateSubscription right after
		// the fresh subscription is live, so no state-change window is lost.
		backoff := d.linkStateResubBackoff
		if backoff <= 0 {
			backoff = linkStateResubBackoffDefault
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// runLinkStateSubscription owns ONE netlink link-update subscription.
// Returns true when the subscription closed on a recoverable receive
// error (the caller should back off and resubscribe); false when ctx was
// cancelled (the caller should exit). done is closed exactly once on every
// path (no double-close, no leak).
//
// seeded gates the re-sync's emit behavior: the FIRST subscription seeds
// prevOper silently (no traps for interfaces already up at boot); every
// later resubscribe emits catch-up traps for transitions missed during the
// overflow. The re-sync runs after the subscription is established so any
// transition racing the enumeration is also streamed on the live socket.
func (d *Daemon) runLinkStateSubscription(ctx context.Context, prevOper map[int]bool, seeded *bool) bool {
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})

	onErr := func(err error) {
		// Runs on the subscribe goroutine. slog is concurrency-safe; the
		// warning names the recoverable receive error (e.g. ENOBUFS) that is
		// about to close the channel and trigger a resubscribe.
		slog.Warn("SNMP link monitor: netlink receive error, resubscribing", "err", err)
	}

	subscribe := d.linkStateSubscribe
	if subscribe == nil {
		subscribe = defaultLinkStateSubscribe
	}
	if err := subscribe(updates, done, onErr); err != nil {
		slog.Warn("SNMP link monitor: subscribe failed", "err", err)
		// The subscribe may have started its done-watcher goroutine before a
		// ListExisting dump failed; close done to avoid leaking it. Treat as
		// recoverable so the caller backs off and retries.
		close(done)
		return true
	}
	defer close(done)

	// Seed / catch-up now that the subscription is live.
	d.resyncLinkState(prevOper, *seeded)
	*seeded = true

	for {
		select {
		case <-ctx.Done():
			return false
		case update, ok := <-updates:
			if !ok {
				// The netlink subscribe goroutine closes the channel on ANY
				// receive error, including a recoverable ENOBUFS. Resubscribe.
				return true
			}
			attrs := update.Attrs()
			if attrs == nil || attrs.Name == "lo" {
				continue
			}
			d.applyLinkState(prevOper, attrs.Index, attrs.Name,
				attrs.OperState == netlink.OperUp, true)
		}
	}
}

// resyncLinkState enumerates all current links via LinkList and reconciles
// prevOper against ground truth. When emit is true (a post-ENOBUFS
// catch-up) it emits an SNMP trap for every interface whose up/down state
// differs from prevOper — messages were dropped, so the current kernel
// state is authoritative for the transitions we missed. When emit is false
// (the boot seed) it only records current state without emitting.
func (d *Daemon) resyncLinkState(prevOper map[int]bool, emit bool) {
	lister := d.linkStateList
	if lister == nil {
		lister = netlink.LinkList
	}
	links, err := lister()
	if err != nil {
		slog.Warn("SNMP link monitor: link re-sync failed", "err", err)
		return
	}
	for _, l := range links {
		attrs := l.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		d.applyLinkState(prevOper, attrs.Index, attrs.Name,
			attrs.OperState == netlink.OperUp, emit)
	}
}

// applyLinkState records the up/down state for ifindex against prevOper
// and, when the state changed from the last-known value AND emit is true,
// emits an SNMP linkUp/linkDown trap. Shared by the streamed-event path and
// the re-sync catch-up so both dedup identically against prevOper.
func (d *Daemon) applyLinkState(prevOper map[int]bool, index int, name string, up, emit bool) {
	was, known := prevOper[index]
	if known && was == up {
		return // no change
	}
	prevOper[index] = up
	if emit {
		d.emitLinkStateTrap(index, name, up)
	}
}

// emitLinkStateTrap dispatches one link up/down transition. The
// linkStateEmit seam (if set) captures it for tests; otherwise it emits an
// SNMP linkUp/linkDown trap via the snmp agent (a no-op when no agent).
func (d *Daemon) emitLinkStateTrap(index int, name string, up bool) {
	if d.linkStateEmit != nil {
		d.linkStateEmit(index, name, up)
		return
	}
	if d.snmpAgent == nil {
		return
	}
	if up {
		d.snmpAgent.NotifyLinkUp(index, name)
	} else {
		d.snmpAgent.NotifyLinkDown(index, name)
	}
}

// defaultLinkStateSubscribe is the production linkStateSubscribe seam. It
// subscribes to netlink RTNLGRP_LINK updates and wires onErr to the
// subscription's ErrorCallback so a recoverable ENOBUFS is logged before
// the channel closes and the loop resubscribes (#3950).
func defaultLinkStateSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
	return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: onErr,
	})
}
