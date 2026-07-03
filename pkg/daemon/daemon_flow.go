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
		if !lease.Gateway.IsValid() {
			continue
		}
		if d.mgmtVRFInterfaces[lease.Interface] {
			continue
		}
		dr := frr.DHCPRoute{
			Gateway:   lease.Gateway.String(),
			Interface: lease.Interface,
			IsIPv6:    lease.Family == dhcp.AFInet6,
		}
		routes = append(routes, dr)
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
		if !lease.Gateway.IsValid() || !d.mgmtVRFInterfaces[lease.Interface] {
			continue
		}
		link, err := nlh.LinkByName(lease.Interface)
		if err != nil {
			slog.Warn("mgmt VRF route: interface not found",
				"interface", lease.Interface, "err", err)
			continue
		}
		var dst *net.IPNet
		if lease.Family == dhcp.AFInet6 {
			dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		} else {
			dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
		}
		gwSlice := lease.Gateway.AsSlice()
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
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

func parseProtocol(proto string) uint8 {
	switch proto {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	case "ICMPv6":
		return 58
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
	for _, site := range cfg.System.Archival.ArchiveSites {
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
	out, err := exec.CommandContext(ctx, "scp",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
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

// applyFlowTrace sets up the initial flow trace writer from config.
func (d *Daemon) applyFlowTrace(cfg *config.Config, er *logging.EventReader) {
	if cfg.Security.Flow.Traceoptions == nil || cfg.Security.Flow.Traceoptions.File == "" {
		return
	}

	tw, err := logging.NewTraceWriter(cfg.Security.Flow.Traceoptions)
	if err != nil {
		slog.Warn("failed to create trace writer", "err", err)
		return
	}
	d.traceWriter = tw
	er.AddCallback(tw.HandleEvent)
	slog.Info("flow traceoptions enabled",
		"file", cfg.Security.Flow.Traceoptions.File,
		"filters", len(cfg.Security.Flow.Traceoptions.PacketFilters))
}

// updateFlowTrace updates the trace writer when config changes.
func (d *Daemon) updateFlowTrace(cfg *config.Config) {
	if d.traceWriter != nil {
		d.traceWriter.Close()
		d.traceWriter = nil
	}

	if d.eventReader == nil {
		return
	}

	if cfg.Security.Flow.Traceoptions == nil || cfg.Security.Flow.Traceoptions.File == "" {
		return
	}

	tw, err := logging.NewTraceWriter(cfg.Security.Flow.Traceoptions)
	if err != nil {
		slog.Warn("failed to create trace writer", "err", err)
		return
	}
	d.traceWriter = tw
	d.eventReader.AddCallback(tw.HandleEvent)
	slog.Info("flow traceoptions updated",
		"file", cfg.Security.Flow.Traceoptions.File,
		"filters", len(cfg.Security.Flow.Traceoptions.PacketFilters))
}

// monitorLinkState subscribes to netlink link updates and sends SNMP traps
// on interface state changes (link up / link down).
func (d *Daemon) monitorLinkState(ctx context.Context) {
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(updates, done); err != nil {
		slog.Warn("SNMP link monitor: failed to subscribe", "err", err)
		return
	}
	slog.Info("SNMP link state monitor started")

	// Track previous oper state per ifindex to avoid duplicate traps.
	prevOper := make(map[int]bool) // true = up

	// Seed with current state.
	links, err := netlink.LinkList()
	if err == nil {
		for _, l := range links {
			attrs := l.Attrs()
			prevOper[attrs.Index] = (attrs.OperState == netlink.OperUp)
		}
	}

	for {
		select {
		case <-ctx.Done():
			close(done)
			return
		case update, ok := <-updates:
			if !ok {
				return
			}
			attrs := update.Attrs()
			if attrs.Name == "lo" {
				continue
			}

			nowUp := (attrs.OperState == netlink.OperUp)
			wasUp, known := prevOper[attrs.Index]
			if known && wasUp == nowUp {
				continue // no change
			}
			prevOper[attrs.Index] = nowUp

			if d.snmpAgent == nil {
				continue
			}

			if nowUp {
				d.snmpAgent.NotifyLinkUp(attrs.Index, attrs.Name)
			} else {
				d.snmpAgent.NotifyLinkDown(attrs.Index, attrs.Name)
			}
		}
	}
}
