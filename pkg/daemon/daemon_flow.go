// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"log/slog"
	"net"
	"os/exec"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/flowexport"
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
func logFinalStats(dp dataplane.DataPlane) {
	if !dp.IsLoaded() {
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
		v, err := dp.ReadGlobalCounter(n.idx)
		if err != nil {
			continue
		}
		attrs = append(attrs, n.name, v)
	}

	slog.Info("final statistics", attrs...)
}

// startFlowExporter starts the NetFlow v9 exporter if configured.
func (d *Daemon) startFlowExporter(ctx context.Context, cfg *config.Config, er *logging.EventReader) {
	ec := flowexport.BuildExportConfig(&cfg.Services, &cfg.ForwardingOptions)
	if ec == nil {
		return
	}

	// Build per-zone sampling direction flags using deterministic zone IDs
	// (same sorted assignment as dataplane compiler).
	zoneIDs := buildZoneIDs(cfg)
	ec.SamplingZones = flowexport.BuildSamplingZones(cfg, zoneIDs)

	exp, err := flowexport.NewExporter(*ec)
	if err != nil {
		slog.Warn("failed to create flow exporter", "err", err)
		return
	}

	flowCtx, cancel := context.WithCancel(ctx)
	d.flowExporter = exp
	d.flowCancel = cancel

	// Register callback for session close events
	er.AddCallback(func(rec logging.EventRecord, raw []byte) {
		if rec.Type != "SESSION_CLOSE" {
			return
		}
		// Check sampling direction: skip if zone has no sampling enabled
		if !ec.ShouldExport(rec.InZone, rec.OutZone) {
			return
		}
		sd := flowexport.SessionCloseData{
			SrcPort:  parseSrcPort(rec.SrcAddr),
			DstPort:  parseSrcPort(rec.DstAddr),
			Protocol: parseProtocol(rec.Protocol),
		}
		sd.SrcIP, sd.DstIP, sd.IsIPv6 = parseAddrPair(rec.SrcAddr, rec.DstAddr)
		exp.ExportSessionClose(rec, sd)
	})

	d.flowWg.Add(1)
	go func() {
		defer d.flowWg.Done()
		exp.Run(flowCtx)
	}()

	slog.Info("NetFlow v9 exporter started",
		"collectors", len(ec.Collectors),
		"active_timeout", ec.FlowActiveTimeout,
		"inactive_timeout", ec.FlowInactiveTimeout,
		"sampling_zones", len(ec.SamplingZones),
		"sampling_rate", ec.SamplingRate)
}

// stopFlowExporter stops the running flow exporter.
func (d *Daemon) stopFlowExporter() {
	if d.flowCancel != nil {
		d.flowCancel()
	}
	d.flowWg.Wait()
	if d.flowExporter != nil {
		d.flowExporter.Close()
		d.flowExporter = nil
	}
}

// startIPFIXExporter starts the IPFIX (NetFlow v10) exporter if configured.
func (d *Daemon) startIPFIXExporter(ctx context.Context, cfg *config.Config, er *logging.EventReader) {
	ec := flowexport.BuildIPFIXExportConfig(&cfg.Services, &cfg.ForwardingOptions)
	if ec == nil {
		return
	}

	zoneIDs := buildZoneIDs(cfg)
	ec.SamplingZones = flowexport.BuildSamplingZones(cfg, zoneIDs)

	exp, err := flowexport.NewIPFIXExporter(*ec)
	if err != nil {
		slog.Warn("failed to create IPFIX exporter", "err", err)
		return
	}

	ipfixCtx, cancel := context.WithCancel(ctx)
	d.ipfixExporter = exp
	d.ipfixCancel = cancel

	er.AddCallback(func(rec logging.EventRecord, raw []byte) {
		if rec.Type != "SESSION_CLOSE" {
			return
		}
		if !ec.ShouldExport(rec.InZone, rec.OutZone) {
			return
		}
		sd := flowexport.SessionCloseData{
			SrcPort:  parseSrcPort(rec.SrcAddr),
			DstPort:  parseSrcPort(rec.DstAddr),
			Protocol: parseProtocol(rec.Protocol),
		}
		sd.SrcIP, sd.DstIP, sd.IsIPv6 = parseAddrPair(rec.SrcAddr, rec.DstAddr)
		exp.ExportSessionClose(rec, sd)
	})

	d.ipfixWg.Add(1)
	go func() {
		defer d.ipfixWg.Done()
		exp.Run(ipfixCtx)
	}()

	slog.Info("IPFIX exporter started",
		"collectors", len(ec.Collectors),
		"active_timeout", ec.FlowActiveTimeout,
		"inactive_timeout", ec.FlowInactiveTimeout,
		"sampling_zones", len(ec.SamplingZones),
		"sampling_rate", ec.SamplingRate)
}

// stopIPFIXExporter stops the running IPFIX exporter.
func (d *Daemon) stopIPFIXExporter() {
	if d.ipfixCancel != nil {
		d.ipfixCancel()
	}
	d.ipfixWg.Wait()
	if d.ipfixExporter != nil {
		d.ipfixExporter.Close()
		d.ipfixExporter = nil
	}
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
func (d *Daemon) archiveConfig(cfg *config.Config) {
	if cfg.System.Archival == nil || !cfg.System.Archival.TransferOnCommit {
		return
	}
	if len(cfg.System.Archival.ArchiveSites) == 0 {
		return
	}

	configFile := d.opts.ConfigFile
	for _, site := range cfg.System.Archival.ArchiveSites {
		go func(dest string) {
			slog.Info("archiving config", "destination", dest)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "scp",
				"-o", "StrictHostKeyChecking=no",
				"-o", "BatchMode=yes",
				configFile, dest,
			).CombinedOutput()
			if err != nil {
				slog.Warn("config archival failed",
					"destination", dest, "err", err, "output", string(out))
			} else {
				slog.Info("config archived successfully", "destination", dest)
			}
		}(site)
	}
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
