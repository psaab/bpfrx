package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	dpuserspace "github.com/psaab/bpfrx/pkg/dataplane/userspace"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// resolveFabricParent checks if name is a fabric IPVLAN overlay (fab0/fab1)
// and returns the physical parent interface name. After the IPVLAN rework,
// cross-chassis forwarding runs on the parent — monitor commands should show
// wire-level traffic, not the overlay (#135, #136).
func resolveFabricParent(name string) string {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return name
	}
	if ipv, ok := link.(*netlink.IPVlan); ok {
		parent, err := netlink.LinkByIndex(ipv.Attrs().ParentIndex)
		if err == nil {
			return parent.Attrs().Name
		}
	}
	return name
}

// ifaceSnapshot holds a point-in-time sample of interface counters.
type ifaceSnapshot struct {
	rxBytes, txBytes   uint64
	rxPkts, txPkts     uint64
	rxErrors, txErrors uint64
	rxDrops, txDrops   uint64
	rxFrame, txCarrier uint64
	collisions         uint64
	userspace          *userspaceIfaceSnapshot
	ts                 time.Time
}

type userspaceIfaceSnapshot struct {
	statusNote          string
	helperEnabled       bool
	forwardingArmed     bool
	neighborGeneration  uint64
	lastSnapshotGen     uint64
	bindings            int
	readyBindings       int
	boundBindings       int
	xskRegistered       int
	zeroCopyBindings    int
	rxPackets           uint64
	rxBytes             uint64
	txPackets           uint64
	txBytes             uint64
	directTXPackets     uint64
	copyTXPackets       uint64
	inPlaceTXPackets    uint64
	sessionMisses       uint64
	neighborMissPackets uint64
	routeMissPackets    uint64
	policyDeniedPackets uint64
	exceptionPackets    uint64
	slowPathPackets     uint64
	lastErrors          []string
	recentExceptions    []string
}

func aggregateUserspaceIfaceSnapshot(kernelName string, status dpuserspace.ProcessStatus) *userspaceIfaceSnapshot {
	snap := &userspaceIfaceSnapshot{
		helperEnabled:      status.Enabled,
		forwardingArmed:    status.ForwardingArmed,
		neighborGeneration: status.NeighborGeneration,
		lastSnapshotGen:    status.LastSnapshotGeneration,
	}
	errorSet := map[string]struct{}{}
	for _, binding := range status.Bindings {
		if binding.Interface != kernelName {
			continue
		}
		snap.bindings++
		if binding.Ready {
			snap.readyBindings++
		}
		if binding.Bound {
			snap.boundBindings++
		}
		if binding.XSKRegistered {
			snap.xskRegistered++
		}
		if binding.ZeroCopy {
			snap.zeroCopyBindings++
		}
		snap.rxPackets += binding.RXPackets
		snap.rxBytes += binding.RXBytes
		snap.txPackets += binding.TXPackets
		snap.txBytes += binding.TXBytes
		snap.directTXPackets += binding.DirectTXPackets
		snap.copyTXPackets += binding.CopyTXPackets
		snap.inPlaceTXPackets += binding.InPlaceTXPackets
		snap.sessionMisses += binding.SessionMisses
		snap.neighborMissPackets += binding.NeighborMissPackets
		snap.routeMissPackets += binding.RouteMissPackets
		snap.policyDeniedPackets += binding.PolicyDeniedPackets
		snap.exceptionPackets += binding.ExceptionPackets
		snap.slowPathPackets += binding.SlowPathPackets
		if binding.LastError != "" {
			errorSet[binding.LastError] = struct{}{}
		}
	}
	for _, exc := range status.RecentExceptions {
		if exc.Interface != kernelName {
			continue
		}
		snap.recentExceptions = append(snap.recentExceptions, formatUserspaceException(exc))
	}
	for msg := range errorSet {
		snap.lastErrors = append(snap.lastErrors, msg)
	}
	sort.Strings(snap.lastErrors)
	if len(snap.recentExceptions) > 3 {
		snap.recentExceptions = snap.recentExceptions[:3]
	}
	if snap.bindings == 0 && len(snap.recentExceptions) == 0 {
		snap.statusNote = fmt.Sprintf("no userspace bindings or exceptions matched %s", kernelName)
	}
	return snap
}

func formatUserspaceException(exc dpuserspace.ExceptionStatus) string {
	fields := []string{exc.Reason}
	if exc.SrcIP != "" || exc.DstIP != "" {
		flow := exc.SrcIP
		if exc.SrcPort != 0 {
			flow = fmt.Sprintf("%s:%d", flow, exc.SrcPort)
		}
		flow += " -> " + exc.DstIP
		if exc.DstPort != 0 {
			flow += fmt.Sprintf(":%d", exc.DstPort)
		}
		fields = append(fields, flow)
	}
	if exc.FromZone != "" || exc.ToZone != "" {
		fields = append(fields, fmt.Sprintf("%s->%s", exc.FromZone, exc.ToZone))
	}
	return strings.Join(fields, " | ")
}

// readIfaceSnapshot reads BPF counters (rx/tx packets/bytes) and kernel
// link statistics (errors, drops, etc.) for a named interface.
func (c *CLI) readIfaceSnapshot(name string) (ifaceSnapshot, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ifaceSnapshot{}, fmt.Errorf("interface %s: %w", name, err)
	}
	snap := ifaceSnapshot{ts: time.Now()}

	// BPF counters (authoritative for rx/tx bytes/packets).
	if c.dp != nil && c.dp.IsLoaded() {
		if ctrs, err := c.dp.ReadInterfaceCounters(iface.Index); err == nil {
			snap.rxBytes = ctrs.RxBytes
			snap.txBytes = ctrs.TxBytes
			snap.rxPkts = ctrs.RxPackets
			snap.txPkts = ctrs.TxPackets
		}
	}

	// Kernel statistics for error/drop counters.
	link, err := netlink.LinkByName(name)
	if err == nil {
		if s := link.Attrs().Statistics; s != nil {
			snap.rxErrors = s.RxErrors
			snap.txErrors = s.TxErrors
			snap.rxDrops = s.RxDropped
			snap.txDrops = s.TxDropped
			snap.rxFrame = s.RxFrameErrors
			snap.txCarrier = s.TxCarrierErrors
			snap.collisions = s.Collisions
			// Use kernel counters as fallback if BPF counters are zero.
			if snap.rxBytes == 0 && snap.txBytes == 0 {
				snap.rxBytes = s.RxBytes
				snap.txBytes = s.TxBytes
				snap.rxPkts = s.RxPackets
				snap.txPkts = s.TxPackets
			}
		}
	}
	return snap, nil
}

func (c *CLI) readUserspaceIfaceSnapshot(kernelName string) *userspaceIfaceSnapshot {
	status, err := c.userspaceDataplaneStatus()
	if err != nil {
		return &userspaceIfaceSnapshot{statusNote: err.Error()}
	}
	return aggregateUserspaceIfaceSnapshot(kernelName, status)
}

// formatLinkSpeed formats a speed in Mbps to a human-readable string.
func formatLinkSpeed(name string) string {
	mbps := readLinkSpeed(name)
	if mbps <= 0 {
		return "unknown"
	}
	if mbps >= 1000 {
		return fmt.Sprintf("%dgbps", mbps/1000)
	}
	return fmt.Sprintf("%dmbps", mbps)
}

// monitorLinkState returns "Up" or "Down" for an interface.
func monitorLinkState(name string) string {
	if data, err := os.ReadFile("/sys/class/net/" + name + "/operstate"); err == nil {
		if strings.TrimSpace(string(data)) == "up" {
			return "Up"
		}
	}
	return "Down"
}

// setRawMode puts the terminal into raw mode for single-character reads.
func setRawMode(fd int) (*unix.Termios, error) {
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	return old, nil
}

func restoreTermMode(fd int, old *unix.Termios) {
	_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
}

const (
	enterAltScreen = "\x1b[?1049h"
	exitAltScreen  = "\x1b[?1049l"
	clearAndHome   = "\x1b[2J\x1b[H"
	hideCursor     = "\x1b[?25l"
	showCursor     = "\x1b[?25h"
)

// handleMonitorInterface dispatches monitor interface sub-commands.
func (c *CLI) handleMonitorInterface(args []string) error {
	if len(args) == 0 {
		monTree := operationalTree["monitor"].Children["interface"]
		fmt.Println("monitor interface:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(monTree.Children))
		// Also show dynamic interface names.
		cfg := c.store.ActiveConfig()
		if monTree.DynamicFn != nil && cfg != nil {
			names := monTree.DynamicFn(cfg)
			sort.Strings(names)
			for _, n := range names {
				fmt.Printf("  %-30s Interface name\n", n)
			}
		}
		return nil
	}

	// "traffic" sub-command shows all-interfaces summary.
	resolved := args[0]
	if resolved == "traffic" {
		return c.monitorInterfaceTraffic()
	}

	// Otherwise it's a specific interface name.
	return c.monitorInterfaceSingle(resolved)
}

// sortedConfiguredInterfaces returns sorted interface names from active config.
func (c *CLI) sortedConfiguredInterfaces() []string {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// resolveToKernel converts a config-level name (ge-0/0/0, reth0) to kernel name.
func (c *CLI) resolveToKernel(cfgName string) string {
	cfg := c.store.ActiveConfig()
	if cfg != nil {
		cfgName = cfg.ResolveReth(cfgName)
	}
	return config.LinuxIfName(cfgName)
}

// monitorInterfaceSingle shows full-screen stats for a single interface.
func (c *CLI) monitorInterfaceSingle(ifaceName string) error {
	displayName := ifaceName
	kernelName := c.resolveToKernel(ifaceName)
	// Resolve fabric IPVLAN overlays to physical parent (#135).
	kernelName = resolveFabricParent(kernelName)
	// Validate interface exists.
	if _, err := net.InterfaceByName(kernelName); err != nil {
		return fmt.Errorf("interface %s not found", ifaceName)
	}
	ifaceName = kernelName

	fd := int(os.Stdin.Fd())
	old, err := setRawMode(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer restoreTermMode(fd, old)

	fmt.Print(enterAltScreen + hideCursor)
	defer fmt.Print(showCursor + exitAltScreen)

	keyCh := make(chan byte, 8)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}
			keyCh <- buf[0]
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	var prev *ifaceSnapshot
	var baseline *ifaceSnapshot
	frozen := false
	allIfaces := c.sortedConfiguredInterfaces()

	// Render immediately.
	renderNow := func() {
		kn := resolveFabricParent(c.resolveToKernel(displayName))
		snap, err := c.readIfaceSnapshot(kn)
		if err != nil {
			return
		}
		snap.userspace = c.readUserspaceIfaceSnapshot(kn)
		if baseline == nil {
			baseline = &snap
		}
		fmt.Print(clearAndHome)
		renderSingleInterface(os.Stdout, c.hostname, displayName, kn, &snap, prev, baseline, startTime)
		prev = &snap
	}
	renderNow()

	for {
		select {
		case <-ticker.C:
			if !frozen {
				renderNow()
			}
		case key := <-keyCh:
			switch key {
			case 'q', 'Q', 0x1b, 0x03: // q, ESC, Ctrl-C
				return nil
			case 'f', 'F': // freeze
				frozen = true
			case 't', 'T': // thaw
				frozen = false
			case 'c', 'C': // clear baseline
				baseline = nil
				prev = nil
				renderNow()
			case 'n', 'N': // next interface
				if len(allIfaces) > 1 {
					idx := 0
					for i, n := range allIfaces {
						if n == displayName {
							idx = (i + 1) % len(allIfaces)
							break
						}
					}
					displayName = allIfaces[idx]
					prev = nil
					baseline = nil
					startTime = time.Now()
					renderNow()
				}
			}
		}
	}
}

// renderSingleInterface renders the vSRX-style single interface display.
// displayName is the config-level name shown to the user, kernelName is used for sysfs lookups.
func renderSingleInterface(w io.Writer, hostname, displayName, kernelName string, snap, prev, baseline *ifaceSnapshot, startTime time.Time) {
	seconds := int(time.Since(startTime).Seconds())
	now := time.Now().Format("15:04:05")
	linkState := monitorLinkState(kernelName)
	speed := formatLinkSpeed(kernelName)

	// Header.
	fmt.Fprintf(w, "%-40s Seconds: %-10d Time: %s\n", hostname, seconds, now)
	fmt.Fprintf(w, "Interface: %s, Enabled, Link is %s\n", displayName, linkState)
	fmt.Fprintf(w, "Encapsulation: Ethernet, Speed: %s\n", speed)

	// Compute 1s rate (bps).
	var rxBps, txBps, rxPps, txPps uint64
	if prev != nil {
		dt := snap.ts.Sub(prev.ts).Seconds()
		if dt > 0 {
			rxBps = uint64(float64(snap.rxBytes-prev.rxBytes) * 8 / dt)
			txBps = uint64(float64(snap.txBytes-prev.txBytes) * 8 / dt)
			rxPps = uint64(float64(snap.rxPkts-prev.rxPkts) / dt)
			txPps = uint64(float64(snap.txPkts-prev.txPkts) / dt)
		}
	}

	// Compute delta from baseline.
	var rxBytesDelta, txBytesDelta, rxPktsDelta, txPktsDelta uint64
	if baseline != nil {
		rxBytesDelta = snap.rxBytes - baseline.rxBytes
		txBytesDelta = snap.txBytes - baseline.txBytes
		rxPktsDelta = snap.rxPkts - baseline.rxPkts
		txPktsDelta = snap.txPkts - baseline.txPkts
	}

	fmt.Fprintf(w, "Traffic statistics:                                Current delta\n")
	fmt.Fprintf(w, "  Input  bytes:         %20d (%d bps)    [%d]\n", snap.rxBytes, rxBps, rxBytesDelta)
	fmt.Fprintf(w, "  Output bytes:         %20d (%d bps)    [%d]\n", snap.txBytes, txBps, txBytesDelta)
	fmt.Fprintf(w, "  Input  packets:       %20d (%d pps)    [%d]\n", snap.rxPkts, rxPps, rxPktsDelta)
	fmt.Fprintf(w, "  Output packets:       %20d (%d pps)    [%d]\n", snap.txPkts, txPps, txPktsDelta)
	fmt.Fprintf(w, "\n")

	// Error statistics — deltas from baseline.
	var rxErrDelta, txErrDelta, rxDropDelta, txDropDelta, rxFrameDelta, txCarrierDelta, colDelta uint64
	if baseline != nil {
		rxErrDelta = snap.rxErrors - baseline.rxErrors
		txErrDelta = snap.txErrors - baseline.txErrors
		rxDropDelta = snap.rxDrops - baseline.rxDrops
		txDropDelta = snap.txDrops - baseline.txDrops
		rxFrameDelta = snap.rxFrame - baseline.rxFrame
		txCarrierDelta = snap.txCarrier - baseline.txCarrier
		colDelta = snap.collisions - baseline.collisions
	}

	fmt.Fprintf(w, "Error statistics:                                  Current delta\n")
	fmt.Fprintf(w, "  Input  errors:        %20d          [%d]\n", snap.rxErrors, rxErrDelta)
	fmt.Fprintf(w, "  Output errors:        %20d          [%d]\n", snap.txErrors, txErrDelta)
	fmt.Fprintf(w, "  Input  drops:         %20d          [%d]\n", snap.rxDrops, rxDropDelta)
	fmt.Fprintf(w, "  Output drops:         %20d          [%d]\n", snap.txDrops, txDropDelta)
	fmt.Fprintf(w, "  Input  frame errors:  %20d          [%d]\n", snap.rxFrame, rxFrameDelta)
	fmt.Fprintf(w, "  Output carrier:       %20d          [%d]\n", snap.txCarrier, txCarrierDelta)
	fmt.Fprintf(w, "  Collisions:           %20d          [%d]\n", snap.collisions, colDelta)
	fmt.Fprintf(w, "\n")

	if snap.userspace != nil {
		var (
			usRxBps, usTxBps, usRxPps, usTxPps                           uint64
			usRxBytesDelta, usTxBytesDelta, usRxPktsDelta, usTxPktsDelta uint64
			usDirectDelta, usCopyDelta, usInPlaceDelta                   uint64
			usSessionMissDelta, usNeighborMissDelta, usRouteMissDelta    uint64
			usPolicyDeniedDelta, usExceptionDelta, usSlowPathDelta       uint64
		)
		if prev != nil && prev.userspace != nil {
			dt := snap.ts.Sub(prev.ts).Seconds()
			if dt > 0 {
				usRxBps = uint64(float64(snap.userspace.rxBytes-prev.userspace.rxBytes) * 8 / dt)
				usTxBps = uint64(float64(snap.userspace.txBytes-prev.userspace.txBytes) * 8 / dt)
				usRxPps = uint64(float64(snap.userspace.rxPackets-prev.userspace.rxPackets) / dt)
				usTxPps = uint64(float64(snap.userspace.txPackets-prev.userspace.txPackets) / dt)
			}
		}
		if baseline != nil && baseline.userspace != nil {
			usRxBytesDelta = snap.userspace.rxBytes - baseline.userspace.rxBytes
			usTxBytesDelta = snap.userspace.txBytes - baseline.userspace.txBytes
			usRxPktsDelta = snap.userspace.rxPackets - baseline.userspace.rxPackets
			usTxPktsDelta = snap.userspace.txPackets - baseline.userspace.txPackets
			usDirectDelta = snap.userspace.directTXPackets - baseline.userspace.directTXPackets
			usCopyDelta = snap.userspace.copyTXPackets - baseline.userspace.copyTXPackets
			usInPlaceDelta = snap.userspace.inPlaceTXPackets - baseline.userspace.inPlaceTXPackets
			usSessionMissDelta = snap.userspace.sessionMisses - baseline.userspace.sessionMisses
			usNeighborMissDelta = snap.userspace.neighborMissPackets - baseline.userspace.neighborMissPackets
			usRouteMissDelta = snap.userspace.routeMissPackets - baseline.userspace.routeMissPackets
			usPolicyDeniedDelta = snap.userspace.policyDeniedPackets - baseline.userspace.policyDeniedPackets
			usExceptionDelta = snap.userspace.exceptionPackets - baseline.userspace.exceptionPackets
			usSlowPathDelta = snap.userspace.slowPathPackets - baseline.userspace.slowPathPackets
		}

		fmt.Fprintf(w, "Userspace dataplane:\n")
		if snap.userspace.statusNote != "" {
			fmt.Fprintf(w, "  Note:                 %s\n", snap.userspace.statusNote)
		}
		fmt.Fprintf(w, "  Helper state:         enabled=%t armed=%t snapshot_gen=%d neighbor_gen=%d\n",
			snap.userspace.helperEnabled, snap.userspace.forwardingArmed, snap.userspace.lastSnapshotGen, snap.userspace.neighborGeneration)
		fmt.Fprintf(w, "  Binding state:        bindings=%d ready=%d bound=%d xsk=%d zc=%d\n",
			snap.userspace.bindings, snap.userspace.readyBindings, snap.userspace.boundBindings, snap.userspace.xskRegistered, snap.userspace.zeroCopyBindings)
		fmt.Fprintf(w, "  RX bytes:             %20d (%d bps)    [%d]\n", snap.userspace.rxBytes, usRxBps, usRxBytesDelta)
		fmt.Fprintf(w, "  TX bytes:             %20d (%d bps)    [%d]\n", snap.userspace.txBytes, usTxBps, usTxBytesDelta)
		fmt.Fprintf(w, "  RX packets:           %20d (%d pps)    [%d]\n", snap.userspace.rxPackets, usRxPps, usRxPktsDelta)
		fmt.Fprintf(w, "  TX packets:           %20d (%d pps)    [%d]\n", snap.userspace.txPackets, usTxPps, usTxPktsDelta)
		fmt.Fprintf(w, "  Direct TX packets:    %20d          [%d]\n", snap.userspace.directTXPackets, usDirectDelta)
		fmt.Fprintf(w, "  Copy TX packets:      %20d          [%d]\n", snap.userspace.copyTXPackets, usCopyDelta)
		fmt.Fprintf(w, "  In-place TX packets:  %20d          [%d]\n", snap.userspace.inPlaceTXPackets, usInPlaceDelta)
		fmt.Fprintf(w, "  Session misses:       %20d          [%d]\n", snap.userspace.sessionMisses, usSessionMissDelta)
		fmt.Fprintf(w, "  Neighbor misses:      %20d          [%d]\n", snap.userspace.neighborMissPackets, usNeighborMissDelta)
		fmt.Fprintf(w, "  Route misses:         %20d          [%d]\n", snap.userspace.routeMissPackets, usRouteMissDelta)
		fmt.Fprintf(w, "  Policy denied:        %20d          [%d]\n", snap.userspace.policyDeniedPackets, usPolicyDeniedDelta)
		fmt.Fprintf(w, "  Exception packets:    %20d          [%d]\n", snap.userspace.exceptionPackets, usExceptionDelta)
		fmt.Fprintf(w, "  Slow path packets:    %20d          [%d]\n", snap.userspace.slowPathPackets, usSlowPathDelta)
		if len(snap.userspace.lastErrors) > 0 {
			fmt.Fprintf(w, "  Binding errors:\n")
			for _, msg := range snap.userspace.lastErrors {
				fmt.Fprintf(w, "    %s\n", msg)
			}
		}
		if len(snap.userspace.recentExceptions) > 0 {
			fmt.Fprintf(w, "  Recent exceptions:\n")
			for _, msg := range snap.userspace.recentExceptions {
				fmt.Fprintf(w, "    %s\n", msg)
			}
		}
		fmt.Fprintf(w, "\n")
	}
	fmt.Fprintf(w, "Keys: q=quit  n=next interface  f=freeze  t=thaw  c=clear baseline\n")
}

// display modes for traffic summary.
const (
	trafficModePackets = iota
	trafficModeBytes
	trafficModeDelta
	trafficModeRate
)

// monitorInterfaceTraffic shows a full-screen all-interfaces summary table.
func (c *CLI) monitorInterfaceTraffic() error {
	fd := int(os.Stdin.Fd())
	old, err := setRawMode(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer restoreTermMode(fd, old)

	fmt.Print(enterAltScreen + hideCursor)
	defer fmt.Print(showCursor + exitAltScreen)

	keyCh := make(chan byte, 8)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}
			keyCh <- buf[0]
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	mode := trafficModePackets
	prevSnaps := make(map[string]*ifaceSnapshot)

	renderNow := func() {
		names := c.sortedConfiguredInterfaces()
		snaps := make(map[string]*ifaceSnapshot, len(names))
		kernelNames := make(map[string]string, len(names))
		for _, name := range names {
			kn := resolveFabricParent(c.resolveToKernel(name))
			kernelNames[name] = kn
			if snap, err := c.readIfaceSnapshot(kn); err == nil {
				snaps[name] = &snap
			}
		}
		fmt.Print(clearAndHome)
		renderTrafficSummary(os.Stdout, c.hostname, names, kernelNames, snaps, prevSnaps, mode, startTime)
		prevSnaps = snaps
	}
	renderNow()

	for {
		select {
		case <-ticker.C:
			renderNow()
		case key := <-keyCh:
			switch key {
			case 'q', 'Q', 0x1b, 0x03: // q, ESC, Ctrl-C
				return nil
			case 'p', 'P':
				mode = trafficModePackets
				renderNow()
			case 'b', 'B':
				mode = trafficModeBytes
				renderNow()
			case 'd', 'D':
				mode = trafficModeDelta
				renderNow()
			case 'r', 'R':
				mode = trafficModeRate
				renderNow()
			}
		}
	}
}

// renderTrafficSummary renders the all-interfaces traffic table.
// kernelNames maps config name → kernel name for sysfs lookups.
func renderTrafficSummary(w io.Writer, hostname string, names []string, kernelNames map[string]string, snaps, prevSnaps map[string]*ifaceSnapshot, mode int, startTime time.Time) {
	seconds := int(time.Since(startTime).Seconds())
	now := time.Now().Format("15:04:05")

	fmt.Fprintf(w, "%-40s Seconds: %-10d Time: %s\n", hostname, seconds, now)

	modeLabel := "packets"
	switch mode {
	case trafficModeBytes:
		modeLabel = "bytes"
	case trafficModeDelta:
		modeLabel = "delta"
	case trafficModeRate:
		modeLabel = "rate"
	}
	fmt.Fprintf(w, "  Mode: %s\n\n", modeLabel)

	switch mode {
	case trafficModePackets:
		fmt.Fprintf(w, "%-16s %4s %20s %12s %20s %12s\n",
			"Interface", "Link", "Input packets", "(pps)", "Output packets", "(pps)")
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			link := monitorLinkState(kernelNames[name])
			var rxPps, txPps uint64
			if prev, ok := prevSnaps[name]; ok && prev != nil {
				dt := snap.ts.Sub(prev.ts).Seconds()
				if dt > 0 {
					rxPps = uint64(float64(snap.rxPkts-prev.rxPkts) / dt)
					txPps = uint64(float64(snap.txPkts-prev.txPkts) / dt)
				}
			}
			fmt.Fprintf(w, "%-16s %4s %20d %11d %20d %11d\n",
				name, link, snap.rxPkts, rxPps, snap.txPkts, txPps)
		}

	case trafficModeBytes:
		fmt.Fprintf(w, "%-16s %4s %20s %14s %20s %14s\n",
			"Interface", "Link", "Input bytes", "(bps)", "Output bytes", "(bps)")
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			link := monitorLinkState(kernelNames[name])
			var rxBps, txBps uint64
			if prev, ok := prevSnaps[name]; ok && prev != nil {
				dt := snap.ts.Sub(prev.ts).Seconds()
				if dt > 0 {
					rxBps = uint64(float64(snap.rxBytes-prev.rxBytes) * 8 / dt)
					txBps = uint64(float64(snap.txBytes-prev.txBytes) * 8 / dt)
				}
			}
			fmt.Fprintf(w, "%-16s %4s %20d %13d %20d %13d\n",
				name, link, snap.rxBytes, rxBps, snap.txBytes, txBps)
		}

	case trafficModeDelta:
		fmt.Fprintf(w, "%-16s %4s %20s %20s\n",
			"Interface", "Link", "Input delta (pkts)", "Output delta (pkts)")
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			link := monitorLinkState(kernelNames[name])
			var rxD, txD uint64
			if prev, ok := prevSnaps[name]; ok && prev != nil {
				rxD = snap.rxPkts - prev.rxPkts
				txD = snap.txPkts - prev.txPkts
			}
			fmt.Fprintf(w, "%-16s %4s %20d %20d\n", name, link, rxD, txD)
		}

	case trafficModeRate:
		fmt.Fprintf(w, "%-16s %4s %14s %14s %12s %12s\n",
			"Interface", "Link", "Rx bps", "Tx bps", "Rx pps", "Tx pps")
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			link := monitorLinkState(kernelNames[name])
			var rxBps, txBps, rxPps, txPps uint64
			if prev, ok := prevSnaps[name]; ok && prev != nil {
				dt := snap.ts.Sub(prev.ts).Seconds()
				if dt > 0 {
					rxBps = uint64(float64(snap.rxBytes-prev.rxBytes) * 8 / dt)
					txBps = uint64(float64(snap.txBytes-prev.txBytes) * 8 / dt)
					rxPps = uint64(float64(snap.rxPkts-prev.rxPkts) / dt)
					txPps = uint64(float64(snap.txPkts-prev.txPkts) / dt)
				}
			}
			fmt.Fprintf(w, "%-16s %4s %14d %14d %12d %12d\n",
				name, link, rxBps, txBps, rxPps, txPps)
		}
	}

	fmt.Fprintf(w, "\nKeys: q=quit  p=packets  b=bytes  d=delta  r=rate\n")
}
