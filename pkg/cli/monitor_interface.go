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
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ifaceSnapshot holds a point-in-time sample of interface counters.
type ifaceSnapshot struct {
	rxBytes, txBytes       uint64
	rxPkts, txPkts         uint64
	rxErrors, txErrors     uint64
	rxDrops, txDrops       uint64
	rxFrame, txCarrier     uint64
	collisions             uint64
	ts                     time.Time
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
		kn := c.resolveToKernel(displayName)
		snap, err := c.readIfaceSnapshot(kn)
		if err != nil {
			return
		}
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
			kn := c.resolveToKernel(name)
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
