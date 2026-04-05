package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	dpuserspace "github.com/psaab/bpfrx/pkg/dataplane/userspace"
	"github.com/psaab/bpfrx/pkg/monitoriface"
	"golang.org/x/sys/unix"
)

type ifaceSnapshot = monitoriface.Snapshot
type userspaceIfaceSnapshot = monitoriface.UserspaceSnapshot

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

func resolveFabricParent(name string) string {
	return monitoriface.ResolvePhysicalParent(name)
}

func aggregateUserspaceIfaceSnapshot(kernelName string, status dpuserspace.ProcessStatus) *userspaceIfaceSnapshot {
	return monitoriface.AggregateUserspaceSnapshot(kernelName, status)
}

func renderSingleInterface(w io.Writer, hostname, displayName, kernelName string, snap, prev, baseline *ifaceSnapshot, startTime time.Time) {
	monitoriface.RenderSingleInterface(w, hostname, displayName, kernelName, snap, prev, baseline, startTime)
}

// handleMonitorInterface dispatches monitor interface sub-commands.
func (c *CLI) handleMonitorInterface(args []string) error {
	if len(args) == 0 {
		monTree := operationalTree["monitor"].Children["interface"]
		fmt.Println("monitor interface:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(monTree.Children))
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

	if args[0] == "traffic" {
		mode, err := parseMonitorSummaryMode(args[1:])
		if err != nil {
			return err
		}
		return c.monitorInterfaceTraffic(mode)
	}

	return c.monitorInterfaceSingle(args[0])
}

func parseMonitorSummaryMode(args []string) (monitoriface.SummaryMode, error) {
	if len(args) == 0 {
		return monitoriface.SummaryModeCombined, nil
	}
	mode, ok := monitoriface.ParseSummaryMode(args[0])
	if !ok {
		return monitoriface.SummaryModeCombined, fmt.Errorf("unknown monitor interface traffic mode: %s", args[0])
	}
	return mode, nil
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

func (c *CLI) sortedMonitorInterfaces() []string {
	names, _ := monitoriface.TrafficSummaryInterfaces(c.store.ActiveConfig())
	if len(names) > 0 {
		return names
	}
	return c.sortedConfiguredInterfaces()
}

func (c *CLI) summaryInterfaces() ([]string, map[string]string) {
	names, kernelNames := monitoriface.TrafficSummaryInterfaces(c.store.ActiveConfig())
	if len(names) > 0 {
		return names, kernelNames
	}
	names = c.sortedConfiguredInterfaces()
	kernelNames = make(map[string]string, len(names))
	for _, name := range names {
		kernelNames[name] = monitoriface.ResolvePhysicalParent(c.resolveToKernel(name))
	}
	return names, kernelNames
}

// resolveToKernel converts a config-level name (ge-0/0/0, reth0) to kernel name.
func (c *CLI) resolveToKernel(cfgName string) string {
	cfg := c.store.ActiveConfig()
	if cfg != nil {
		cfgName = cfg.ResolveReth(cfgName)
	}
	return config.LinuxIfName(cfgName)
}

func (c *CLI) readMonitorSnapshot(kernelName string) (monitoriface.Snapshot, error) {
	return monitoriface.ReadSnapshot(c.dp, c.userspaceDataplaneStatus, kernelName)
}

// monitorInterfaceSingle shows full-screen stats for a single interface.
func (c *CLI) monitorInterfaceSingle(ifaceName string) error {
	displayName := ifaceName
	kernelName := monitoriface.ResolvePhysicalParent(c.resolveToKernel(ifaceName))
	if _, err := c.readMonitorSnapshot(kernelName); err != nil {
		return fmt.Errorf("interface %s not found", ifaceName)
	}

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
	var prev *monitoriface.Snapshot
	var baseline *monitoriface.Snapshot
	frozen := false
	allIfaces := c.sortedMonitorInterfaces()

	renderNow := func() {
		kn := monitoriface.ResolvePhysicalParent(c.resolveToKernel(displayName))
		snap, err := c.readMonitorSnapshot(kn)
		if err != nil {
			return
		}
		if baseline == nil {
			snapCopy := snap
			baseline = &snapCopy
		}
		fmt.Print(clearAndHome)
		monitoriface.RenderSingleInterface(os.Stdout, c.hostname, displayName, kn, &snap, prev, baseline, startTime)
		snapCopy := snap
		prev = &snapCopy
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
			case 'q', 'Q', 0x1b, 0x03:
				return nil
			case 'f', 'F':
				frozen = true
			case 't', 'T':
				frozen = false
			case 'c', 'C':
				baseline = nil
				prev = nil
				renderNow()
			case 'n', 'N':
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

// monitorInterfaceTraffic shows a full-screen all-interfaces summary table.
func (c *CLI) monitorInterfaceTraffic(mode monitoriface.SummaryMode) error {
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
	prevSnaps := make(map[string]*monitoriface.Snapshot)

	renderNow := func() {
		names, kernelNames := c.summaryInterfaces()
		snaps := make(map[string]*monitoriface.Snapshot, len(names))
		for _, name := range names {
			snap, err := c.readMonitorSnapshot(kernelNames[name])
			if err != nil {
				continue
			}
			snapCopy := snap
			snaps[name] = &snapCopy
		}
		fmt.Print(clearAndHome)
		monitoriface.RenderTrafficSummary(os.Stdout, c.hostname, names, kernelNames, snaps, prevSnaps, mode, startTime)
		prevSnaps = snaps
	}
	renderNow()

	for {
		select {
		case <-ticker.C:
			renderNow()
		case key := <-keyCh:
			switch key {
			case 'q', 'Q', 0x1b, 0x03:
				return nil
			case 'c', 'C':
				mode = monitoriface.SummaryModeCombined
				renderNow()
			case 'p', 'P':
				mode = monitoriface.SummaryModePackets
				renderNow()
			case 'b', 'B':
				mode = monitoriface.SummaryModeBytes
				renderNow()
			case 'd', 'D':
				mode = monitoriface.SummaryModeDelta
				renderNow()
			case 'r', 'R':
				mode = monitoriface.SummaryModeRate
				renderNow()
			}
		}
	}
}
