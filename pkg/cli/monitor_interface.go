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
)

type ifaceSnapshot = monitoriface.Snapshot
type userspaceIfaceSnapshot = monitoriface.UserspaceSnapshot

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
		view, err := parseMonitorTrafficView(args[1:])
		if err != nil {
			return err
		}
		return c.monitorInterfaceTraffic(view)
	}

	return c.monitorInterfaceSingle(args[0])
}

func parseMonitorTrafficView(args []string) (monitoriface.TrafficViewState, error) {
	return monitoriface.ParseTrafficViewArgs(args)
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
	names, err := monitoriface.ListTrafficInterfaces()
	if err == nil && len(names) > 0 {
		return names
	}
	return c.sortedConfiguredInterfaces()
}

func (c *CLI) summaryInterfaces() ([]string, map[string]string) {
	names, err := monitoriface.ListTrafficInterfaces()
	if err == nil && len(names) > 0 {
		kernelNames := make(map[string]string, len(names))
		for _, name := range names {
			kernelNames[name] = name
		}
		return names, kernelNames
	}

	names = c.sortedConfiguredInterfaces()
	kernelNames := make(map[string]string, len(names))
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
	old, err := monitoriface.SetRawMode(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer monitoriface.RestoreTermMode(fd, old)

	fmt.Print(monitoriface.EnterAltScreen + monitoriface.HideCursor)
	defer fmt.Print(monitoriface.ShowCursor + monitoriface.ExitAltScreen)

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
		fmt.Print(monitoriface.ClearAndHome)
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
func (c *CLI) monitorInterfaceTraffic(view monitoriface.TrafficViewState) error {
	fd := int(os.Stdin.Fd())
	old, err := monitoriface.SetRawMode(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer monitoriface.RestoreTermMode(fd, old)

	fmt.Print(monitoriface.EnterAltScreen + monitoriface.HideCursor)
	defer fmt.Print(monitoriface.ShowCursor + monitoriface.ExitAltScreen)

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

	ticker := time.NewTicker(view.Refresh)
	defer ticker.Stop()

	startTime := time.Now()
	tracker := monitoriface.NewTrafficTracker(startTime)
	showHelp := false

	renderNow := func() {
		fmt.Print(monitoriface.ClearAndHome)
		if showHelp {
			monitoriface.RenderTrafficHelp(os.Stdout, view)
			return
		}
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
		tracker.Update(snaps)
		tracker.Render(os.Stdout, c.hostname, names, snaps, view)
	}
	renderNow()

	for {
		select {
		case <-ticker.C:
			if !showHelp {
				renderNow()
			}
		case key := <-keyCh:
			if showHelp {
				showHelp = false
				renderNow()
				continue
			}
			switch view.HandleKey(key) {
			case monitoriface.TrafficKeyQuit:
				return nil
			case monitoriface.TrafficKeyShowHelp:
				showHelp = true
				renderNow()
			case monitoriface.TrafficKeyChanged:
				ticker.Reset(view.Refresh)
				renderNow()
			}
		}
	}
}
