package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/logging"
)

// monitorFlowFilter holds the criteria for a single named flow filter.
type monitorFlowFilter struct {
	Name     string
	SrcIP    *net.IPNet // source prefix
	DstIP    *net.IPNet // destination prefix
	SrcPort  uint16
	DstPort  uint16
	Protocol string // "tcp", "udp", "icmp", etc. or numeric
	Iface    string // interface name
}

// matches returns true if the event record matches this filter.
// An empty filter (no criteria) matches everything.
func (f *monitorFlowFilter) matches(rec *logging.EventRecord) bool {
	if f.SrcIP != nil {
		srcIP := extractIP(rec.SrcAddr)
		if srcIP == nil || !f.SrcIP.Contains(srcIP) {
			return false
		}
	}
	if f.DstIP != nil {
		dstIP := extractIP(rec.DstAddr)
		if dstIP == nil || !f.DstIP.Contains(dstIP) {
			return false
		}
	}
	if f.SrcPort != 0 {
		port := extractPort(rec.SrcAddr)
		if port != f.SrcPort {
			return false
		}
	}
	if f.DstPort != 0 {
		port := extractPort(rec.DstAddr)
		if port != f.DstPort {
			return false
		}
	}
	if f.Protocol != "" {
		if !strings.EqualFold(rec.Protocol, f.Protocol) {
			return false
		}
	}
	if f.Iface != "" {
		if rec.IngressIface != f.Iface {
			return false
		}
	}
	return true
}

// monitorFlowState holds the daemon-side state for "monitor security flow".
type monitorFlowState struct {
	mu       sync.Mutex
	filename string // trace file name (base name, written to /var/log/)
	fileSize int64  // max file size in bytes
	files    int    // max number of trace files
	match    string // regex for line filtering
	filters  map[string]*monitorFlowFilter
	active   bool
	cancel   context.CancelFunc // cancel the active monitor goroutine
	sub      *logging.Subscription
}

func newMonitorFlowState() *monitorFlowState {
	return &monitorFlowState{
		filters: make(map[string]*monitorFlowFilter),
	}
}

// extractIP parses the IP from "addr:port" or bare IP strings.
func extractIP(addrPort string) net.IP {
	// Try host:port first
	host, _, err := net.SplitHostPort(addrPort)
	if err != nil {
		// Might be bare IP (e.g., ICMP)
		host = addrPort
	}
	return net.ParseIP(host)
}

// extractPort parses the port number from "addr:port" strings.
func extractPort(addrPort string) uint16 {
	_, portStr, err := net.SplitHostPort(addrPort)
	if err != nil {
		return 0
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

// formatFlowEvent formats an EventRecord into Junos-style flow trace output.
func formatFlowEvent(rec logging.EventRecord) string {
	ts := rec.Time.Format("15:04:05.000000")
	return fmt.Sprintf("%s %s %s->%s %s %s/%s %s policy=%s",
		ts,
		rec.InZoneName+"/"+rec.OutZoneName,
		rec.SrcAddr, rec.DstAddr,
		rec.Protocol,
		rec.InZoneName, rec.OutZoneName,
		rec.Action,
		rec.PolicyName)
}

// formatPacketDropEvent formats an EventRecord into Junos-style packet-drop output.
func formatPacketDropEvent(rec logging.EventRecord) string {
	ts := rec.Time.Format("15:04:05.000000")
	reason := rec.Action
	if rec.ScreenCheck != "" {
		reason = "Dropped by SCREEN:" + rec.ScreenCheck
	} else if rec.Type == "POLICY_DENY" {
		reason = "Dropped by FLOW:Policy deny"
		if rec.PolicyName != "" {
			reason = "Dropped by FLOW:Policy " + rec.PolicyName
		}
	}
	return fmt.Sprintf("%s %s-->%s;%s,%s,%s",
		ts,
		rec.SrcAddr, rec.DstAddr,
		strings.ToLower(rec.Protocol),
		rec.IngressIface,
		reason)
}

// handleMonitorSecurity dispatches monitor security sub-commands.
func (c *CLI) handleMonitorSecurity(args []string) error {
	secTree := operationalTree["monitor"].Children["security"].Children
	if len(args) == 0 {
		fmt.Println("monitor security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(secTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(secTree))
	if err != nil {
		return err
	}

	switch resolved {
	case "flow":
		return c.handleMonitorSecurityFlow(args[1:])
	case "packet-drop":
		return c.handleMonitorSecurityPacketDrop(args[1:])
	default:
		return fmt.Errorf("unknown monitor security target: %s", resolved)
	}
}

// handleMonitorSecurityFlow dispatches flow sub-commands.
func (c *CLI) handleMonitorSecurityFlow(args []string) error {
	flowTree := operationalTree["monitor"].Children["security"].Children["flow"].Children
	if len(args) == 0 {
		fmt.Println("monitor security flow:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(flowTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(flowTree))
	if err != nil {
		return err
	}

	switch resolved {
	case "file":
		return c.handleMonitorSecurityFlowFile(args[1:])
	case "filter":
		return c.handleMonitorSecurityFlowFilter(args[1:])
	case "start":
		return c.handleMonitorSecurityFlowStart()
	case "stop":
		return c.handleMonitorSecurityFlowStop()
	default:
		return fmt.Errorf("unknown monitor security flow target: %s", resolved)
	}
}

// handleMonitorSecurityFlowFile configures the flow trace file.
func (c *CLI) handleMonitorSecurityFlowFile(args []string) error {
	if c.monitorFlow == nil {
		c.monitorFlow = newMonitorFlowState()
	}
	c.monitorFlow.mu.Lock()
	defer c.monitorFlow.mu.Unlock()

	if len(args) == 0 {
		fmt.Println("error: Please specify the trace filename.")
		return nil
	}

	// First non-option arg is the filename.
	c.monitorFlow.filename = args[0]
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "size":
			if i+1 < len(args) {
				i++
				v, err := strconv.ParseInt(args[i], 10, 64)
				if err != nil || v < 10240 || v > 1073741824 {
					fmt.Println("error: size must be 10240..1073741824")
					return nil
				}
				c.monitorFlow.fileSize = v
			}
		case "files":
			if i+1 < len(args) {
				i++
				v, err := strconv.Atoi(args[i])
				if err != nil || v < 2 || v > 1000 {
					fmt.Println("error: files must be 2..1000")
					return nil
				}
				c.monitorFlow.files = v
			}
		case "match":
			if i+1 < len(args) {
				i++
				c.monitorFlow.match = args[i]
			}
		}
	}
	return nil
}

// handleMonitorSecurityFlowFilter configures a named flow filter.
func (c *CLI) handleMonitorSecurityFlowFilter(args []string) error {
	if c.monitorFlow == nil {
		c.monitorFlow = newMonitorFlowState()
	}
	c.monitorFlow.mu.Lock()
	defer c.monitorFlow.mu.Unlock()

	if len(args) == 0 {
		fmt.Println("error: Please specify the filter name.")
		return nil
	}

	name := args[0]
	f, ok := c.monitorFlow.filters[name]
	if !ok {
		f = &monitorFlowFilter{Name: name}
		c.monitorFlow.filters[name] = f
	}

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "source-prefix":
			if i+1 < len(args) {
				i++
				_, cidr, err := net.ParseCIDR(args[i])
				if err != nil {
					// Try as host address
					ip := net.ParseIP(args[i])
					if ip == nil {
						fmt.Printf("error: invalid source-prefix: %s\n", args[i])
						return nil
					}
					if ip.To4() != nil {
						cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
					} else {
						cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
					}
				}
				f.SrcIP = cidr
			}
		case "destination-prefix":
			if i+1 < len(args) {
				i++
				_, cidr, err := net.ParseCIDR(args[i])
				if err != nil {
					ip := net.ParseIP(args[i])
					if ip == nil {
						fmt.Printf("error: invalid destination-prefix: %s\n", args[i])
						return nil
					}
					if ip.To4() != nil {
						cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
					} else {
						cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
					}
				}
				f.DstIP = cidr
			}
		case "source-port":
			if i+1 < len(args) {
				i++
				p, err := strconv.ParseUint(args[i], 10, 16)
				if err != nil {
					fmt.Printf("error: invalid source-port: %s\n", args[i])
					return nil
				}
				f.SrcPort = uint16(p)
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				p, err := strconv.ParseUint(args[i], 10, 16)
				if err != nil {
					fmt.Printf("error: invalid destination-port: %s\n", args[i])
					return nil
				}
				f.DstPort = uint16(p)
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				f.Protocol = args[i]
			}
		case "interface":
			if i+1 < len(args) {
				i++
				f.Iface = args[i]
			}
		}
	}
	return nil
}

// handleMonitorSecurityFlowStart starts flow tracing.
func (c *CLI) handleMonitorSecurityFlowStart() error {
	if c.monitorFlow == nil {
		c.monitorFlow = newMonitorFlowState()
	}
	c.monitorFlow.mu.Lock()

	if c.monitorFlow.filename == "" {
		c.monitorFlow.mu.Unlock()
		fmt.Println("error: Please specify the monitor flow trace file.")
		return nil
	}
	if len(c.monitorFlow.filters) == 0 {
		c.monitorFlow.mu.Unlock()
		fmt.Println("error: Please specify monitor security flow filter.")
		return nil
	}
	if c.monitorFlow.active {
		c.monitorFlow.mu.Unlock()
		fmt.Println("error: Flow monitor is already active. Stop it first.")
		return nil
	}

	c.monitorFlow.active = true

	// Snapshot the current filters.
	filters := make([]*monitorFlowFilter, 0, len(c.monitorFlow.filters))
	for _, f := range c.monitorFlow.filters {
		fc := *f
		filters = append(filters, &fc)
	}

	// Open trace file.
	path := "/var/log/" + c.monitorFlow.filename
	logFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		c.monitorFlow.active = false
		c.monitorFlow.mu.Unlock()
		return fmt.Errorf("failed to open trace file %s: %w", path, err)
	}

	// Subscribe to event buffer.
	sub := c.eventBuf.Subscribe(256)
	c.monitorFlow.sub = sub

	ctx, cancel := context.WithCancel(context.Background())
	c.monitorFlow.cancel = cancel
	c.monitorFlow.mu.Unlock()

	// Run the monitor goroutine in the background.
	go func() {
		defer logFile.Close()
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case rec := <-sub.C:
				// Check if any filter matches.
				matched := false
				for _, f := range filters {
					if f.matches(&rec) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
				line := formatFlowEvent(rec)
				fmt.Fprintln(logFile, line)
			}
		}
	}()

	// Silent success per Junos behavior.
	return nil
}

// handleMonitorSecurityFlowStop stops flow tracing.
func (c *CLI) handleMonitorSecurityFlowStop() error {
	if c.monitorFlow == nil {
		return nil
	}
	c.monitorFlow.mu.Lock()
	defer c.monitorFlow.mu.Unlock()

	if c.monitorFlow.cancel != nil {
		c.monitorFlow.cancel()
		c.monitorFlow.cancel = nil
	}
	c.monitorFlow.sub = nil
	c.monitorFlow.active = false
	// Silent success per Junos behavior.
	return nil
}

// showMonitorSecurityFlow displays the current monitor security flow status.
func (c *CLI) showMonitorSecurityFlow() error {
	if c.monitorFlow == nil {
		c.monitorFlow = newMonitorFlowState()
	}
	c.monitorFlow.mu.Lock()
	defer c.monitorFlow.mu.Unlock()

	status := "Inactive"
	if c.monitorFlow.active {
		status = "Active"
	}

	fmt.Printf("  Monitor security flow session status: %s\n", status)
	if c.monitorFlow.filename != "" {
		fmt.Printf("  Monitor security flow trace file: /var/log/%s\n", c.monitorFlow.filename)
	} else {
		fmt.Printf("  Monitor security flow trace file: (not configured)\n")
	}
	fmt.Printf("  Monitor security flow filters: %d\n", len(c.monitorFlow.filters))

	// Sort filter names for deterministic output.
	names := make([]string, 0, len(c.monitorFlow.filters))
	for name := range c.monitorFlow.filters {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		f := c.monitorFlow.filters[name]
		filterStatus := "Inactive"
		if c.monitorFlow.active {
			filterStatus = "Active"
		}
		fmt.Printf("\n  Filter: %s\n", f.Name)
		fmt.Printf("    Status: %s\n", filterStatus)

		src := "any"
		if f.SrcIP != nil {
			src = f.SrcIP.String()
		}
		if f.SrcPort != 0 {
			src += fmt.Sprintf(" port %d", f.SrcPort)
		}
		fmt.Printf("    Source: %s\n", src)

		dst := "any"
		if f.DstIP != nil {
			dst = f.DstIP.String()
		}
		if f.DstPort != 0 {
			dst += fmt.Sprintf(" port %d", f.DstPort)
		}
		fmt.Printf("    Destination: %s\n", dst)

		if f.Protocol != "" {
			fmt.Printf("    Protocol: %s\n", f.Protocol)
		}
		if f.Iface != "" {
			fmt.Printf("    Interface: %s\n", f.Iface)
		}
	}

	return nil
}

// handleMonitorSecurityPacketDrop streams packet drop events to stdout.
func (c *CLI) handleMonitorSecurityPacketDrop(args []string) error {
	// Parse optional filters.
	var (
		srcIP    *net.IPNet
		dstIP    *net.IPNet
		srcPort  uint16
		dstPort  uint16
		protocol string
		fromZone string
		iface    string
		count    int
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "source-prefix":
			if i+1 < len(args) {
				i++
				_, cidr, err := net.ParseCIDR(args[i])
				if err != nil {
					ip := net.ParseIP(args[i])
					if ip == nil {
						fmt.Printf("error: invalid source-prefix: %s\n", args[i])
						return nil
					}
					if ip.To4() != nil {
						cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
					} else {
						cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
					}
				}
				srcIP = cidr
			}
		case "destination-prefix":
			if i+1 < len(args) {
				i++
				_, cidr, err := net.ParseCIDR(args[i])
				if err != nil {
					ip := net.ParseIP(args[i])
					if ip == nil {
						fmt.Printf("error: invalid destination-prefix: %s\n", args[i])
						return nil
					}
					if ip.To4() != nil {
						cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
					} else {
						cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
					}
				}
				dstIP = cidr
			}
		case "source-port":
			if i+1 < len(args) {
				i++
				p, err := strconv.ParseUint(args[i], 10, 16)
				if err != nil {
					fmt.Printf("error: invalid source-port: %s\n", args[i])
					return nil
				}
				srcPort = uint16(p)
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				p, err := strconv.ParseUint(args[i], 10, 16)
				if err != nil {
					fmt.Printf("error: invalid destination-port: %s\n", args[i])
					return nil
				}
				dstPort = uint16(p)
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				protocol = args[i]
			}
		case "from-zone":
			if i+1 < len(args) {
				i++
				fromZone = args[i]
			}
		case "interface":
			if i+1 < len(args) {
				i++
				iface = args[i]
			}
		case "count":
			if i+1 < len(args) {
				i++
				v, err := strconv.Atoi(args[i])
				if err != nil || v < 1 || v > 8192 {
					fmt.Println("error: count must be 1..8192")
					return nil
				}
				count = v
			}
		}
	}

	fmt.Println("Starting packet drop:")

	// Subscribe to event buffer.
	sub := c.eventBuf.Subscribe(256)
	defer sub.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	defer func() {
		c.cmdMu.Lock()
		c.cmdCancel = nil
		c.cmdMu.Unlock()
	}()

	seen := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Println() // newline after ^C
			return nil
		case rec := <-sub.C:
			// Only show drops (POLICY_DENY and SCREEN_DROP).
			if rec.Type != "POLICY_DENY" && rec.Type != "SCREEN_DROP" {
				continue
			}

			// Apply filters.
			if srcIP != nil {
				ip := extractIP(rec.SrcAddr)
				if ip == nil || !srcIP.Contains(ip) {
					continue
				}
			}
			if dstIP != nil {
				ip := extractIP(rec.DstAddr)
				if ip == nil || !dstIP.Contains(ip) {
					continue
				}
			}
			if srcPort != 0 && extractPort(rec.SrcAddr) != srcPort {
				continue
			}
			if dstPort != 0 && extractPort(rec.DstAddr) != dstPort {
				continue
			}
			if protocol != "" && !strings.EqualFold(rec.Protocol, protocol) {
				continue
			}
			if fromZone != "" && rec.InZoneName != fromZone {
				continue
			}
			if iface != "" && rec.IngressIface != iface {
				continue
			}

			fmt.Println(formatPacketDropEvent(rec))

			seen++
			if count > 0 && seen >= count {
				return nil
			}
		}
	}
}
