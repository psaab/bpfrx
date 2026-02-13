package logging

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/psaab/bpfrx/pkg/config"
)

// TraceWriter writes matching flow events to a trace file with rotation.
type TraceWriter struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	maxSize  int64 // bytes
	maxFiles int
	written  int64
	filters  []traceFilter
	flags    map[string]bool // which event types to trace
}

type traceFilter struct {
	name   string
	srcNet netip.Prefix
	dstNet netip.Prefix
}

// NewTraceWriter creates a trace writer from flow traceoptions config.
func NewTraceWriter(opts *config.FlowTraceoptions) (*TraceWriter, error) {
	if opts == nil || opts.File == "" {
		return nil, fmt.Errorf("no trace file specified")
	}

	path := opts.File
	if !filepath.IsAbs(path) {
		path = filepath.Join("/var/log", path)
	}

	maxSize := int64(opts.FileSize)
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10MB default
	}
	maxFiles := opts.FileCount
	if maxFiles <= 0 {
		maxFiles = 3
	}

	tw := &TraceWriter{
		path:     path,
		maxSize:  maxSize,
		maxFiles: maxFiles,
		flags:    make(map[string]bool),
	}

	// Parse flags
	for _, f := range opts.Flags {
		tw.flags[f] = true
	}
	// If no flags specified, trace everything
	if len(tw.flags) == 0 {
		tw.flags["basic-datapath"] = true
		tw.flags["session"] = true
	}

	// Parse packet filters
	for _, pf := range opts.PacketFilters {
		f := traceFilter{name: pf.Name}
		if pf.SourcePrefix != "" {
			prefix, err := netip.ParsePrefix(pf.SourcePrefix)
			if err != nil {
				slog.Warn("invalid trace filter source prefix",
					"filter", pf.Name, "prefix", pf.SourcePrefix, "err", err)
				continue
			}
			f.srcNet = prefix
		}
		if pf.DestinationPrefix != "" {
			prefix, err := netip.ParsePrefix(pf.DestinationPrefix)
			if err != nil {
				slog.Warn("invalid trace filter destination prefix",
					"filter", pf.Name, "prefix", pf.DestinationPrefix, "err", err)
				continue
			}
			f.dstNet = prefix
		}
		tw.filters = append(tw.filters, f)
	}

	// Open trace file
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create trace dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open trace file: %w", err)
	}
	tw.file = f

	// Get current file size
	if info, err := f.Stat(); err == nil {
		tw.written = info.Size()
	}

	return tw, nil
}

// Close closes the trace file.
func (tw *TraceWriter) Close() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.file != nil {
		tw.file.Close()
		tw.file = nil
	}
}

// HandleEvent is an EventCallback that writes matching events to the trace file.
func (tw *TraceWriter) HandleEvent(rec EventRecord, raw []byte) {
	// Check if event type matches trace flags
	if !tw.matchFlags(rec.Type) {
		return
	}

	// Check packet filters (if any configured)
	if len(tw.filters) > 0 && !tw.matchFilters(rec) {
		return
	}

	// Format trace line
	line := tw.formatTrace(rec)

	tw.mu.Lock()
	defer tw.mu.Unlock()

	if tw.file == nil {
		return
	}

	n, err := tw.file.WriteString(line)
	if err != nil {
		return
	}
	tw.written += int64(n)

	// Rotate if needed
	if tw.written >= tw.maxSize {
		tw.rotate()
	}
}

func (tw *TraceWriter) matchFlags(eventType string) bool {
	if tw.flags["basic-datapath"] {
		return true // trace everything
	}
	switch eventType {
	case "SESSION_OPEN", "SESSION_CLOSE":
		return tw.flags["session"]
	case "POLICY_DENY":
		return tw.flags["session"] || tw.flags["basic-datapath"]
	default:
		return tw.flags["basic-datapath"]
	}
}

func (tw *TraceWriter) matchFilters(rec EventRecord) bool {
	srcAddr := extractAddr(rec.SrcAddr)
	dstAddr := extractAddr(rec.DstAddr)

	for _, f := range tw.filters {
		srcMatch := !f.srcNet.IsValid() || (srcAddr.IsValid() && f.srcNet.Contains(srcAddr))
		dstMatch := !f.dstNet.IsValid() || (dstAddr.IsValid() && f.dstNet.Contains(dstAddr))
		if srcMatch && dstMatch {
			return true
		}
	}
	return false
}

// extractAddr parses an IP address from "IP:port" or "[IPv6]:port" format.
func extractAddr(addrPort string) netip.Addr {
	// Try "[ipv6]:port" format
	if strings.HasPrefix(addrPort, "[") {
		end := strings.Index(addrPort, "]")
		if end > 0 {
			if addr, err := netip.ParseAddr(addrPort[1:end]); err == nil {
				return addr
			}
		}
		return netip.Addr{}
	}
	// Try "ip:port" format
	host := addrPort
	if idx := strings.LastIndex(addrPort, ":"); idx >= 0 {
		host = addrPort[:idx]
	}
	addr, _ := netip.ParseAddr(host)
	return addr
}

func (tw *TraceWriter) formatTrace(rec EventRecord) string {
	ts := rec.Time.Format("2006-01-02 15:04:05.000")
	if rec.Type == "SESSION_CLOSE" {
		return fmt.Sprintf("%s %-14s %s -> %s proto=%s action=%s policy=%d zone=%d->%d pkts=%d bytes=%d\n",
			ts, rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			rec.PolicyID, rec.InZone, rec.OutZone, rec.SessionPkts, rec.SessionBytes)
	}
	if rec.Type == "SCREEN_DROP" {
		return fmt.Sprintf("%s %-14s %s -> %s proto=%s screen=%s zone=%d\n",
			ts, rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.ScreenCheck, rec.InZone)
	}
	return fmt.Sprintf("%s %-14s %s -> %s proto=%s action=%s policy=%d zone=%d->%d\n",
		ts, rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
		rec.PolicyID, rec.InZone, rec.OutZone)
}

func (tw *TraceWriter) rotate() {
	tw.file.Close()
	tw.file = nil

	// Shift existing files: .2 -> .3, .1 -> .2, current -> .1
	for i := tw.maxFiles - 1; i > 0; i-- {
		old := fmt.Sprintf("%s.%d", tw.path, i)
		new := fmt.Sprintf("%s.%d", tw.path, i+1)
		os.Rename(old, new)
	}
	os.Rename(tw.path, tw.path+".1")

	// Remove excess files
	excess := fmt.Sprintf("%s.%d", tw.path, tw.maxFiles+1)
	os.Remove(excess)

	// Open fresh file
	f, err := os.OpenFile(tw.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		slog.Warn("failed to open rotated trace file", "err", err)
		return
	}
	tw.file = f
	tw.written = 0
}
