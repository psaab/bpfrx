package logging

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// traceLogDir is the directory persistent flow-trace files are written to. It
// is a package var (not a const) only so tests can redirect it to a temp dir;
// production always writes under /var/log. The persistent
// `security flow traceoptions file <name>` knob accepts a bare basename and the
// file always lives directly under this directory.
var traceLogDir = "/var/log"

// sanitizeTraceFileName validates an operator-supplied flow-trace filename.
// The trace file always lives directly under traceLogDir, so only a bare
// basename is accepted: path separators, "." / "..", and absolute paths are
// rejected. Without this a committed `security flow traceoptions file
// ../../tmp/x` resolves to /tmp/x and the daemon appends root-written flow
// telemetry (internal addresses, ports, zones, actions, policy IDs) outside the
// log directory (#3420). This is the persistent-config sibling of the
// interactive monitor-path hardening (#3378). The commit-time gate
// (validateFlowTraceFileAST) rejects such a value loudly; this runtime check is
// defense-in-depth that fails safe (tracing disabled) on a leniently-loaded or
// peer-synced config.
func sanitizeTraceFileName(name string) error {
	if name == "" {
		return fmt.Errorf("trace filename must not be empty")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid trace filename: %q", name)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("trace filename must be a bare name, not a path: %q", name)
	}
	if filepath.IsAbs(name) || name != filepath.Base(name) {
		return fmt.Errorf("trace filename must be a bare name, not a path: %q", name)
	}
	return nil
}

// openTraceFile opens a flow-trace file (the active file or a rotated
// generation) inside traceLogDir with restrictive semantics: O_NOFOLLOW so a
// pre-planted symlink under /var/log cannot redirect the root-written telemetry
// (#3420), the opened descriptor is verified to be a regular file, and it is
// created mode 0600 rather than world-readable 0644 — flow tuples/zones/policy
// names are audit-grade telemetry. The caller passes an already-sanitized
// basename (NewTraceWriter validates once up front).
func openTraceFile(name string) (*os.File, error) {
	path := filepath.Join(traceLogDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("trace target %s is not a regular file", path)
	}
	return f, nil
}

// TraceWriter writes matching flow events to a trace file with rotation.
type TraceWriter struct {
	mu       sync.Mutex
	file     *os.File
	name     string // sanitized basename, written under traceLogDir
	path     string // traceLogDir/name (rotation suffixes append to this)
	maxSize  int64  // bytes
	maxFiles int
	written  int64
	filters  []traceFilter
	flags    map[string]bool // which event types to trace
}

type traceFilter struct {
	name   string
	srcNet netip.Prefix
	dstNet netip.Prefix
	proto  string // normalized protocol name (e.g. "TCP"); "" = any
}

// NewTraceWriter creates a trace writer from flow traceoptions config.
func NewTraceWriter(opts *config.FlowTraceoptions) (*TraceWriter, error) {
	if opts == nil || opts.File == "" {
		return nil, fmt.Errorf("no trace file specified")
	}

	// Reject a non-basename file value (absolute path, separator, or ".."
	// escape) so a committed config cannot steer root-written flow telemetry
	// outside /var/log (#3420). The commit-time gate rejects this loudly; here
	// we fail safe (no trace writer) for a leniently-loaded / peer-synced value.
	if err := sanitizeTraceFileName(opts.File); err != nil {
		return nil, err
	}
	name := opts.File
	path := filepath.Join(traceLogDir, name)

	maxSize := int64(opts.FileSize)
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10MB default
	}
	maxFiles := opts.FileCount
	if maxFiles <= 0 {
		maxFiles = 3
	}

	tw := &TraceWriter{
		name:     name,
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
		if pf.Protocol != "" {
			f.proto = normalizeTraceProto(pf.Protocol)
		}
		tw.filters = append(tw.filters, f)
	}

	// Open trace file under traceLogDir (O_NOFOLLOW, regular-file checked, 0600).
	if err := os.MkdirAll(traceLogDir, 0755); err != nil {
		return nil, fmt.Errorf("create trace dir: %w", err)
	}
	f, err := openTraceFile(name)
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

	recProto := normalizeTraceProto(rec.Protocol)

	for _, f := range tw.filters {
		srcMatch := !f.srcNet.IsValid() || (srcAddr.IsValid() && f.srcNet.Contains(srcAddr))
		dstMatch := !f.dstNet.IsValid() || (dstAddr.IsValid() && f.dstNet.Contains(dstAddr))
		protoMatch := f.proto == "" || f.proto == recProto
		if srcMatch && dstMatch && protoMatch {
			return true
		}
	}
	return false
}

// normalizeTraceProto canonicalizes a protocol identifier so a config filter
// value (a Junos name like "tcp" or a numeric value like "6") compares equal
// to the EventRecord.Protocol string (which protoName renders as "TCP",
// "UDP", "ICMP", "ICMPv6", or a decimal string). Names are upper-cased and
// known numbers are mapped to their canonical name.
func normalizeTraceProto(p string) string {
	up := strings.ToUpper(strings.TrimSpace(p))
	switch up {
	case "1", "ICMP":
		return "ICMP"
	case "6", "TCP":
		return "TCP"
	case "17", "UDP":
		return "UDP"
	case "58", "ICMPV6", "ICMP6":
		return "ICMPv6"
	default:
		return up
	}
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

	// Open fresh file (O_NOFOLLOW, regular-file checked, 0600). The active path
	// was just renamed to .1, so this creates a new empty file.
	f, err := openTraceFile(tw.name)
	if err != nil {
		slog.Warn("failed to open rotated trace file", "err", err)
		return
	}
	tw.file = f
	tw.written = 0
}
