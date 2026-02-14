package flowexport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/logging"
)

// SamplingDir tracks per-zone sampling direction flags.
type SamplingDir struct {
	Input  bool
	Output bool
}

// ExportConfig holds the resolved NetFlow export configuration.
type ExportConfig struct {
	Collectors          []CollectorConfig
	FlowActiveTimeout   time.Duration
	FlowInactiveTimeout time.Duration
	TemplateRefreshRate time.Duration
	SamplingZones       map[uint16]SamplingDir // zone ID -> sampling directions
	SamplingRate        int                    // 1-in-N sampling (0 = export all)
	sampleCounter       atomic.Uint64          // monotonic counter for 1-in-N
}

// CollectorConfig defines a single NetFlow collector destination.
type CollectorConfig struct {
	Address       string // "host:port"
	SourceAddress string // local bind address (empty = auto)
}

// BuildExportConfig resolves config types into an ExportConfig.
// Returns nil if no flow export is configured.
func BuildExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig {
	if fo == nil || fo.Sampling == nil || len(fo.Sampling.Instances) == 0 {
		return nil
	}

	// Collect template timeouts from services config
	activeTimeout := 60 * time.Second
	inactiveTimeout := 15 * time.Second
	refreshRate := 60 * time.Second

	if svc != nil && svc.FlowMonitoring != nil && svc.FlowMonitoring.Version9 != nil {
		for _, tmpl := range svc.FlowMonitoring.Version9.Templates {
			if tmpl.FlowActiveTimeout > 0 {
				activeTimeout = time.Duration(tmpl.FlowActiveTimeout) * time.Second
			}
			if tmpl.FlowInactiveTimeout > 0 {
				inactiveTimeout = time.Duration(tmpl.FlowInactiveTimeout) * time.Second
			}
			if tmpl.TemplateRefreshRate > 0 {
				refreshRate = time.Duration(tmpl.TemplateRefreshRate) * time.Second
			}
			break // use first template
		}
	}

	ec := &ExportConfig{
		FlowActiveTimeout:   activeTimeout,
		FlowInactiveTimeout: inactiveTimeout,
		TemplateRefreshRate: refreshRate,
	}

	// Use the first sampling instance's input rate as the global sampling rate
	for _, inst := range fo.Sampling.Instances {
		if inst.InputRate > 0 {
			ec.SamplingRate = inst.InputRate
			break
		}
	}

	// Collect flow servers from all sampling instances
	for _, inst := range fo.Sampling.Instances {
		families := []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6}
		for _, fam := range families {
			if fam == nil {
				continue
			}
			for _, fs := range fam.FlowServers {
				addr := fs.Address
				if fs.Port > 0 {
					addr = fmt.Sprintf("%s:%d", fs.Address, fs.Port)
				}
				srcAddr := fam.SourceAddress
				if srcAddr == "" {
					srcAddr = fam.InlineJflowSourceAddress
				}
				ec.Collectors = append(ec.Collectors, CollectorConfig{
					Address:       addr,
					SourceAddress: srcAddr,
				})
			}
		}
	}

	if len(ec.Collectors) == 0 {
		return nil
	}

	// Deduplicate collectors by address
	seen := make(map[string]bool)
	deduped := ec.Collectors[:0]
	for _, c := range ec.Collectors {
		if !seen[c.Address] {
			seen[c.Address] = true
			deduped = append(deduped, c)
		}
	}
	ec.Collectors = deduped

	return ec
}

// BuildSamplingZones builds a map of zone ID to sampling direction flags.
// For each zone, it checks whether any interface in that zone has
// sampling input or output enabled on its unit.
func BuildSamplingZones(cfg *config.Config, zoneIDs map[string]uint16) map[uint16]SamplingDir {
	result := make(map[uint16]SamplingDir)
	for zoneName, zone := range cfg.Security.Zones {
		zid, ok := zoneIDs[zoneName]
		if !ok {
			continue
		}
		var dir SamplingDir
		for _, ifaceRef := range zone.Interfaces {
			physName, unitNum := parseIfaceRef(ifaceRef)
			ifCfg, ok := cfg.Interfaces.Interfaces[physName]
			if !ok {
				continue
			}
			unit, ok := ifCfg.Units[unitNum]
			if !ok {
				continue
			}
			if unit.SamplingInput {
				dir.Input = true
			}
			if unit.SamplingOutput {
				dir.Output = true
			}
		}
		if dir.Input || dir.Output {
			result[zid] = dir
		}
	}
	return result
}

// ShouldExport checks whether a session close event should be exported based
// on the ingress/egress zone sampling configuration and sampling rate.
// A session is exported if the ingress zone has sampling input enabled OR
// the egress zone has sampling output enabled. If no SamplingZones are
// configured, all sessions are eligible. When SamplingRate > 0, only
// 1-in-N eligible sessions are actually exported.
func (ec *ExportConfig) ShouldExport(inZone, outZone uint16) bool {
	if len(ec.SamplingZones) > 0 {
		eligible := false
		if d, ok := ec.SamplingZones[inZone]; ok && d.Input {
			eligible = true
		}
		if d, ok := ec.SamplingZones[outZone]; ok && d.Output {
			eligible = true
		}
		if !eligible {
			return false
		}
	}
	// Apply 1-in-N sampling rate
	if ec.SamplingRate > 1 {
		n := ec.sampleCounter.Add(1)
		return n%uint64(ec.SamplingRate) == 0
	}
	return true
}

// parseIfaceRef splits "eth0.0" into ("eth0", 0).
func parseIfaceRef(ref string) (string, int) {
	for i := len(ref) - 1; i >= 0; i-- {
		if ref[i] == '.' {
			unitNum := 0
			for _, c := range ref[i+1:] {
				if c >= '0' && c <= '9' {
					unitNum = unitNum*10 + int(c-'0')
				}
			}
			return ref[:i], unitNum
		}
	}
	return ref, 0
}

// Exporter sends NetFlow v9 packets to configured collectors.
type Exporter struct {
	cfg      ExportConfig
	bootTime time.Time
	sourceID uint32

	mu    sync.Mutex
	seq   uint32
	conns []net.Conn

	// Batching: accumulate records, flush periodically
	batchMu sync.Mutex
	batchV4 []FlowRecord
	batchV6 []FlowRecord

	// Stats
	exportedFlows atomic.Uint64
	exportedPkts  atomic.Uint64
}

// NewExporter creates a new NetFlow v9 exporter.
func NewExporter(cfg ExportConfig) (*Exporter, error) {
	e := &Exporter{
		cfg:      cfg,
		bootTime: time.Now(),
		sourceID: 1,
	}

	for _, cc := range cfg.Collectors {
		var conn net.Conn
		var err error
		if cc.SourceAddress != "" {
			laddr, _ := net.ResolveUDPAddr("udp", cc.SourceAddress+":0")
			raddr, err2 := net.ResolveUDPAddr("udp", cc.Address)
			if err2 != nil {
				return nil, fmt.Errorf("resolve collector %s: %w", cc.Address, err2)
			}
			conn, err = net.DialUDP("udp", laddr, raddr)
		} else {
			conn, err = net.Dial("udp", cc.Address)
		}
		if err != nil {
			// Close already-opened connections
			for _, c := range e.conns {
				c.Close()
			}
			return nil, fmt.Errorf("dial collector %s: %w", cc.Address, err)
		}
		e.conns = append(e.conns, conn)
	}

	return e, nil
}

// Run starts the exporter's background goroutines. Blocks until ctx is cancelled.
func (e *Exporter) Run(ctx context.Context) {
	// Send initial template
	e.sendTemplates()

	templateTicker := time.NewTicker(e.cfg.TemplateRefreshRate)
	defer templateTicker.Stop()

	batchTicker := time.NewTicker(100 * time.Millisecond)
	defer batchTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining batches
			e.flushBatches()
			return
		case <-templateTicker.C:
			e.sendTemplates()
		case <-batchTicker.C:
			e.flushBatches()
		}
	}
}

// ExportSessionClose converts a session-close event into a flow record and queues it.
func (e *Exporter) ExportSessionClose(rec logging.EventRecord, evt SessionCloseData) {
	fr := FlowRecord{
		SrcIP:     evt.SrcIP,
		DstIP:     evt.DstIP,
		SrcPort:   evt.SrcPort,
		DstPort:   evt.DstPort,
		Protocol:  evt.Protocol,
		Packets:   rec.SessionPkts,
		Bytes:     rec.SessionBytes,
		StartTime: rec.Time.Add(-estimateSessionDuration(rec.SessionPkts, evt.Protocol)),
		EndTime:   rec.Time,
		IsIPv6:    evt.IsIPv6,
	}

	e.batchMu.Lock()
	if fr.IsIPv6 {
		e.batchV6 = append(e.batchV6, fr)
	} else {
		e.batchV4 = append(e.batchV4, fr)
	}
	e.batchMu.Unlock()
}

// SessionCloseData holds parsed session data for flow export.
type SessionCloseData struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	IsIPv6   bool
}

// Stats returns export statistics.
func (e *Exporter) Stats() (flows, packets uint64) {
	return e.exportedFlows.Load(), e.exportedPkts.Load()
}

// Close shuts down all collector connections.
func (e *Exporter) Close() {
	for _, c := range e.conns {
		c.Close()
	}
}

func (e *Exporter) sendTemplates() {
	tmplFS := encodeTemplateFlowSet()

	e.mu.Lock()
	seq := e.seq
	e.seq++
	e.mu.Unlock()

	now := time.Now()
	hdr := nfHeader{
		Version:   9,
		Count:     2, // 2 templates
		SysUptime: uptimeMs(e.bootTime, now),
		UnixSecs:  uint32(now.Unix()),
		SeqNumber: seq,
		SourceID:  e.sourceID,
	}

	pkt := append(encodeHeader(hdr), tmplFS...)
	for _, c := range e.conns {
		if _, err := c.Write(pkt); err != nil {
			slog.Debug("netflow template send failed", "err", err)
		}
	}
}

func (e *Exporter) flushBatches() {
	e.batchMu.Lock()
	v4 := e.batchV4
	v6 := e.batchV6
	e.batchV4 = nil
	e.batchV6 = nil
	e.batchMu.Unlock()

	if len(v4) > 0 {
		e.sendRecords(v4)
	}
	if len(v6) > 0 {
		e.sendRecords(v6)
	}
}

func (e *Exporter) sendRecords(records []FlowRecord) {
	if len(records) == 0 {
		return
	}

	isV6 := records[0].IsIPv6
	var recSize int
	if isV6 {
		recSize = recordSizeV6
	} else {
		recSize = recordSizeV4
	}

	// Split into chunks that fit in maxPayload
	// Reserve 20 bytes for header + 4 bytes for flowset header
	maxRecords := (maxPayload - 20 - 4) / recSize
	if maxRecords < 1 {
		maxRecords = 1
	}

	for i := 0; i < len(records); i += maxRecords {
		end := i + maxRecords
		if end > len(records) {
			end = len(records)
		}
		batch := records[i:end]

		dataFS := encodeDataFlowSet(batch, e.bootTime)
		if dataFS == nil {
			continue
		}

		e.mu.Lock()
		seq := e.seq
		e.seq++
		e.mu.Unlock()

		now := time.Now()
		hdr := nfHeader{
			Version:   9,
			Count:     uint16(len(batch)),
			SysUptime: uptimeMs(e.bootTime, now),
			UnixSecs:  uint32(now.Unix()),
			SeqNumber: seq,
			SourceID:  e.sourceID,
		}

		pkt := append(encodeHeader(hdr), dataFS...)
		for _, c := range e.conns {
			if _, err := c.Write(pkt); err != nil {
				slog.Debug("netflow data send failed", "err", err)
			}
		}

		e.exportedFlows.Add(uint64(len(batch)))
		e.exportedPkts.Add(1)
	}
}

// estimateSessionDuration provides a rough duration estimate based on packet count.
func estimateSessionDuration(pkts uint64, proto uint8) time.Duration {
	if pkts == 0 {
		return 0
	}
	// Use a heuristic: TCP sessions ~100ms per packet average,
	// UDP/ICMP ~50ms per packet
	if proto == 6 { // TCP
		return time.Duration(pkts) * 100 * time.Millisecond
	}
	return time.Duration(pkts) * 50 * time.Millisecond
}
