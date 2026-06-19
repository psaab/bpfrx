// Package flowexport implements NetFlow v9 and IPFIX (NetFlow v10) flow
// data export. Session-close events are turned into flow records and
// shipped to remote collectors over UDP, with per-zone direction
// filtering and 1-in-N session sampling.
//
// The package is split by responsibility:
//   - manager.go   — resolved export config, sampling scheduler, the
//     shared FlowRecord shape, and the BuildExportConfig family of
//     config resolvers.
//   - netflow.go   — NetFlow v9 template/record encoding and the
//     Exporter that drives it.
//   - ipfix.go     — IPFIX (v10) template/record encoding and the
//     IPFIXExporter that drives it.
//   - transport.go — collector connection management and per-family
//     batch accumulation shared by both exporters.
package flowexport

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
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
	V9TemplateOpts      V9TemplateOptions      // optional v9 template field control
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

	var v9opts V9TemplateOptions
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
			for _, ext := range tmpl.ExportExtensions {
				switch ext {
				case "flow-dir":
					v9opts.IncludeFlowDir = true
				}
			}
			break // use first template
		}
	}

	ec := &ExportConfig{
		FlowActiveTimeout:   activeTimeout,
		FlowInactiveTimeout: inactiveTimeout,
		TemplateRefreshRate: refreshRate,
		V9TemplateOpts:      v9opts,
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
		key := collectorKey(c)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, c)
		}
	}
	ec.Collectors = deduped

	return ec
}

// BuildIPFIXExportConfig resolves IPFIX config into an ExportConfig.
// Falls back to v9 collectors/sampling if no IPFIX-specific overrides.
func BuildIPFIXExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig {
	if fo == nil || fo.Sampling == nil || len(fo.Sampling.Instances) == 0 {
		return nil
	}
	if svc == nil || svc.FlowMonitoring == nil || svc.FlowMonitoring.VersionIPFIX == nil {
		return nil
	}

	activeTimeout := 60 * time.Second
	inactiveTimeout := 15 * time.Second
	refreshRate := 60 * time.Second

	for _, tmpl := range svc.FlowMonitoring.VersionIPFIX.Templates {
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

	ec := &ExportConfig{
		FlowActiveTimeout:   activeTimeout,
		FlowInactiveTimeout: inactiveTimeout,
		TemplateRefreshRate: refreshRate,
	}

	// Reuse same sampling rate + collectors as v9 (shared forwarding-options)
	for _, inst := range fo.Sampling.Instances {
		if inst.InputRate > 0 {
			ec.SamplingRate = inst.InputRate
			break
		}
	}

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

	// Deduplicate collectors
	seen := make(map[string]bool)
	deduped := ec.Collectors[:0]
	for _, c := range ec.Collectors {
		key := collectorKey(c)
		if !seen[key] {
			seen[key] = true
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

// FlowRecord holds the data for a single flow, shared by the NetFlow v9
// and IPFIX encoders.
type FlowRecord struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	TOS       uint8
	TCPFlags  uint8
	Direction uint8
	InIf      uint32
	OutIf     uint32
	Packets   uint64
	Bytes     uint64
	StartTime time.Time
	EndTime   time.Time
	SrcMask   uint8
	DstMask   uint8
	IsIPv6    bool
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

func collectorKey(c CollectorConfig) string {
	return c.Address + "\x00" + c.SourceAddress
}
