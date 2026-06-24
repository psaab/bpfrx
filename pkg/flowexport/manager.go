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
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// SamplingDir tracks per-zone sampling direction flags.
type SamplingDir struct {
	Input  bool
	Output bool
}

// ExportConfig holds the resolved NetFlow export configuration for a
// single template group: the collectors that referenced one template (or
// the default-template collectors that referenced none), the timeouts and
// v9 field options resolved from THAT template, plus the per-instance
// sampling state.
//
// #2461: before this change a single ExportConfig was built per family
// from the FIRST Go-map-iteration template and broadcast to every
// collector, so a per-flow-server template reference was silently ignored
// and the chosen template flipped across restarts. The resolver now emits
// one ExportConfig per referenced template — the group key is
// (instance, version, template_name); source-address is a deterministic
// sort tiebreak, NOT part of the key, so collectors that share a template
// but pin different source-addresses land in ONE group and each still gets
// its own source-pinned UDP connection from dialCollectors (see
// ResolveV9TemplateGroups / ResolveIPFIXTemplateGroups).
//
// #2462: sampling-instance identity is now first-class. Each sampling
// instance resolves to its OWN ExportConfig(s) carrying its OWN InputRate
// and its OWN sampleCounter, so a flow eligible for instance A exports ONLY
// to instance A's collectors at instance A's rate (1-in-N is independent
// per instance) and NEVER crosses to instance B. The template groups of one
// instance share that instance's sampleCounter (pointer below) so 1-in-N
// stays a single cadence across the instance's templates, but two instances
// never share a counter. Attribution to an instance is by address family:
// ServesInet / ServesInet6 record which families the instance configured a
// collector for, and ShouldExportFamily gates a record so an IPv6 flow is
// not exported by an instance that configured only inet collectors. Two
// instances claiming the SAME (version, family) are genuinely ambiguous (no
// per-interface instance selector exists to attribute a flow) and are
// rejected at commit — see validateSamplingInstanceConflictsStrict.
type ExportConfig struct {
	Collectors          []CollectorConfig
	InstanceName        string // sampling instance this config belongs to (#2462)
	TemplateName        string // referenced template ("" = default group)
	FlowActiveTimeout   time.Duration
	FlowInactiveTimeout time.Duration
	TemplateRefreshRate time.Duration
	SamplingZones       map[uint16]SamplingDir // zone ID -> sampling directions
	SamplingRate        int                    // 1-in-N sampling (0 = export all)
	// ServesInet / ServesInet6 record which address families this instance
	// configured a flow-server for (#2462). ShouldExportFamily uses them to
	// attribute a flow to the right instance: an instance with only inet
	// collectors must not export an IPv6 flow. An instance that configured
	// neither (no flow-servers for this version) produces no ExportConfig at
	// all, so both true-everywhere defaults are never observed.
	ServesInet     bool
	ServesInet6    bool
	V9TemplateOpts V9TemplateOptions // optional v9 template field control
	// sampleCounter is the monotonic 1-in-N counter. It is a POINTER so all
	// ExportConfig template groups of one INSTANCE share a single counter
	// (the sampling rate is a per-instance property; #2462). Two different
	// instances each get their own counter. A nil pointer is lazily
	// allocated on first use so a hand-built ExportConfig (tests, the
	// singular Build* helpers) still samples correctly. json.Marshal skips
	// the unexported field, so the reconcile config-hash is unaffected.
	sampleCounter *atomic.Uint64
	counterOnce   sync.Once
}

// CollectorConfig defines a single NetFlow collector destination.
type CollectorConfig struct {
	Address       string // "host:port"
	SourceAddress string // local bind address (empty = auto)
	// Template is the per-flow-server template the collector referenced
	// ("" = none → default group). It is the grouping key for #2461 and is
	// NOT serialized into the dialed connection; it only steers which
	// ExportConfig (template context) the collector is placed under.
	Template string `json:"-"`
}

// resolveFlowServerVersion returns the export protocol a single
// flow-server is bound to, given the per-server selector and which
// global flow-monitoring version stanzas are configured. Junos binds
// each flow-server to exactly one export version + template; xpf
// honours that binding so a collector never receives both a NetFlow v9
// and an IPFIX datagram for the same flow (#2136).
//
// Resolution:
//   - An explicit per-server selector (`version9` / `version-ipfix`
//     nested under the flow-server) wins outright — but only if the
//     matching global `services flow-monitoring` stanza is configured
//     (the global stanza supplies the template timeouts/fields). A
//     server bound to a version whose global stanza is absent exports
//     nothing (it has no template), matching the existing global gates.
//   - With no per-server selector, the server inherits the single
//     configured global version. When BOTH global versions are set the
//     unbound server resolves to IPFIX (documented precedence): IPFIX
//     (v10) is the IETF-standard superset of NetFlow v9, so an operator
//     who turned on both and did not pin the collector gets the modern
//     protocol — and, critically, exactly ONE datagram stream rather
//     than the pre-#2136 double-export.
//
// Returns "" when the server resolves to no configured version (it is
// then skipped by both collector builders).
func resolveFlowServerVersion(fs *config.FlowServer, hasV9, hasIPFIX bool) string {
	switch fs.Version {
	case config.FlowServerVersion9:
		if hasV9 {
			return config.FlowServerVersion9
		}
		return ""
	case config.FlowServerVersionIPFIX:
		if hasIPFIX {
			return config.FlowServerVersionIPFIX
		}
		return ""
	}
	// Unbound: inherit the single configured global version. IPFIX wins
	// when both are configured (documented precedence — see above).
	switch {
	case hasIPFIX:
		return config.FlowServerVersionIPFIX
	case hasV9:
		return config.FlowServerVersion9
	default:
		return ""
	}
}

// collectInstanceVersionCollectors walks ONE sampling instance's
// flow-servers and returns the deduplicated collector set for the requested
// export version, skipping flow-servers resolved to the other version. It
// also reports which address families (inet / inet6) the instance
// configured a collector for under this version, so the caller can scope the
// resulting ExportConfig to those families (#2462 attribution). This is the
// per-flow-server version binding that prevents double-export (#2136): the
// v9 resolver calls it with version=version9, the IPFIX resolver with
// version=version-ipfix, and a server appears in at most one of the two
// sets.
//
// #2462: this is now per-INSTANCE (was a global walk over every instance,
// which merged distinct instances into one collector set — the defect).
func collectInstanceVersionCollectors(inst *config.SamplingInstance, version string, hasV9, hasIPFIX bool) (collectors []CollectorConfig, servesInet, servesInet6 bool) {
	families := []struct {
		fam  *config.SamplingFamily
		isV6 bool
	}{
		{inst.FamilyInet, false},
		{inst.FamilyInet6, true},
	}
	for _, fe := range families {
		fam := fe.fam
		if fam == nil {
			continue
		}
		for _, fs := range fam.FlowServers {
			if resolveFlowServerVersion(fs, hasV9, hasIPFIX) != version {
				continue
			}
			addr := fs.Address
			if fs.Port > 0 {
				// net.JoinHostPort brackets an IPv6 literal
				// ([2001:db8::9]:4739) so net.ResolveUDPAddr /
				// net.Dial in transport.go can parse it. A plain
				// "%s:%d" leaves an IPv6 address unbracketed
				// (2001:db8::9:4739), which they cannot parse, so
				// IPv6 flow collectors never dial (#2183).
				addr = net.JoinHostPort(fs.Address, strconv.Itoa(fs.Port))
			}
			srcAddr := fam.SourceAddress
			if srcAddr == "" {
				srcAddr = fam.InlineJflowSourceAddress
			}
			tmpl := fs.Version9Template
			if version == config.FlowServerVersionIPFIX {
				tmpl = fs.VersionIPFIXTemplate
			}
			collectors = append(collectors, CollectorConfig{
				Address:       addr,
				SourceAddress: srcAddr,
				Template:      tmpl,
			})
			if fe.isV6 {
				servesInet6 = true
			} else {
				servesInet = true
			}
		}
	}
	return dedupeCollectors(collectors), servesInet, servesInet6
}

// dedupeCollectors removes duplicate collector destinations (same
// address + source-address + referenced template — see collectorKey)
// in-place, preserving first-seen order. This is the dedup key, NOT the
// grouping key: grouping is by template name alone (groupCollectorsByTemplate).
func dedupeCollectors(collectors []CollectorConfig) []CollectorConfig {
	seen := make(map[string]bool)
	deduped := collectors[:0]
	for _, c := range collectors {
		key := collectorKey(c)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, c)
		}
	}
	return deduped
}

// templateContext is the resolved per-template export parameters (the
// timeouts and the v9 field options) carried into every ExportConfig built
// for the collectors that referenced that template. #2461.
type templateContext struct {
	activeTimeout   time.Duration
	inactiveTimeout time.Duration
	refreshRate     time.Duration
	v9opts          V9TemplateOptions
}

// defaultTemplateContext is the timeout/refresh fallback used for a
// collector that referenced no template and when a referenced template
// name has no matching definition that overrides a field.
func defaultTemplateContext() templateContext {
	return templateContext{
		activeTimeout:   60 * time.Second,
		inactiveTimeout: 15 * time.Second,
		refreshRate:     60 * time.Second,
	}
}

// v9TemplateContext resolves one NetFlow v9 template definition into a
// templateContext. A zero/absent field keeps the default.
func v9TemplateContext(tmpl *config.NetFlowV9Template) templateContext {
	tc := defaultTemplateContext()
	if tmpl == nil {
		return tc
	}
	if tmpl.FlowActiveTimeout > 0 {
		tc.activeTimeout = time.Duration(tmpl.FlowActiveTimeout) * time.Second
	}
	if tmpl.FlowInactiveTimeout > 0 {
		tc.inactiveTimeout = time.Duration(tmpl.FlowInactiveTimeout) * time.Second
	}
	if tmpl.TemplateRefreshRate > 0 {
		tc.refreshRate = time.Duration(tmpl.TemplateRefreshRate) * time.Second
	}
	for _, ext := range tmpl.ExportExtensions {
		if ext == "flow-dir" {
			tc.v9opts.IncludeFlowDir = true
		}
	}
	return tc
}

// ipfixTemplateContext resolves one IPFIX template definition into a
// templateContext (IPFIX has no v9 field options).
func ipfixTemplateContext(tmpl *config.NetFlowIPFIXTemplate) templateContext {
	tc := defaultTemplateContext()
	if tmpl == nil {
		return tc
	}
	if tmpl.FlowActiveTimeout > 0 {
		tc.activeTimeout = time.Duration(tmpl.FlowActiveTimeout) * time.Second
	}
	if tmpl.FlowInactiveTimeout > 0 {
		tc.inactiveTimeout = time.Duration(tmpl.FlowInactiveTimeout) * time.Second
	}
	if tmpl.TemplateRefreshRate > 0 {
		tc.refreshRate = time.Duration(tmpl.TemplateRefreshRate) * time.Second
	}
	return tc
}

// sortedInstanceNames returns the sampling-instance names in deterministic
// (lexical) order so the resolved exporter wiring is restart-stable (#2462).
// Killing the Go-map-iteration order is half of the determinism fix; the
// other half is per-instance rate selection (no more first-nonzero
// map-order-dependent global rate).
func sortedInstanceNames(fo *config.ForwardingOptionsConfig) []string {
	names := make([]string, 0, len(fo.Sampling.Instances))
	for name := range fo.Sampling.Instances {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// groupCollectorsByTemplate partitions the deduplicated collector list into
// one slice per referenced template name, returning the group keys sorted
// deterministically. The empty-string key holds collectors that referenced
// no template (the default group). Determinism (#2461): the group order and
// the per-group collector order are stable across process restarts, killing
// the Go-map-iteration nondeterminism that let a collector silently flip
// between templates.
func groupCollectorsByTemplate(collectors []CollectorConfig) ([]string, map[string][]CollectorConfig) {
	groups := make(map[string][]CollectorConfig)
	for _, c := range collectors {
		groups[c.Template] = append(groups[c.Template], c)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cs := groups[k]
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].Address != cs[j].Address {
				return cs[i].Address < cs[j].Address
			}
			return cs[i].SourceAddress < cs[j].SourceAddress
		})
		groups[k] = cs
	}
	return keys, groups
}

// ResolveV9TemplateGroups resolves the NetFlow v9 export configuration into
// one ExportConfig per referenced template (#2461). Each group carries the
// timeouts / field options of the template its collectors actually
// referenced, instead of broadcasting the first map-iteration template to
// every collector. A collector referencing no template lands in the default
// group, which uses the lone configured template's parameters when there is
// exactly one (the common single-template case, unchanged behavior), else
// the built-in defaults. A collector referencing a template that is not
// defined is DROPPED (the strict commit-time gate
// validateFlowServerTemplateReferencesStrict rejects it on commit; this is
// the lenient-load backstop — export nothing for that collector rather than
// the wrong template). All groups share one sampleCounter so 1-in-N
// sampling stays global. Returns nil when no v9 export is configured.
func ResolveV9TemplateGroups(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) []*ExportConfig {
	if fo == nil || fo.Sampling == nil || len(fo.Sampling.Instances) == 0 {
		return nil
	}
	// #2129: a NetFlow v9 exporter must only start when `services
	// flow-monitoring version9` is configured.
	if svc == nil || svc.FlowMonitoring == nil || svc.FlowMonitoring.Version9 == nil {
		return nil
	}

	hasIPFIX := svc.FlowMonitoring.VersionIPFIX != nil
	defined := svc.FlowMonitoring.Version9.Templates
	// defaultCtx: when exactly one template is defined, an unreferenced
	// collector inherits it (preserves the pre-#2461 single-template case);
	// with zero or multiple templates it uses the built-in defaults.
	defaultCtx := defaultTemplateContext()
	if len(defined) == 1 {
		for _, tmpl := range defined {
			defaultCtx = v9TemplateContext(tmpl)
		}
	}

	var out []*ExportConfig
	// #2462: iterate instances in deterministic order; each instance is an
	// independent export policy (own collectors, own rate, own counter).
	for _, instName := range sortedInstanceNames(fo) {
		inst := fo.Sampling.Instances[instName]
		if inst == nil {
			continue
		}
		// #2136 per-flow-server version binding: collect only THIS instance's
		// flow-servers bound to NetFlow v9.
		collectors, servesInet, servesInet6 := collectInstanceVersionCollectors(inst, config.FlowServerVersion9, true, hasIPFIX)
		if len(collectors) == 0 {
			continue
		}
		rate := inst.InputRate
		shared := &atomic.Uint64{} // per-INSTANCE counter (#2462)
		keys, groups := groupCollectorsByTemplate(collectors)
		for _, name := range keys {
			ctx := defaultCtx
			if name != "" {
				tmpl, ok := defined[name]
				if !ok {
					// Undefined reference: drop (the strict gate rejects on
					// commit; lenient load exports nothing for these collectors).
					continue
				}
				ctx = v9TemplateContext(tmpl)
			}
			out = append(out, &ExportConfig{
				Collectors:          groups[name],
				InstanceName:        instName,
				TemplateName:        name,
				FlowActiveTimeout:   ctx.activeTimeout,
				FlowInactiveTimeout: ctx.inactiveTimeout,
				TemplateRefreshRate: ctx.refreshRate,
				V9TemplateOpts:      ctx.v9opts,
				SamplingRate:        rate,
				ServesInet:          servesInet,
				ServesInet6:         servesInet6,
				sampleCounter:       shared,
			})
		}
	}
	return out
}

// ResolveIPFIXTemplateGroups is the IPFIX equivalent of
// ResolveV9TemplateGroups (#2461). Returns nil when no IPFIX export is
// configured.
func ResolveIPFIXTemplateGroups(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) []*ExportConfig {
	if fo == nil || fo.Sampling == nil || len(fo.Sampling.Instances) == 0 {
		return nil
	}
	if svc == nil || svc.FlowMonitoring == nil || svc.FlowMonitoring.VersionIPFIX == nil {
		return nil
	}

	hasV9 := svc.FlowMonitoring.Version9 != nil
	defined := svc.FlowMonitoring.VersionIPFIX.Templates
	defaultCtx := defaultTemplateContext()
	if len(defined) == 1 {
		for _, tmpl := range defined {
			defaultCtx = ipfixTemplateContext(tmpl)
		}
	}

	var out []*ExportConfig
	for _, instName := range sortedInstanceNames(fo) {
		inst := fo.Sampling.Instances[instName]
		if inst == nil {
			continue
		}
		collectors, servesInet, servesInet6 := collectInstanceVersionCollectors(inst, config.FlowServerVersionIPFIX, hasV9, true)
		if len(collectors) == 0 {
			continue
		}
		rate := inst.InputRate
		shared := &atomic.Uint64{} // per-INSTANCE counter (#2462)
		keys, groups := groupCollectorsByTemplate(collectors)
		for _, name := range keys {
			ctx := defaultCtx
			if name != "" {
				tmpl, ok := defined[name]
				if !ok {
					continue
				}
				ctx = ipfixTemplateContext(tmpl)
			}
			out = append(out, &ExportConfig{
				Collectors:          groups[name],
				InstanceName:        instName,
				TemplateName:        name,
				FlowActiveTimeout:   ctx.activeTimeout,
				FlowInactiveTimeout: ctx.inactiveTimeout,
				TemplateRefreshRate: ctx.refreshRate,
				SamplingRate:        rate,
				ServesInet:          servesInet,
				ServesInet6:         servesInet6,
				sampleCounter:       shared,
			})
		}
	}
	return out
}

// BuildExportConfig resolves config types into a single NetFlow v9
// ExportConfig. It returns the FIRST template group (deterministically the
// default/empty-template group, else the lowest template name) and is
// retained for callers that want a single aggregate config; the daemon uses
// ResolveV9TemplateGroups so each collector gets its referenced template
// (#2461). Returns nil if no flow export is configured.
func BuildExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig {
	groups := ResolveV9TemplateGroups(svc, fo)
	if len(groups) == 0 {
		return nil
	}
	return groups[0]
}

// BuildIPFIXExportConfig is the IPFIX equivalent of BuildExportConfig.
func BuildIPFIXExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig {
	groups := ResolveIPFIXTemplateGroups(svc, fo)
	if len(groups) == 0 {
		return nil
	}
	return groups[0]
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
		n := ec.counter().Add(1)
		return n%uint64(ec.SamplingRate) == 0
	}
	return true
}

// ServesFamily reports whether this instance's ExportConfig should handle a
// flow of the given address family (#2462). An instance that configured only
// inet collectors must not export an IPv6 flow (and vice versa) — that is the
// control-plane attribution that keeps two family-disjoint instances
// isolated. An ExportConfig is only ever built for a version the instance has
// at least one collector for, so at least one of ServesInet / ServesInet6 is
// always true here.
func (ec *ExportConfig) ServesFamily(isIPv6 bool) bool {
	if isIPv6 {
		return ec.ServesInet6
	}
	return ec.ServesInet
}

// counter returns the shared 1-in-N counter, lazily allocating a private
// one for a hand-built ExportConfig that the resolver did not wire. The
// sync.Once converges a concurrent first-call race on a single counter.
func (ec *ExportConfig) counter() *atomic.Uint64 {
	ec.counterOnce.Do(func() {
		if ec.sampleCounter == nil {
			ec.sampleCounter = &atomic.Uint64{}
		}
	})
	return ec.sampleCounter
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
	return c.Address + "\x00" + c.SourceAddress + "\x00" + c.Template
}
