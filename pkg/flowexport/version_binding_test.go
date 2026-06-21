package flowexport

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2136 — per-flow-server export-version binding.
//
// Before #2136 BuildExportConfig (v9) and BuildIPFIXExportConfig (ipfix)
// each flattened ALL flow-servers into their own collector set, so a
// flow-server reachable under both global version stanzas received every
// flow twice — one NetFlow v9 datagram and one IPFIX datagram to the same
// socket. These tests assert each flow-server now binds to exactly one
// export version, so a given collector appears in at most one builder's
// collector set. The "both versions" cases FAIL on the pre-#2136 code
// (the v9 builder returned the collector that the IPFIX builder also
// returned -> two streams to one collector).

func bothSvc() *config.ServicesConfig {
	return &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{"t": {Name: "t"}},
			},
			VersionIPFIX: &config.NetFlowIPFIXConfig{
				Templates: map[string]*config.NetFlowIPFIXTemplate{"t": {Name: "t"}},
			},
		},
	}
}

func ipfixSvc() *config.ServicesConfig {
	return &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			VersionIPFIX: &config.NetFlowIPFIXConfig{
				Templates: map[string]*config.NetFlowIPFIXTemplate{"t": {Name: "t"}},
			},
		},
	}
}

func samplingFO(servers ...*config.FlowServer) *config.ForwardingOptionsConfig {
	return &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"s": {
					Name:       "s",
					InputRate:  100,
					FamilyInet: &config.SamplingFamily{FlowServers: servers},
				},
			},
		},
	}
}

func collectorAddrs(ec *ExportConfig) []string {
	if ec == nil {
		return nil
	}
	out := make([]string, 0, len(ec.Collectors))
	for _, c := range ec.Collectors {
		out = append(out, c.Address)
	}
	return out
}

// TestBindingV9Only: a v9-only global stanza routes every flow-server to
// the v9 exporter and starts no IPFIX exporter.
func TestBindingV9Only(t *testing.T) {
	fo := samplingFO(&config.FlowServer{Address: "10.0.0.1", Port: 2055})

	v9 := BuildExportConfig(v9Svc(), fo)
	if v9 == nil || len(v9.Collectors) != 1 {
		t.Fatalf("v9-only: want exactly 1 v9 collector, got %v", collectorAddrs(v9))
	}
	if v9.Collectors[0].Address != "10.0.0.1:2055" {
		t.Errorf("v9 collector = %q, want 10.0.0.1:2055", v9.Collectors[0].Address)
	}

	if ipfix := BuildIPFIXExportConfig(v9Svc(), fo); ipfix != nil {
		t.Errorf("v9-only must start no IPFIX exporter, got %v", collectorAddrs(ipfix))
	}
}

// TestBindingIPFIXOnly: an ipfix-only global stanza routes every
// flow-server to the IPFIX exporter and starts no v9 exporter.
func TestBindingIPFIXOnly(t *testing.T) {
	fo := samplingFO(&config.FlowServer{Address: "10.0.0.1", Port: 2055})

	ipfix := BuildIPFIXExportConfig(ipfixSvc(), fo)
	if ipfix == nil || len(ipfix.Collectors) != 1 {
		t.Fatalf("ipfix-only: want exactly 1 ipfix collector, got %v", collectorAddrs(ipfix))
	}
	if v9 := BuildExportConfig(ipfixSvc(), fo); v9 != nil {
		t.Errorf("ipfix-only must start no v9 exporter, got %v", collectorAddrs(v9))
	}
}

// TestBindingBothVersionsUnboundServerGoesToIPFIXOnly is the headline
// #2136 regression: a SINGLE flow-server with NO per-server selector,
// under BOTH global version stanzas, must export exactly ONCE — to IPFIX
// (the documented precedence) — NOT twice. On the pre-#2136 code the v9
// builder ALSO returned this collector, so it received both a v9 and an
// IPFIX datagram (double-export). This test fails on that code.
func TestBindingBothVersionsUnboundServerGoesToIPFIXOnly(t *testing.T) {
	fo := samplingFO(&config.FlowServer{Address: "10.0.0.1", Port: 2055})

	v9 := BuildExportConfig(bothSvc(), fo)
	ipfix := BuildIPFIXExportConfig(bothSvc(), fo)

	// Exactly one collector total across both exporters — no double-export.
	if v9 != nil {
		t.Errorf("#2136: an unbound server under both versions must NOT also "+
			"export v9 (double-export); v9 collectors = %v", collectorAddrs(v9))
	}
	if ipfix == nil || len(ipfix.Collectors) != 1 {
		t.Fatalf("#2136: unbound server under both versions must export once "+
			"via IPFIX, got ipfix=%v", collectorAddrs(ipfix))
	}
	if ipfix.Collectors[0].Address != "10.0.0.1:2055" {
		t.Errorf("ipfix collector = %q, want 10.0.0.1:2055", ipfix.Collectors[0].Address)
	}
}

// TestBindingExplicitPerServerSplit: two flow-servers, one pinned to v9
// and one pinned to IPFIX, each appear in exactly one builder's set even
// though both global version stanzas are configured.
func TestBindingExplicitPerServerSplit(t *testing.T) {
	fo := samplingFO(
		&config.FlowServer{Address: "10.0.0.1", Port: 2055, Version: config.FlowServerVersion9},
		&config.FlowServer{Address: "10.0.0.2", Port: 4739, Version: config.FlowServerVersionIPFIX},
	)

	v9 := BuildExportConfig(bothSvc(), fo)
	ipfix := BuildIPFIXExportConfig(bothSvc(), fo)

	if v9 == nil || len(v9.Collectors) != 1 || v9.Collectors[0].Address != "10.0.0.1:2055" {
		t.Fatalf("v9 must hold only the v9-bound server, got %v", collectorAddrs(v9))
	}
	if ipfix == nil || len(ipfix.Collectors) != 1 || ipfix.Collectors[0].Address != "10.0.0.2:4739" {
		t.Fatalf("ipfix must hold only the ipfix-bound server, got %v", collectorAddrs(ipfix))
	}
}

// TestBindingSameCollectorPinnedToOneVersion: the exact #2136 harm — ONE
// collector address:port, configured under both global versions, pinned
// to v9. It must receive v9 only, never IPFIX. (Pinning to IPFIX is the
// symmetric case.)
func TestBindingSameCollectorPinnedToOneVersion(t *testing.T) {
	foV9 := samplingFO(&config.FlowServer{
		Address: "10.0.0.1", Port: 2055, Version: config.FlowServerVersion9,
	})
	if v9 := BuildExportConfig(bothSvc(), foV9); v9 == nil || len(v9.Collectors) != 1 {
		t.Fatalf("v9-pinned server must export v9, got %v", collectorAddrs(v9))
	}
	if ipfix := BuildIPFIXExportConfig(bothSvc(), foV9); ipfix != nil {
		t.Errorf("#2136: a v9-pinned collector must NOT also receive IPFIX, got %v",
			collectorAddrs(ipfix))
	}

	foIPFIX := samplingFO(&config.FlowServer{
		Address: "10.0.0.1", Port: 2055, Version: config.FlowServerVersionIPFIX,
	})
	if ipfix := BuildIPFIXExportConfig(bothSvc(), foIPFIX); ipfix == nil || len(ipfix.Collectors) != 1 {
		t.Fatalf("ipfix-pinned server must export ipfix, got %v", collectorAddrs(ipfix))
	}
	if v9 := BuildExportConfig(bothSvc(), foIPFIX); v9 != nil {
		t.Errorf("#2136: an ipfix-pinned collector must NOT also receive v9, got %v",
			collectorAddrs(v9))
	}
}

// TestBindingPinnedToVersionWithoutGlobalStanza: a server pinned to a
// version whose global flow-monitoring stanza is absent exports nothing
// (it has no template) — and does NOT silently fall back to the other
// version. Mirrors the existing global gates.
func TestBindingPinnedToVersionWithoutGlobalStanza(t *testing.T) {
	// Server pinned to IPFIX, but only the v9 global stanza exists.
	fo := samplingFO(&config.FlowServer{
		Address: "10.0.0.1", Port: 2055, Version: config.FlowServerVersionIPFIX,
	})
	if v9 := BuildExportConfig(v9Svc(), fo); v9 != nil {
		t.Errorf("an ipfix-pinned server must NOT fall back to v9, got %v",
			collectorAddrs(v9))
	}
	if ipfix := BuildIPFIXExportConfig(v9Svc(), fo); ipfix != nil {
		t.Errorf("ipfix not globally configured: no ipfix exporter, got %v",
			collectorAddrs(ipfix))
	}
}
