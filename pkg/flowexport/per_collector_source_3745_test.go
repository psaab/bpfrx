package flowexport

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildExportConfig_PerCollectorSourceAddress is the #3745
// fix-confirming RED-on-revert test at the flowexport resolver level: two
// flow-servers of the SAME family, each carrying its own per-collector
// FlowServer.SourceAddress, must each dial with its OWN configured source
// bind. Before #3745 the compiler collapsed the two nested sources into
// one family-wide SamplingFamily.SourceAddress (last-writer-wins) and the
// resolver applied that single value to every collector, so both
// collectors bound the same (last) source — a wrong / failed dial for the
// first collector.
//
// RED-on-revert: reverting collectInstanceVersionCollectors to
// `srcAddr := fam.SourceAddress` (ignoring fs.SourceAddress) makes both
// collectors carry the same source (empty here, since the per-collector
// values live only on the FlowServer) and this test fails.
func TestBuildExportConfig_PerCollectorSourceAddress(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.100", Port: 2055, SourceAddress: "10.0.0.2"},
							{Address: "10.0.0.200", Port: 2055, SourceAddress: "10.0.0.3"},
						},
					},
				},
			},
		},
	}

	ec := BuildExportConfig(v9Svc(), fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if len(ec.Collectors) != 2 {
		t.Fatalf("expected 2 collectors, got %d: %+v", len(ec.Collectors), ec.Collectors)
	}
	// Index the resolved collectors by destination so the assertion is
	// order-independent.
	got := map[string]string{}
	for _, c := range ec.Collectors {
		got[c.Address] = c.SourceAddress
	}
	if got["10.0.0.100:2055"] != "10.0.0.2" {
		t.Errorf("collector 10.0.0.100 source = %q, want 10.0.0.2 (collapsed to family LWW before #3745)", got["10.0.0.100:2055"])
	}
	if got["10.0.0.200:2055"] != "10.0.0.3" {
		t.Errorf("collector 10.0.0.200 source = %q, want 10.0.0.3 (collapsed to family LWW before #3745)", got["10.0.0.200:2055"])
	}
}

// TestBuildExportConfig_PerCollectorSourceOverridesFamilyDefault confirms
// the precedence in the resolver: a per-collector FlowServer.SourceAddress
// overrides the family output-level default, while a flow-server WITHOUT a
// nested source inherits the family default (#3745). This proves the
// default (no per-collector source) path is unchanged.
func TestBuildExportConfig_PerCollectorSourceOverridesFamilyDefault(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						// Family output-level default bind.
						SourceAddress: "10.0.0.1",
						FlowServers: []*config.FlowServer{
							// Overrides the family default.
							{Address: "10.0.0.100", Port: 2055, SourceAddress: "10.0.0.9"},
							// No nested source -> inherits the family default.
							{Address: "10.0.0.200", Port: 2055},
						},
					},
				},
			},
		},
	}

	ec := BuildExportConfig(v9Svc(), fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	got := map[string]string{}
	for _, c := range ec.Collectors {
		got[c.Address] = c.SourceAddress
	}
	if got["10.0.0.100:2055"] != "10.0.0.9" {
		t.Errorf("overriding collector source = %q, want 10.0.0.9", got["10.0.0.100:2055"])
	}
	if got["10.0.0.200:2055"] != "10.0.0.1" {
		t.Errorf("inheriting collector source = %q, want family default 10.0.0.1", got["10.0.0.200:2055"])
	}
}

// TestCollectorHealth_ExposesSourceAddress proves the per-collector source
// bind is surfaced in the write-health snapshot (#3745): dialCollectors
// records each connection's source bind and health() returns it in
// CollectorHealth.SourceAddress, so the CLI / REST / Prometheus surfaces
// can identify which source-bound connection failed.
//
// RED-on-revert: dropping the srcAddr plumbing (collectorConn.srcAddr or
// the CollectorHealth.SourceAddress assignment in health()) makes the
// returned SourceAddress empty and this test fails.
func TestCollectorHealth_ExposesSourceAddress(t *testing.T) {
	// dialCollectors dials real UDP sockets; a source bind to a loopback
	// address the kernel owns resolves and dials without any collector
	// being up (UDP connect does not handshake).
	cc, err := dialCollectors([]CollectorConfig{
		{Address: "127.0.0.1:2055", SourceAddress: "127.0.0.1"},
		{Address: "127.0.0.1:2056"}, // no source -> OS-selected
	})
	if err != nil {
		t.Fatalf("dialCollectors: %v", err)
	}
	defer cc.close()

	h := cc.health()
	if len(h) != 2 {
		t.Fatalf("expected 2 health entries, got %d", len(h))
	}
	got := map[string]string{}
	for _, e := range h {
		got[e.Address] = e.SourceAddress
	}
	if got["127.0.0.1:2055"] != "127.0.0.1" {
		t.Errorf("source-bound collector health source = %q, want 127.0.0.1", got["127.0.0.1:2055"])
	}
	if got["127.0.0.1:2056"] != "" {
		t.Errorf("auto-source collector health source = %q, want empty", got["127.0.0.1:2056"])
	}
}
