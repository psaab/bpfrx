package flowexport

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestBuildExportConfig_InlineJflowSourceAddress(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						InlineJflow:              true,
						InlineJflowSourceAddress: "10.0.1.10",
					},
				},
			},
		},
	}

	ec := BuildExportConfig(nil, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if len(ec.Collectors) != 1 {
		t.Fatalf("expected 1 collector, got %d", len(ec.Collectors))
	}
	if ec.Collectors[0].SourceAddress != "10.0.1.10" {
		t.Errorf("SourceAddress = %q, want %q", ec.Collectors[0].SourceAddress, "10.0.1.10")
	}
}

func TestBuildSamplingZones(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust": {
					Interfaces: []string{"eth0.0"},
				},
				"untrust": {
					Interfaces: []string{"eth1.0"},
				},
				"dmz": {
					Interfaces: []string{"eth2.0"},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"eth0": {
					Units: map[int]*config.InterfaceUnit{
						0: {SamplingInput: true, SamplingOutput: true},
					},
				},
				"eth1": {
					Units: map[int]*config.InterfaceUnit{
						0: {SamplingInput: true},
					},
				},
				"eth2": {
					Units: map[int]*config.InterfaceUnit{
						0: {}, // no sampling
					},
				},
			},
		},
	}

	// Deterministic zone IDs: dmz=1, trust=2, untrust=3 (sorted)
	zoneIDs := map[string]uint16{"dmz": 1, "trust": 2, "untrust": 3}
	sz := BuildSamplingZones(cfg, zoneIDs)

	// trust (id=2) should have both input and output
	if d, ok := sz[2]; !ok || !d.Input || !d.Output {
		t.Errorf("trust zone: got %+v, want Input=true Output=true", sz[2])
	}
	// untrust (id=3) should have input only
	if d, ok := sz[3]; !ok || !d.Input || d.Output {
		t.Errorf("untrust zone: got %+v, want Input=true Output=false", sz[3])
	}
	// dmz (id=1) should not be in the map (no sampling)
	if _, ok := sz[1]; ok {
		t.Errorf("dmz zone should not have sampling, got %+v", sz[1])
	}
}

func TestShouldExport(t *testing.T) {
	ec := &ExportConfig{
		SamplingZones: map[uint16]SamplingDir{
			2: {Input: true, Output: true},  // trust
			3: {Input: true, Output: false},  // untrust
		},
	}

	// Ingress zone has sampling input -> export
	if !ec.ShouldExport(2, 1) {
		t.Error("should export when ingress zone has sampling input")
	}
	// Egress zone has sampling output -> export
	if !ec.ShouldExport(1, 2) {
		t.Error("should export when egress zone has sampling output")
	}
	// Ingress zone=untrust (input only), egress zone=dmz (no sampling) -> export
	if !ec.ShouldExport(3, 1) {
		t.Error("should export when ingress zone has sampling input")
	}
	// Ingress zone=dmz (no sampling), egress zone=untrust (no output) -> skip
	if ec.ShouldExport(1, 3) {
		t.Error("should not export when neither zone has matching sampling")
	}
	// No sampling zones configured -> export all
	ecNone := &ExportConfig{}
	if !ecNone.ShouldExport(1, 2) {
		t.Error("should export all when no sampling zones configured")
	}
}

func TestParseIfaceRef(t *testing.T) {
	tests := []struct {
		ref      string
		wantName string
		wantUnit int
	}{
		{"eth0.0", "eth0", 0},
		{"trust0.5", "trust0", 5},
		{"enp6s0", "enp6s0", 0},
		{"ge-0/0/0.100", "ge-0/0/0", 100},
	}
	for _, tt := range tests {
		name, unit := parseIfaceRef(tt.ref)
		if name != tt.wantName || unit != tt.wantUnit {
			t.Errorf("parseIfaceRef(%q) = (%q, %d), want (%q, %d)",
				tt.ref, name, unit, tt.wantName, tt.wantUnit)
		}
	}
}

func TestBuildExportConfig_FlowServerSourceAddressTakesPrecedence(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress:            "10.0.1.20",
						InlineJflow:              true,
						InlineJflowSourceAddress: "10.0.1.10",
					},
				},
			},
		},
	}

	ec := BuildExportConfig(nil, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if ec.Collectors[0].SourceAddress != "10.0.1.20" {
		t.Errorf("SourceAddress = %q, want flow-server source-address %q", ec.Collectors[0].SourceAddress, "10.0.1.20")
	}
}
