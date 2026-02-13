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
