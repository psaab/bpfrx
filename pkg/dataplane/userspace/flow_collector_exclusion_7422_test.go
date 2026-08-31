package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6565 row 11 / #7422 — the builder half of the shared flow-collector verdict.
//
// The show surfaces annotate a flow-server with config.FlowServerExcludedReason.
// That annotation is only honest if the builder REALLY skips exactly what the
// predicate excludes and REALLY installs everything else; a builder that
// quietly started installing port-0 collectors would leave the CLI cells green
// while the annotation cried wolf on a working export.
//
// TestBuildFlowExportSnapshotCoercesOutOfRange_1977 already pins the ±range
// ends. This cell adds the port-0 "absent" sentinel — the shape #7422 is about,
// and the one that used to `continue` SILENTLY, with no journal record at all —
// and asserts the two halves agree across the whole boundary.
func TestFlowExportBuilderAgreesWithTheSharedExclusionPredicate7422(t *testing.T) {
	mk := func(port int) *config.Config {
		cfg := &config.Config{}
		cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"t1": {Name: "t1"},
				},
			},
		}
		cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"i1": {Name: "i1", InputRate: 100, FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: "10.0.0.1", Port: port, Version9Template: "t1"},
					},
				}},
			},
		}
		return cfg
	}

	// Both edges of the UDP range plus the sentinel and the two out-of-range
	// directions. 1 and 65535 are the cells an off-by-one in either half would
	// red; 0 is the #7422 shape.
	for _, port := range []int{-2, -1, 0, 1, 2, 2055, 65534, 65535, 65536, 70000} {
		fs := &config.FlowServer{Address: "10.0.0.1", Port: port}
		excluded := config.FlowServerExcludedReason(fs) != ""
		snap := buildFlowExportSnapshot(mk(port))
		installed := snap != nil
		if installed == excluded {
			t.Errorf("port %d: predicate says excluded=%v but the builder %s it. "+
				"The show surfaces render the PREDICATE's verdict, so the two "+
				"disagreeing means `show forwarding-options` is once again "+
				"describing a collector state the dataplane does not have.",
				port, excluded, map[bool]string{true: "installed", false: "skipped"}[installed])
			continue
		}
		if installed && snap.CollectorPort != port {
			t.Errorf("port %d installed as CollectorPort %d", port, snap.CollectorPort)
		}
	}

	// Non-vacuity: the loop above would report a clean agreement if the builder
	// returned nil for EVERY port (e.g. the flow-monitoring fixture stopped
	// compiling), because the predicate excludes most of the sample. Pin one
	// positive.
	if snap := buildFlowExportSnapshot(mk(2055)); snap == nil {
		t.Fatal("the fixture no longer produces ANY snapshot; every agreement " +
			"above was between two 'not installed' answers")
	}
}
