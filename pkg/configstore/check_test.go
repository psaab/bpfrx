package configstore

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// minimal valid day-0 style config: management DHCP plus a zone.
const checkValidConfig = `
system {
    host-name day0-test;
}
interfaces {
    fxp0 {
        unit 0 {
            family inet {
                dhcp;
            }
        }
    }
}
`

func TestCheckTextValid(t *testing.T) {
	cfg, err := CheckText(checkValidConfig, -1)
	if err != nil {
		t.Fatalf("CheckText(valid) = %v, want nil", err)
	}
	if cfg == nil || cfg.System.HostName != "day0-test" {
		t.Fatalf("CheckText(valid) compiled config missing host-name: %+v", cfg)
	}
}

func TestCheckTextParseError(t *testing.T) {
	if _, err := CheckText("system { host-name {{{", -1); err == nil {
		t.Fatal("CheckText(garbage) = nil, want parse error")
	} else if !strings.Contains(err.Error(), "parse error") {
		t.Fatalf("CheckText(garbage) = %v, want parse error", err)
	}
}

// The strict gate must reject what a real commit rejects: the retired
// eBPF dataplane is a compile-time hard reject (#1373/#1476).
func TestCheckTextRetiredDataplaneRejected(t *testing.T) {
	conf := checkValidConfig + `
system {
    dataplane-type ebpf;
}
`
	_, err := CheckText(conf, -1)
	if err == nil {
		t.Fatal("CheckText(dataplane-type ebpf) = nil, want retired-dataplane reject")
	}
	if !errors.Is(err, config.ErrEBPFDataplaneRetired) {
		t.Fatalf("CheckText(dataplane-type ebpf) = %v, want ErrEBPFDataplaneRetired", err)
	}
}

// Typed-leaf SchemaValidate gate must fire exactly as it does on the
// operator commit path (#1319).
func TestCheckTextSchemaValidateGate(t *testing.T) {
	conf := checkValidConfig + `
chassis {
    cluster {
        reth-advertise-interval garbage;
    }
}
`
	if _, err := CheckText(conf, -1); err == nil {
		t.Fatal("CheckText(typed-leaf garbage) = nil, want schema validation error")
	}
}

// ${node} apply-groups must expand for an explicit cluster node ID the
// same way Store.Commit does with SetNodeID.
func TestCheckTextNodeExpansion(t *testing.T) {
	conf := `
groups {
    node0 {
        system {
            host-name fw0;
        }
    }
    node1 {
        system {
            host-name fw1;
        }
    }
}
apply-groups "${node}";
` + checkValidConfig

	for _, nodeID := range []int{0, 1} {
		cfg, err := CheckText(conf, nodeID)
		if err != nil {
			t.Fatalf("CheckText(node %d) = %v, want nil", nodeID, err)
		}
		if cfg == nil {
			t.Fatalf("CheckText(node %d) returned nil config", nodeID)
		}
	}

	// Standalone (-1) keeps the historical "${node} → node0" fallback in
	// schemaValidateExpandedTreeForNode — must not hard-fail.
	if _, err := CheckText(conf, -1); err != nil {
		t.Fatalf("CheckText(standalone with ${node} groups) = %v, want nil", err)
	}
}
