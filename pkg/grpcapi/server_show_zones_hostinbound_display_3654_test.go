package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3654: the gRPC TEXT surfaces (ShowText "zones-detail" and the "test-zone:"
// interface diagnostic) rendered ONLY the zone-level host-inbound set, dropping
// the per-interface override (#3362) and the no-stanza default-deny posture
// (#3405). These golden tests assert both now appear.
//
// RED-on-revert: routing the surfaces back through the old
// `if zone.HostInboundTraffic != nil { ... }` block drops the override block
// and the "default deny" posture line, failing the matching assertions.

func hostInboundGRPCServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                system-services { ssh; ping; }
                protocols { ospf; }
            }
        }
        security-zone edge {
            interfaces {
                ge-0/0/9.0 {
                    host-inbound-traffic { system-services { https; } }
                }
            }
        }
        security-zone plain {
            interfaces {
                ge-0/0/1.0;
            }
        }
        security-zone open;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store}
}

func TestShowTextZonesDetailHostInbound3654(t *testing.T) {
	s := hostInboundGRPCServer(t)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "zones-detail"})
	if err != nil {
		t.Fatalf("ShowText(zones-detail) error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{
		"Host-inbound system-services: ssh, ping",
		"Host-inbound protocols: ospf",
		"Host-inbound interface overrides:",
		"ge-0/0/9.0:",
		"override system-services: https",
		"effective system-services: https",
		"Host-inbound: default deny (no stanza)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("gRPC text zones-detail missing %q\n%s", want, out)
		}
	}
}

func TestShowTextTestZoneHostInbound3654(t *testing.T) {
	s := hostInboundGRPCServer(t)

	// Overridden interface: flag the override + effective set.
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "test-zone:interface=ge-0/0/9.0"})
	if err != nil {
		t.Fatalf("ShowText(test-zone override) error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{
		"Interface ge-0/0/9.0 belongs to zone: edge",
		"Host-inbound interface override on ge-0/0/9.0:",
		"effective host-inbound services: https",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("gRPC text test-zone (override) missing %q\n%s", want, out)
		}
	}

	// No-stanza zone interface: default-deny posture line.
	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "test-zone:interface=ge-0/0/1.0"})
	if err != nil {
		t.Fatalf("ShowText(test-zone no-stanza) error = %v", err)
	}
	if out := resp.GetOutput(); !strings.Contains(out, "Host-inbound: default deny (no stanza)") {
		t.Errorf("gRPC text test-zone (no-stanza) missing posture line\n%s", out)
	}
}
