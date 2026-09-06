package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3654 (H09/M03/M06): the remote `cmd/cli show security zones` collapsed the
// structured host-inbound admission set into one legacy "Host-inbound services"
// line, dropping the service-vs-protocol split, the per-interface overrides
// (interface_host_inbound), and the no-stanza default-deny posture. It now
// consumes the split fields + overrides from the gRPC response and renders them
// through the shared presenter.
//
// RED-on-revert: restoring the single `Host-inbound services` line (reading
// only z.HostInboundServices) fails the split-field, override-block, and
// posture-line assertions below.
func TestShowZonesHostInbound3654(t *testing.T) {
	fake := &fakeBpfrxClient{
		getZonesResp: &pb.GetZonesResponse{
			Zones: []*pb.ZoneInfo{
				{
					Name:                      "trust",
					HostInboundConfigured:     true,
					HostInboundServices:       []string{"ssh", "ping", "ospf"},
					HostInboundSystemServices: []string{"ssh", "ping"},
					HostInboundProtocols:      []string{"ospf"},
				},
				{
					Name:                  "edge",
					HostInboundConfigured: true,
					InterfaceHostInbound: []*pb.InterfaceHostInbound{
						{Interface: "ge-0/0/9.0", Configured: true, SystemServices: []string{"https"}},
					},
				},
				{
					Name:                  "open",
					HostInboundConfigured: true,
				},
			},
		},
	}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showZones(""); err != nil {
			t.Fatalf("showZones: %v", err)
		}
	})
	if fake.getZonesCalls != 1 {
		t.Fatalf("GetZones called %d times, want 1", fake.getZonesCalls)
	}
	for _, want := range []string{
		// split fields (M06 — previously collapsed into one line)
		"Host-inbound system-services: ssh, ping",
		"Host-inbound protocols: ospf",
		// per-interface override block (H09 — previously dropped)
		"Host-inbound interface overrides:",
		"ge-0/0/9.0:",
		"override system-services: https",
		"effective system-services: https",
		// no-stanza default-deny posture (M03 — previously blank)
		"Host-inbound: default deny (no stanza)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("remote show security zones missing %q\n%s", want, out)
		}
	}
	// The legacy collapsed line must be gone.
	if strings.Contains(out, "Host-inbound services:") {
		t.Errorf("remote show security zones still renders legacy collapsed line\n%s", out)
	}
}
