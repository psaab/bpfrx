package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestZoneHostInboundViewReplacesZoneSet_6515 binds the REMOTE CLI's projection
// to the same zone↔interface rule the local CLI, the gRPC text surface and the
// enforcement path use (#6515): a per-interface `host-inbound-traffic` stanza
// REPLACES the zone-level stanza on that interface.
//
// The remote CLI is the one surface that cannot ask the config — it re-derives
// the effective set client-side from the structured GetZones response, so it is
// also the one surface a change to the resolver can silently leave behind. It
// did before this test existed: reverting this call site to a union kept every
// cmd/cli test green. An operator reading `show security zones` over the remote
// CLI would then be told SSH is admitted on an interface the firewall drops it
// on — worse than no output at all.
//
// Every element of InterfaceHostInbound is by construction a ref that declares a
// stanza (the server projects SortedInterfaceHostInboundRefs), which is why the
// projection passes overridden=true unconditionally.
func TestZoneHostInboundViewReplacesZoneSet_6515(t *testing.T) {
	z := &pb.ZoneInfo{
		Name:                      "trust",
		HostInboundSystemServices: []string{"ssh", "ping"},
		HostInboundProtocols:      []string{"ospf"},
		InterfaceHostInbound: []*pb.InterfaceHostInbound{{
			Interface:      "ge-0/0/9.0",
			Configured:     true,
			SystemServices: []string{"https"},
		}},
	}
	v := zoneHostInboundView(z)
	if len(v.Interfaces) != 1 {
		t.Fatalf("projected %d interface rows, want 1", len(v.Interfaces))
	}
	row := v.Interfaces[0]
	if got := strings.Join(row.EffectiveSystemServices, ","); got != "https" {
		t.Errorf("effective system-services = %q, want %q: the interface stanza REPLACES the "+
			"zone's [ssh ping] (#6515), it does not add to it", got, "https")
	}
	if len(row.EffectiveProtocols) != 0 {
		t.Errorf("effective protocols = %v, want none: the WHOLE zone stanza is replaced, so "+
			"the zone's `ospf` does not reach an interface that declares its own "+
			"host-inbound-traffic (#6515 granularity)", row.EffectiveProtocols)
	}
	// The zone-level lines are unchanged: they still govern every interface that
	// declares no stanza. Without this the test would also pass for a projection
	// that had simply stopped carrying the zone set at all.
	if got := strings.Join(v.ZoneSystemServices, ","); got != "ssh,ping" {
		t.Errorf("zone system-services = %q, want %q", got, "ssh,ping")
	}
}
