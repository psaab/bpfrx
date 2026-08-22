package nftables

import (
	"testing"

	"github.com/google/nftables"
)

// #5719: ReadHostInboundDenyCounters used to answer (nil, nil) for BOTH "no
// xpf_hostinbound table installed" and "table installed but carrying no named
// counters" — the latter being the #5644 M37 cold-boot fail-closed FENCE, which
// renders catch-all DROPs with deliberately NO counters. Collapsing those two
// states let the REST/Prometheus surfaces publish an AUTHORITATIVE zero while
// the appliance was degraded and actively dropping host-bound traffic.
//
// classifyHostInboundDenyObjects is the pure object-walk seam the netlink read
// delegates the present-table half of that discrimination to, so this test runs
// WITHOUT a kernel or CAP_NET_ADMIN — it never skips. (The absent-table half is
// decided before the walk; TestFenceTableReadsCounterless proves the end-to-end
// absent/counterless/counted split against the real kernel, and SKIPs without
// CAP_NET_ADMIN.)
func TestClassifyHostInboundDenyObjects(t *testing.T) {
	denyV4 := HostInboundDenyCounterName("wan", "ip")
	denyV6 := HostInboundDenyCounterName("wan", "ip6")
	acceptND := HostInboundAcceptCounterName(HostInboundAcceptICMP6ND)

	tests := []struct {
		name      string
		objs      []nftables.Obj
		wantState HostInboundTableState
		wantDeny  map[string]uint64 // zone/family -> packets
	}{
		{
			// The FENCE: table present, zero named counter objects. An aggregate
			// zero read from here is NOT certifiable as "no denies happened".
			name:      "fence: table present with no objects at all",
			objs:      nil,
			wantState: HostInboundTableCounterless,
			wantDeny:  map[string]uint64{},
		},
		{
			// A real generation always declares the three #4759 ICMP/ND ACCEPT
			// counters, so a junos-host-program-only ruleset (no per-zone catch-all
			// DROP, hence no deny counter) must still read as Counted. This is what
			// keeps the discriminator on "no counter OBJECTS" rather than "no DENY
			// counters" from false-alarming on a legitimate, fully-enforcing table.
			name:      "real table with accept counters but no deny counters",
			objs:      []nftables.Obj{&nftables.CounterObj{Name: acceptND}},
			wantState: HostInboundTableCounted,
			wantDeny:  map[string]uint64{},
		},
		{
			// THE assertion that proves the fix did not simply make every zero
			// unavailable: real deny counter objects that merely READ zero exist in
			// the table, come back with Packets: 0, and stay AUTHORITATIVE.
			name: "real deny counters whose values are all zero",
			objs: []nftables.Obj{
				&nftables.CounterObj{Name: denyV4, Packets: 0, Bytes: 0},
				&nftables.CounterObj{Name: denyV6, Packets: 0, Bytes: 0},
			},
			wantState: HostInboundTableCounted,
			wantDeny:  map[string]uint64{"wan/ip": 0, "wan/ip6": 0},
		},
		{
			name: "real deny counters with traffic",
			objs: []nftables.Obj{
				&nftables.CounterObj{Name: denyV4, Packets: 7, Bytes: 700},
				&nftables.CounterObj{Name: denyV6, Packets: 3, Bytes: 300},
			},
			wantState: HostInboundTableCounted,
			wantDeny:  map[string]uint64{"wan/ip": 7, "wan/ip6": 3},
		},
		{
			// A foreign / non-counter object is not a named counter: it neither
			// contributes a deny row nor rescues the table from Counterless.
			name:      "non-counter objects only",
			objs:      []nftables.Obj{&nftables.QuotaObj{Name: "xpfhi_quota"}},
			wantState: HostInboundTableCounterless,
			wantDeny:  map[string]uint64{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counts, state := classifyHostInboundDenyObjects(tt.objs)
			if state != tt.wantState {
				t.Errorf("state = %d, want %d", state, tt.wantState)
			}
			got := map[string]uint64{}
			for _, c := range counts {
				got[c.Zone+"/"+c.Family] = c.Packets
			}
			if len(got) != len(tt.wantDeny) {
				t.Fatalf("deny rows = %v, want %v", got, tt.wantDeny)
			}
			for k, want := range tt.wantDeny {
				v, ok := got[k]
				if !ok {
					t.Errorf("deny row %q missing; got %v", k, got)
					continue
				}
				if v != want {
					t.Errorf("deny row %q = %d packets, want %d", k, v, want)
				}
			}
		})
	}
}
