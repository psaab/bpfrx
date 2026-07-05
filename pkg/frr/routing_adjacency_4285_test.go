package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4285 / #4286 (fable-review-167 R-1/R-2): OSPF adjacency timers + DR
// priority and BGP update-source / passive / hold-time / local-as must reach
// the rendered frr.conf. Without them FRR keeps its defaults (OSPF hello 10s /
// dead 40s / priority 1) so an adjacency to a fast-timer neighbor never forms,
// and an iBGP loopback session sources from the egress interface IP the peer
// has no `neighbor` for, so it never establishes.
//
// FAIL-ON-REVERT: with the renderer/compiler additions reverted these lines
// are absent from the output and the test turns RED.
func TestGenerateProtocols_OSPFInterfaceTimersAndPriority(t *testing.T) {
	m := New()

	ospf := &config.OSPFConfig{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFArea{
			{
				ID: "0",
				Interfaces: []*config.OSPFInterface{
					{
						Name:          "ge-0-0-1",
						HelloInterval: 1,
						DeadInterval:  3,
						RetransmitInt: 5,
						Priority:      200,
						HasPriority:   true,
					},
				},
			},
		},
	}
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFv3Area{
			{
				ID: "0",
				Interfaces: []*config.OSPFv3Interface{
					{
						Name:          "ge-0-0-1",
						HelloInterval: 2,
						DeadInterval:  6,
						RetransmitInt: 7,
						Priority:      0, // valid: "never DR" — must still emit
						HasPriority:   true,
					},
				},
			},
		},
	}

	got := m.generateProtocols(ospf, ospfv3, nil, nil, nil, "", 0, nil)

	for _, want := range []string{
		" ip ospf hello-interval 1\n",
		" ip ospf dead-interval 3\n",
		" ip ospf retransmit-interval 5\n",
		" ip ospf priority 200\n",
		" ipv6 ospf6 hello-interval 2\n",
		" ipv6 ospf6 dead-interval 6\n",
		" ipv6 ospf6 retransmit-interval 7\n",
		" ipv6 ospf6 priority 0\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered frr.conf missing OSPF adjacency line %q; output:\n%s", want, got)
		}
	}
}

// An OSPF interface with HasPriority == false (unset) must NOT emit a priority
// line; a stray `ip ospf priority 0` would override FRR's default DR priority.
func TestGenerateProtocols_OSPFPriorityUnsetOmitted(t *testing.T) {
	m := New()

	ospf := &config.OSPFConfig{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFArea{
			{ID: "0", Interfaces: []*config.OSPFInterface{{Name: "ge-0-0-1", Cost: 5}}},
		},
	}

	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil)
	if strings.Contains(got, "ip ospf priority") {
		t.Errorf("renderer emitted an OSPF priority line for an unset priority; output:\n%s", got)
	}
	// Cost still renders — the interface block is not suppressed.
	if !strings.Contains(got, " ip ospf cost 5\n") {
		t.Errorf("renderer dropped the OSPF cost line; output:\n%s", got)
	}
}

func TestGenerateProtocols_BGPUpdateSourcePassiveHoldTimeLocalAS(t *testing.T) {
	m := New()

	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "10.255.0.1",
		Neighbors: []*config.BGPNeighbor{
			{
				Address:      "10.255.0.2",
				PeerAS:       65001,
				LocalAS:      65100,
				LocalAddress: "10.255.0.1",
				HoldTime:     30,
				Passive:      true,
			},
		},
	}

	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)

	for _, want := range []string{
		" neighbor 10.255.0.2 update-source 10.255.0.1\n",
		" neighbor 10.255.0.2 passive\n",
		" neighbor 10.255.0.2 timers 10 30\n", // keepalive = hold/3
		" neighbor 10.255.0.2 local-as 65100\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered frr.conf missing BGP neighbor line %q; output:\n%s", want, got)
		}
	}
}
