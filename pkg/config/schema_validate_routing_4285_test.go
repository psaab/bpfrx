package config_test

// fable-review-167 MERGE-NEEDS-MINOR follow-up: commit-time range validators
// for the new OSPF adjacency-timer / DR-priority and BGP hold-time / local-as
// leaves (#4285 / #4286). Without these, an out-of-range value COMMITS and then
// renders an frr-reload-BREAKING stanza — one bad leaf fails the whole reload
// (a `vtysh -f` add-batch exits non-zero on any CMD_WARNING_CONFIG_FAILED),
// taking down every routing change on that reload. Each leaf is exercised
// through the SchemaValidate gate (flat-set shape) with in-range, boundary, and
// out-of-range values.
//
// SHARPEST case: BGP hold-time 1 or 2 renders `neighbor X timers 1 1|2`, but
// FRR requires holdtime 0 OR >= 3 — a value of 1/2 is REJECTED by FRR and
// fails the reload. The validator must reject 1/2 at commit while still
// accepting 0 (hold-timer disabled, treated as unset by the renderer's > 0
// gate).
//
// RED-on-revert: dropping the `validator:` on any leaf lets the reject values
// through SchemaValidate and this test turns RED.

import (
	"fmt"
	"strings"
	"testing"
)

type routingLeafCase struct {
	name     string
	template string
	leaf     string
	accept   []string
	reject   []string
}

var routingLeafMatrix = []routingLeafCase{
	{
		// FRR ip ospf hello-interval range 1..65535; 0 is invalid.
		name:     "ospf hello-interval",
		leaf:     "hello-interval",
		template: "set protocols ospf area 0 interface ge-0-0-1 hello-interval %s",
		accept:   []string{"1", "3", "10", "65535"},
		reject:   []string{"0", "65536", "-1", "asd", ""},
	},
	{
		name:     "ospf dead-interval",
		leaf:     "dead-interval",
		template: "set protocols ospf area 0 interface ge-0-0-1 dead-interval %s",
		accept:   []string{"1", "40", "65535"},
		reject:   []string{"0", "65536", "-1", "asd", ""},
	},
	{
		name:     "ospf retransmit-interval",
		leaf:     "retransmit-interval",
		template: "set protocols ospf area 0 interface ge-0-0-1 retransmit-interval %s",
		accept:   []string{"1", "5", "65535"},
		reject:   []string{"0", "65536", "-1", "asd", ""},
	},
	{
		// FRR ip ospf priority range 0..255; 0 = "never DR" is valid.
		name:     "ospf priority",
		leaf:     "priority",
		template: "set protocols ospf area 0 interface ge-0-0-1 priority %s",
		accept:   []string{"0", "1", "100", "255"},
		reject:   []string{"256", "-1", "asd", ""},
	},
	{
		name:     "ospf3 hello-interval",
		leaf:     "hello-interval",
		template: "set protocols ospf3 area 0 interface ge-0-0-1 hello-interval %s",
		accept:   []string{"1", "2", "65535"},
		reject:   []string{"0", "65536", "-1", "asd", ""},
	},
	{
		name:     "ospf3 priority",
		leaf:     "priority",
		template: "set protocols ospf3 area 0 interface ge-0-0-1 priority %s",
		accept:   []string{"0", "100", "255"},
		reject:   []string{"256", "-1", "asd", ""},
	},
	{
		// BGP hold-time: 0 or 3..65535 — the sharpest gap (1/2 fail the reload).
		name:     "bgp group hold-time",
		leaf:     "hold-time",
		template: "set protocols bgp group ibgp hold-time %s",
		accept:   []string{"0", "3", "30", "180", "65535"},
		reject:   []string{"1", "2", "65536", "-1", "asd", ""},
	},
	{
		name:     "bgp neighbor hold-time",
		leaf:     "hold-time",
		template: "set protocols bgp group ibgp neighbor 10.0.0.2 hold-time %s",
		accept:   []string{"0", "3", "90"},
		reject:   []string{"1", "2", "asd", ""},
	},
	{
		// Per-peering local-as: a valid 32-bit ASN 1..4294967295; AS 0 is
		// reserved (RFC 7607).
		name:     "bgp group local-as",
		leaf:     "local-as",
		template: "set protocols bgp group ibgp local-as %s",
		accept:   []string{"1", "65001", "4294967295"},
		reject:   []string{"0", "4294967296", "-1", "asd", ""},
	},
	{
		name:     "bgp neighbor local-as",
		leaf:     "local-as",
		template: "set protocols bgp group ibgp neighbor 10.0.0.2 local-as %s",
		accept:   []string{"1", "65100"},
		reject:   []string{"0", "asd", ""},
	},
}

func TestSchemaValidate_RoutingAdjacencyLeaves_Matrix_4285(t *testing.T) {
	for _, tc := range routingLeafMatrix {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range tc.accept {
				cmd := strings.TrimSpace(fmt.Sprintf(tc.template, v))
				if err := flatSchemaCheck(t, cmd); err != nil {
					t.Errorf("accept %q: unexpected error: %v", cmd, err)
				}
			}
			for _, v := range tc.reject {
				cmd := strings.TrimSpace(fmt.Sprintf(tc.template, v))
				err := flatSchemaCheck(t, cmd)
				if err == nil {
					t.Errorf("reject %q: expected a commit error, got nil", cmd)
					continue
				}
				// The error must reference the leaf keyword so the operator
				// can find the offending statement.
				if !strings.Contains(err.Error(), tc.leaf) {
					t.Errorf("reject %q: error should reference %q: %v", cmd, tc.leaf, err)
				}
			}
		})
	}
}
