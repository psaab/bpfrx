package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// reject builds a match-all `then reject` policy, mirroring the sibling
// permit/deny helpers (permit in policymatch_test.go, deny in scheduler_test.go)
// so the reject row of the #4422 zone-matrix reads the same as its neighbors.
func reject(name string, m config.PolicyMatch) *config.Policy {
	return &config.Policy{Name: name, Match: m, Action: config.PolicyReject}
}

// TestPolicyZoneMatrixRejectVerdict closes the two REJECT cells of the #4422
// policy zone-matrix (action × destination-class) at the SSOT flow-match engine
// level. The rest of the matrix is already pinned against Match():
//
//	transit permit      -> policymatch_test.go "allow-http" (Action=PolicyPermit)
//	transit deny        -> policymatch_test.go "block-feed" (Action=PolicyDeny)
//	transit default     -> policymatch_test.go "no match -> default deny/permit"
//	junos-host permit   -> junos_host_test.go "exact junos-host outranks from-any"
//	junos-host deny     -> junos_host_test.go "exact junos-host deny matches"
//	junos-host default  -> junos_host_test.go "no junos-host policy -> host-inbound"
//
// but NO Match() test drove a `then reject` policy in EITHER destination class
// (grep: PolicyReject is asserted nowhere in pkg/policymatch), and
// DisplayAction()'s reject arm is likewise unexercised (display_action_3375_test.go
// covers permit/deny/default/host-inbound, not reject). A reject policy is a
// distinct terminal action — the dataplane deny-with-notification path — that
// matchedResult carries verbatim (Action: pol.Action) and DisplayAction renders
// via ActionString(PolicyReject). This test pins both reject cells to the
// concrete matched verdict so a match-engine or renderer regression on the
// reject action flips an assertion.
//
// FAIL-ON-REVERT: fold reject into deny in matchedResult/ActionString (or make
// the junos-host gate swallow a `then reject` host rule as HostInboundUnmatched
// instead of a concrete match) and the Action / DisplayAction / non-default
// assertions below go RED.
func TestPolicyZoneMatrixRejectVerdict(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		q          Query
		host       bool // destination-class is junos-host (host-bound) vs transit
		wantName   string
		wantAction config.PolicyAction
		wantRender string
	}{
		{
			// REJECT × transit: a concrete zone-pair `from-zone trust to-zone
			// untrust ... then reject` must resolve to a Matched reject verdict,
			// not the default-policy (which is permit here, so a lost match would
			// be observably wrong).
			name: "transit reject matches",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", reject("t-reject", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			host:       false,
			wantName:   "t-reject",
			wantAction: config.PolicyReject,
			wantRender: "reject",
		},
		{
			// REJECT × junos-host: an exact `from-zone trust to-zone junos-host
			// ... then reject` host-inbound rule must resolve to a Matched reject
			// verdict on the host gate — NOT HostInboundUnmatched (the
			// local-delivery default) and NOT the transit default. DefaultPolicy
			// is permit to make a mis-routed fall-through observable.
			name: "junos-host reject matches",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "junos-host", reject("h-reject", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "junos-host"},
			host:       true,
			wantName:   "h-reject",
			wantAction: config.PolicyReject,
			wantRender: "reject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Match(tt.cfg, tt.q)
			if !res.Matched {
				t.Fatalf("Matched = false, want true (reject rule not matched; res=%+v)", res)
			}
			if res.PolicyName != tt.wantName {
				t.Errorf("PolicyName = %q, want %q", res.PolicyName, tt.wantName)
			}
			if res.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v (reject folded to another action?)", res.Action, tt.wantAction)
			}
			if got := res.DisplayAction(); got != tt.wantRender {
				t.Errorf("DisplayAction() = %q, want %q", got, tt.wantRender)
			}
			// A concrete reject is a MATCH, never the default fall-through, and on
			// the host path never the unmatched local-delivery verdict.
			if res.DefaultUsed {
				t.Errorf("DefaultUsed = true; a matched reject must not read as the default-policy verdict")
			}
			if tt.host && res.HostInboundUnmatched {
				t.Errorf("HostInboundUnmatched = true; a matched junos-host reject must not read as local delivery")
			}
		})
	}
}
