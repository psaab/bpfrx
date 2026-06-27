package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestJunosHostGateNoTransitFallback pins the #3285 fix: a `to-zone junos-host`
// query must mirror the dataplane host gate evaluate_junos_host_policy
// (policy.rs) — exact `from-zone <ingress> to-zone junos-host`, then
// `from-zone any to-zone junos-host`, with NO global / default transit
// fallback. An unmatched host-bound flow returns HostInboundUnmatched (local
// delivery proceeds), NOT the transit default-policy or a global verdict. The
// pre-#3285 simulator ran the transit chain (exact -> every global -> default)
// for every query, so it reported the wrong verdict on the host path.
func TestJunosHostGateNoTransitFallback(t *testing.T) {
	tests := []struct {
		name          string
		cfg           *config.Config
		q             Query
		wantMatched   bool
		wantHostUnmat bool
		wantName      string
		wantAction    config.PolicyAction
	}{
		{
			// Host-inbound permits SSH, no matching to-zone junos-host policy,
			// default deny-all: runtime delivers locally (host gate None). The
			// old simulator reported default DENY.
			name: "no junos-host policy, default deny -> host-inbound (not default deny)",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("transit", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:             Query{FromZone: "trust", ToZone: "junos-host"},
			wantMatched:   false,
			wantHostUnmat: true,
		},
		{
			// A global deny exists: runtime ignores global on the host path. The
			// old simulator reported the global deny as the matching rule.
			name: "global deny is NOT applied on the host path",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Zones:         zones("trust"),
				GlobalPolicies: []*config.Policy{
					{Name: "global-deny", Action: config.PolicyDeny},
				},
			}, config.ApplicationsConfig{}),
			q:             Query{FromZone: "trust", ToZone: "junos-host"},
			wantMatched:   false,
			wantHostUnmat: true,
		},
		{
			// A `to-zone any` rule must NOT be pulled onto the host path.
			name: "to-zone any is NOT applied on the host path",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Zones:         zones("trust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "any", deny3285("to-any-deny", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:             Query{FromZone: "trust", ToZone: "junos-host"},
			wantMatched:   false,
			wantHostUnmat: true,
		},
		{
			// An exact `from-zone trust to-zone junos-host deny` MATCHES.
			name: "exact junos-host deny matches",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "junos-host", deny3285("host-deny", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "junos-host"},
			wantMatched: true, wantName: "host-deny", wantAction: config.PolicyDeny,
		},
		{
			// A `from-zone any to-zone junos-host deny` wildcard MATCHES every
			// ingress (the host path DOES consult from-any).
			name: "from-any junos-host deny matches",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "dmz"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "junos-host", deny3285("host-any-deny", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "dmz", ToZone: "junos-host"},
			wantMatched: true, wantName: "host-any-deny", wantAction: config.PolicyDeny,
		},
		{
			// Exact ingress->junos-host outranks the from-any junos-host
			// wildcard (most-specific-first).
			name: "exact junos-host outranks from-any junos-host",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Zones:         zones("trust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "junos-host", deny3285("any-host-deny", config.PolicyMatch{})),
					zonePair("trust", "junos-host", permit("trust-host-permit", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "junos-host"},
			wantMatched: true, wantName: "trust-host-permit", wantAction: config.PolicyPermit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Match(tt.cfg, tt.q)
			if res.HostInboundUnmatched != tt.wantHostUnmat {
				t.Errorf("HostInboundUnmatched = %v, want %v", res.HostInboundUnmatched, tt.wantHostUnmat)
			}
			if res.Matched != tt.wantMatched {
				t.Errorf("Matched = %v, want %v (policy %q)", res.Matched, tt.wantMatched, res.PolicyName)
			}
			if tt.wantHostUnmat {
				// Host-inbound-unmatched must NOT be reported as a transit
				// default verdict.
				if res.DefaultUsed {
					t.Errorf("DefaultUsed = true; host-inbound must not inherit the transit default")
				}
				return
			}
			if tt.wantName != "" {
				if res.PolicyName != tt.wantName {
					t.Errorf("PolicyName = %q, want %q", res.PolicyName, tt.wantName)
				}
				if res.Action != tt.wantAction {
					t.Errorf("Action = %v, want %v", res.Action, tt.wantAction)
				}
			}
		})
	}
}

func deny3285(name string, m config.PolicyMatch) *config.Policy {
	return &config.Policy{Name: name, Match: m, Action: config.PolicyDeny}
}
