package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3684: direct unit tests for the shared zone-detail policy summary presenter
// consumed by the local CLI + gRPC-text renderers (L10). These pin the
// metadata thread (id/scheduler/log/count/exclusion + default posture) and the
// haveSched=false fallback (no rule claimed inactive) at the SSOT boundary,
// independent of the CLI/gRPC harnesses.

func metadataSummaryConfig() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy:               config.PolicyPermit,
			DefaultPolicyLogSessionInit: true,
			Zones:                       zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{
						{
							Name:          "sched-off",
							Action:        config.PolicyPermit,
							SchedulerName: "workhours",
							Match: config.PolicyMatch{
								SourceAddresses:      []string{"any"},
								DestinationAddresses: []string{"any"},
								Applications:         []string{"any"},
							},
						},
						{
							Name:   "logged-rule",
							Action: config.PolicyPermit,
							Count:  true,
							Log:    &config.PolicyLog{SessionInit: true, SessionClose: true},
							Match: config.PolicyMatch{
								SourceAddresses:            []string{"net10"},
								SourceAddressExcluded:      true,
								DestinationAddresses:       []string{"any"},
								DestinationAddressExcluded: true,
								Applications:               []string{"any"},
							},
						},
					},
				},
			},
			GlobalPolicies: []*config.Policy{
				{
					Name:          "g-sched-off",
					Action:        config.PolicyDeny,
					SchedulerName: "workhours",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
					},
				},
			},
		},
	}
}

// TestZoneDetailPolicySummaryMetadata pins the full metadata render for an
// inactive scheduler.
func TestZoneDetailPolicySummaryMetadata(t *testing.T) {
	cfg := metadataSummaryConfig()
	got := strings.Join(
		ZoneDetailPolicySummary(cfg, "untrust", map[string]bool{"workhours": false}, true),
		"\n",
	)
	for _, want := range []string{
		"  Policy summary (evaluation order: zone-pair, global, default-policy):",
		"    [zone-pair] trust -> untrust: sched-off (permit) [id 0, scheduler workhours (inactive)]",
		"    [zone-pair] trust -> untrust: logged-rule (permit) [id 1, log at-create,at-close, count, source-address (except), destination-address (except)]",
		"    [global] any -> any: g-sched-off (deny) [id 256, scheduler workhours (inactive)]",
		"    [default] default-policy: permit [id 4294967295, log at-create]",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q:\n%s", want, got)
		}
	}
}

// TestZoneDetailPolicySummaryNoRuntimeSchedulerState asserts the fallback:
// haveSched=false means the runtime scheduler state is unknown, so NO rule is
// claimed inactive (matching the #3062/#3414 detail renderer), while the
// scheduler binding is still shown.
func TestZoneDetailPolicySummaryNoRuntimeSchedulerState(t *testing.T) {
	cfg := metadataSummaryConfig()
	got := strings.Join(
		ZoneDetailPolicySummary(cfg, "untrust", nil, false),
		"\n",
	)
	if strings.Contains(got, "(inactive)") {
		t.Fatalf("haveSched=false must not claim any rule inactive:\n%s", got)
	}
	if !strings.Contains(got, "[zone-pair] trust -> untrust: sched-off (permit) [id 0, scheduler workhours]") {
		t.Fatalf("scheduler binding dropped in the unknown-state fallback:\n%s", got)
	}
}

// TestZoneDetailPolicySummaryNoApplicablePolicy asserts a zone with no
// zone-pair/global rule still shows the "(no ...)" note AND the effective
// default-policy catch-all (with sentinel id), never a bare omission.
func TestZoneDetailPolicySummaryNoApplicablePolicy(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust", "mgmt"),
		},
	}
	got := strings.Join(ZoneDetailPolicySummary(cfg, "mgmt", nil, false), "\n")
	if !strings.Contains(got, "    (no zone-pair or global policies affecting this zone)") {
		t.Fatalf("missing no-applicable-policy note:\n%s", got)
	}
	if !strings.Contains(got, "    [default] default-policy: deny [id 4294967295]") {
		t.Fatalf("missing default-policy catch-all with sentinel id:\n%s", got)
	}
}

// TestZoneDetailPolicySummaryNilConfig guards the nil-config path.
func TestZoneDetailPolicySummaryNilConfig(t *testing.T) {
	if lines := ZoneDetailPolicySummary(nil, "trust", nil, false); lines != nil {
		t.Fatalf("nil cfg should return nil, got %v", lines)
	}
}
