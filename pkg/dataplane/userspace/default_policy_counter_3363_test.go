package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// Test_3363_DefaultPolicyCounterReadThroughSentinel verifies the IMPLICIT
// default-policy hit counter is readable through the reserved
// DefaultPolicySentinelID handle (#3363). The userspace helper reports that
// counter under the stable rule id dataplane.DefaultPolicyName
// ("default-policy"); the resolver maps the sentinel handle to that name so
// every existing counter surface (CLI, gRPC text, REST, Prometheus) reads it
// via the unchanged ReadPolicyCounters path, with no new interface method.
//
// Fail-on-revert: drop the sentinel branch in policyRuleIDForCounter and the
// handle resolves to "" → the default counter reads 0/0 → RED.
func Test_3363_DefaultPolicyCounterReadThroughSentinel(t *testing.T) {
	// The resolver must map the reserved sentinel to the default-policy rule id
	// regardless of the active config (the default counter has no config rule).
	if got := policyRuleIDForCounter(nil, dataplane.DefaultPolicySentinelID); got != dataplane.DefaultPolicyName {
		t.Fatalf("policyRuleIDForCounter(sentinel) = %q, want %q",
			got, dataplane.DefaultPolicyName)
	}

	m := New()
	m.lastStatus = ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{
			{RuleID: stablePolicyRuleID("lan", "wan", "allow-web"), Packets: 50, Bytes: 5000},
			{RuleID: dataplane.DefaultPolicyName, Packets: 7, Bytes: 700},
		},
	}

	got, err := m.ReadPolicyCounters(dataplane.DefaultPolicySentinelID)
	if err != nil {
		t.Fatalf("ReadPolicyCounters(sentinel): %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 7, Bytes: 700}) {
		t.Fatalf("default-policy counter = %+v, want packets=7 bytes=700", got)
	}

	// The sentinel must NOT resolve to any configured rule's counter: a
	// configured handle (0,0) still reads its own rule, not the default.
	web, err := m.ReadPolicyCounters(callerCounterID(0, 0))
	if err == nil && web == (dataplane.CounterValue{Packets: 7, Bytes: 700}) {
		t.Fatalf("configured handle (0,0) leaked the default-policy counter")
	}
}
