package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestNoDirectPerPolicyReadInSecurityHandler is the #4344 L08 static canary for
// the REST policy inventory: security.go must NOT call dp.ReadPolicyCounters
// directly (including for the M02 default-policy row) — every read goes through
// the #3965 bulk reader (dpuserspace.NewPolicyCounterReader). The permitted
// mention is the fallback method value passed to NewPolicyCounterReader
// (`s.dp.ReadPolicyCounters`, no trailing `(`), so a direct `.ReadPolicyCounters(`
// CALL fails the test.
func TestNoDirectPerPolicyReadInSecurityHandler(t *testing.T) {
	const f = "security.go"
	src, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("read %s: %v", f, err)
	}
	if n := strings.Count(string(src), ".ReadPolicyCounters("); n != 0 {
		t.Errorf("%s makes %d direct .ReadPolicyCounters( call(s); the policy inventory (incl. the default-policy row) must read via dpuserspace.NewPolicyCounterReader (#4344 M02)", f, n)
	}
}

// #4344 (M02): the REST `GET /api/v1/security/policies` structured
// default-policy row must read its hit counter through the SAME #3965 bulk
// reader (dpuserspace.NewPolicyCounterReader -> ReadAllPolicyCounters) as the
// configured rows, instead of a standalone per-policy s.dp.ReadPolicyCounters
// call that took a second dataplane snapshot for the sentinel handle.
//
// bulkReaderAPIDP implements BOTH paths: the bulk map holds the authoritative
// values (including the DefaultPolicySentinelID handle), and the per-policy
// fallback returns a distinct poison value + records that it was called. With
// the endpoint fully migrated, EVERY row (configured + default) reads from the
// bulk snapshot, so the per-policy fallback is never invoked (perPolicyCalls ==
// 0). Before the M02 fix the default-policy row alone bumped it.
type bulkReaderAPIDP struct {
	*dataplane.Manager
	bulk           map[uint32]dataplane.CounterValue
	perPolicyVal   dataplane.CounterValue
	perPolicyCalls *int
}

func (d *bulkReaderAPIDP) IsLoaded() bool { return true }

func (d *bulkReaderAPIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	*d.perPolicyCalls++
	return d.perPolicyVal, nil
}

func (d *bulkReaderAPIDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return d.bulk, nil
}

func TestPoliciesHandlerDefaultRowUsesBulkReader(t *testing.T) {
	store := newSchedulerCounterAPIStore(t)
	enablePolicyStatsAPI(t, store)
	scheduledID := scheduledCounterPolicyID(t, store)
	calls := 0
	s := &Server{
		store: store,
		dp: &bulkReaderAPIDP{
			Manager: dataplane.New(),
			bulk: map[uint32]dataplane.CounterValue{
				// plain-allow occupies slot 0; both configured rows are read
				// because policy-stats is enabled, so both handles must resolve
				// from the bulk snapshot or the reader signals unpublished.
				0:           {Packets: 11, Bytes: 1100},
				scheduledID: {Packets: 23, Bytes: 2300},
				// M02: the implicit default-policy catch-all sentinel handle.
				dataplane.DefaultPolicySentinelID: {Packets: 55, Bytes: 5500},
			},
			perPolicyVal:   dataplane.CounterValue{Packets: 7, Bytes: 700},
			perPolicyCalls: &calls,
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []PolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	var sawDefault bool
	for _, policy := range resp.Data {
		for _, rule := range policy.Rules {
			if rule.Name != dataplane.DefaultPolicyName {
				continue
			}
			sawDefault = true
			// The default row must show the BULK sentinel value, not the
			// per-policy poison 7/700.
			if rule.HitPackets != 55 || rule.HitBytes != 5500 {
				t.Fatalf("default-policy row counters = %d/%d, want the bulk sentinel 55/5500",
					rule.HitPackets, rule.HitBytes)
			}
		}
	}
	if !sawDefault {
		t.Fatal("default-policy row not found in REST response")
	}
	if calls != 0 {
		t.Fatalf("per-policy ReadPolicyCounters called %d times; want 0 (the default-policy row must read the shared bulk snapshot, not a standalone per-policy read)", calls)
	}
}
