package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestNoDirectPerPolicyReadInShowSurfaces is the #4344 L08 static canary: the
// local-CLI policy display surfaces must NOT call dp.ReadPolicyCounters
// directly in a per-rule loop — every read goes through the #3965 bulk reader
// (dpuserspace.NewPolicyCounterReader). The only permitted mention of
// ReadPolicyCounters is the fallback method value passed to
// NewPolicyCounterReader (`c.dp.ReadPolicyCounters`, no trailing `(`), so a
// direct `.ReadPolicyCounters(` CALL in these files fails the test. This keeps a
// future show surface from regressing to the O(policies) per-policy loop.
func TestNoDirectPerPolicyReadInShowSurfaces(t *testing.T) {
	for _, f := range []string{"cli_show_security.go", "cli_show_security_dispatch.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if n := strings.Count(string(src), ".ReadPolicyCounters("); n != 0 {
			t.Errorf("%s makes %d direct .ReadPolicyCounters( call(s); policy display surfaces must read via dpuserspace.NewPolicyCounterReader (#4344)", f, n)
		}
	}
}

// #4344: the local-CLI policy-counter display surfaces (`show security policies
// hit-count` and `show security policies brief`) must read the whole policy set
// through the #3965 bulk reader (dpuserspace.NewPolicyCounterReader ->
// ReadAllPolicyCounters), NOT a per-policy ReadPolicyCounters loop.
//
// bulkReaderCLIDP is a fake dataplane that implements BOTH paths. The bulk map
// holds the AUTHORITATIVE per-policy values; the per-policy ReadPolicyCounters
// fallback returns a DISTINCT poison value and records that it was called. A
// correctly-migrated surface builds the reader once, reads every counter from
// the bulk snapshot, and never touches the per-policy fallback — so it renders
// the bulk value and leaves perPolicyCalls == 0. A surface still looping the
// per-policy read would render the poison value and bump perPolicyCalls.
type bulkReaderCLIDP struct {
	*dataplane.Manager
	bulk           map[uint32]dataplane.CounterValue
	perPolicyVal   dataplane.CounterValue
	perPolicyCalls *int
}

func (d *bulkReaderCLIDP) IsLoaded() bool { return true }

func (d *bulkReaderCLIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	*d.perPolicyCalls++
	return d.perPolicyVal, nil
}

func (d *bulkReaderCLIDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return d.bulk, nil
}

func rowContaining(out, needle string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

func TestCLIShowPoliciesHitCountUsesBulkReader(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	calls := 0
	c := &CLI{
		store: store,
		dp: &bulkReaderCLIDP{
			Manager: dataplane.New(),
			bulk: map[uint32]dataplane.CounterValue{
				// trust->untrust allow-web is the only policy set -> handle 0.
				0: {Packets: 42, Bytes: 4242},
				// implicit default-policy catch-all sentinel handle.
				dataplane.DefaultPolicySentinelID: {Packets: 99, Bytes: 9900},
			},
			perPolicyVal:   dataplane.CounterValue{Packets: 7, Bytes: 700},
			perPolicyCalls: &calls,
		},
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.showPoliciesHitCount(cfg, "", "")
	})
	if callErr != nil {
		t.Fatalf("showPoliciesHitCount() error = %v", callErr)
	}

	// The configured allow-web row must show the BULK value 42, not the
	// per-policy poison 7 — proving the render read the bulk snapshot.
	if row := rowContaining(out, "allow-web"); !strings.Contains(row, "42") {
		t.Fatalf("allow-web row = %q, want the bulk count 42 (not the per-policy poison 7)\nfull:\n%s", row, out)
	}
	// M02-parity: the default-policy sentinel row also reads via the bulk map.
	if row := rowContaining(out, dataplane.DefaultPolicyName); !strings.Contains(row, "99") {
		t.Fatalf("default-policy row = %q, want the bulk sentinel count 99\nfull:\n%s", row, out)
	}
	if calls != 0 {
		t.Fatalf("per-policy ReadPolicyCounters called %d times; want 0 (the render must read the bulk snapshot, not loop the per-policy read)", calls)
	}
}

func TestCLIShowPoliciesBriefUsesBulkReader(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true)
	calls := 0
	c := &CLI{
		store: store,
		dp: &bulkReaderCLIDP{
			Manager: dataplane.New(),
			bulk: map[uint32]dataplane.CounterValue{
				0: {Packets: 42, Bytes: 4242},
			},
			perPolicyVal:   dataplane.CounterValue{Packets: 7, Bytes: 700},
			perPolicyCalls: &calls,
		},
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleShowSecurity([]string{"policies", "brief"})
	})
	if callErr != nil {
		t.Fatalf("handleShowSecurity(policies brief) error = %v", callErr)
	}

	if row := rowContaining(out, "allow-web"); !strings.Contains(row, "42") {
		t.Fatalf("brief allow-web row = %q, want the bulk hits 42 (not the per-policy poison 7)\nfull:\n%s", row, out)
	}
	if calls != 0 {
		t.Fatalf("per-policy ReadPolicyCounters called %d times; want 0 (brief must read the bulk snapshot)", calls)
	}
}
