package monitoriface

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestParseSummaryMode(t *testing.T) {
	cases := map[string]SummaryMode{
		"":         SummaryModeCombined,
		"combined": SummaryModeCombined,
		"all":      SummaryModeCombined,
		"packets":  SummaryModePackets,
		"bytes":    SummaryModeBytes,
		"delta":    SummaryModeDelta,
		"rate":     SummaryModeRate,
	}
	for input, want := range cases {
		got, ok := ParseSummaryMode(input)
		if !ok {
			t.Fatalf("ParseSummaryMode(%q) unexpectedly rejected", input)
		}
		if got != want {
			t.Fatalf("ParseSummaryMode(%q) = %v, want %v", input, got, want)
		}
	}
	if _, ok := ParseSummaryMode("bogus"); ok {
		t.Fatal("ParseSummaryMode accepted invalid mode")
	}
}

func TestRenderTrafficSummaryCombinedIncludesTotals(t *testing.T) {
	now := time.Now()
	names := []string{"lan0", "wan0"}
	kernelNames := map[string]string{
		"lan0": "lan0",
		"wan0": "wan0",
	}
	snaps := map[string]*Snapshot{
		"lan0": {
			RxBytes:   2_000_000,
			TxBytes:   4_000_000,
			RxPkts:    2_000,
			TxPkts:    4_000,
			Timestamp: now,
		},
		"wan0": {
			RxBytes:   6_000_000,
			TxBytes:   8_000_000,
			RxPkts:    6_000,
			TxPkts:    8_000,
			Timestamp: now,
		},
	}
	prev := map[string]*Snapshot{
		"lan0": {
			RxBytes:   1_000_000,
			TxBytes:   2_000_000,
			RxPkts:    1_000,
			TxPkts:    2_000,
			Timestamp: now.Add(-1 * time.Second),
		},
		"wan0": {
			RxBytes:   3_000_000,
			TxBytes:   4_000_000,
			RxPkts:    3_000,
			TxPkts:    4_000,
			Timestamp: now.Add(-1 * time.Second),
		},
	}

	var buf bytes.Buffer
	RenderTrafficSummary(&buf, "bpfrx", names, kernelNames, snaps, prev, SummaryModeCombined, now.Add(-5*time.Second))
	out := buf.String()
	for _, needle := range []string{
		"mode: combined",
		"iface",
		"total:",
		"Rx",
		"Tx",
		"1.00 MB/s",
		"3.00 MB/s",
		"10.00 MB/s",
		"lan0",
		"wan0",
		"Keys: q=quit  c=combined",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("combined summary missing %q\n%s", needle, out)
		}
	}
}

func TestMergedTrafficCountersIncludeUserspaceXSK(t *testing.T) {
	snap := &Snapshot{
		RxBytes: 1000,
		TxBytes: 2000,
		RxPkts:  10,
		TxPkts:  20,
		Userspace: &UserspaceSnapshot{
			RxBytes:   3000,
			TxBytes:   4000,
			RxPackets: 30,
			TxPackets: 40,
		},
	}

	counters := mergedTrafficCounters(snap)
	if counters.rxBytes != 4000 || counters.txBytes != 6000 || counters.rxPkts != 40 || counters.txPkts != 60 {
		t.Fatalf("mergedTrafficCounters() = %+v, want rxBytes=4000 txBytes=6000 rxPkts=40 txPkts=60", counters)
	}
}

func TestSnapshotRatesCounterResetReturnsZero(t *testing.T) {
	now := time.Now()
	rxPps, txPps, rxBps, txBps := snapshotRates(&Snapshot{
		RxBytes:   100,
		TxBytes:   200,
		RxPkts:    10,
		TxPkts:    20,
		Timestamp: now,
	}, &Snapshot{
		RxBytes:   1_000,
		TxBytes:   2_000,
		RxPkts:    100,
		TxPkts:    200,
		Timestamp: now.Add(-1 * time.Second),
	})
	if rxPps != 0 || txPps != 0 || rxBps != 0 || txBps != 0 {
		t.Fatalf("snapshotRates should clamp counter resets to zero, got rxPps=%d txPps=%d rxBps=%d txBps=%d", rxPps, txPps, rxBps, txBps)
	}
}

func TestSnapshotRatesIncludeUserspaceXSKCounters(t *testing.T) {
	now := time.Now()
	rxPps, txPps, rxBps, txBps := snapshotRates(&Snapshot{
		RxBytes:   1000,
		TxBytes:   2000,
		RxPkts:    10,
		TxPkts:    20,
		Timestamp: now,
		Userspace: &UserspaceSnapshot{
			RxBytes:   2000,
			TxBytes:   3000,
			RxPackets: 20,
			TxPackets: 30,
		},
	}, &Snapshot{
		RxBytes:   400,
		TxBytes:   500,
		RxPkts:    4,
		TxPkts:    5,
		Timestamp: now.Add(-1 * time.Second),
		Userspace: &UserspaceSnapshot{
			RxBytes:   600,
			TxBytes:   700,
			RxPackets: 6,
			TxPackets: 7,
		},
	})
	if rxPps != 20 || txPps != 38 || rxBps != 2000 || txBps != 3800 {
		t.Fatalf("snapshotRates() = rxPps=%d txPps=%d rxBps=%d txBps=%d, want 20/38/2000/3800", rxPps, txPps, rxBps, txBps)
	}
}

func TestRenderTrafficSummaryCombinedIncludesUserspaceXSKTotals(t *testing.T) {
	now := time.Now()
	names := []string{"wan0"}
	kernelNames := map[string]string{"wan0": "wan0"}
	snaps := map[string]*Snapshot{
		"wan0": {
			RxBytes:   1_000_000,
			TxBytes:   2_000_000,
			RxPkts:    1_000,
			TxPkts:    2_000,
			Timestamp: now,
			Userspace: &UserspaceSnapshot{
				RxBytes:   4_000_000,
				TxBytes:   5_000_000,
				RxPackets: 4_000,
				TxPackets: 5_000,
			},
		},
	}
	prev := map[string]*Snapshot{
		"wan0": {
			RxBytes:   500_000,
			TxBytes:   1_000_000,
			RxPkts:    500,
			TxPkts:    1_000,
			Timestamp: now.Add(-1 * time.Second),
			Userspace: &UserspaceSnapshot{
				RxBytes:   2_000_000,
				TxBytes:   2_500_000,
				RxPackets: 2_000,
				TxPackets: 2_500,
			},
		},
	}

	var buf bytes.Buffer
	RenderTrafficSummary(&buf, "bpfrx", names, kernelNames, snaps, prev, SummaryModeCombined, now.Add(-5*time.Second))
	out := buf.String()
	for _, needle := range []string{
		"2.50 MB/s",
		"3.50 MB/s",
		"6.00 MB/s",
		"2.50K",
		"3.50K",
		"6.00K",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("combined summary missing merged userspace traffic %q\n%s", needle, out)
		}
	}
}

func TestBuildTrafficSummaryInterfacesPrefersFabAndRethAliases(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"ge-0/0/7": {Name: "ge-0/0/7"},
				"fab0":     {Name: "fab0", LocalFabricMember: "ge-0/0/7", FabricMembers: []string{"ge-0/0/7"}},
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
			},
		},
	}

	names, kernelNames := buildTrafficSummaryInterfaces(cfg, []string{"ge-0-0-0", "ge-0-0-7", "fxp0"}, func(name string) string {
		return name
	})

	if len(names) != 3 {
		t.Fatalf("summary names = %v, want 3 entries", names)
	}
	if !contains(names, "fab0") {
		t.Fatalf("summary names %v missing fab0", names)
	}
	if !contains(names, "reth0") {
		t.Fatalf("summary names %v missing reth0", names)
	}
	if kernelNames["fab0"] != "ge-0-0-7" {
		t.Fatalf("fab0 kernel = %q, want ge-0-0-7", kernelNames["fab0"])
	}
	if kernelNames["reth0"] != "ge-0-0-0" {
		t.Fatalf("reth0 kernel = %q, want ge-0-0-0", kernelNames["reth0"])
	}
	if contains(names, "ge-0-0-0") || contains(names, "ge-0-0-7") {
		t.Fatalf("summary names %v should prefer config aliases over raw kernel names", names)
	}
}

func TestBuildTrafficSummaryInterfacesCollapsesFabricOverlayToOneRow(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fab0": {Name: "fab0", LocalFabricMember: "ge-0/0/7", FabricMembers: []string{"ge-0/0/7"}},
			},
		},
	}

	names, kernelNames := buildTrafficSummaryInterfaces(cfg, []string{"fab0", "ge-0-0-7"}, func(name string) string {
		if name == "fab0" {
			return "ge-0-0-7"
		}
		return name
	})

	if len(names) != 1 {
		t.Fatalf("summary names = %v, want a single deduplicated row", names)
	}
	if names[0] != "fab0" {
		t.Fatalf("summary name = %q, want fab0", names[0])
	}
	if kernelNames["fab0"] != "ge-0-0-7" {
		t.Fatalf("fab0 kernel = %q, want ge-0-0-7", kernelNames["fab0"])
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
