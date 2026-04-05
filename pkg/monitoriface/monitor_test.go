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
