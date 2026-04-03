package monitoriface

import (
	"bytes"
	"strings"
	"testing"
	"time"
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
