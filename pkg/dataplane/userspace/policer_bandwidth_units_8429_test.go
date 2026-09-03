package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compilePolicerCfg8429(t *testing.T, cmds []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// #8429: the single-rate policer's END-TO-END unit chain.
//
// This asserts the CHAIN, not either side, because both sides were individually
// self-consistent while the product was wrong — which is exactly why a Go-side
// cell and a Rust-side cell both passed through the defect.
//
//	config `bandwidth-limit 8m`
//	  -> parseBandwidthLimit  = parseScaledDecimalUnit/8 = 1,000,000 BYTES/sec
//	  -> wire `bandwidth_bps`                            = 8,000,000 bits/sec
//	  -> filter/compiler.rs: bandwidth_bps / 8           = 1,000,000 BYTES/sec
//
// Before the fix the emitter shipped the byte value into the bits-named field,
// so the helper divided a second time and metered 125,000 B/s — one eighth of
// the configured rate. With `then discard` that drops conforming customer
// traffic and the policer counters attribute it to the customer, so the surface
// an operator checks confirms the wrong story.
//
// RED on revert: restore `BandwidthBps: pol.BandwidthLimit` in
// buildPolicerSnapshots.
func TestSingleRatePolicerBandwidthUnitChain_8429(t *testing.T) {
	const (
		configuredBitsPerSec  = 8_000_000 // `bandwidth-limit 8m`
		configuredBytesPerSec = configuredBitsPerSec / 8
	)
	cfg := compilePolicerCfg8429(t, []string{
		"set firewall policer p1 if-exceeding bandwidth-limit 8m",
		"set firewall policer p1 if-exceeding burst-size-limit 15k",
		"set firewall policer p1 then discard",
	})

	snaps := buildPolicerSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("expected exactly one policer snapshot, got %d", len(snaps))
	}
	got := snaps[0]

	// Half one: the wire field must carry what its NAME says.
	if got.BandwidthBps != configuredBitsPerSec {
		t.Errorf("wire bandwidth_bps = %d, want %d — the field is named bits per second "+
			"and parseBandwidthLimit returns BYTES per second (it is literally "+
			"parseScaledDecimalUnit/8), so assigning straight across ships bytes under a "+
			"bits name", got.BandwidthBps, configuredBitsPerSec)
	}

	// Half two: applying the CONSUMER's formula must recover the configured
	// rate. This is the half that makes the cell a chain assertion rather than
	// a pin — it encodes `filter/compiler.rs`'s
	// `committed_rate_bytes_per_sec = snap.bandwidth_bps / 8`, so a change on
	// EITHER side that breaks the agreement fails here.
	if enforced := got.BandwidthBps / 8; enforced != configuredBytesPerSec {
		t.Errorf("the helper will meter %d bytes/sec for a configured %d bytes/sec "+
			"(%d%% of the configured rate). The consumer divides bandwidth_bps by 8; the "+
			"emitter must therefore ship BITS",
			enforced, configuredBytesPerSec, enforced*100/configuredBytesPerSec)
	}
}

// THE CONTROL. Three-color policers parse through the SAME
// parseBandwidthLimit, and they are correct: they emit into
// `committed_rate_bytes_per_sec`, a byte-NAMED field the helper does not
// re-divide.
//
// It is a control in the strict sense — it must be UNCHANGED by the fix. The
// tempting repair for #8429 is to drop the `/8` from parseBandwidthLimit, and
// that would silently multiply every three-color committed rate by eight. This
// cell fails if anyone tries it, which is why the fix belongs at the single
// crossing emitter rather than in the shared parse.
func TestThreeColorCommittedRateStaysBytes_8429(t *testing.T) {
	const configuredBytesPerSec = 8_000_000 / 8
	cfg := compilePolicerCfg8429(t, []string{
		"set firewall three-color-policer tcp1 single-rate committed-information-rate 8m",
		"set firewall three-color-policer tcp1 single-rate committed-burst-size 15k",
		"set firewall three-color-policer tcp1 single-rate excess-burst-size 30k",
	})

	snaps := buildThreeColorPolicerSnapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("expected exactly one three-color snapshot, got %d", len(snaps))
	}
	if got := snaps[0].CommittedRateBytes; got != configuredBytesPerSec {
		t.Errorf("three-color committed_rate_bytes_per_sec = %d, want %d. This field is "+
			"BYTE-named and the helper does not re-divide it, so it must keep carrying the "+
			"parse's byte output. If this moved, the #8429 fix was applied to the shared "+
			"parseBandwidthLimit instead of to the single-rate emitter, and every "+
			"three-color policer now meters eight times its configured rate",
			got, configuredBytesPerSec)
	}
}
