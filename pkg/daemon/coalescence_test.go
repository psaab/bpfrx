// Unit tests for mlx5 coalescence tuning (#801).
//
// Reuses the fakeRSSExecutor already defined in rss_indirection_test.go
// so we don't duplicate the ethtool/sysfs abstraction. Adds a couple of
// coalesce-specific helpers on top (scripted `ethtool -c` output for
// the idempotency probe, recording of `ethtool -C` argvs).
//
// Covers:
//   - parseEthtoolCoalesce against realistic mlx5 output.
//   - Allowlist + non-mlx5 gate (matches D3's H1 invariant).
//   - Default RX/TX usecs substitution (issue #801: default 8).
//   - Idempotency skip when the live probe already reflects the target.
//   - Clean skip when `ethtool` is missing.
//   - Empty allowlist = no-op.
//   - adaptiveEnable=true re-enables adaptive (mirror of the default
//     path — needed so the `coalescence adaptive enable` opt-out works).
package daemon

import (
	"testing"
)

// Sample `ethtool -c` output shape from a real mlx5 adapter — matches
// the format the Step-0 audit (docs/line-rate-step0-audit.md) captured.
const mlx5CoalesceProbeAdaptiveOn = `Coalesce parameters for ge-0-0-1:
Adaptive RX: on  TX: on
stats-block-usecs: 0
sample-interval: 0
pkt-rate-low: 0
pkt-rate-high: 0

rx-usecs: 8
rx-frames: 128
rx-usecs-irq: 0
rx-frames-irq: 0

tx-usecs: 8
tx-frames: 128
tx-usecs-irq: 0
tx-frames-irq: 0

rx-usecs-low: 0
rx-frame-low: 0
tx-usecs-low: 0
tx-frame-low: 0

rx-usecs-high: 128
rx-frame-high: 0
tx-usecs-high: 128
tx-frame-high: 0

CQE mode RX: n/a  TX: n/a
`

const mlx5CoalesceProbeAdaptiveOff = `Coalesce parameters for ge-0-0-1:
Adaptive RX: off  TX: off
rx-usecs: 8
tx-usecs: 8
`

// parseEthtoolCoalesce --------------------------------------------------

func TestParseEthtoolCoalesce_AdaptiveOn(t *testing.T) {
	rx, tx, aRX, aTX, ok := parseEthtoolCoalesce([]byte(mlx5CoalesceProbeAdaptiveOn))
	if !ok {
		t.Fatal("parse returned !ok on known-good input")
	}
	if !aRX || !aTX {
		t.Errorf("want adaptive RX=on TX=on, got RX=%v TX=%v", aRX, aTX)
	}
	if rx != 8 || tx != 8 {
		t.Errorf("want rx/tx usecs = 8/8, got %d/%d", rx, tx)
	}
}

func TestParseEthtoolCoalesce_AdaptiveOff(t *testing.T) {
	rx, tx, aRX, aTX, ok := parseEthtoolCoalesce([]byte(mlx5CoalesceProbeAdaptiveOff))
	if !ok {
		t.Fatal("parse returned !ok on adaptive-off input")
	}
	if aRX || aTX {
		t.Errorf("want adaptive RX=off TX=off, got RX=%v TX=%v", aRX, aTX)
	}
	if rx != 8 || tx != 8 {
		t.Errorf("want rx/tx usecs = 8/8, got %d/%d", rx, tx)
	}
}

func TestParseEthtoolCoalesce_Garbage(t *testing.T) {
	_, _, _, _, ok := parseEthtoolCoalesce([]byte("not ethtool output\n"))
	if ok {
		t.Error("parse on garbage must return ok=false")
	}
}

// applyCoalescence top-level ------------------------------------------

// Non-mlx5 allowlist entries must skip silently — no ethtool call.
func TestApplyCoalescence_NonMlxSkipped(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers: map[string]string{"eth0": "virtio_net"},
	}
	applyCoalescence(false, 8, 8, []string{"eth0"}, f)
	if len(f.calls) != 0 {
		t.Fatalf("non-mlx5 must not trigger ethtool, got %v", f.calls)
	}
}

func TestApplyCoalescence_EmptyAllowlist_NoOp(t *testing.T) {
	f := &fakeRSSExecutor{}
	applyCoalescence(false, 8, 8, nil, f)
	if len(f.calls) != 0 {
		t.Fatalf("empty allowlist must not call ethtool, got %v", f.calls)
	}
}

// Default rx/tx usecs substitution: passing 0 picks up the per-issue
// default (8). Matches the "default 8" ask in the issue body.
func TestApplyCoalescence_ZeroUsecs_SubstitutesDefault(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"mlx0": "mlx5_core"},
		ethtoolC: map[string][]byte{"mlx0": []byte(mlx5CoalesceProbeAdaptiveOn)},
	}
	// rx=0 tx=0 → should resolve to defaultCoalesceRX / defaultCoalesceTX (8).
	applyCoalescence(false, 0, 0, []string{"mlx0"}, f)

	sawWrite := false
	for _, c := range f.calls {
		if len(c) >= 2 && c[0] == "-C" && c[1] == "mlx0" {
			sawWrite = true
			// rx-usecs and tx-usecs should both be "8" after default
			// substitution.
			var rx, tx string
			for i := 0; i < len(c)-1; i++ {
				if c[i] == "rx-usecs" {
					rx = c[i+1]
				}
				if c[i] == "tx-usecs" {
					tx = c[i+1]
				}
			}
			if rx != "8" || tx != "8" {
				t.Errorf("want rx/tx=8/8 after default substitution, got %s/%s", rx, tx)
			}
		}
	}
	if !sawWrite {
		t.Fatalf("expected an ethtool -C write, got %v", f.calls)
	}
}

// Idempotent: when the probe already reflects the requested state, no
// -C write happens.
func TestApplyCoalescence_IdempotentAtTarget(t *testing.T) {
	// Probe says adaptive=off, rx=8, tx=8 — which is exactly the
	// target we're going to request.
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"mlx0": "mlx5_core"},
		ethtoolC: map[string][]byte{"mlx0": []byte(mlx5CoalesceProbeAdaptiveOff)},
	}
	applyCoalescence(false, 8, 8, []string{"mlx0"}, f)
	for _, c := range f.calls {
		if len(c) >= 1 && c[0] == "-C" {
			t.Fatalf("idempotent path must skip -C write, got %v", c)
		}
	}
}

// A probe that says adaptive=on when we want adaptive=off forces a
// rewrite — covers the "#801 disable-adaptive" default case.
func TestApplyCoalescence_AdaptiveOnProbe_ForcesWrite(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"mlx0": "mlx5_core"},
		ethtoolC: map[string][]byte{"mlx0": []byte(mlx5CoalesceProbeAdaptiveOn)},
	}
	applyCoalescence(false, 8, 8, []string{"mlx0"}, f)

	// Expect exactly one -C with adaptive-rx=off adaptive-tx=off.
	sawOff := false
	for _, c := range f.calls {
		if len(c) >= 3 && c[0] == "-C" && c[1] == "mlx0" {
			m := map[string]string{}
			for i := 2; i < len(c)-1; i += 2 {
				m[c[i]] = c[i+1]
			}
			if m["adaptive-rx"] == "off" && m["adaptive-tx"] == "off" &&
				m["rx-usecs"] == "8" && m["tx-usecs"] == "8" {
				sawOff = true
			}
		}
	}
	if !sawOff {
		t.Fatalf("expected ethtool -C mlx0 adaptive-rx off adaptive-tx off rx-usecs 8 tx-usecs 8, got %v", f.calls)
	}
}

// Operator override: `coalescence adaptive enable` must switch the
// target to on and re-invoke ethtool (otherwise the knob is a lie).
func TestApplyCoalescence_AdaptiveEnable_WritesOn(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"mlx0": "mlx5_core"},
		ethtoolC: map[string][]byte{"mlx0": []byte(mlx5CoalesceProbeAdaptiveOff)},
	}
	applyCoalescence(true, 8, 8, []string{"mlx0"}, f)
	sawOn := false
	for _, c := range f.calls {
		if len(c) >= 4 && c[0] == "-C" && c[1] == "mlx0" {
			for i := 2; i < len(c)-1; i += 2 {
				if c[i] == "adaptive-rx" && c[i+1] == "on" {
					sawOn = true
				}
			}
		}
	}
	if !sawOn {
		t.Fatalf("adaptive=enable must write adaptive-rx on, got %v", f.calls)
	}
}

// When ethtool is missing on the host, the probe returns ErrNotFound.
// Must log + skip, not propagate an error.
func TestApplyCoalescence_EthtoolMissing_SkipsGracefully(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers: map[string]string{"mlx0": "mlx5_core"},
		// ethtoolX intentionally unset — runEthtool returns ErrNotFound.
	}
	applyCoalescence(false, 8, 8, []string{"mlx0"}, f)
	// Expect exactly one probe call (the -c) and no -C.
	for _, c := range f.calls {
		if len(c) >= 1 && c[0] == "-C" {
			t.Fatalf("missing ethtool must not trigger a -C write, got %v", f.calls)
		}
	}
}

// Mixed allowlist: only the mlx5 entry gets ethtool calls, virtio is
// ignored. Parallels the D3 mixed-drivers test.
func TestApplyCoalescence_MixedAllowlist_OnlyMlxTouched(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers: map[string]string{
			"mlx0":  "mlx5_core",
			"virt0": "virtio_net",
		},
		ethtoolC: map[string][]byte{"mlx0": []byte(mlx5CoalesceProbeAdaptiveOn)},
	}
	applyCoalescence(false, 8, 8, []string{"virt0", "mlx0"}, f)
	for _, c := range f.calls {
		if len(c) < 2 {
			t.Fatalf("malformed call %v", c)
		}
		if c[1] != "mlx0" {
			t.Fatalf("ethtool invoked on non-mlx iface %q", c[1])
		}
	}
}
