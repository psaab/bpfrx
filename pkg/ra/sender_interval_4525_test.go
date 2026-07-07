package ra

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestRandomAdvInterval_NeverZero is the #4525 RED-on-revert guard: the
// unsolicited periodic RA timer must never be armed with a 0 (or sub-second)
// delay. Before the fix, max-advertisement-interval 1 gave minI=maxI/3=0 and
// rand.IntN(2) drew 0 ~50% of the time → advTimer.Reset(0) fired immediately
// → sendRA re-armed in a tight loop (RA/ND flood + CPU spin). We draw many
// samples across the smallest legacy-reachable maxI values; every draw MUST
// be >= 1s. On revert (no runtime floor) a maxI of 1 or 2 yields a 0 within a
// handful of iterations, failing this test.
func TestRandomAdvInterval_NeverZero(t *testing.T) {
	for _, maxI := range []int{1, 2, 3, 4} {
		s := newSender(&config.RAInterfaceConfig{MaxAdvInterval: maxI}, nil)
		for i := 0; i < 2000; i++ {
			d := s.randomAdvInterval()
			if d < minAdvInterval {
				t.Fatalf("maxI=%d draw %d: randomAdvInterval()=%v, want >= %v (0-delay hot-loop)",
					maxI, i, d, minAdvInterval)
			}
		}
	}
}

// TestRandomAdvInterval_ZeroConfigUsesDefault confirms the unconfigured path
// (both intervals 0 → default 600s max, minI=200) is unaffected by the floor:
// draws stay in the RFC jitter window and are always well above the 1s floor.
func TestRandomAdvInterval_ZeroConfigUsesDefault(t *testing.T) {
	s := newSender(&config.RAInterfaceConfig{}, nil)
	for i := 0; i < 2000; i++ {
		d := s.randomAdvInterval()
		if d < minAdvInterval {
			t.Fatalf("default draw %d: randomAdvInterval()=%v, want >= %v", i, d, minAdvInterval)
		}
		if d > time.Duration(defaultMaxAdvInterval)*time.Second {
			t.Fatalf("default draw %d: randomAdvInterval()=%v exceeds max %ds", i, d, defaultMaxAdvInterval)
		}
	}
}
