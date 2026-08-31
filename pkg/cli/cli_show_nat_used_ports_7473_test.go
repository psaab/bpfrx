package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// usedPortsDP reports a PoolID for every pool and a zero port counter — which
// is exactly what production does for a pool the snapshot builder REFUSED.
// `pkg/dataplane/compiler_nat.go` assigns `PoolIDs` without consulting any
// disarm predicate, so the lookup succeeds and `ReadNATPortCounter` returns 0.
//
// The fixture is therefore not contrived: it reproduces the premise that made
// three surfaces publish an unmeasured zero.
type usedPortsDP struct {
	*dataplane.Manager
	poolIDs map[string]uint8
}

// IsLoaded must be true or `showNATSourcePool` never resolves an apply result,
// the ports block is skipped for BOTH legs, and the disarmed assertion passes
// vacuously. The armed control is what caught that: it failed first.
func (d *usedPortsDP) IsLoaded() bool { return true }

func (d *usedPortsDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{PoolIDs: d.poolIDs}
}
func (d *usedPortsDP) ReadNATPortCounter(uint32) (uint64, error) { return 0, nil }

func usedPortsCLI(poolIDs map[string]uint8) *CLI {
	return &CLI{dp: &usedPortsDP{Manager: dataplane.New(), poolIDs: poolIDs}}
}

// #7473: the live port-usage figures must follow the same disarm verdict the
// NOT INSTALLED / Unusable annotation follows.
//
// Both renderers below already CONSULTED the verdict — which is why neither is
// in the #6534 census: `reachesPredicate` marks a function annotated once it
// consults the predicate anywhere in its body, so a renderer that gates one
// output and not another drops out and is never re-examined (#8185). They
// printed the reason AND an ungated usage number in the same breath.
//
// The two legs are PRESENCE-shaped, not value-shaped, because the value cannot
// separate the states: `ReadNATPortCounter` returns 0 for a refused pool, and 0
// is also the honest reading for a healthy idle one.
func TestSourceNATUsedPortsFollowsTheDisarmVerdict7473(t *testing.T) {
	t.Run("showNATSourcePool", func(t *testing.T) {
		c := usedPortsCLI(map[string]uint8{"p1": 0})

		out := captureStdout(t, func() {
			if err := c.showNATSourcePool(disarmedSourceCfg(), ""); err != nil {
				t.Fatalf("disarmed: %v", err)
			}
		})
		if !strings.Contains(out, "Unusable:") {
			t.Fatalf("the disarmed fixture did not render an Unusable line, so the "+
				"assertion below is not about the gate:\n%s", out)
		}
		if strings.Contains(out, "Ports allocated:") {
			t.Errorf("show security nat source pool printed \"Ports allocated\" for a "+
				"pool it had just declared Unusable. The dataplane installs no "+
				"allocator, so that number was never measured — the view states a "+
				"reason it is not installed and then reports usage as though it "+
				"were (#7473).\ngot:\n%s", out)
		}

		// Control: an armed pool MUST still report its usage, or the fix is
		// "suppress the numbers" rather than "follow the verdict".
		armedOut := captureStdout(t, func() {
			if err := c.showNATSourcePool(armedSourceCfg(), ""); err != nil {
				t.Fatalf("armed: %v", err)
			}
		})
		if !strings.Contains(armedOut, "Ports allocated:") {
			t.Errorf("an ARMED pool no longer reports \"Ports allocated\"; the gate is "+
				"suppressing every pool rather than the refused ones, and the "+
				"disarmed leg above proves nothing.\ngot:\n%s", armedOut)
		}
	})

	t.Run("showNATSourceSummary", func(t *testing.T) {
		c := usedPortsCLI(map[string]uint8{"p1": 0})

		out := captureStdout(t, func() {
			if err := c.showNATSourceSummary(disarmedSourceCfg()); err != nil {
				t.Fatalf("disarmed: %v", err)
			}
		})
		// The row is "<name> <address> <ports> <used> <avail> <util>". For a
		// refused pool every column is N/A after the fix; before it, the used
		// column alone carried a bare 0 above the NOT INSTALLED line.
		if !strings.Contains(out, notInstalled7473) {
			t.Fatalf("the disarmed fixture did not render a NOT INSTALLED line, so "+
				"the assertion below is not about the gate:\n%s", out)
		}
		for _, line := range strings.Split(out, "\n") {
			if !strings.HasPrefix(line, "p1") {
				continue
			}
			if !strings.Contains(line, "N/A") || strings.Fields(line)[3] != "N/A" {
				t.Errorf("the summary row for a REFUSED pool reports a used-ports "+
					"figure: %q. Ports/Available/Utilization already render N/A "+
					"(they are gated on the reportable capacity), so this was the "+
					"one measured-looking number in the row and it is the one "+
					"nobody measured (#7473)", line)
			}
		}

		armedOut := captureStdout(t, func() {
			if err := c.showNATSourceSummary(armedSourceCfg()); err != nil {
				t.Fatalf("armed: %v", err)
			}
		})
		armedUsed := ""
		for _, line := range strings.Split(armedOut, "\n") {
			if strings.HasPrefix(line, "p1") {
				armedUsed = strings.Fields(line)[3]
			}
		}
		if armedUsed == "N/A" || armedUsed == "" {
			t.Errorf("an ARMED pool's summary row reports used=%q; the gate is "+
				"suppressing every pool rather than the refused ones, and the "+
				"disarmed leg above proves nothing.\ngot:\n%s", armedUsed, armedOut)
		}
	})
}

// Guards the premise the whole cell rests on: that a REFUSED pool still gets a
// PoolID in production. If `compiler_nat.go` ever starts consulting the disarm
// verdict, the lookup stops succeeding, the usage number disappears on its own,
// and both legs above would pass without the gates they exist to bind.
func TestRefusedPoolStillCarriesAPoolID7473(t *testing.T) {
	cfg := disarmedSourceCfg()
	if reason := sourceNATPoolNotInstalled(cfg.Security.NAT.SourcePools["p1"]); reason == "" {
		t.Fatal("the disarmed fixture is not disarmed; both legs above are vacuous")
	}
	armed := armedSourceCfg()
	if reason := sourceNATPoolNotInstalled(armed.Security.NAT.SourcePools["p1"]); reason != "" {
		t.Fatalf("the ARMED fixture is disarmed (%q); every control leg above is vacuous", reason)
	}
}
