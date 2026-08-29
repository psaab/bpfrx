package natshow

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7173: a `port no-translation` source pool must not be shown with a port
// range it does not use.
//
// The dataplane takes the address-only path for such a pool and ignores the
// range entirely (the #3906 note in pkg/dataplane/userspace/nat_source.go says
// so). The display nonetheless printed "Port range: 1024-65535" — and those
// numbers were a default the display invented locally, not anything the
// operator configured. An operator reading that was told the pool uses a port
// range that plays no part in its behaviour.
//
// Both directions are asserted. Showing the range for a NORMAL pool is correct
// and must survive: a fix that simply stopped printing the line would satisfy
// the no-translation assertion while removing real information from every other
// pool.

func renderSourcePools(t *testing.T, cfg *config.Config) string {
	t.Helper()
	var buf bytes.Buffer
	RenderSourceRuleDetail(&buf, cfg, nil, nil)
	return buf.String()
}

func poolCfg(noTranslation bool) *config.Config {
	pool := &config.NATPool{
		Name:              "p1",
		Addresses:         []string{"198.51.100.10"},
		PortNoTranslation: noTranslation,
	}
	if !noTranslation {
		pool.PortLow, pool.PortHigh = 5000, 6000
	}
	return &config.Config{
		Security: config.SecurityConfig{
			NAT: config.NATConfig{
				SourcePools: map[string]*config.NATPool{"p1": pool},
				Source: []*config.NATRuleSet{
					{
						Name: "rs1",
						Rules: []*config.NATRule{
							{Name: "r1", Then: config.NATThen{PoolName: "p1"}},
						},
					},
				},
			},
		},
	}
}

func TestNoTranslationPoolShowsNoPortRange7173(t *testing.T) {
	out := renderSourcePools(t, poolCfg(true))

	if strings.Contains(out, "Port range:") {
		t.Errorf("a `port no-translation` pool was shown with a Port range line. The pool "+
			"does not translate the source port at all, and the numbers printed were a "+
			"default the display invented locally — not configuration (#7173).\ngot:\n%s", out)
	}
	if !strings.Contains(out, "Port translation:") {
		t.Errorf("the no-translation state must be REPORTED, not merely omitted — an "+
			"operator needs to see that port translation is off, and silence reads as "+
			"'not applicable' rather than 'disabled'.\ngot:\n%s", out)
	}
}

// Control: a normal pool must STILL show its configured range. Without this,
// deleting the line entirely passes the cell above while hiding real
// information from every pool that does translate ports.
func TestNormalPoolStillShowsItsPortRange7173(t *testing.T) {
	out := renderSourcePools(t, poolCfg(false))

	if !strings.Contains(out, "Port range:") {
		t.Fatalf("a normal pool must still show its port range.\ngot:\n%s", out)
	}
	if !strings.Contains(out, "5000-6000") {
		t.Errorf("the CONFIGURED range must be shown, not a default: want 5000-6000.\ngot:\n%s", out)
	}
}
