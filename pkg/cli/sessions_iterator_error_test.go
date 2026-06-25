// #2469: CLI session-derived views (top-talkers, NAT source/destination
// summaries) must NOT print a truncated count as if it were the full
// picture when the backend session iterator errors. Top-talkers fails
// the command (its scan precedes any output); the NAT summaries print a
// stderr WARNING alongside the (now-understated) count.
//
// FAIL-ON-REVERT: restoring `_ = c.dp.IterateSessions(...)` makes
// showTopTalkers return nil (no error) and the NAT summaries print no
// warning — the assertions below go RED.
package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// viewFaultCLIDP fails the session iterators to model a backend (helper)
// error mid-scan. Embeds *dataplane.Manager for the unused surface.
type viewFaultCLIDP struct {
	*dataplane.Manager
	iterErr   error
	iterV6Err error
}

func (d *viewFaultCLIDP) IsLoaded() bool { return true }

func (d *viewFaultCLIDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return d.iterErr
}

func (d *viewFaultCLIDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return d.iterV6Err
}

// LastApplyResult returns a non-nil (empty) ApplyResult so the
// destination-NAT summary's `cr != nil`-gated session-count path is
// reached (showNATDestinationSummary skips the scan otherwise).
func (d *viewFaultCLIDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("stderr close error = %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}
	return string(out)
}

func newViewCLI(t *testing.T, dp cliRuntime) *CLI {
	t.Helper()
	return &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
	}
}

func TestShowTopTalkersFailsOnIteratorError(t *testing.T) {
	dp := &viewFaultCLIDP{
		Manager: dataplane.New(),
		iterErr: fmt.Errorf("helper restart: session map closed"),
	}
	c := newViewCLI(t, dp)

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.showTopTalkers(sessionFilter{sortBy: "bytes"})
	})
	if callErr == nil {
		t.Fatalf("showTopTalkers returned nil error on iterator failure; want error.\noutput:\n%s", out)
	}
	if !strings.Contains(callErr.Error(), "iterate sessions") {
		t.Fatalf("error did not mention iterate sessions: %v", callErr)
	}
}

func TestShowNATSummariesWarnOnIteratorError(t *testing.T) {
	cfg := &config.Config{}
	// One interface-mode source NAT rule-set so showNATSourceSummary
	// reaches the SNAT-session count path, and one destination pool so
	// showNATDestinationSummary reaches the DNAT-session count path.
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "trust-to-untrust",
			FromZone: "trust",
			ToZone:   "untrust",
			Rules: []*config.NATRule{
				{Name: "r1", Then: config.NATThen{Interface: true}},
			},
		},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dpool": {Address: "10.0.0.1"},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name: "dns",
				Rules: []*config.NATRule{
					{Name: "dr1", Then: config.NATThen{PoolName: "dpool"}},
				},
			},
		},
	}

	dp := &viewFaultCLIDP{
		Manager: dataplane.New(),
		iterErr: fmt.Errorf("helper restart: session map closed"),
	}
	c := newViewCLI(t, dp)

	t.Run("source summary", func(t *testing.T) {
		var callErr error
		errOut := captureStderr(t, func() {
			_ = captureStdout(t, func() { callErr = c.showNATSourceSummary(cfg) })
		})
		if callErr != nil {
			t.Fatalf("showNATSourceSummary error = %v", callErr)
		}
		if !strings.Contains(errOut, "warning") || !strings.Contains(errOut, "incomplete") {
			t.Fatalf("source summary did not warn on iterator error; stderr:\n%s", errOut)
		}
	})

	t.Run("destination summary", func(t *testing.T) {
		var callErr error
		errOut := captureStderr(t, func() {
			_ = captureStdout(t, func() { callErr = c.showNATDestinationSummary(cfg) })
		})
		if callErr != nil {
			t.Fatalf("showNATDestinationSummary error = %v", callErr)
		}
		if !strings.Contains(errOut, "warning") || !strings.Contains(errOut, "incomplete") {
			t.Fatalf("destination summary did not warn on iterator error; stderr:\n%s", errOut)
		}
	})
}
