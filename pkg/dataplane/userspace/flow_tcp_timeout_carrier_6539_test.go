package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6539: the claim the whole fix rests on is that `security flow tcp-session
// initial/closing/time-wait-timeout` have NO dataplane wire carrier — only
// established-timeout does. The three `show` surfaces annotate them as not
// enforced and the commit advisory says so, and all four statements are false
// the moment a carrier appears.
//
// This test binds that claim where it is actually decided: the lowering. It
// serializes the wire snapshot rather than comparing selected fields, so a new
// carrier for any of the three reds here — including one added under a field
// name this test does not know about.
func TestTCPSessionTimeoutsHaveNoWireCarrier_6539(t *testing.T) {
	withAll := &config.Config{}
	withAll.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout: 600,
		InitialTimeout:     45,
		ClosingTimeout:     15,
		TimeWaitTimeout:    90,
	}
	establishedOnly := &config.Config{}
	establishedOnly.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout: 600,
	}

	marshal := func(cfg *config.Config) string {
		t.Helper()
		b, err := json.Marshal(buildFlowSnapshot(cfg))
		if err != nil {
			t.Fatalf("marshal flow snapshot: %v", err)
		}
		return string(b)
	}

	got, want := marshal(withAll), marshal(establishedOnly)
	if got != want {
		t.Fatalf("setting initial/closing/time-wait-timeout changed the wire snapshot, so one of them "+
			"now HAS a carrier — the config.TCPSessionTimeoutLeaves table, the three `show` "+
			"annotations and the #6539 commit advisory all still say it does not.\n"+
			" with all four: %s\nestablished only: %s", got, want)
	}

	// Negative control: established-timeout IS carried, so the same comparison
	// against a config that omits it MUST differ. Without this cell the
	// assertion above would also pass if buildFlowSnapshot stopped carrying
	// anything at all.
	none := &config.Config{}
	none.Security.Flow.TCPSession = &config.TCPSessionConfig{}
	if marshal(establishedOnly) == marshal(none) {
		t.Fatal("dropping established-timeout did not change the wire snapshot either — the " +
			"comparison above is vacuous and buildFlowSnapshot carries no tcp-session timeout at all")
	}

	// And the table must agree with what was just measured.
	for _, e := range config.TCPSessionTimeoutLeaves() {
		if e.Leaf == config.TCPSessionEstablishedTimeoutLeaf {
			if !e.Enforced {
				t.Errorf("established-timeout is carried on the wire but the table marks it unenforced")
			}
			continue
		}
		if e.Enforced {
			t.Errorf("table marks %q enforced, but it does not reach the wire snapshot", e.Leaf)
		}
	}
}
