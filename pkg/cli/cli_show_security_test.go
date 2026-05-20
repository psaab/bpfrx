package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type firewallFilterUserspaceDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
}

func (f *firewallFilterUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

func newFirewallFilterTestStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter bandwidth-output term 0 from destination-port 80",
		"firewall family inet filter bandwidth-output term 0 then accept",
		"firewall family inet6 filter bandwidth-output term 0 from destination-port 5201",
		"firewall family inet6 filter bandwidth-output term 0 then count iperf-a-v6",
		"firewall family inet6 filter bandwidth-output term 0 then accept",
		"firewall family inet6 filter bandwidth-output term 1 from destination-port 5300",
		"firewall family inet6 filter bandwidth-output term 1 then accept",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestHandleShowFirewallFilterHonorsFamilyAndUserspaceCounters(t *testing.T) {
	store := newFirewallFilterTestStore(t)
	c := &CLI{
		store: store,
		dp: &firewallFilterUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
					{
						Family:     "inet6",
						FilterName: "bandwidth-output",
						TermName:   "0",
						Packets:    12,
						Bytes:      3456,
					},
				},
			},
		},
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleShow([]string{"firewall", "filter", "bandwidth-output", "family", "inet6"})
	})
	if callErr != nil {
		t.Fatalf("handleShow() error = %v", callErr)
	}
	if !strings.Contains(out, "Filter: bandwidth-output (family inet6)") {
		t.Fatalf("output = %q, want inet6 filter heading", out)
	}
	if strings.Contains(out, "destination-port 80") {
		t.Fatalf("output = %q, unexpectedly rendered inet family term", out)
	}
	if !strings.Contains(out, "destination-port 5201") {
		t.Fatalf("output = %q, want inet6 destination-port 5201", out)
	}
	if !strings.Contains(out, "Hit count: 12 packets, 3456 bytes") {
		t.Fatalf("output = %q, want userspace hit counters", out)
	}
	if strings.Count(out, "Hit count:") != 1 {
		t.Fatalf("output = %q, want a hit count only for the counted term", out)
	}
}

func TestScreenSYNCookieCounterRowsUsesUserspaceStatus(t *testing.T) {
	c := &CLI{
		dp: &firewallFilterUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				Bindings: []dpuserspace.BindingStatus{
					{
						SYNCookieChallenges:        3,
						SYNCookieSecretUnavailable: 5,
						SYNCookieSynAckSent:        7,
						SYNCookieAckRstSent:        11,
						SYNCookieReplyBudgetDrops:  13,
						SYNCookieAckValid:          17,
						SYNCookieAckInvalid:        19,
						SYNCookieBypass:            23,
					},
					{
						SYNCookieChallenges:        17,
						SYNCookieSecretUnavailable: 19,
						SYNCookieSynAckSent:        29,
						SYNCookieAckRstSent:        31,
						SYNCookieReplyBudgetDrops:  37,
						SYNCookieAckValid:          41,
						SYNCookieAckInvalid:        43,
						SYNCookieBypass:            47,
					},
				},
			},
		},
	}

	out := c.screenSYNCookieCounterRows()
	for _, want := range []string{
		"Userspace SYN-cookie scope",
		"all bindings",
		"SYN-cookie challenges",
		"20",
		"SYN-cookie secret unavailable",
		"24",
		"SYN-cookie SYN-ACK sent",
		"36",
		"SYN-cookie ACK RST sent",
		"42",
		"SYN-cookie budget drops",
		"50",
		"SYN-cookie ACK valid",
		"58",
		"SYN-cookie ACK invalid",
		"62",
		"SYN-cookie bypass",
		"70",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("screen SYN-cookie rows missing %q:\n%s", want, out)
		}
	}
}
