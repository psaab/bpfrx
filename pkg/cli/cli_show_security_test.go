package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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

// matchPoliciesCLITestConfig builds a config with a single trust->untrust
// policy whose terms reference a restricted address-book entry (not
// "any"), so the test exercises the actual #1711 false-positive shape in
// the local in-process simulator.
func matchPoliciesCLITestConfig(t *testing.T) *config.Config {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address trust-net 10.0.1.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy restricted-allow {
                match { source-address trust-net; destination-address trust-net; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	return cfg
}

// TestShowMatchPoliciesValidation covers the local interactive CLI
// simulator (which runs in-process, not via the gRPC handler): malformed
// source/destination IP input must return an error rather than silently
// wildcard-matching, while empty IPs preserve the "any" semantics (#1711).
func TestShowMatchPoliciesValidation(t *testing.T) {
	cfg := matchPoliciesCLITestConfig(t)
	c := &CLI{}

	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		wantMatch bool // for the no-error cases: must the simulator report a match?
	}{
		{
			name:    "invalid source-ip",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.0.999"},
			wantErr: true,
		},
		{
			name:    "invalid destination-ip",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "destination-ip", "garbage"},
			wantErr: true,
		},
		{
			name:    "cidr in ip field rejected",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.0.0/24"},
			wantErr: true,
		},
		{
			name:      "empty ips match any",
			args:      []string{"from-zone", "trust", "to-zone", "untrust"},
			wantErr:   false,
			wantMatch: true,
		},
		{
			name:      "valid in-term ip",
			args:      []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.1.5", "destination-ip", "10.0.1.6"},
			wantErr:   false,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() {
				err = c.showMatchPolicies(cfg, tt.args)
			})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("showMatchPolicies(%v) returned no error; out = %q (false-positive #1711)", tt.args, out)
				}
				if strings.Contains(out, "Matching policy") {
					t.Fatalf("showMatchPolicies(%v) printed a match for malformed input: %q", tt.args, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("showMatchPolicies(%v) error = %v, want nil", tt.args, err)
			}
			// Assert the actual simulator verdict, not just "no error" — a
			// silent default-deny would otherwise pass the no-error cases.
			gotMatch := strings.Contains(out, "Matching policy") && strings.Contains(out, "restricted-allow")
			if gotMatch != tt.wantMatch {
				t.Fatalf("showMatchPolicies(%v) match=%v, want %v; out = %q", tt.args, gotMatch, tt.wantMatch, out)
			}
		})
	}
}

// TestTestPolicyValidation covers the operational `test policy` CLI
// simulator (pkg/cli/cli_request.go testPolicy), a separate in-process
// copy of the matcher. Malformed IPs must error rather than
// wildcard-match; empty/valid inputs report a match (#1711).
func TestTestPolicyValidation(t *testing.T) {
	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address trust-net 10.0.1.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy restricted-allow {
                match { source-address trust-net; destination-address trust-net; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	c := &CLI{store: store}

	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		wantMatch bool
	}{
		{
			name:    "invalid source-ip",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.0.999"},
			wantErr: true,
		},
		{
			name:    "invalid destination-ip",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "destination-ip", "garbage"},
			wantErr: true,
		},
		{
			name:      "empty ips match any",
			args:      []string{"from-zone", "trust", "to-zone", "untrust"},
			wantErr:   false,
			wantMatch: true,
		},
		{
			name:      "valid in-term ip",
			args:      []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.1.5"},
			wantErr:   false,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() {
				err = c.testPolicy(tt.args)
			})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("testPolicy(%v) returned no error; out = %q (false-positive #1711)", tt.args, out)
				}
				if strings.Contains(out, "Policy match") {
					t.Fatalf("testPolicy(%v) printed a match for malformed input: %q", tt.args, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("testPolicy(%v) error = %v, want nil", tt.args, err)
			}
			gotMatch := strings.Contains(out, "Policy match") && strings.Contains(out, "restricted-allow")
			if gotMatch != tt.wantMatch {
				t.Fatalf("testPolicy(%v) match=%v, want %v; out = %q", tt.args, gotMatch, tt.wantMatch, out)
			}
		})
	}
}
