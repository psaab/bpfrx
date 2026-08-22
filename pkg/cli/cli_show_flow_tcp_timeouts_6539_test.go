package cli

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// flowTimeoutStore commits the given set lines and returns the store.
func flowTimeoutStore(t *testing.T, lines []string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range lines {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// #6539: `show security flow` must not render the three tcp-session timeouts
// that have NO dataplane wire carrier in the same shape as established-timeout,
// which does. The annotation is read from config.TCPSessionTimeoutNote, binding
// this surface to the same authority the REST and gRPC surfaces use.
func TestShowFlowTimeoutsAnnotateUnenforced_6539(t *testing.T) {
	c := &CLI{store: flowTimeoutStore(t, []string{
		"set security flow tcp-session established-timeout 600",
		"set security flow tcp-session initial-timeout 45",
		"set security flow tcp-session closing-timeout 15",
		"set security flow tcp-session time-wait-timeout 90",
	})}

	out := captureStdout(t, func() {
		if err := c.showFlowTimeouts(); err != nil {
			t.Fatalf("showFlowTimeouts() error = %v", err)
		}
	})

	lineWith := func(sub string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, sub) {
				return l
			}
		}
		return ""
	}

	for _, tc := range []struct {
		label string
		leaf  string
		value string
	}{
		{"TCP initial timeout", config.TCPSessionInitialTimeoutLeaf, "45s"},
		{"TCP closing timeout", config.TCPSessionClosingTimeoutLeaf, "15s"},
		{"TCP time-wait timeout", config.TCPSessionTimeWaitTimeoutLeaf, "90s"},
	} {
		line := lineWith(tc.label + ":")
		if line == "" {
			t.Errorf("no %q row rendered; the operator surface vanished.\n%s", tc.label, out)
			continue
		}
		if !strings.Contains(line, tc.value) {
			t.Errorf("%s row lost the configured value %s: %q", tc.label, tc.value, line)
		}
		note := config.TCPSessionTimeoutNote(tc.leaf)
		if note == "" {
			t.Fatalf("config table says %q is enforced; this test is stale", tc.leaf)
		}
		if !strings.Contains(line, note) {
			t.Errorf("%s row does not carry the shared not-enforced annotation, so the CLI reports "+
				"a value in force.\n got: %q\nwant substring: %q", tc.label, line, note)
		}
	}

	est := lineWith("TCP established timeout:")
	if est == "" {
		t.Fatalf("no TCP established row rendered.\n%s", out)
	}
	if !strings.Contains(est, "600s") {
		t.Errorf("TCP established row lost its value: %q", est)
	}
	if strings.Contains(est, "not enforced") {
		t.Errorf("established-timeout is wire-carried and must render unannotated: %q", est)
	}
}

// With NO tcp-session stanza at all, every row must still render, and the
// "(default)" it prints must be the window the DATAPLANE falls back to — not
// the Junos default the CLI used to print. A default value is itself an
// enforcement claim: before #6539 the CLI said an unset established-timeout
// meant 1800s, when nothing in the Go path fills that in and the helper
// actually idles the session out at its own constant.
//
// time-wait has no dataplane window at all (no TIME_WAIT state), so it must
// NOT claim a default.
func TestShowFlowTimeoutsUnsetDefaultsAreTheDataplanes_6539(t *testing.T) {
	c := &CLI{store: flowTimeoutStore(t, []string{"set security zones security-zone trust"})}

	out := captureStdout(t, func() {
		if err := c.showFlowTimeouts(); err != nil {
			t.Fatalf("showFlowTimeouts() error = %v", err)
		}
	})

	lineWith := func(sub string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, sub) {
				return l
			}
		}
		return ""
	}

	est := lineWith("TCP established timeout:")
	if est == "" {
		t.Fatalf("no TCP established row rendered for an absent tcp-session stanza.\n%s", out)
	}
	if strings.Contains(est, "1800s") {
		t.Errorf("unset established-timeout still renders the Junos 1800s default, which this "+
			"dataplane does not use: %q", est)
	}
	wantEst := strconv.Itoa(config.DataplaneTCPEstablishedWindowSecs) + "s (default)"
	if !strings.Contains(est, wantEst) {
		t.Errorf("unset established-timeout must render the dataplane fallback %q: %q", wantEst, est)
	}

	init := lineWith("TCP initial timeout:")
	wantInit := strconv.Itoa(config.DataplaneTCPOpeningWindowSecs) + "s (default)"
	if !strings.Contains(init, wantInit) {
		t.Errorf("unset initial-timeout must render the dataplane half-open window %q: %q", wantInit, init)
	}
	if !strings.Contains(init, config.TCPSessionTimeoutNote(config.TCPSessionInitialTimeoutLeaf)) {
		t.Errorf("unset initial-timeout row lost its not-enforced annotation: %q", init)
	}

	tw := lineWith("TCP time-wait timeout:")
	if tw == "" {
		t.Fatalf("no TCP time-wait row rendered.\n%s", out)
	}
	if strings.Contains(tw, "(default)") {
		t.Errorf("the dataplane has no TIME_WAIT state, so time-wait must claim no default: %q", tw)
	}
	if !strings.Contains(tw, "not set") {
		t.Errorf("unset time-wait-timeout should render as not set: %q", tw)
	}
}
