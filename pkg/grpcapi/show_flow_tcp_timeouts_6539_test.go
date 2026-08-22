package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6539: `show security flow` must not render the three tcp-session timeouts
// that have NO dataplane wire carrier in the same shape as established-timeout,
// which does. This is the surface an operator reads AFTER committing, so the
// commit-time advisory does not cover it — a box configured by someone else, or
// before an upgrade, shows this and nothing else.
//
// The expected annotation is read from config.TCPSessionTimeoutNote rather than
// spelled here, so this test binds the surface to the single authority the REST
// and CLI surfaces also render through. A surface that hard-codes its own
// wording reds here even if the wording reads correctly.
func TestShowFlowTCPTimeoutsAnnotateUnenforced_6539(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout: 600,
		InitialTimeout:     45,
		ClosingTimeout:     15,
		TimeWaitTimeout:    90,
	}

	var buf strings.Builder
	(&Server{}).showFlowTimeouts(cfg, &buf)
	got := buf.String()

	lineWith := func(sub string) string {
		for _, l := range strings.Split(got, "\n") {
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
		{"TCP initial", config.TCPSessionInitialTimeoutLeaf, "45s"},
		{"TCP closing", config.TCPSessionClosingTimeoutLeaf, "15s"},
		{"TCP time-wait", config.TCPSessionTimeWaitTimeoutLeaf, "90s"},
	} {
		line := lineWith(tc.label + ":")
		if line == "" {
			t.Errorf("no %q row rendered at all; the operator surface vanished.\n%s", tc.label, got)
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
			t.Errorf("%s row does not carry the shared not-enforced annotation, so it reads as a "+
				"value in force.\n got: %q\nwant substring: %q", tc.label, line, note)
		}
	}

	// established-timeout IS carried to the dataplane and must stay
	// unannotated — otherwise the annotation is decoration applied to every
	// row and tells an operator nothing about which knob works.
	est := lineWith("TCP established:")
	if est == "" {
		t.Fatalf("no TCP established row rendered.\n%s", got)
	}
	if !strings.Contains(est, "600s") {
		t.Errorf("TCP established row lost its value: %q", est)
	}
	if strings.Contains(est, "not enforced") {
		t.Errorf("established-timeout is wire-carried and must render unannotated: %q", est)
	}
}
