package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #6515 requirement (b): the migration advisory must reach the operator who
// types `commit`, not only the one who types `commit check`.
//
// The advisory warns that a per-interface host-inbound-traffic stanza REPLACES
// the zone-level one, so services the zone admits are now DENIED on that
// interface — and that established sessions to them are FLUSHED at commit
// (#5566), not merely refused for new connections. An operator who never runs
// `commit check` is exactly the operator who most needs to read that before
// their shell dies, so "it is emitted at commit-check time" is not good enough
// and must not be inferred from how sibling validators are wired.
//
// These tests DRIVE the real handlers — the same `handleCommit` entry the
// interactive CLI dispatches to, over a real configstore — and read what the
// operator would actually see on stdout. They deliberately do not assert on
// `cfg.Warnings`: the question is not whether the warning is produced, it is
// whether it is PRINTED.

// newCLIHostInboundNarrowingStore stages a candidate whose per-interface
// host-inbound stanza takes `ssh` away from an interface the zone admits it on
// — the #6515 narrowing the advisory exists to announce.
func newCLIHostInboundNarrowingStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ping",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	return store
}

// assertNarrowingAdvisory checks the operator-visible output carries the
// advisory, names the zone/interface/token that is being taken away, AND says
// established sessions are flushed. The flush sentence is asserted separately
// because it is the half an operator's instinct gets wrong: reading only "ssh
// will no longer be admitted here" invites "fine, I am already connected, I
// will fix it afterwards", which is false — the commit drops the live session.
func assertNarrowingAdvisory(t *testing.T, where, out string) {
	t.Helper()
	for _, want := range []string{
		"REPLACES the zone-level stanza",
		`zone "trust"`,
		`interface "ge-0/0/0.0"`,
		"ssh",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%s output does not mention %q — the operator cannot act on an advisory "+
				"that does not name what it is taking away.\n--- output ---\n%s", where, want, out)
		}
	}
	if !strings.Contains(out, "flushed") {
		t.Errorf("%s output does not say established sessions are FLUSHED. Without it an "+
			"operator reads 'ssh is no longer admitted' and concludes 'I am already "+
			"connected, I will fix it after' — which is wrong: the #5566 reconcile deletes "+
			"the established conntrack entry at commit.\n--- output ---\n%s", where, out)
	}
}

// TestHostInboundNarrowingAdvisorySurfacesOnPlainCommit is the requirement: an
// operator who types `commit` and never runs `commit check` still sees it.
func TestHostInboundNarrowingAdvisorySurfacesOnPlainCommit_6515(t *testing.T) {
	c := &CLI{store: newCLIHostInboundNarrowingStore(t)}

	var callErr error
	out := captureStdout(t, func() { callErr = c.handleCommit(nil) })
	if callErr != nil {
		t.Fatalf("commit failed: %v (the advisory is WARN-only and must never reject)", callErr)
	}
	if !strings.Contains(out, "commit complete") {
		t.Fatalf("commit did not complete; out=%q", out)
	}
	assertNarrowingAdvisory(t, "plain `commit`", out)
}

// TestHostInboundNarrowingAdvisorySurfacesOnCommitCheck is the control: the
// check path shows it too. Asserting only the commit path would leave a
// regression that moved the advisory to commit-only looking like a pass.
func TestHostInboundNarrowingAdvisorySurfacesOnCommitCheck_6515(t *testing.T) {
	c := &CLI{store: newCLIHostInboundNarrowingStore(t)}

	var callErr error
	out := captureStdout(t, func() { callErr = c.handleCommit([]string{"check"}) })
	if callErr != nil {
		t.Fatalf("commit check failed: %v", callErr)
	}
	if !strings.Contains(out, "configuration check succeeds") {
		t.Fatalf("commit check did not succeed; out=%q", out)
	}
	assertNarrowingAdvisory(t, "`commit check`", out)
}

// TestHostInboundNarrowingAdvisorySurfacesOnCommitConfirmed covers the third
// operator entry point. `commit confirmed` is the one an operator reaches for
// when they suspect a change might lock them out, so an advisory about being
// locked out that is missing precisely there would be the worst gap of the
// three.
func TestHostInboundNarrowingAdvisorySurfacesOnCommitConfirmed_6515(t *testing.T) {
	c := &CLI{store: newCLIHostInboundNarrowingStore(t)}

	var callErr error
	out := captureStdout(t, func() { callErr = c.handleCommit([]string{"confirmed", "5"}) })
	if callErr != nil {
		t.Fatalf("commit confirmed failed: %v", callErr)
	}
	assertNarrowingAdvisory(t, "`commit confirmed`", out)
}

// TestNoNarrowingAdvisoryWhenNothingIsLost is the anti-vacuity control: a
// candidate whose interface stanza repeats the zone token loses nothing and
// must commit silently. Without it, all three assertions above would be
// satisfied by an advisory that fires on every commit.
func TestNoNarrowingAdvisoryWhenNothingIsLost_6515(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ping",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	c := &CLI{store: store}

	out := captureStdout(t, func() {
		if err := c.handleCommit(nil); err != nil {
			t.Fatalf("commit failed: %v", err)
		}
	})
	if strings.Contains(out, "REPLACES the zone-level stanza") {
		t.Fatalf("the interface stanza repeats the zone's ssh, so nothing is lost and the "+
			"advisory must stay silent — one that fires on every commit is one operators "+
			"learn to ignore.\n--- output ---\n%s", out)
	}
}
