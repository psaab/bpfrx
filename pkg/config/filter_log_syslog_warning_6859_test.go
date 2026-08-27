package config

import (
	"strings"
	"testing"
)

// filter_log_syslog_warning_6859_test.go — #6859, the advisory half.
//
// Correcting the routing is right AND it silently stops a stream some
// deployments may have built alerting or retention on. The advisory is what
// makes that break visible at commit, while the operator has the config in
// front of them — so it is load-bearing, and it is a CLAIM that owes a test in
// all three directions:
//
//   - it fires for a `then log` term when syslog streams are configured;
//   - it does NOT fire when no stream is configured (nothing was leaving the
//     box, so nothing changed and a warning would be noise);
//   - it does NOT fire for `then syslog`, whose destination is unchanged.
//
// The middle cell is the one that would be missing from a happy-path-only test,
// and its absence is exactly what would let a warning that fires
// UNCONDITIONALLY ship: a fixture that always configures a stream cannot see
// the difference.

func setTree6859(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// filterLogAdvisory6859 returns the #6859 advisory from a compiled config, or
// "" when it did not fire. It matches on the distinctive clause rather than the
// whole sentence so a wording change does not red every cell — but the clause
// is specific enough that another warning cannot satisfy it.
func filterLogAdvisory6859(t *testing.T, tree *ConfigTree) string {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "'then log' no longer forwards") {
			return w
		}
	}
	return ""
}

// streamCmds6859 configures one remote syslog stream — the state in which
// filter-log events actually leave the box.
func streamCmds6859() []string {
	return []string{
		"set security log stream collector host 10.9.9.9",
		"set security log stream collector severity info",
	}
}

// logOnlyFilterCmds6859 defines a filter term carrying `then log` and nothing
// else — the term that loses a destination.
func logOnlyFilterCmds6859() []string {
	return []string{
		"set firewall family inet filter WATCH term t1 from protocol tcp",
		"set firewall family inet filter WATCH term t1 then log",
		"set firewall family inet filter WATCH term t1 then accept",
	}
}

func TestThenLogAdvisoryFiresWhenAStreamIsConfigured6859(t *testing.T) {
	tree := setTree6859(t, append(streamCmds6859(), logOnlyFilterCmds6859()...)...)

	got := filterLogAdvisory6859(t, tree)
	if got == "" {
		t.Fatal("no #6859 advisory: a `then log` term lost its syslog destination " +
			"and the operator was told nothing")
	}
	// It must NAME the term. A warning that says "some terms changed" is not
	// actionable, and naming is the whole reason this ships with the change
	// rather than as a release note.
	if !strings.Contains(got, "WATCH term t1") {
		t.Fatalf("advisory does not name the affected term, so the operator cannot "+
			"act on it: %q", got)
	}
	// And it must point at the remedy.
	if !strings.Contains(got, "then syslog") {
		t.Fatalf("advisory does not name the one-line remedy: %q", got)
	}
	// It must NOT read as a deprecation: `then log` is the correct Junos
	// spelling and is not going away. Telling operators otherwise sends them to
	// change configs that are already right.
	if strings.Contains(strings.ToLower(got), "deprecat") {
		t.Fatalf("advisory reads as a deprecation notice, but `then log` is correct "+
			"and is not going away: %q", got)
	}
}

// TestThenLogAdvisorySilentWithNoStream6859 is the MIDDLE cell.
//
// With no stream configured the daemon installs no syslog clients
// (applySecurityLogConfig clears them), so a `then log` hit was never leaving
// the box and this change took nothing away. A warning here would be pure noise
// on every standalone box.
//
// Deleting the stream half of the predicate leaves the cell above green and
// only this one reds.
func TestThenLogAdvisorySilentWithNoStream6859(t *testing.T) {
	tree := setTree6859(t, logOnlyFilterCmds6859()...)

	if got := filterLogAdvisory6859(t, tree); got != "" {
		t.Fatalf("the #6859 advisory fired on a box with NO syslog stream, where "+
			"nothing was being forwarded and nothing changed: %q", got)
	}
}

// TestThenLogAdvisorySilentInEventMode6859 is the second half of the same
// predicate. `security log mode event` writes local files and explicitly clears
// the syslog clients, so it is the other configuration in which nothing left
// the box.
func TestThenLogAdvisorySilentInEventMode6859(t *testing.T) {
	cmds := append([]string{"set security log mode event"}, logOnlyFilterCmds6859()...)
	// A stream is present too, to prove `mode event` is what silences it rather
	// than the absence of a stream (which the previous cell already owns).
	cmds = append(cmds, streamCmds6859()...)
	tree := setTree6859(t, cmds...)

	if got := filterLogAdvisory6859(t, tree); got != "" {
		t.Fatalf("the #6859 advisory fired in `security log mode event`, which "+
			"installs local writers and no syslog clients: %q", got)
	}
}

// TestThenSyslogDoesNotWarn6859 is the third direction: a term that already
// says `then syslog` keeps its destination, so there is nothing to report.
//
// Without this, "warn about filter terms" is satisfied by a warning that fires
// for every logging term, which would tell operators their correct configs
// broke.
func TestThenSyslogDoesNotWarn6859(t *testing.T) {
	tree := setTree6859(t, append(streamCmds6859(),
		"set firewall family inet filter WATCH term t1 from protocol tcp",
		"set firewall family inet filter WATCH term t1 then syslog",
		"set firewall family inet filter WATCH term t1 then accept",
	)...)

	if got := filterLogAdvisory6859(t, tree); got != "" {
		t.Fatalf("the #6859 advisory fired for a `then syslog` term, whose "+
			"destination is unchanged: %q", got)
	}
}

// TestThenLogAdvisoryCoversInet6Filters6859 guards the family loop. An
// inet6-only config loses exactly the same stream, and a collector walking only
// FiltersInet would report a clean commit while the feed stopped.
func TestThenLogAdvisoryCoversInet6Filters6859(t *testing.T) {
	tree := setTree6859(t, append(streamCmds6859(),
		"set firewall family inet6 filter V6WATCH term t6 from next-header tcp",
		"set firewall family inet6 filter V6WATCH term t6 then log",
		"set firewall family inet6 filter V6WATCH term t6 then accept",
	)...)

	got := filterLogAdvisory6859(t, tree)
	if got == "" {
		t.Fatal("no #6859 advisory for an inet6-only filter — the family loop is " +
			"walking inet only")
	}
	if !strings.Contains(got, "V6WATCH term t6") {
		t.Fatalf("advisory does not name the inet6 term: %q", got)
	}
}
