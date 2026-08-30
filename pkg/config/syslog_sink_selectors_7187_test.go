package config

import (
	"strings"
	"testing"
)

// #7187: the `file` and `user` syslog sinks discarded every authored selector
// but the last.
//
// SyslogFileConfig / SyslogUserConfig held a SCALAR facility/severity pair, and
// the compiler ASSIGNED into it inside the per-child loop:
//
//	file.Facility = fac; file.Severity = sev
//
// So `file messages { daemon info; authorization warning; }` compiled to
// exactly one selector — `authorization warning`, the last one parsed. The
// earlier pairs were gone before any renderer, validator or `show` command
// could see them, which is why no diagnostic ever fired: the operator's config
// was silently reduced at compile time. The host sink already appended into
// SyslogHostConfig.Facilities; this brings the other two sinks to that shape.
//
// WHY THE FIXTURE HAS THREE SELECTORS, NOT TWO. With two, an implementation
// that keeps the FIRST (the other obvious wrong answer) and one that keeps them
// all are distinguished, but an implementation that keeps the first TWO is not.
// Three separates every "keeps a prefix" and "keeps a suffix" variant from
// "keeps them all", and the ORDER assertion below then has something to say.
func compileSyslogSinks(t *testing.T, lines ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func selectorPairs(sels []SyslogFacility) string {
	parts := make([]string, 0, len(sels))
	for _, s := range sels {
		parts = append(parts, s.Facility+"."+s.Severity)
	}
	return strings.Join(parts, " ")
}

func TestSyslogFileKeepsEverySelector7187(t *testing.T) {
	cfg := compileSyslogSinks(t,
		"set system syslog file messages daemon info",
		"set system syslog file messages authorization warning",
		"set system syslog file messages change-log any",
	)
	files := cfg.System.Syslog.Files
	if len(files) != 1 {
		t.Fatalf("compiled %d file destinations, want 1", len(files))
	}
	got := selectorPairs(files[0].Selectors)
	want := "daemon.info authorization.warning change-log.any"
	if got != want {
		t.Errorf("file `messages` kept selectors %q, want %q.\n"+
			"Every selector the operator authored under one `file` stanza must survive "+
			"compilation, in config order. Keeping only the last one is the #7187 defect: "+
			"the discard happens in the compiler, so nothing downstream can warn about it.",
			got, want)
	}
}

func TestSyslogUserKeepsEverySelector7187(t *testing.T) {
	cfg := compileSyslogSinks(t,
		"set system syslog user * daemon info",
		"set system syslog user * authorization warning",
		"set system syslog user * change-log any",
	)
	users := cfg.System.Syslog.Users
	if len(users) != 1 {
		t.Fatalf("compiled %d user destinations, want 1", len(users))
	}
	got := selectorPairs(users[0].Selectors)
	want := "daemon.info authorization.warning change-log.any"
	if got != want {
		t.Errorf("user `*` kept selectors %q, want %q (#7187)", got, want)
	}
}

// The RECOGNIZED-MODIFIER interaction. #4303 S-1 made the sink loops switch on
// known non-selector sub-statements (match, structured-data, archive, ...)
// before the facility/severity fallback. Appending rather than assigning must
// not reopen that: a modifier must still not become a selector, and — the part
// a two-line fixture cannot see — a modifier sitting BETWEEN two selectors must
// not truncate the list either.
func TestSyslogSinkModifiersAreNotSelectors7187(t *testing.T) {
	cfg := compileSyslogSinks(t,
		"set system syslog file messages daemon info",
		"set system syslog file messages structured-data",
		"set system syslog file messages explicit-priority",
		"set system syslog file messages authorization warning",
	)
	got := selectorPairs(cfg.System.Syslog.Files[0].Selectors)
	want := "daemon.info authorization.warning"
	if got != want {
		t.Errorf("file selectors = %q, want %q.\n"+
			"Either a recognized modifier (structured-data / explicit-priority) was "+
			"captured as a bogus selector — the #4303 S-1 defect — or a modifier between "+
			"two selectors truncated the list.", got, want)
	}
}

// A SINGLE selector is the overwhelmingly common config and must be unchanged.
// This is the control that keeps the two cells above from passing on an
// implementation that, say, prepends a synthetic entry.
func TestSyslogSinkSingleSelectorUnchanged7187(t *testing.T) {
	cfg := compileSyslogSinks(t, "set system syslog file messages any info")
	if got := selectorPairs(cfg.System.Syslog.Files[0].Selectors); got != "any.info" {
		t.Errorf("single-selector file = %q, want %q", got, "any.info")
	}
	cfg = compileSyslogSinks(t, "set system syslog user root any emergency")
	if got := selectorPairs(cfg.System.Syslog.Users[0].Selectors); got != "any.emergency" {
		t.Errorf("single-selector user = %q, want %q", got, "any.emergency")
	}
}
