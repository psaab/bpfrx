package config

import "testing"

// TestSyslogLogFilePath pins #4860: `show log <name>` must be restricted to the
// operator-configured `system syslog file` allowlist so a view-only (PermView)
// account cannot tail an arbitrary root-readable child of /var/log
// (auth.log/audit.log/dpkg.log/...) or traverse out of /var/log.
//
// RED on revert: replacing SyslogLogFilePath with the old
// filepath.Join("/var/log", filepath.Base(name)) accepts every non-allowlisted
// basename, so the "auth.log" / "shadow"-via-traversal denial subtests fail.
func TestSyslogLogFilePath(t *testing.T) {
	cfg := &Config{}
	cfg.System.Syslog = &SystemSyslogConfig{
		Files: []*SyslogFileConfig{
			{Name: "messages"},
			{Name: "security"},
			nil,        // tolerated: skipped
			{Name: ""}, // tolerated: skipped
		},
	}

	// Allowlisted names resolve to /var/log/<name>.
	for _, name := range []string{"messages", "security"} {
		got, err := SyslogLogFilePath(cfg, name)
		if err != nil {
			t.Errorf("SyslogLogFilePath(%q) errored: %v (want allowed)", name, err)
			continue
		}
		if want := "/var/log/" + name; got != want {
			t.Errorf("SyslogLogFilePath(%q) = %q, want %q", name, got, want)
		}
	}

	// Everything else is refused: non-allowlisted host logs, traversal,
	// absolute paths, and the "."/".." components.
	denied := []string{
		"auth.log", "audit.log", "dpkg.log", "syslog", "kern.log",
		"../../etc/shadow", "../messages", "/etc/shadow",
		"a/b", "messages/", ".", "..", "",
	}
	for _, name := range denied {
		if _, err := SyslogLogFilePath(cfg, name); err == nil {
			t.Errorf("SyslogLogFilePath(%q) allowed; want refused", name)
		}
	}
}

// TestSyslogLogFilePathNoSyslogConfig asserts a config with no `system syslog`
// block (nil) has an empty allowlist — every name is refused (fail closed).
func TestSyslogLogFilePathNoSyslogConfig(t *testing.T) {
	if _, err := SyslogLogFilePath(&Config{}, "messages"); err == nil {
		t.Fatal("SyslogLogFilePath with no syslog config allowed a read; want refused")
	}
	if _, err := SyslogLogFilePath(nil, "messages"); err == nil {
		t.Fatal("SyslogLogFilePath(nil, ...) allowed a read; want refused")
	}
}
