package config

import (
	"fmt"
	"path/filepath"
)

// SyslogLogFileNames returns the operator-configured `system syslog file
// <name>` destination basenames. These are the xpf-managed log files under
// /var/log that a `show log <name>` request is permitted to read.
func (c *Config) SyslogLogFileNames() []string {
	if c == nil || c.System.Syslog == nil {
		return nil
	}
	names := make([]string, 0, len(c.System.Syslog.Files))
	for _, f := range c.System.Syslog.Files {
		if f != nil && f.Name != "" {
			names = append(names, f.Name)
		}
	}
	return names
}

// SyslogLogFilePath validates a `show log <name>` request against the
// configured syslog-file allowlist and returns the absolute /var/log path to
// read. It closes #4860 — the CLI/gRPC `show log` handlers previously shelled
// `tail` on any basename under /var/log, letting a view-only (PermView) account
// read arbitrary root-readable logs (auth.log, audit.log, dpkg.log, ...).
//
// The gate is twofold:
//   - name must be a bare filename (no path separator, no "." / ".." component,
//     not empty) — so a value like "../../etc/shadow" or "/etc/shadow" is
//     refused outright rather than merely base-sanitized; and
//   - name must appear in the `system syslog file` set — nothing else under
//     /var/log is reachable, so the daemon never returns a host log the CLI
//     account was not explicitly granted.
//
// The returned path is always filepath.Join("/var/log", name) for an
// allowlisted name.
func SyslogLogFilePath(cfg *Config, name string) (string, error) {
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
		return "", fmt.Errorf("invalid log file name %q", name)
	}
	for _, allowed := range cfg.SyslogLogFileNames() {
		if allowed == name {
			return filepath.Join("/var/log", name), nil
		}
	}
	return "", fmt.Errorf("log file %q is not a configured 'system syslog file' destination", name)
}
