package upgrade

import "testing"

func TestValidateVersionSegment(t *testing.T) {
	valid := []string{
		"1.0.0",
		"2.4.1-rc3",
		"1.0.0+build.7",
		"1:2.3.4-1", // epoch (Debian)
		"1.0.0~beta1",
		"dev",
		"0.0.1_snapshot",
		"v1.2.3",
	}
	for _, v := range valid {
		if err := ValidateVersionSegment(v); err != nil {
			t.Errorf("ValidateVersionSegment(%q) = %v, want nil", v, err)
		}
	}

	invalid := []string{
		"",                   // empty
		".",                  // relative
		"..",                 // parent
		"../escape",          // traversal
		"a/b",                // separator
		"/abs",               // leading separator
		".hidden",            // leading dot (dotfile namespace)
		"ver with space",     // whitespace
		"tab\there",          // tab
		"new\nline",          // newline
		"cr\rret",            // carriage return
		"ctrl\x01char",       // control char
		"del\x7fchar",        // DEL
		"trailing ",          // trailing space
		"...current.partial", // leading-dot dotfile collision
		"1.0.0é",             // non-ASCII (parity with shell tr -d [:graph:])
		"veré",               // non-ASCII rune
		// #5713 M41: '%' is a systemd unit specifier — a version carrying it
		// would rewrite the pinned ExecStart path when substituted into the
		// unit drop-in. These MUST be rejected (fail-on-revert: without the
		// strict allowlist, '%' passes as a "safe path segment" and lands in
		// ExecStart, where systemd expands it).
		"%i",    // bare systemd instance specifier
		"1.0%n", // %n = unit name
		"100%",  // trailing percent
		"%%",    // escaped percent (still not a legal version char)
		// Other systemd argv metacharacters, also illegal in Debian/semver.
		"1.0.0$x",  // env-var expansion
		`1.0.0"x`,  // argv quote
		`1.0.0\x`,  // argv escape
		"1.0.0`x",  // backtick
		"1.0*",     // glob (harmless in a path, but not a version char)
		"1.0.0;rm", // shell metachar (not that ExecStart runs a shell, but not a version char)
		"1.0 2.0",  // embedded space
		"a,b",      // comma
		"a=b",      // equals
	}
	for _, v := range invalid {
		if err := ValidateVersionSegment(v); err == nil {
			t.Errorf("ValidateVersionSegment(%q) = nil, want error", v)
		}
	}
}
