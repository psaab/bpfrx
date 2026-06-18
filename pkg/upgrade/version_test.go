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
		"",                 // empty
		".",                // relative
		"..",               // parent
		"../escape",        // traversal
		"a/b",              // separator
		"/abs",             // leading separator
		".hidden",          // leading dot (dotfile namespace)
		"ver with space",   // whitespace
		"tab\there",        // tab
		"new\nline",        // newline
		"cr\rret",          // carriage return
		"ctrl\x01char",     // control char
		"del\x7fchar",      // DEL
		"trailing ",        // trailing space
		"...current.partial", // leading-dot dotfile collision
	}
	for _, v := range invalid {
		if err := ValidateVersionSegment(v); err == nil {
			t.Errorf("ValidateVersionSegment(%q) = nil, want error", v)
		}
	}
}
