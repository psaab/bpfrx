package daemon

// #5011 render-side belt (defense-in-depth): applyTimezone builds the
// /etc/localtime symlink target from the operator-supplied `system time-zone`
// value. Even if a traversal value slips past the strict commit-check
// (config.ValidateTimeZone) on the tolerant load / peer-sync path (#1960),
// zoneinfoTarget must refuse a target that escapes /usr/share/zoneinfo, so
// applyTimezone's `if !ok { return }` guard never points /etc/localtime out of
// the zoneinfo tree.
//
// Fail-on-revert: make zoneinfoTarget's containment check always succeed (or
// run against origin/master, which built target with a bare string concat and
// no containment test) and the "escapes" assertions below fire.

import "testing"

func TestZoneinfoTarget_ContainsValid_5011(t *testing.T) {
	cases := map[string]string{
		"UTC":                 "/usr/share/zoneinfo/UTC",
		"America/Los_Angeles": "/usr/share/zoneinfo/America/Los_Angeles",
		"Etc/GMT+5":           "/usr/share/zoneinfo/Etc/GMT+5",
	}
	for tz, want := range cases {
		got, ok := zoneinfoTarget(tz)
		if !ok {
			t.Errorf("zoneinfoTarget(%q) ok=false, want true", tz)
			continue
		}
		if got != want {
			t.Errorf("zoneinfoTarget(%q) = %q, want %q", tz, got, want)
		}
	}
}

func TestZoneinfoTarget_RejectsEscape_5011(t *testing.T) {
	escapes := []string{
		"",                  // root itself, not a zone file
		".",                 // root itself
		"..",                // parent of root
		"../../etc/shadow",  // traversal to an arbitrary file
		"/etc/localtime",    // absolute path -> outside root
		"Foo/../../etc/pwd", // interior traversal escaping root
	}
	for _, tz := range escapes {
		if got, ok := zoneinfoTarget(tz); ok {
			t.Errorf("zoneinfoTarget(%q) = (%q, true), want ok=false", tz, got)
		}
	}
}
