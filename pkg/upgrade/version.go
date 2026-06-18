package upgrade

import (
	"fmt"
	"strings"
)

// ValidateVersionSegment rejects any version string that is not a safe
// single path segment (plan §4/§6 C1, #1964/#1967). The version keys the
// on-disk runtime layout: versions/<ver>/, the `current` symlink target,
// the per-version DB-snapshot dotfile (.<ver>.dbsnap), and the unit
// drop-in's ExecStart path. A version carrying a path separator, "..",
// whitespace, a control char, or a leading dot would let an attacker (or a
// corrupted/format-drifted `xpfd version` output) escape VersionsDir,
// collide with a dotfile namespace, or strand the daemon on a path that
// cannot be resolved.
//
// It is deliberately NOT a strict alphanumeric regex: Debian/semver
// versions legitimately carry `+`, `:`, `~`, `-`, `.`, and `_`. The rule is
// "a safe single path segment", not "alnum only".
//
// Rejected:
//   - empty
//   - "." or ".." (and any leading dot — collides with the .partial /
//     .dbsnap dotfile namespace and is hidden from ReadDir-based GC)
//   - any "/" (path traversal / escape from VersionsDir)
//   - any whitespace (space, tab, newline, CR, vertical tab, form feed)
//   - any ASCII control char (< 0x20) or DEL (0x7f)
func ValidateVersionSegment(ver string) error {
	if ver == "" {
		return fmt.Errorf("version is empty")
	}
	if ver == "." || ver == ".." {
		return fmt.Errorf("version %q is a relative path element", ver)
	}
	if strings.HasPrefix(ver, ".") {
		return fmt.Errorf("version %q has a leading dot (collides with the "+
			"runtime dotfile namespace and is hidden from GC)", ver)
	}
	if strings.ContainsRune(ver, '/') {
		return fmt.Errorf("version %q contains a path separator", ver)
	}
	for _, r := range ver {
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f':
			return fmt.Errorf("version %q contains whitespace", ver)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("version %q contains a control character (0x%02x)", ver, r)
		}
	}
	return nil
}
