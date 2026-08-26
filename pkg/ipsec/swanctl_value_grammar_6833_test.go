package ipsec

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// swanctl_value_grammar_6833_test.go -- #6833.
//
// sanitizeSwanctlValue replaces control bytes with a SPACE. Whether that is safe
// is a fact about swanctl.conf's grammar, and it was not recorded anywhere until
// now. These cells pin both halves: the byte the belt is actually for, and the
// call-site inventory that makes the substitute correct.

// TestSwanctlSanitizerReplacesTheNewline_6833 pins the live byte. swanctl.conf is
// `section { key = value }` with values running to end of line, so a newline ends
// the setting and lets the remainder be read as a new key or section.
func TestSwanctlSanitizerReplacesTheNewline_6833(t *testing.T) {
	got := sanitizeSwanctlValue("conn\n  rogue = 1")
	if strings.ContainsRune(got, '\n') {
		t.Fatalf("a newline survived sanitizeSwanctlValue (%q): values run to end "+
			"of line, so the remainder is read as a NEW setting -- the #1798 "+
			"injection this belt exists to stop", got)
	}
}

// TestSwanctlSanitizerCallSitesAreUnquotedOrEscaped_6833 is the INVENTORY guard.
//
// A space is safe at every current call site for two different reasons, and the
// distinction matters because only one of them survives a new call site:
//
//   - UNQUOTED keys (local_addrs, remote_addrs, proposals, esp_proposals,
//     local_ts, remote_ts) and section names: swanctl's list-valued keys are
//     COMMA-separated, not whitespace-separated, so an injected space yields one
//     malformed value rather than two entries.
//   - QUOTED keys (certs, id, secret): additionally wrapped by
//     escapeSwanctlQuoted, so the quoting protects them independently of the
//     substitute.
//
// If a future call site interpolates into a key whose grammar makes whitespace
// SIGNIFICANT, the space stops being safe and manufactures the delimiter -- the
// #6829 shape, where the space and not the newline was the live byte.
//
// This asserts the known-safe key inventory. A new key REDS, which forces
// whoever adds it to state why a space is ordinary text there. The point is not
// to forbid new call sites; it is to make the derivation unavoidable.
func TestSwanctlSanitizerCallSitesAreUnquotedOrEscaped_6833(t *testing.T) {
	src := stripLineComments6833(readIPsecSource6833(t, "policy.go"))

	// Keys whose grammar has been checked and recorded in sanitizeSwanctlValue's
	// doc comment. Section headers ("  %s {") and the quoted keys are handled
	// separately below.
	known := map[string]bool{
		"local_addrs": true, "remote_addrs": true,
		"proposals": true, "esp_proposals": true,
		"local_ts": true, "remote_ts": true,
	}

	key := regexp.MustCompile(`"\s*([a-z_]+) = %s\\n", sanitizeSwanctlValue\(`)
	found := key.FindAllStringSubmatch(src, -1)
	if len(found) == 0 {
		t.Fatal("found no unquoted key-equals-value sanitizeSwanctlValue call " +
			"sites; the inventory guard is matching nothing and would pass over " +
			"any change")
	}
	for _, m := range found {
		if !known[m[1]] {
			t.Errorf("sanitizeSwanctlValue is interpolated into the unquoted key %q, "+
				"which is not in the checked inventory. A SPACE is only ordinary text "+
				"where the key is not whitespace-list-valued; swanctl's list keys are "+
				"comma-separated, but that was verified for the keys listed in the "+
				"function's doc comment and not for %q. Re-derive it, then add %q "+
				"here (#6833).", m[1], m[1], m[1])
		}
	}

	// Every QUOTED interpolation must still pass through escapeSwanctlQuoted --
	// the second, independent reason a space is safe there. A quoted site that
	// dropped the escape would rely on the substitute alone.
	quoted := regexp.MustCompile(`= \\"%s\\"\\n", ([A-Za-z]+)\(`)
	for _, m := range quoted.FindAllStringSubmatch(src, -1) {
		if m[1] != "escapeSwanctlQuoted" {
			t.Errorf("a quoted swanctl value is rendered through %q rather than "+
				"escapeSwanctlQuoted; the quoting is the independent protection for "+
				"quoted keys and must not be dropped (#6833)", m[1])
		}
	}
}

func readIPsecSource6833(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func stripLineComments6833(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
