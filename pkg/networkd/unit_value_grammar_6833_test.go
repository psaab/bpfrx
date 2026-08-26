package networkd

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// unit_value_grammar_6833_test.go -- #6833.
//
// sanitizeUnitValue replaces control bytes with a SPACE. That is safe only
// because it is applied to `Description=` and ONLY to `Description=`, which
// systemd treats as free text. It would NOT be safe on several `[Match]` keys,
// which are WHITESPACE-SEPARATED LISTS: `OriginalName=` takes a list of
// patterns, so a space inside one value makes a single .link file match several
// kernel interfaces -- the substitution manufacturing the very delimiter the
// belt exists to prevent.
//
// So the risk is not today's call sites; it is a FUTURE one. These cells pin the
// justification so it cannot be quietly invalidated.

// TestUnitValueSanitizerReplacesTheNewline pins the byte the belt is actually
// for. Its failure message says why, so a relaxation that keeps "no control
// characters" while admitting the live byte cannot pass silently.
func TestUnitValueSanitizerReplacesTheNewline_6833(t *testing.T) {
	got := sanitizeUnitValue("lan\nDHCP=ipv4")
	if strings.ContainsRune(got, '\n') {
		t.Fatalf("a newline survived sanitizeUnitValue (%q): systemd units are "+
			"one Key=Value per line, so the remainder is read as a NEW directive "+
			"-- this is the #1798 injection the belt exists to stop", got)
	}
	if got != "lan DHCP=ipv4" {
		t.Errorf("got %q, want %q", got, "lan DHCP=ipv4")
	}
}

// TestUnitValueSanitizerIsAppliedOnlyToDescription_6833 is the INVENTORY guard,
// and it is the load-bearing cell of the pair.
//
// The space substitution is correct only for a free-text key. Applying this
// function to a whitespace-separated `[Match]` key would silently widen a .link
// file to match interfaces it was never meant to -- and nothing about that change
// would look wrong at the call site, because the function name does not say
// "free text only".
//
// So this asserts the inventory: every call is to `Description=`. Adding a call
// on any other key REDS, which forces whoever adds it to re-derive whether a
// space is ordinary text for that key's grammar. That is the whole point -- not
// to forbid new call sites, but to make the derivation unavoidable.
//
// FAIL-ON-REVERT: apply sanitizeUnitValue to any other Fprintf key and this reds.
func TestUnitValueSanitizerIsAppliedOnlyToDescription_6833(t *testing.T) {
	src := stripLineComments6833(readNetworkdSource6833(t, "networkd.go"))

	// Every call, with the format string it is interpolated into.
	call := regexp.MustCompile(`"([A-Za-z]+)=%s\\n", sanitizeUnitValue\(`)
	calls := call.FindAllStringSubmatch(src, -1)
	if len(calls) == 0 {
		t.Fatal("found no sanitizeUnitValue call sites; the inventory guard is " +
			"matching nothing and would pass over any change at all")
	}
	for _, m := range calls {
		if m[1] != "Description" {
			t.Errorf("sanitizeUnitValue is applied to %q=. A SPACE is only ordinary "+
				"text for a free-text key; on a whitespace-separated [Match] key "+
				"(OriginalName=, Path=, Driver=, Type=) the substitution splits one "+
				"value into several and widens what the unit matches. Re-derive the "+
				"safe substitute for %q's grammar before using this belt there "+
				"(#6833).", m[1], m[1])
		}
	}

	// And no bare sanitizeUnitValue call outside that shape, which would evade
	// the check above entirely.
	total := strings.Count(src, "sanitizeUnitValue(")
	if total != len(calls)+1 { // +1 for the definition itself
		t.Errorf("found %d sanitizeUnitValue( occurrences but only %d matched the "+
			"Key=%%s call shape (+1 definition); an unrecognised call site is "+
			"invisible to this guard", total, len(calls))
	}
}

func readNetworkdSource6833(t *testing.T, name string) string {
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
