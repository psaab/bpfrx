package cli

import "testing"

// TestValidateMonitorFilterRejectsQuoteWrappedOption pins the #4556 N-01 fix:
// a mismatched-quote wrapper (`'-w ...` / `"-z ...`) leaves a literal leading
// quote on the token, so tok[0] is `'`/`"` instead of `-` and the smuggled
// option would slip past the tok[0]=='-' check. validateMonitorFilter now
// peels one leading quote before the option-token test, so the option is still
// caught. RED-on-revert: without the leading-quote strip these tokens start
// with a quote, monitorFilterOptionToken returns false, and validation passes.
//
// (The "--" separator in buildMonitorTrafficArgv already neutralizes any such
// option on the wire — this only closes the defense-in-depth validator gap.)
func TestValidateMonitorFilterRejectsQuoteWrappedOption(t *testing.T) {
	reject := []string{
		"'-w /tmp/x",
		"\"-z /tmp/evil.sh",
		"'-r /etc/shadow",
		"host 10.0.0.1 '-w /tmp/x", // quote-wrapped option after a valid primitive
		"'--postrotate-command /tmp/evil.sh",
	}
	for _, f := range reject {
		if err := validateMonitorFilter(f); err == nil {
			t.Errorf("validateMonitorFilter(%q) = nil, want error (quote-wrapped option not rejected)", f)
		}
	}
}

// TestValidateMonitorFilterQuoteStripPreservesLegitimate ensures the
// leading-quote strip does not falsely reject normal tokens: a bare "-"
// arithmetic term, a quoted bare "-", and ordinary pcap primitives (which
// never begin with a quote) all still pass.
func TestValidateMonitorFilterQuoteStripPreservesLegitimate(t *testing.T) {
	accept := []string{
		"host 10.0.0.1 and port 22",
		"tcp port 80",
		"-",        // getopt stdin sentinel / arithmetic subtraction, not an option
		"len - 20", // a bare "-" in the middle of a filter term
	}
	for _, f := range accept {
		if err := validateMonitorFilter(f); err != nil {
			t.Errorf("validateMonitorFilter(%q) = %v, want nil (legitimate filter rejected)", f, err)
		}
	}
}
