// C179-021 (codex-179): `show security flow session limit <n>` parsed the
// limit with strconv.Atoi (a 64-bit int), so a value exceeding int32 passed
// the `n < 1` guard and then int32(n) wrapped NEGATIVE. The daemon clamps
// <= 0 to the default limit, so an over-range request silently became the
// default instead of erroring. The parser now uses ParseInt(v,10,32) so an
// out-of-range limit is rejected.
package main

import "testing"

// FAIL-ON-REVERT: restoring strconv.Atoi makes the over-int32 cases parse
// clean (wrapping negative) so the want-error assertions go RED.
func TestParseFlowSessionArgsRejectsOverflowLimit_5523(t *testing.T) {
	wantErr := [][]string{
		{"limit", "3000000000"},  // > math.MaxInt32 — wraps negative under Atoi
		{"limit", "2147483648"},  // math.MaxInt32 + 1
		{"limit", "99999999999"}, // far over range
	}
	for _, args := range wantErr {
		if _, err := parseFlowSessionArgs(args); err == nil {
			t.Errorf("parseFlowSessionArgs(%v) = nil error; want an out-of-range rejection", args)
		}
	}
}

// A valid limit at the top of the int32 range is still accepted (no over-reject).
func TestParseFlowSessionArgsAcceptsMaxInt32Limit_5523(t *testing.T) {
	p, err := parseFlowSessionArgs([]string{"limit", "2147483647"}) // math.MaxInt32
	if err != nil {
		t.Fatalf("parseFlowSessionArgs(limit 2147483647) = %v; want accepted", err)
	}
	if p.req.Limit != 2147483647 {
		t.Errorf("Limit = %d, want 2147483647", p.req.Limit)
	}
}
