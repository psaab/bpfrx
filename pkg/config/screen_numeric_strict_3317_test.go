package config

import (
	"strings"
	"testing"
)

// #3317: screen numeric threshold / count leaves are untyped and compileScreen
// swallowed the strconv.Atoi failure — a typo'd value committed cleanly and the
// leaf silently fell back to a Junos default (icmp/udp flood, ip-sweep,
// port-scan, syn-flood attack-threshold) or to zero/disabled (the other
// syn-flood subfields, limit-session), a fail-open. validateScreenNumericStrict
// makes a non-positive-integer value an operator-visible commit error.
//
// FAIL-ON-REVERT: remove the parseThresh BadNumeric recording in compileScreen
// (compiler_security.go) OR the validateScreenNumericStrict dispatch in
// compiler.go and the bad-value subtests below go green on the BAD config,
// which is exactly the regression this test exists to catch.
func TestScreenNumericBadValueFailsCommit(t *testing.T) {
	cases := []struct {
		name string
		line string // the offending `set` line under ids-option bad-screen
		want string // substring the error must name
	}{
		{
			name: "icmp-flood-non-numeric",
			line: "set security screen ids-option bad-screen icmp flood threshold abc",
			want: "icmp flood",
		},
		{
			name: "udp-flood-non-numeric",
			line: "set security screen ids-option bad-screen udp flood threshold xyz",
			want: "udp flood",
		},
		{
			name: "ip-sweep-threshold-non-numeric",
			line: "set security screen ids-option bad-screen ip ip-sweep threshold notnum",
			want: "ip ip-sweep threshold",
		},
		{
			name: "port-scan-threshold-non-numeric",
			line: "set security screen ids-option bad-screen tcp port-scan threshold bad",
			want: "tcp port-scan threshold",
		},
		{
			name: "syn-flood-attack-threshold-non-numeric",
			line: "set security screen ids-option bad-screen tcp syn-flood attack-threshold zzz",
			want: "tcp syn-flood attack-threshold",
		},
		{
			name: "syn-flood-source-threshold-negative",
			line: "set security screen ids-option bad-screen tcp syn-flood source-threshold -5",
			want: "tcp syn-flood source-threshold",
		},
		{
			name: "limit-session-source-ip-based-non-numeric",
			line: "set security screen ids-option bad-screen limit-session source-ip-based foo",
			want: "limit-session source-ip-based",
		},
		{
			name: "limit-session-destination-ip-based-zero",
			line: "set security screen ids-option bad-screen limit-session destination-ip-based 0",
			want: "limit-session destination-ip-based",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject a non-positive-integer screen value, got nil error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the offending leaf %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "bad-screen") {
				t.Fatalf("error %q does not name the screen profile", err.Error())
			}
		})
	}
}

// TestScreenNumericValidCommit asserts well-formed positive-integer screen
// values (and the threshold-less "enabled at default" forms — #3230) commit
// cleanly (anti-over-reject).
func TestScreenNumericValidCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option ok-screen icmp flood threshold 1000",
		"set security screen ids-option ok-screen udp flood threshold 2000",
		"set security screen ids-option ok-screen ip ip-sweep threshold 10",
		"set security screen ids-option ok-screen tcp port-scan threshold 14",
		"set security screen ids-option ok-screen tcp syn-flood attack-threshold 200",
		"set security screen ids-option ok-screen tcp syn-flood alarm-threshold 512",
		"set security screen ids-option ok-screen tcp syn-flood timeout 20",
		"set security screen ids-option ok-screen limit-session source-ip-based 128",
		"set security screen ids-option ok-screen limit-session destination-ip-based 128",
		// threshold-less enable forms must NOT be flagged (default applies)
		"set security screen ids-option ok-screen tcp land",
		"set security screen ids-option ok-screen icmp ping-death",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a well-formed screen profile: %v", err)
	}
}

// TestScreenNumericLenientDowngradesToWarning asserts the tolerant load /
// peer-sync path downgrades the bad-value error to a warning so an
// already-persisted or peer-synced config carrying a typo'd threshold still
// boots (#3317 / #1960 no-brick); compileScreen applies the default for the bad
// value independently on that path.
func TestScreenNumericLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option bad-screen tcp syn-flood attack-threshold abc",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must not hard-fail on a bad screen value: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "screen numeric value") && strings.Contains(w, "attack-threshold") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path did not record a downgraded screen-numeric warning; warnings=%v", cfg.Warnings)
	}
}
