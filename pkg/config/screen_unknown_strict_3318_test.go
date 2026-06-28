package config

import (
	"strings"
	"testing"
)

// #3318: the screen schema subtrees are open and compileScreen switched only on
// known child names with no default case — a misspelled or unsupported screen
// leaf committed cleanly and was silently dropped, so the operator believed a
// protection was enabled when it was absent. validateScreenUnknownStrict makes
// the unsupported leaf an operator-visible commit error.
//
// FAIL-ON-REVERT: remove the compileScreen default arms that record
// UnknownLeaves (compiler_security.go) OR the validateScreenUnknownStrict
// dispatch in compiler.go and the subtests below go green on the BAD config,
// which is exactly the regression this test exists to catch.
func TestScreenUnknownLeafFailsCommit(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string // the `<family> <leaf>` path the error must name
	}{
		{
			name: "unknown-top-level-family",
			line: "set security screen ids-option bad-screen bogus-family something",
			want: "bogus-family",
		},
		{
			name: "unknown-icmp-leaf",
			line: "set security screen ids-option bad-screen icmp pong-death",
			want: "icmp pong-death",
		},
		{
			name: "unknown-ip-leaf",
			line: "set security screen ids-option bad-screen ip block-frag",
			want: "ip block-frag",
		},
		{
			name: "unknown-ip-sweep-subleaf",
			line: "set security screen ids-option bad-screen ip ip-sweep bogus 10",
			want: "ip ip-sweep bogus",
		},
		{
			name: "unknown-tcp-leaf",
			line: "set security screen ids-option bad-screen tcp sweep",
			want: "tcp sweep",
		},
		{
			name: "unknown-syn-flood-subleaf",
			line: "set security screen ids-option bad-screen tcp syn-flood whitelist foo",
			want: "tcp syn-flood whitelist",
		},
		{
			name: "unknown-port-scan-subleaf",
			line: "set security screen ids-option bad-screen tcp port-scan bogus 10",
			want: "tcp port-scan bogus",
		},
		{
			name: "unknown-udp-leaf",
			line: "set security screen ids-option bad-screen udp bad-udp-option",
			want: "udp bad-udp-option",
		},
		{
			name: "unknown-limit-session-leaf",
			line: "set security screen ids-option bad-screen limit-session both-ip-based 10",
			want: "limit-session both-ip-based",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject an unsupported screen leaf, got nil error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the unsupported leaf %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "bad-screen") {
				t.Fatalf("error %q does not name the screen profile", err.Error())
			}
		})
	}
}

// TestScreenSupportedLeavesCommit asserts the full set of supported screen
// leaves commits cleanly (anti-over-reject) — every compileScreen switch case
// across all families.
func TestScreenSupportedLeavesCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option ok-screen icmp ping-death",
		"set security screen ids-option ok-screen icmp flood threshold 1000",
		"set security screen ids-option ok-screen ip source-route-option",
		"set security screen ids-option ok-screen ip tear-drop",
		"set security screen ids-option ok-screen ip ip-sweep threshold 10",
		"set security screen ids-option ok-screen tcp land",
		"set security screen ids-option ok-screen tcp winnuke",
		"set security screen ids-option ok-screen tcp syn-frag",
		"set security screen ids-option ok-screen tcp syn-fin",
		"set security screen ids-option ok-screen tcp no-flag",
		"set security screen ids-option ok-screen tcp fin-no-ack",
		"set security screen ids-option ok-screen tcp syn-flood attack-threshold 200",
		"set security screen ids-option ok-screen tcp syn-flood alarm-threshold 512",
		"set security screen ids-option ok-screen tcp syn-flood source-threshold 100",
		"set security screen ids-option ok-screen tcp syn-flood destination-threshold 200",
		"set security screen ids-option ok-screen tcp syn-flood timeout 20",
		"set security screen ids-option ok-screen tcp port-scan threshold 14",
		"set security screen ids-option ok-screen udp flood threshold 1000",
		"set security screen ids-option ok-screen limit-session source-ip-based 128",
		"set security screen ids-option ok-screen limit-session destination-ip-based 128",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a fully-supported screen profile: %v", err)
	}
}

// TestScreenIcmpFragmentNotRejected guards the #3316 (`icmp fragment`) /
// #3318 (unknown-leaf gate) interaction across the merge ordering: with #3316's
// `case "fragment"` arm present in compileScreen's icmp switch, `icmp fragment`
// is a HANDLED leaf — it sets ScreenProfile.ICMP.Fragment and is NOT recorded on
// UnknownLeaves, so validateScreenUnknownStrict must NOT reject it.
//
// FAIL-ON-REVERT: drop #3316's `case "fragment"` arm and the leaf falls through
// to compileScreen's `default:` → UnknownLeaves → validateScreenUnknownStrict
// rejects it, turning this test RED. This is exactly the merge-ordering hazard
// the #3316/#3318 rebase had to resolve (keep BOTH the fragment case and the
// default arm).
func TestScreenIcmpFragmentNotRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option frag-screen icmp fragment",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected `icmp fragment` (a supported #3316 leaf): %v", err)
	}
	profile := cfg.Security.Screen["frag-screen"]
	if profile == nil {
		t.Fatalf("screen profile frag-screen missing from compiled config")
	}
	if !profile.ICMP.Fragment {
		t.Fatalf("`icmp fragment` did not set ICMP.Fragment; it was dropped or misrouted")
	}
	if len(profile.UnknownLeaves) != 0 {
		t.Fatalf("`icmp fragment` was recorded as an unknown leaf %v; the #3316 case arm is missing or below the default", profile.UnknownLeaves)
	}
}

// TestScreenUnknownLenientDowngradesToWarning asserts the tolerant load /
// peer-sync path downgrades the unknown-leaf error to a warning so an
// already-persisted or peer-synced config carrying an unsupported leaf still
// boots (#3318 / #1960 no-brick).
func TestScreenUnknownLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option bad-screen icmp pong-death",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must not hard-fail on an unsupported screen leaf: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "screen unknown leaf") && strings.Contains(w, "pong-death") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path did not record a downgraded screen-unknown warning; warnings=%v", cfg.Warnings)
	}
}
