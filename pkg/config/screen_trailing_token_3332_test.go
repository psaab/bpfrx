package config

import (
	"strings"
	"testing"
)

// #3332: a flat-set screen leaf that is itself SUPPORTED but carries EXTRA
// trailing tokens beyond its value arity silently dropped the garbage at
// commit. `set security screen ids-option X tcp land bogus` parses as a `land`
// leaf with Keys=["land","bogus"]; compileScreen reads only Keys[0] ("land"),
// enables Land, and "bogus" was consumed with no warning. This is distinct from
// #3318 (which rejects an unknown leaf KEYWORD): here the keyword IS known, so
// the #3318 default arm can never see it. compileScreen now records the trailing
// token(s) on ScreenProfile.UnknownLeaves and validateScreenUnknownStrict makes
// the commit fail.
//
// FAIL-ON-REVERT: drop the recordKeyExtras / recordChildExtras calls in
// compileScreen (compiler_security.go) and every subtest below goes GREEN on the
// garbage config, which is exactly the regression this guards.
func TestScreenTrailingTokenFailsCommit(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string // substring the error must name (the dropped garbage token in context)
	}{
		{
			name: "tcp-boolean-land",
			line: "set security screen ids-option bad-screen tcp land bogus",
			want: "tcp land bogus",
		},
		{
			name: "tcp-boolean-winnuke",
			line: "set security screen ids-option bad-screen tcp winnuke extra",
			want: "tcp winnuke extra",
		},
		{
			name: "icmp-boolean-ping-death",
			line: "set security screen ids-option bad-screen icmp ping-death garbage",
			want: "icmp ping-death garbage",
		},
		{
			name: "ip-boolean-source-route-option",
			line: "set security screen ids-option bad-screen ip source-route-option junk",
			want: "ip source-route-option junk",
		},
		{
			name: "ip-boolean-tear-drop",
			line: "set security screen ids-option bad-screen ip tear-drop nope",
			want: "ip tear-drop nope",
		},
		{
			name: "icmp-flood-trailing",
			line: "set security screen ids-option bad-screen icmp flood threshold 1000 extra",
			want: "icmp flood extra",
		},
		{
			name: "udp-flood-trailing",
			line: "set security screen ids-option bad-screen udp flood threshold 1000 extra",
			want: "udp flood extra",
		},
		{
			name: "tcp-port-scan-threshold-trailing",
			line: "set security screen ids-option bad-screen tcp port-scan threshold 14 extra",
			want: "tcp port-scan threshold extra",
		},
		{
			name: "ip-ip-sweep-threshold-trailing",
			line: "set security screen ids-option bad-screen ip ip-sweep threshold 10 extra",
			want: "ip ip-sweep threshold extra",
		},
		{
			name: "tcp-syn-flood-subfield-trailing",
			line: "set security screen ids-option bad-screen tcp syn-flood attack-threshold 200 extra",
			want: "tcp syn-flood attack-threshold extra",
		},
		{
			// args>0 leaf: SetPath parks the trailing token as a CHILD of the
			// leaf, not on its Keys, so recordChildExtras is the catch.
			name: "limit-session-source-ip-based-trailing",
			line: "set security screen ids-option bad-screen limit-session source-ip-based 128 extra",
			want: "limit-session source-ip-based extra",
		},
		{
			name: "limit-session-destination-ip-based-trailing",
			line: "set security screen ids-option bad-screen limit-session destination-ip-based 128 extra",
			want: "limit-session destination-ip-based extra",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject trailing garbage on a supported screen leaf, got nil error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the trailing-token leaf %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "bad-screen") {
				t.Fatalf("error %q does not name the screen profile", err.Error())
			}
		})
	}
}

// TestScreenExactAritySupportedLeavesCommit is the anti-over-reject guard: every
// supported screen leaf with its EXACT legitimate token arity (boolean flag, or
// keyword + value) must still commit cleanly. A bug in recordKeyExtras' `allowed`
// count (e.g. off-by-one on `flood threshold <n>` or the syn-flood subfields)
// would turn one of these green-path lines RED.
func TestScreenExactAritySupportedLeavesCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option ok-screen icmp ping-death",
		"set security screen ids-option ok-screen icmp fragment",
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
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected an exact-arity supported screen profile: %v", err)
	}
	if profile := cfg.Security.Screen["ok-screen"]; profile == nil || len(profile.UnknownLeaves) != 0 {
		t.Fatalf("exact-arity supported leaves recorded spurious UnknownLeaves: %+v", profile)
	}
}

// TestScreenTrailingTokenLenientDowngradesToWarning asserts the tolerant load /
// peer-sync path downgrades the trailing-token error to a warning so an
// already-persisted or peer-synced config carrying the garbage still boots
// (#3332 reuses the #3318 / #1960 no-brick downgrade).
func TestScreenTrailingTokenLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option bad-screen tcp land bogus",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must not hard-fail on a trailing-token screen leaf: %v", err)
	}
	// The supported leaf must still compile (Land enabled) on the lenient path —
	// the garbage trailing token does not disable the protection it rides on.
	if profile := cfg.Security.Screen["bad-screen"]; profile == nil || !profile.TCP.Land {
		t.Fatalf("lenient path dropped the supported `tcp land` leaf while tolerating its trailing token: %+v", profile)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "screen unknown leaf") && strings.Contains(w, "tcp land bogus") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path did not record a downgraded trailing-token warning; warnings=%v", cfg.Warnings)
	}
}
