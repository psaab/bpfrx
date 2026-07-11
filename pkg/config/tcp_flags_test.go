package config

import (
	"strings"
	"testing"
)

func TestParseTCPFlagsExpression(t *testing.T) {
	cases := []struct {
		name      string
		in        []string
		required  uint8
		forbidden uint8
		ok        bool
		wantErr   bool
	}{
		{"empty", nil, 0, 0, false, false},
		{"blank", []string{"", "  "}, 0, 0, false, false},
		{"single", []string{"syn"}, 0x02, 0, true, false},
		{"upper", []string{"SYN"}, 0x02, 0, true, false},
		{"list", []string{"syn", "ack"}, 0x12, 0, true, false},
		{"quoted-list", []string{"syn ack"}, 0x12, 0, true, false},
		{"conjunction", []string{"syn & ack"}, 0x12, 0, true, false},
		// The #3076 idiom: match SYN, not ACK.
		{"syn-not-ack", []string{"syn & !ack"}, 0x02, 0x10, true, false},
		{"paren-syn-not-ack", []string{"(syn & !ack)"}, 0x02, 0x10, true, false},
		{"negation-only", []string{"!rst"}, 0, 0x04, true, false},
		{"push-alias", []string{"push"}, 0x08, 0, true, false},
		{"all", []string{"fin", "syn", "rst", "psh", "ack", "urg"}, 0x3f, 0, true, false},
		// Unrepresentable / invalid → error (fail-closed at commit).
		{"disjunction", []string{"ack | rst"}, 0, 0, false, true},
		{"negated-group", []string{"!(syn & ack)"}, 0, 0, false, true},
		{"unknown-flag", []string{"bogus"}, 0, 0, false, true},
		{"unknown-in-list", []string{"syn", "bogus"}, 0, 0, false, true},
		{"contradiction", []string{"syn & !syn"}, 0, 0, false, true},
		// #4714: a dangling negation with no flag operand must be rejected
		// (fail-closed) rather than silently dropped (fail-open).
		{"dangling-neg-only", []string{"!"}, 0, 0, false, true},
		{"dangling-neg-trailing", []string{"syn & !"}, 0, 0, false, true},
		{"dangling-neg-before-sep", []string{"! & ack"}, 0, 0, false, true},
		// #5455: an operator-only / empty-operand / dangling-'&' expression is
		// NON-EMPTY yet sets no flag bits (or drops a trailing '&'). It must be
		// rejected (fail-closed) rather than returning "no constraint" or the
		// partially-parsed mask, either of which silently matches all TCP
		// (fail-open widening of a security filter).
		{"amp-only", []string{"&"}, 0, 0, false, true},
		{"parens-only", []string{"()"}, 0, 0, false, true},
		{"amp-trailing", []string{"syn", "&"}, 0, 0, false, true},
		{"amp-trailing-quoted", []string{"syn &"}, 0, 0, false, true},
		{"amp-leading", []string{"& syn"}, 0, 0, false, true},
		{"amp-duplicated", []string{"syn && ack"}, 0, 0, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, forb, ok, err := ParseTCPFlagsExpression(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ParseTCPFlagsExpression(%v): expected error, got req=0x%02x forb=0x%02x ok=%v", c.in, req, forb, ok)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTCPFlagsExpression(%v): unexpected error: %v", c.in, err)
			}
			if ok != c.ok || req != c.required || forb != c.forbidden {
				t.Errorf("ParseTCPFlagsExpression(%v) = (req=0x%02x, forb=0x%02x, ok=%v), want (req=0x%02x, forb=0x%02x, ok=%v)",
					c.in, req, forb, ok, c.required, c.forbidden, c.ok)
			}
		})
	}
}

// TestParseTCPFlagsDanglingNegation is the #4714 RED-on-revert guard. A
// tcp-flags expression whose '!' has no flag operand (a trailing '!', or a '!'
// standing immediately before a '&' separator) must be REJECTED with an error
// naming the malformed expression — otherwise the '!' is silently dropped and
// the term matches more than intended (fail-open). Reverting the pendingNeg
// guards in ParseTCPFlagsExpression makes these inputs parse cleanly and the
// wantErr assertions below FAIL.
func TestParseTCPFlagsDanglingNegation(t *testing.T) {
	// Dangling negation → error naming the expression (fail-closed).
	danglers := []struct {
		name string
		in   []string
	}{
		{"neg-only", []string{"!"}},
		{"trailing-after-flag", []string{"syn & !"}},
		{"trailing-space-list", []string{"syn ack !"}},
		{"before-separator", []string{"! & ack"}},
		{"neg-flag-then-dangling", []string{"!ack & !"}},
	}
	for _, d := range danglers {
		t.Run("reject/"+d.name, func(t *testing.T) {
			req, forb, ok, err := ParseTCPFlagsExpression(d.in)
			if err == nil {
				t.Fatalf("ParseTCPFlagsExpression(%v): expected dangling-negation error, got req=0x%02x forb=0x%02x ok=%v",
					d.in, req, forb, ok)
			}
			if !strings.Contains(err.Error(), "dangling negation") {
				t.Errorf("ParseTCPFlagsExpression(%v): error %q should name the dangling negation", d.in, err)
			}
		})
	}

	// Over-rejection guard: legitimate expressions — including valid negations —
	// must still parse to the SAME masks as before the #4714 fix.
	valid := []struct {
		name      string
		in        []string
		required  uint8
		forbidden uint8
	}{
		{"plain-flag", []string{"syn"}, 0x02, 0},
		{"conjunction", []string{"syn & ack"}, 0x12, 0},
		{"neg-flag", []string{"!ack"}, 0, 0x10},
		{"syn-not-ack", []string{"syn & !ack"}, 0x02, 0x10},
		{"paren-syn-not-ack", []string{"(syn & !ack)"}, 0x02, 0x10},
		{"two-negations", []string{"!syn & !ack"}, 0, 0x12},
		{"space-list", []string{"syn ack"}, 0x12, 0},
	}
	for _, v := range valid {
		t.Run("accept/"+v.name, func(t *testing.T) {
			req, forb, ok, err := ParseTCPFlagsExpression(v.in)
			if err != nil {
				t.Fatalf("ParseTCPFlagsExpression(%v): unexpected error (over-rejection): %v", v.in, err)
			}
			if !ok || req != v.required || forb != v.forbidden {
				t.Errorf("ParseTCPFlagsExpression(%v) = (req=0x%02x, forb=0x%02x, ok=%v), want (req=0x%02x, forb=0x%02x, ok=true)",
					v.in, req, forb, ok, v.required, v.forbidden)
			}
		})
	}
}

// TestParseTCPFlagsOperatorOnly is the #5455 RED-on-revert guard. A NON-EMPTY
// tcp-flags expression that sets NO flag bits — because it is operator-only
// ("&"), an empty parenthesized operand ("()"), or a leading / trailing /
// duplicated '&' conjunction separator ("& ack", "syn &", "syn && ack") — must
// be REJECTED with an error. Before the #5455 fix these returned either
// (ok=false, err=nil) ("no constraint") or the partially-parsed mask with the
// dangling '&' silently dropped; the strict validator only rejects on err!=nil,
// so the malformed value COMMITTED and the term matched EVERY TCP segment
// (fail-open widening of a security filter). Reverting the segHasFlag / final
// no-bits guards in ParseTCPFlagsExpression makes these inputs parse cleanly and
// the wantErr assertions below FAIL.
//
// This is distinct from #4714 (a dangling '!' with no flag operand): #4714
// rejected a bare / trailing negation; #5455 rejects a bare / dangling / empty
// '&' conjunction and any non-empty expression that sets no flag bits.
func TestParseTCPFlagsOperatorOnly(t *testing.T) {
	// Operator-only / empty-operand / dangling-'&' → error (fail-closed).
	reject := []struct {
		name string
		in   []string
	}{
		{"amp-only", []string{"&"}},
		{"parens-empty", []string{"()"}},
		{"parens-empty-spaced", []string{"( )"}},
		{"amp-trailing-listed", []string{"syn", "&"}},
		{"amp-trailing-quoted", []string{"syn &"}},
		{"amp-leading", []string{"& syn"}},
		{"amp-duplicated", []string{"syn && ack"}},
		{"amp-only-spaced", []string{" & "}},
	}
	for _, r := range reject {
		t.Run("reject/"+r.name, func(t *testing.T) {
			req, forb, ok, err := ParseTCPFlagsExpression(r.in)
			if err == nil {
				t.Fatalf("ParseTCPFlagsExpression(%v): expected operator-only/dangling-'&' error, got req=0x%02x forb=0x%02x ok=%v",
					r.in, req, forb, ok)
			}
			if ok {
				t.Errorf("ParseTCPFlagsExpression(%v): ok must be false on error, got true", r.in)
			}
		})
	}

	// Absent value stays "no constraint" (ok=false, no error) — the fix must NOT
	// break the legitimately-absent case that returns match-nothing-extra.
	for _, absent := range [][]string{nil, {}, {""}, {"", "  "}} {
		req, forb, ok, err := ParseTCPFlagsExpression(absent)
		if err != nil || ok || req != 0 || forb != 0 {
			t.Errorf("ParseTCPFlagsExpression(%v) absent case = (req=0x%02x, forb=0x%02x, ok=%v, err=%v), want (0,0,false,nil)",
				absent, req, forb, ok, err)
		}
	}

	// Over-rejection guard: valid expressions still parse to the SAME masks.
	valid := []struct {
		name      string
		in        []string
		required  uint8
		forbidden uint8
	}{
		{"plain-flag", []string{"syn"}, 0x02, 0},
		{"conjunction", []string{"syn & ack"}, 0x12, 0},
		{"neg-flag", []string{"!syn"}, 0, 0x02},
		{"syn-not-ack", []string{"syn & !ack"}, 0x02, 0x10},
		{"paren-syn-not-ack", []string{"(syn & ack)"}, 0x12, 0},
	}
	for _, v := range valid {
		t.Run("accept/"+v.name, func(t *testing.T) {
			req, forb, ok, err := ParseTCPFlagsExpression(v.in)
			if err != nil {
				t.Fatalf("ParseTCPFlagsExpression(%v): unexpected error (over-rejection): %v", v.in, err)
			}
			if !ok || req != v.required || forb != v.forbidden {
				t.Errorf("ParseTCPFlagsExpression(%v) = (req=0x%02x, forb=0x%02x, ok=%v), want (req=0x%02x, forb=0x%02x, ok=true)",
					v.in, req, forb, ok, v.required, v.forbidden)
			}
		})
	}
}

// TestFirewallFilterTCPFlagsCommitReject is the #3076 commit-layer guard. A
// firewall filter carrying a tcp-flags expression the dataplane cannot enforce
// (here a disjunction) MUST fail to compile rather than commit with the
// constraint silently dropped (fail-open). REVERT (removing the compileFirewall
// validation) makes CompileConfig succeed and this assert FAIL.
func TestFirewallFilterTCPFlagsCommitReject(t *testing.T) {
	build := func(flags string) (*Config, error) {
		tree := &ConfigTree{}
		cmds := []string{
			"set firewall family inet filter f term t from protocol tcp",
			"set firewall family inet filter f term t from tcp-flags \"" + flags + "\"",
			"set firewall family inet filter f term t then discard",
		}
		for _, cmd := range cmds {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return CompileConfig(tree)
	}

	// A representable expression compiles cleanly.
	if _, err := build("syn & !ack"); err != nil {
		t.Errorf("tcp-flags \"syn & !ack\" should compile, got: %v", err)
	}
	// A disjunction is not representable and must be rejected at commit.
	if _, err := build("ack | rst"); err == nil {
		t.Error("tcp-flags \"ack | rst\" should be rejected at commit (fail-closed), but compiled")
	}
	// An unknown flag is rejected at commit.
	if _, err := build("bogus"); err == nil {
		t.Error("tcp-flags \"bogus\" should be rejected at commit (fail-closed), but compiled")
	}
	// #4714: a dangling trailing negation must be rejected at commit rather
	// than committing with the '!' silently dropped (fail-open).
	if _, err := build("syn & !"); err == nil {
		t.Error("tcp-flags \"syn & !\" (dangling negation) should be rejected at commit (fail-closed), but compiled")
	}
	// #5455: an operator-only '&' (and a trailing '&') sets no flag bits; the
	// strict validator must reject it at commit rather than committing a term
	// that silently matches every TCP segment (fail-open).
	if _, err := build("&"); err == nil {
		t.Error("tcp-flags \"&\" (operator-only) should be rejected at commit (fail-closed), but compiled")
	}
	if _, err := build("syn &"); err == nil {
		t.Error("tcp-flags \"syn &\" (trailing '&') should be rejected at commit (fail-closed), but compiled")
	}
}
