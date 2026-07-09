package main

import "testing"

// #4869: `xpfd upgrade` must REJECT stray positional arguments rather than
// silently dropping them and running a wrong/default action. The canonical
// hazard is `xpfd upgrade rolling` (missing the two dashes): the bool flag
// stays false and the STANDALONE STOP->FLIP->START cut runs on a clustered
// node with no drain/takeover. A positional before flags, or any unknown
// token, must be a hard error with NO run.
func TestParseUpgradeArgsRejectsPositionals_4869(t *testing.T) {
	cases := [][]string{
		{"rolling"},                       // the classic missing-dashes typo
		{"rolling", "--staged-dir", "/x"}, // positional shadows the trailing flags too
		{"bogus"},
		{"--rolling", "extra"}, // valid flag + stray positional
		{"start"},
	}
	for _, args := range cases {
		t.Run(joinArgs(args), func(t *testing.T) {
			if _, err := parseUpgradeArgs(args); err == nil {
				t.Fatalf("parseUpgradeArgs(%v) returned nil; expected rejection of the "+
					"positional argument (must not silently run a default/standalone cut)", args)
			}
		})
	}
}

// The supported forms still parse cleanly and map to the right runner.
func TestParseUpgradeArgsValidForms_4869(t *testing.T) {
	// Bare `xpfd upgrade` -> standalone cut (rolling false).
	f, err := parseUpgradeArgs(nil)
	if err != nil {
		t.Fatalf("bare upgrade: %v", err)
	}
	if f.rolling {
		t.Fatal("bare upgrade must NOT select the rolling path")
	}

	// `xpfd upgrade --rolling` -> HA rolling cut.
	f, err = parseUpgradeArgs([]string{"--rolling"})
	if err != nil {
		t.Fatalf("--rolling: %v", err)
	}
	if !f.rolling {
		t.Fatal("--rolling must select the rolling path")
	}

	// A recognized value flag is accepted and threaded through.
	f, err = parseUpgradeArgs([]string{"--rolling", "--unit", "xpfd-test.service"})
	if err != nil {
		t.Fatalf("--rolling --unit: %v", err)
	}
	if !f.rolling || f.unit != "xpfd-test.service" {
		t.Fatalf("flags not parsed: rolling=%v unit=%q", f.rolling, f.unit)
	}
}

func joinArgs(a []string) string {
	if len(a) == 0 {
		return "<empty>"
	}
	s := a[0]
	for _, x := range a[1:] {
		s += "_" + x
	}
	return s
}
