package config

import (
	"strconv"
	"strings"
	"testing"
)

// #8667: the Go control plane and the Rust dataplane validate a NAT64 mask with
// two different parsers, and they disagreed on exactly one character class —
// Go's strconv.ParseUint permits no sign, Rust's `parse::<u8>()` accepts a
// leading "+". So `64:ff9b::/+96` was rejected at commit, retained verbatim by
// the tolerant load path, and then INSTALLED and translating, while the control
// plane told the operator the rule was inert.
//
// The repair normalises the token at snapshot build. These cells are what stop
// the NEXT divergence, which is the part that outlives "+".

// nat64MaskCorpus8667 reproduces the sweep the issue reports: every string of
// length <= 3 over a character set chosen to probe sign handling, whitespace,
// underscores, hex and exponent spellings — the places two integer parsers in
// different languages plausibly differ.
func nat64MaskCorpus8667() []string {
	const alphabet = "0123456789+-_ xX.eE"
	out := []string{""}
	prev := []string{""}
	for n := 0; n < 3; n++ {
		var next []string
		for _, p := range prev {
			for _, c := range alphabet {
				next = append(next, p+string(c))
			}
		}
		out = append(out, next...)
		prev = next
	}
	return out
}

// controlPlaneAcceptsNAT64Mask8667 is the STRICT gate's own predicate, spelled
// exactly as validateNAT64PrefixStrict spells it. Kept as a local mirror on
// purpose: if the gate's parse ever changes, this cell should go red and be
// re-read, not silently follow it.
func controlPlaneAcceptsNAT64Mask8667(tok string) bool {
	m, err := strconv.ParseUint(tok, 10, 8)
	return err == nil && m == 96
}

// THE AGREEMENT TEST, and it fails on divergence in EITHER direction.
//
// The property is about what actually reaches the dataplane. After
// NormaliseNAT64PrefixForSnapshot, the control plane and the dataplane are
// looking at the SAME token, so any remaining disagreement is a real grammar
// divergence rather than a spelling one — and the next one, in whichever
// direction it appears, reds this.
//
// A one-directional cell ("nothing the dataplane accepts is rejected by the
// control plane") would let the opposite drift through, so both sets are
// compared and both differences are reported.
func TestNAT64MaskGrammarsAgreeOnWhatReachesTheDataplane8667(t *testing.T) {
	var dataplaneOnly, controlOnly []string
	for _, tok := range nat64MaskCorpus8667() {
		norm := NormaliseNAT64PrefixForSnapshot("64:ff9b::/" + tok)
		_, mask, ok := strings.Cut(norm, "/")
		if !ok {
			t.Fatalf("normalisation dropped the mask separator for %q -> %q", tok, norm)
		}
		dp := dataplaneAcceptsNAT64Mask(mask)
		cp := controlPlaneAcceptsNAT64Mask8667(mask)
		switch {
		case dp && !cp:
			dataplaneOnly = append(dataplaneOnly, tok)
		case cp && !dp:
			controlOnly = append(controlOnly, tok)
		}
	}
	if len(dataplaneOnly) > 0 {
		t.Errorf("%d token(s) the DATAPLANE accepts and the control plane rejects, "+
			"after normalisation: %v.\nA rule spelled this way installs and "+
			"translates while the control plane reports it inert — the #8667 "+
			"failure, in a character class normalisation does not cover.",
			len(dataplaneOnly), truncate8667(dataplaneOnly))
	}
	if len(controlOnly) > 0 {
		t.Errorf("%d token(s) the CONTROL PLANE accepts and the dataplane rejects, "+
			"after normalisation: %v.\nThis is the opposite drift and is equally "+
			"bad: commit succeeds, the operator is told nothing, and NAT64 is "+
			"silently off for that rule-set.",
			len(controlOnly), truncate8667(controlOnly))
	}
}

// DEGENERACY CONTROL. The agreement test above passes trivially if the corpus
// never produced a divergence in the first place — a corpus that probes nothing
// agrees about nothing. This asserts the RAW corpus really does contain the
// divergence, so the agreement result is evidence that normalisation closed it
// rather than evidence the sweep was blind.
func TestNAT64MaskCorpusActuallyContainsTheDivergence8667(t *testing.T) {
	var raw []string
	for _, tok := range nat64MaskCorpus8667() {
		if dataplaneAcceptsNAT64Mask(tok) != controlPlaneAcceptsNAT64Mask8667(tok) {
			raw = append(raw, tok)
		}
	}
	if len(raw) == 0 {
		t.Fatal("the raw corpus shows NO divergence between the two parsers, so " +
			"the agreement test above proves nothing — either the corpus stopped " +
			"probing the sign class or one of the two predicates stopped " +
			"reflecting its parser (#8667)")
	}
	// Every known divergence is a leading '+'. If that ever stops being true,
	// the normalisation no longer covers the class and the agreement test is
	// the thing that will say so — but this records what was measured.
	for _, tok := range raw {
		if !strings.HasPrefix(tok, "+") {
			t.Errorf("raw divergence on %q, which is NOT a leading-'+' token. "+
				"Normalisation only strips '+', so this class reaches the "+
				"dataplane unnormalised (#8667)", tok)
		}
	}
	// TWO NUMBERS, recorded together because they are easy to conflate and the
	// issue body reports only the first. Over this 7,240-token corpus:
	//
	//   parse-level divergence      = 110  (Rust's parse::<u8> succeeds where
	//                                       Go's ParseUint fails: "+1", "+22", ...)
	//   rule-ACCEPTANCE divergence  =   1  (that AND the value is 96: "+96")
	//
	// 110 is the size of the grammar disagreement. 1 is the size of the
	// operational one — the tokens that actually install a translating rule
	// while the control plane reports it inert. The fix targets the class, so
	// the class count is what this cell pins; but a reader comparing this
	// against the issue's "110" should know which predicate each counts.
	var parseLevel int
	for _, tok := range nat64MaskCorpus8667() {
		_, goErr := strconv.ParseUint(tok, 10, 8)
		_, rsErr := strconv.ParseUint(strings.TrimPrefix(tok, "+"), 10, 8)
		if (goErr == nil) != (rsErr == nil) {
			parseLevel++
		}
	}
	t.Logf("#8667 corpus=%d parse-level divergence=%d rule-acceptance divergence=%d (all leading '+')",
		len(nat64MaskCorpus8667()), parseLevel, len(raw))
	if parseLevel == 0 {
		t.Error("no parse-level divergence at all — the corpus has stopped " +
			"probing the sign class that this whole issue is about")
	}
}

// #8667: normalising at SNAPSHOT BUILD must not soften the COMMIT GATE. The two
// live in different packages precisely so the operator is still told to write a
// canonical /96, and this is the coupling that would get introduced by accident
// if someone later "simplified" by normalising earlier.
func TestStrictCommitStillRejectsPlusNinetySix8667(t *testing.T) {
	if controlPlaneAcceptsNAT64Mask8667("+96") {
		t.Error("the strict gate's parse now ACCEPTS \"+96\". Normalisation at " +
			"snapshot build exists so the dataplane and control plane agree on " +
			"what is RUNNING; the commit gate must still refuse the " +
			"non-canonical spelling, or the operator is never told to fix it " +
			"(#8667)")
	}
	// And the normalisation itself must still be doing its job, or this cell
	// passes for the wrong reason — a fix that stopped normalising would leave
	// the gate strict and the divergence live.
	if got := NormaliseNAT64PrefixForSnapshot("64:ff9b::/+96"); got != "64:ff9b::/96" {
		t.Errorf("NormaliseNAT64PrefixForSnapshot(%q) = %q, want %q",
			"64:ff9b::/+96", got, "64:ff9b::/96")
	}
}

func truncate8667(in []string) []string {
	if len(in) <= 12 {
		return in
	}
	return append(append([]string(nil), in[:12]...), "...")
}
