package grpcapi

import "testing"

func hasPairName(pairs []completionPair, want string) bool {
	for _, p := range pairs {
		if p.name == want {
			return true
		}
	}
	return false
}

func TestCompleteConfigPairsCommitReturnsAllMatches(t *testing.T) {
	s := &Server{}
	pairs := s.completeConfigPairs([]string{"commit"}, "")
	if !hasPairName(pairs, "check") || !hasPairName(pairs, "confirmed") || !hasPairName(pairs, "comment") {
		t.Fatalf("expected all commit completions, got %#v", pairs)
	}
}

func TestCompleteConfigPairsLoadReturnsAllMatches(t *testing.T) {
	s := &Server{}
	pairs := s.completeConfigPairs([]string{"load"}, "")
	if !hasPairName(pairs, "override") || !hasPairName(pairs, "merge") || !hasPairName(pairs, "set") {
		t.Fatalf("expected all load completions, got %#v", pairs)
	}
}

func TestCompleteOperationalPairsShowConfigurationResolvesPrefixes(t *testing.T) {
	s := &Server{}
	pairs := s.completeOperationalPairs([]string{"show", "conf", "sec"}, "po")
	if !hasPairName(pairs, "policies") {
		t.Fatalf("expected policies completion for prefixed show configuration path, got %#v", pairs)
	}
}

func TestCompleteConfigPairsUniquePrefixDescends(t *testing.T) {
	s := &Server{}
	pairs := s.completeConfigPairs([]string{"com"}, "")
	if !hasPairName(pairs, "check") || !hasPairName(pairs, "confirmed") || !hasPairName(pairs, "comment") {
		t.Fatalf("expected commit subtree completions after unique prefix, got %#v", pairs)
	}
}

func TestCompleteConfigPairsAmbiguousPrefixReturnsMatches(t *testing.T) {
	s := &Server{}
	pairs := s.completeConfigPairs([]string{"co"}, "")
	if !hasPairName(pairs, "commit") || !hasPairName(pairs, "copy") {
		t.Fatalf("expected ambiguous top-level config matches, got %#v", pairs)
	}
}
