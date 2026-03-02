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
	if !hasPairName(pairs, "check") || !hasPairName(pairs, "confirmed") {
		t.Fatalf("expected both commit completions, got %#v", pairs)
	}
}

func TestCompleteConfigPairsLoadReturnsAllMatches(t *testing.T) {
	s := &Server{}
	pairs := s.completeConfigPairs([]string{"load"}, "")
	if !hasPairName(pairs, "override") || !hasPairName(pairs, "merge") {
		t.Fatalf("expected both load completions, got %#v", pairs)
	}
}
