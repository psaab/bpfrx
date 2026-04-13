package config

import "testing"

func completionNames(results []SchemaCompletion) []string {
	names := make([]string, len(results))
	for i, result := range results {
		names[i] = result.Name
	}
	return names
}

func containsCompletionName(results []SchemaCompletion, want string) bool {
	for _, result := range results {
		if result.Name == want {
			return true
		}
	}
	return false
}

func TestResolveConsumedSetPathTokensResolvesPrefixes(t *testing.T) {
	resolved, ok := ResolveConsumedSetPathTokens([]string{"secu", "na", "sou"})
	if !ok {
		t.Fatal("ResolveConsumedSetPathTokens() returned false")
	}
	results := CompleteSetPathWithValues(resolved, nil)
	if !containsCompletionName(results, "pool") || !containsCompletionName(results, "rule-set") {
		t.Fatalf("expected source NAT subtree completions after consumed prefixes, got %v", completionNames(results))
	}
}

func TestCompleteSetPathWithValuesReturnsAmbiguousLastPrefixMatches(t *testing.T) {
	results := CompleteSetPathWithValues([]string{"security", "s"}, nil)
	if !containsCompletionName(results, "screen") || !containsCompletionName(results, "ssh-known-hosts") {
		t.Fatalf("expected ambiguous security subtree matches, got %v", completionNames(results))
	}
}
