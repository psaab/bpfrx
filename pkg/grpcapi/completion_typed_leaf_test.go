package grpcapi

import "testing"

// #1319 PR 1 — frontend-boundary tests for typed-leaf value completion on
// the gRPC completer (completeConfigPairs), which serves the remote `cli`
// binary. Mirrors the local-CLI boundary tests in pkg/cli; both frontends
// route `set` completion through config.CompleteSetPathWithValues over
// setSchema, so both must surface the typed-leaf value examples.

// Symptom-1 demonstration on the gRPC path: `set class-of-service
// schedulers be transmit-rate ?` surfaces <rate> + examples.
func TestCompleteConfigPairs_TransmitRate_ShowsRatePlaceholderAndExamples(t *testing.T) {
	s := &Server{}
	pairs := s.completeConfigPairs(
		[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate"},
		"",
	)
	if !hasPairName(pairs, "<rate>") {
		t.Fatalf("expected <rate> placeholder at value slot, got %#v", pairs)
	}
	for _, ex := range []string{"100k", "10m", "1g", "10g"} {
		if !hasPairName(pairs, ex) {
			t.Fatalf("expected rate example %q, got %#v", ex, pairs)
		}
	}
}

func TestCompleteConfigPairs_TransmitRate_AfterValueShowsExact(t *testing.T) {
	s := &Server{}
	pairs := s.completeConfigPairs(
		[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate", "1g"},
		"",
	)
	if !hasPairName(pairs, "exact") {
		t.Fatalf("expected `exact` modifier after consumed rate, got %#v", pairs)
	}
	if hasPairName(pairs, "<rate>") {
		t.Fatalf("placeholder should not reappear after value, got %#v", pairs)
	}
}

func TestCompleteConfigPairs_Priority_ShowsEnumExamples(t *testing.T) {
	s := &Server{}
	pairs := s.completeConfigPairs(
		[]string{"set", "class-of-service", "schedulers", "be", "priority"},
		"",
	)
	for _, want := range []string{"low", "medium-low", "medium-high", "high", "strict-high"} {
		if !hasPairName(pairs, want) {
			t.Fatalf("expected priority enum example %q, got %#v", want, pairs)
		}
	}
}

func TestCompleteConfigPairs_BufferSize_ShowsExamples(t *testing.T) {
	s := &Server{}
	pairs := s.completeConfigPairs(
		[]string{"set", "class-of-service", "schedulers", "be", "buffer-size"},
		"",
	)
	if !hasPairName(pairs, "<bytes|percent>") {
		t.Fatalf("expected <bytes|percent> placeholder, got %#v", pairs)
	}
	for _, ex := range []string{"16m", "256k", "10%"} {
		if !hasPairName(pairs, ex) {
			t.Fatalf("expected buffer-size example %q, got %#v", ex, pairs)
		}
	}
}
