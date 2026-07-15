package config

import (
	"runtime"
	"strings"
	"testing"
)

// #5827: the recursive-descent parser recorded one ParseError per bad token with
// an uncapped addError, so a hostile/corrupt payload (up to the 16 MiB
// MaxConfigSize) pinned millions of ParseError structs LIVE simultaneously — an
// unbounded-heap DoS on every config-parse entry point (load/commit, HA
// config-sync, CheckText). The fix caps the RETAINED diagnostic set at
// maxParseErrors and folds the rest into one trailing summary. The lexer still
// drains the whole input in O(input) for deterministic termination.

// invalidByte is a character the lexer always tokenizes as TokenError (not an
// identifier char, brace, bracket, semicolon, quote, or whitespace). Verified by
// the guard test below so the dense-payload tests can rely on it.
const invalidByte = "@"

// TestParseErrorCap_InvalidByteReallyErrors_5827 guards the assumption the
// dense-payload tests rest on: a single invalidByte parses to exactly one error.
func TestParseErrorCap_InvalidByteReallyErrors_5827(t *testing.T) {
	_, errs := NewParser(invalidByte).Parse()
	if len(errs) != 1 {
		t.Fatalf("a single %q must yield exactly one parse error, got %d: %v", invalidByte, len(errs), errs)
	}
}

// TestParseErrorCap_16MiBInvalidBounded_5827 is the primary deterministic
// fail-on-revert lever: a 16 MiB all-invalid payload must parse+terminate with
// NO panic/OOM and retain at most maxParseErrors+1 diagnostics (the cap errors
// plus the trailing summary). It also pins that the summary reports the huge
// suppressed count.
//
// FAIL-ON-REVERT: with the uncapped addError, len(errs) is ~16 million (one per
// bad byte) — hugely greater than maxParseErrors+1 — and the summary is absent.
func TestParseErrorCap_16MiBInvalidBounded_5827(t *testing.T) {
	payload := strings.Repeat(invalidByte, 16<<20) // 16 MiB, MaxConfigSize
	tree, errs := NewParser(payload).Parse()

	if tree == nil {
		t.Fatal("Parse must return a (possibly empty) tree, not nil, even on an all-invalid payload")
	}
	if len(errs) > maxParseErrors+1 {
		t.Fatalf("retained diagnostics = %d, want <= maxParseErrors+1 (%d) — the uncapped "+
			"addError pins one ParseError per bad byte (~16M) = OOM DoS (#5827)", len(errs), maxParseErrors+1)
	}
	// The trailing summary must be present and name a large suppressed count.
	last := errs[len(errs)-1].Message
	if !strings.HasPrefix(last, "additional parse errors suppressed (") {
		t.Fatalf("last diagnostic must be the suppression summary, got %q", last)
	}
	// The first maxParseErrors diagnostics are the real per-byte errors.
	if len(errs) != maxParseErrors+1 {
		t.Fatalf("a 16 MiB all-invalid payload must fill the cap exactly: len=%d, want %d",
			len(errs), maxParseErrors+1)
	}
}

// TestParseErrorCap_RetainedHeapBudget_5827 asserts the retained heap after
// parsing a dense-error payload is O(cap), not O(error count). It measures the
// live-heap growth (runtime.MemStats HeapAlloc) with the returned diagnostics
// kept alive; capped, this is dominated by the input payload + a handful of
// structs; uncapped it would be hundreds of MiB of ParseError structs.
//
// The len<=cap+1 assertion above is the deterministic primary lever; this is the
// stronger budget guard. The ceiling is generous (well above the payload, far
// below the uncapped struct heap) to stay robust against GC/measurement noise.
func TestParseErrorCap_RetainedHeapBudget_5827(t *testing.T) {
	const payloadBytes = 8 << 20 // 8 MiB dense-error payload
	payload := strings.Repeat(invalidByte, payloadBytes)

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	_, errs := NewParser(payload).Parse()
	runtime.GC() // reclaim transient lexer strings + the empty tree; errs stays referenced below
	runtime.ReadMemStats(&m2)

	grew := int64(m2.HeapAlloc) - int64(m1.HeapAlloc)
	// Uncapped: ~8M ParseError structs (each struct + its message string) ≈
	// hundreds of MiB. Capped: the 8 MiB payload (still referenced) + ~cap
	// structs. A 64 MiB ceiling passes the capped case and fails the uncapped.
	const budget = 64 << 20
	if grew > budget {
		t.Fatalf("retained heap grew %d bytes after parsing an %d-byte dense-error payload; "+
			"want <= %d — retention must be O(cap), not O(error count) (#5827)", grew, payloadBytes, budget)
	}
	if len(errs) > maxParseErrors+1 {
		t.Fatalf("retained diagnostics = %d, want <= %d", len(errs), maxParseErrors+1)
	}
	runtime.KeepAlive(errs)
	runtime.KeepAlive(payload)
}

// TestParseErrorCap_MixedValidInvalidOrderAndSummary_5827 pins that the FIRST
// diagnostics preserve parse order + line/column, the trailing summary is
// present when suppression happened, and valid statements before the error flood
// still parse into the tree (the cap does not drop real config).
func TestParseErrorCap_MixedValidInvalidOrderAndSummary_5827(t *testing.T) {
	var b strings.Builder
	// A valid statement first, then a flood of invalid bytes (each on its own
	// line so line numbers advance and are checkable).
	b.WriteString("system {\n")
	b.WriteString("host-name fw;\n")
	b.WriteString("}\n")
	firstErrLine := 4 // the flood starts on line 4
	for i := 0; i < maxParseErrors*3; i++ {
		b.WriteString(invalidByte + "\n")
	}
	tree, errs := NewParser(b.String()).Parse()

	// The valid `system { host-name fw; }` block parsed.
	if len(tree.Children) == 0 || tree.Children[0].Keys[0] != "system" {
		t.Fatalf("valid statement before the error flood was dropped; tree=%+v", tree.Children)
	}
	if len(errs) > maxParseErrors+1 {
		t.Fatalf("len(errs)=%d, want <= %d", len(errs), maxParseErrors+1)
	}
	// First error keeps its line/column (ordering preserved).
	if errs[0].Line != firstErrLine {
		t.Fatalf("first diagnostic line = %d, want %d (order/position must be preserved)", errs[0].Line, firstErrLine)
	}
	// Errors are in non-decreasing line order for the retained prefix.
	for i := 1; i < len(errs)-1; i++ { // exclude the trailing summary (line 0)
		if errs[i].Line < errs[i-1].Line {
			t.Fatalf("retained diagnostics out of order at %d: line %d < %d", i, errs[i].Line, errs[i-1].Line)
		}
	}
	last := errs[len(errs)-1].Message
	if !strings.HasPrefix(last, "additional parse errors suppressed (") {
		t.Fatalf("trailing summary missing; last=%q", last)
	}
}

// TestParseErrorCap_DepthAndTokenCapInteract_5827 exercises BOTH suppression
// paths together: a payload with a flood of token errors AND over-deep nesting.
// Both must suppress, the parse must terminate without panic, and the retained
// set stays bounded (no double-count or blow-up).
func TestParseErrorCap_DepthAndTokenCapInteract_5827(t *testing.T) {
	var b strings.Builder
	// A flood of token errors to reach the token cap...
	for i := 0; i < maxParseErrors*2; i++ {
		b.WriteString(invalidByte + " ")
	}
	// ...followed by an over-deep brace nest (well past maxParseDepth, far below
	// any stack-overflow threshold) to also drive the depth-cap path.
	b.WriteString("a " + strings.Repeat("{ ", maxParseDepth+50))
	tree, errs := NewParser(b.String()).Parse()

	if tree == nil {
		t.Fatal("Parse returned nil tree on the combined token+depth payload")
	}
	if len(errs) > maxParseErrors+1 {
		t.Fatalf("combined token+depth suppression retained %d diagnostics, want <= %d (#5827)",
			len(errs), maxParseErrors+1)
	}
}

// FuzzParseErrorBound_5827 pins the diagnostic bound for ARBITRARY input: for any
// bytes, Parse must not panic and must retain at most maxParseErrors+1
// diagnostics. The seeded corpus runs under `go test`; `go test -fuzz` explores
// further. Deterministic termination relies on the lexer draining O(input).
func FuzzParseErrorBound_5827(f *testing.F) {
	f.Add("")
	f.Add("system { host-name fw; }")
	f.Add(strings.Repeat(invalidByte, 1000))
	f.Add("a { b { c ] @ ; } }")
	f.Add(strings.Repeat("@ ", 500) + strings.Repeat("{ ", maxParseDepth+10)) // token + depth caps
	f.Fuzz(func(t *testing.T, in string) {
		if len(in) > 16<<20 {
			t.Skip() // every parse entry point size-gates at MaxConfigSize
		}
		_, errs := NewParser(in).Parse()
		if len(errs) > maxParseErrors+1 {
			t.Fatalf("len(errs)=%d exceeds maxParseErrors+1 (%d) for a %d-byte input", len(errs), maxParseErrors+1, len(in))
		}
	})
}
