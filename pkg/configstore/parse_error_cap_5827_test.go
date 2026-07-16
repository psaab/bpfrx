package configstore

import (
	"strings"
	"testing"
)

// #5827 integration: the strict config-parse entry points (CheckText — day-0 /
// check-config; the Load/SyncApply paths share the same NewParser().Parse()) must
// stay safe on a dense-error payload. The parser fix caps the RETAINED diagnostic
// set, so a hostile blob no longer pins O(input) ParseError structs before the
// caller ever reads errs[0]. This pins the load-path contract: a bounded, concise
// error and NO partial config applied. (The deterministic count/heap
// fail-on-revert lever lives in pkg/config's parser_error_cap_5827_test.go.)

// TestCheckText_DenseErrorPayloadConciseNoPartialApply_5827 drives the real
// CheckText entry point with an 8 MiB all-invalid payload (under MaxConfigSize)
// and asserts it returns a CONCISE error and a nil compiled config (no partial
// apply), without OOM/panic.
func TestCheckText_DenseErrorPayloadConciseNoPartialApply_5827(t *testing.T) {
	payload := strings.Repeat("@", 8<<20) // 8 MiB dense-error, under the 16 MiB cap

	compiled, err := CheckText(payload, -1)
	if err == nil {
		t.Fatal("CheckText must reject an all-invalid payload")
	}
	if compiled != nil {
		t.Fatal("CheckText must NOT return a partial compiled config on a parse failure")
	}
	// Concise: the error surfaces the first diagnostic, never a dump of millions.
	if !strings.Contains(err.Error(), "parse error") {
		t.Fatalf("expected a concise parse error, got %q", err.Error())
	}
	if len(err.Error()) > 500 {
		t.Fatalf("parse error must be concise (<=500 chars), got %d chars: %.120q...", len(err.Error()), err.Error())
	}
}

// TestCheckText_OversizePayloadRejectedBeforeParse_5827 confirms the size gate
// still fires first: a payload over MaxConfigSize is rejected up front (never
// reaching the parser), a defence-in-depth layer complementing the parser cap.
func TestCheckText_OversizePayloadRejectedBeforeParse_5827(t *testing.T) {
	payload := strings.Repeat("@", (16<<20)+1) // one byte over MaxConfigSize
	if _, err := CheckText(payload, -1); err == nil {
		t.Fatal("CheckText must reject an over-MaxConfigSize payload before parsing")
	}
}
