package api

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteJSONMarshalFailureReturns500 is the #4541 regression guard.
// writeJSON used to set Content-Type + WriteHeader(200) BEFORE running
// json.NewEncoder(w).Encode(v) and ignored the encode error, so a value
// that fails to marshal committed a 200 status line and then produced a
// truncated/empty body — a success code over a broken response. The fix
// marshals to a buffer first and, on failure, writes a 500 with a static
// error body.
//
// Goes RED on revert: the old code records status 200 (httptest's default
// once WriteHeader(200) runs) with an empty body instead of 500. math.NaN
// is not representable in JSON, so json.Marshal returns an error.
func TestWriteJSONMarshalFailureReturns500(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, math.NaN())

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (marshal failure must not yield a success code)", rec.Code, http.StatusInternalServerError)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body Response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("500 body not valid JSON: %v (raw %q)", err, rec.Body.String())
	}
	if body.Success {
		t.Errorf("500 body success = true, want false")
	}
	if body.Error == "" {
		t.Errorf("500 body error is empty, want a diagnostic message")
	}
}

// TestWriteJSONSuccessByteIdentical pins that the common success path is
// byte-identical to the previous json.NewEncoder(w).Encode(v) behavior for
// a valid value: same status, same Content-Type, and the same wire body
// (compact JSON followed by a single trailing newline, exactly what
// Encoder.Encode emitted).
func TestWriteJSONSuccessByteIdentical(t *testing.T) {
	v := Response{Success: true, Data: map[string]any{"count": 3, "name": "trust"}}

	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, v)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Reconstruct the exact bytes the old Encoder.Encode(v) would have
	// written: json.Marshal output plus a trailing '\n'.
	want, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal reference value: %v", err)
	}
	want = append(want, '\n')
	if got := rec.Body.Bytes(); string(got) != string(want) {
		t.Fatalf("body = %q, want %q (success path must be byte-identical to Encoder.Encode)", got, want)
	}
}
