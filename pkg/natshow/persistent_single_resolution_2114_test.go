package natshow

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #2114 (Codex PR #6743 r6-F2): the persistent-NAT renderers must resolve
// the table ONCE per render.
//
// The daemon hands these renderers a live indirection whose
// GetPersistentNAT() performs a fresh cell load on EVERY call, so the old
// `dp.GetPersistentNAT() == nil` check followed by a second
// `dp.GetPersistentNAT().All()` was a check-then-use spanning two distinct
// resolutions. A setDataplane(nil) landing between them returned nil to a
// caller that had already proven non-nil, and .All() dereferenced it.

// vanishingTableReader models exactly that: the FIRST GetPersistentNAT
// hands back a real table, every later call returns nil — the observable
// behaviour of the live indirection once the daemon disowns the backend.
type vanishingTableReader struct {
	Reader // nil embed: no other method is called by these renderers
	table  *dataplane.PersistentNATTable
	calls  int
}

func (r *vanishingTableReader) GetPersistentNAT() *dataplane.PersistentNATTable {
	r.calls++
	if r.calls > 1 {
		return nil
	}
	return r.table
}

// TestRenderPersistent_ResolvesTableOnce is the F2 binder for the render
// path.
//
// Fail-on-revert: restore
//
//	if dp == nil || dp.GetPersistentNAT() == nil { ... }
//	bindings := dp.GetPersistentNAT().All()
//
// and the second resolution returns nil, so .All() dereferences a nil
// *PersistentNATTable and `show security nat source persistent-nat-table`
// panics the process.
func TestRenderPersistent_ResolvesTableOnce(t *testing.T) {
	dp := &vanishingTableReader{table: dataplane.NewPersistentNATTable()}

	var buf bytes.Buffer
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		RenderPersistent(&buf, dp)
	}()

	if panicked != nil {
		t.Fatalf("RenderPersistent PANICKED (%v): it resolved GetPersistentNAT %d times, so a "+
			"disown between the nil-check and the use handed nil to a caller that had already "+
			"proven non-nil", panicked, dp.calls)
	}
	if dp.calls != 1 {
		t.Fatalf("GetPersistentNAT resolved %d times, want exactly 1", dp.calls)
	}
	if !strings.Contains(buf.String(), "No persistent NAT bindings") {
		t.Fatalf("render output = %q, want the empty-table line", buf.String())
	}
}

// TestRenderPersistentDetail_ResolvesTableOnce is the same binder for the
// detail renderer, in its own body so a failure of one cannot hide the
// other.
func TestRenderPersistentDetail_ResolvesTableOnce(t *testing.T) {
	dp := &vanishingTableReader{table: dataplane.NewPersistentNATTable()}

	var buf bytes.Buffer
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		RenderPersistentDetail(context.Background(), &buf, dp)
	}()

	if panicked != nil {
		t.Fatalf("RenderPersistentDetail PANICKED (%v) after %d resolutions", panicked, dp.calls)
	}
	if dp.calls != 1 {
		t.Fatalf("GetPersistentNAT resolved %d times, want exactly 1", dp.calls)
	}
	if !strings.Contains(buf.String(), "No persistent NAT bindings") {
		t.Fatalf("render output = %q, want the empty-table line", buf.String())
	}
}

// TestRenderPersistent_NoTableIsUnavailable is the negative control: a
// reader that never has a table must still take the "not available"
// branch, so the single-resolution change cannot be satisfied by simply
// dropping the nil check.
func TestRenderPersistent_NoTableIsUnavailable(t *testing.T) {
	dp := &vanishingTableReader{table: nil}

	var buf bytes.Buffer
	RenderPersistent(&buf, dp)
	if !strings.Contains(buf.String(), "Persistent NAT table not available") {
		t.Fatalf("render output = %q, want the unavailable line", buf.String())
	}

	buf.Reset()
	RenderPersistentDetail(context.Background(), &buf, dp)
	if !strings.Contains(buf.String(), "Persistent NAT table not available") {
		t.Fatalf("detail render output = %q, want the unavailable line", buf.String())
	}
}
