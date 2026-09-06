package daemon

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// traceOptsCfg builds a config that enables flow traceoptions to the given
// basename with the `session` flag so SESSION_CLOSE events are traced.
func traceOptsCfg(file string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Flow.Traceoptions = &config.FlowTraceoptions{
		File:  file,
		Flags: []string{"session"},
	}
	return cfg
}

// TestFlowTraceSingleCallbackAcrossReconciles pins #3932: repeated
// traceoptions reconciles must leave EXACTLY ONE registered EventReader
// callback and ONE live TraceWriter, swapping the underlying writer in place
// rather than registering a new callback on every commit.
//
// RED-on-revert: the old applyFlowTrace/updateFlowTrace called er.AddCallback
// on every commit, so after 3 reconciles the reader held 3 callbacks (not 1)
// and every event was dispatched to all of them — including the stale, closed
// writers (each bumping DroppedWrites). Both the CallbackCount == 1 assertions
// and the stale-writer DroppedWrites-unchanged assertions flip on revert.
func TestFlowTraceSingleCallbackAcrossReconciles(t *testing.T) {
	dir := t.TempDir()
	restore := logging.SetTraceLogDirForTest(dir)
	defer restore()

	d := &Daemon{
		daemonCtx:   context.Background(),
		eventReader: logging.NewEventReader(nil, nil),
	}

	// Boot enable.
	d.applyFlowTrace(traceOptsCfg("trace.log"), d.eventReader)
	w1 := d.traceWriterPtr.Load()
	if w1 == nil {
		t.Fatal("applyFlowTrace must install a live trace writer")
	}
	if n := d.eventReader.CallbackCount(); n != 1 {
		t.Fatalf("after enable: callbacks=%d, want 1", n)
	}

	// Two more reconciles, distinct files so writer identity is observable.
	d.updateFlowTrace(traceOptsCfg("trace2.log"))
	w2 := d.traceWriterPtr.Load()
	if n := d.eventReader.CallbackCount(); n != 1 {
		t.Fatalf("after 2nd reconcile: callbacks=%d, want 1 (callback leaked on revert)", n)
	}
	if w2 == w1 {
		t.Fatal("2nd reconcile must swap in a new writer")
	}

	d.updateFlowTrace(traceOptsCfg("trace3.log"))
	w3 := d.traceWriterPtr.Load()
	if n := d.eventReader.CallbackCount(); n != 1 {
		t.Fatalf("after 3rd reconcile: callbacks=%d, want 1 (callback leaked on revert)", n)
	}
	if w3 == nil || w3 == w2 {
		t.Fatal("3rd reconcile must swap in a new writer")
	}

	// The two superseded writers must have been closed on swap; capture their
	// drop counters so we can prove the dispatch below never touches them.
	before1, before2 := w1.DroppedWrites(), w2.DroppedWrites()

	// Dispatch ONE SESSION_CLOSE through the reader. Exactly the single stable
	// callback fires, so only the CURRENT writer (w3) sees the event.
	payload := buildSessionCloseRawEventV4(
		6, // TCP
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		12345, 443,
		[4]byte{0, 0, 0, 0}, 0,
		2, 3, // trust -> untrust
	)
	if !d.eventReader.ProcessRawEvent(payload) {
		t.Fatal("ProcessRawEvent rejected a valid SESSION_CLOSE payload")
	}

	// On the fix the stale writers are unregistered, so the dispatch never
	// reaches them: their DroppedWrites counters do not move. On revert each
	// stale-but-closed writer's leaked callback fires and bumps DroppedWrites.
	if got := w1.DroppedWrites(); got != before1 {
		t.Fatalf("stale writer w1 received a dispatched event (DroppedWrites %d->%d): callback leaked", before1, got)
	}
	if got := w2.DroppedWrites(); got != before2 {
		t.Fatalf("stale writer w2 received a dispatched event (DroppedWrites %d->%d): callback leaked", before2, got)
	}

	// #9025: the trace write is now handed to a bounded queue on a dedicated
	// goroutine, so drain it before reading the file. This does not weaken the
	// dispatch-once assertion — it still counts LINES, and a second dispatch
	// would still produce a second line.
	w3.SyncForTest()

	// The single live writer wrote the event exactly once (dispatch-once).
	data, err := os.ReadFile(filepath.Join(dir, "trace3.log"))
	if err != nil {
		t.Fatalf("read current trace file: %v", err)
	}
	if got := bytes.Count(data, []byte("\n")); got != 1 {
		t.Fatalf("current trace file has %d lines, want 1 (dispatch-once)", got)
	}

	// Disabling traceoptions clears the live writer and closes it; the stable
	// callback stays but becomes a no-op.
	d.updateFlowTrace(&config.Config{})
	if d.traceWriterPtr.Load() != nil {
		t.Fatal("disabling traceoptions must clear the live writer")
	}
	if n := d.eventReader.CallbackCount(); n != 1 {
		t.Fatalf("after disable: callbacks=%d, want 1 (single stable callback stays)", n)
	}
	// A dispatch after disable must not panic and must write nothing.
	if !d.eventReader.ProcessRawEvent(payload) {
		t.Fatal("ProcessRawEvent rejected a valid SESSION_CLOSE after disable")
	}
}
