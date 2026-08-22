package grpcapi

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/bootstrapshow"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #6496: `show system bootstrap-import` over the gRPC ShowText path.
//
// The recorded day-0 import outcome had exactly one renderer — the /health
// JSON on the loopback REST API — so an operator at a fresh box could not
// answer "why didn't my day-0 config apply?" from the CLI they were in. These
// bind the wiring end-to-end: the topic must be dispatched, it must render the
// snapshot the DAEMON supplied (not a default), and it must render it through
// the shared package so this and the in-process CLI cannot diverge.

// The dispatcher must actually consult the wired hook. RED on revert: drop
// `bootstrapImportFn: cfg.BootstrapImportFn` from NewServer, or stop calling
// the hook in the dispatcher, and the staged detail disappears from the render
// while the topic still "works" — the exact shape of a surface that reports a
// healthy default for a failed box.
func TestShowTextBootstrapImportRendersTheWiredSnapshot(t *testing.T) {
	const detail = `day-0 config REJECTED: unknown statement "dataplane-type"`
	// Constructed through NewServer, NOT as a bare &Server{...}: the wiring
	// under test is Config.BootstrapImportFn -> server.bootstrapImportFn, and a
	// test that sets the private field directly stays GREEN with that assignment
	// deleted. It did, on the first draft — the mutation that removed the
	// NewServer line left this file passing, which is what sent the tests back.
	s := NewServer("127.0.0.1:0", Config{
		Store: newConfigStore(t, t.TempDir()+"/xpf.conf"),
		BootstrapImportFn: func() bootstrapshow.Snapshot {
			return bootstrapshow.Snapshot{
				Status:  bootstrapshow.StatusFailed,
				Error:   detail,
				UnixSec: 1755792000,
				Failed:  true,
			}
		},
	})
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "bootstrap-import"})
	if err != nil {
		t.Fatalf("ShowText(bootstrap-import) error = %v", err)
	}
	out := resp.GetOutput()
	if !strings.Contains(out, "import-failed") {
		t.Errorf("wired status not rendered:\n%s", out)
	}
	if !strings.Contains(out, detail) {
		t.Errorf("wired error detail not rendered — the reason is the whole point "+
			"of the command, and /health cannot carry it (#5031):\n%s", out)
	}
}

// The gRPC render must be BYTE-IDENTICAL to pkg/bootstrapshow's, so the remote
// `cli`, the in-process console CLI (which calls Render directly) and this path
// cannot drift into showing different answers for one recorded fact.
func TestShowTextBootstrapImportMatchesTheSharedRenderer(t *testing.T) {
	for _, snap := range []bootstrapshow.Snapshot{
		{Status: bootstrapshow.StatusOK, UnixSec: 1755792000},
		{Status: bootstrapshow.StatusNoConfig, UnixSec: 1755792000},
		{Status: bootstrapshow.StatusLoadedDB, UnixSec: 1755792000},
		{Status: bootstrapshow.StatusFailed, Error: "boom", UnixSec: 1755792000, Failed: true},
		{},
	} {
		s := NewServer("127.0.0.1:0", Config{
			Store:             newConfigStore(t, t.TempDir()+"/xpf.conf"),
			BootstrapImportFn: func() bootstrapshow.Snapshot { return snap },
		})
		resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "bootstrap-import"})
		if err != nil {
			t.Fatalf("ShowText(%q) error = %v", snap.Status, err)
		}
		var want bytes.Buffer
		bootstrapshow.Render(&want, snap)
		if resp.GetOutput() != want.String() {
			t.Errorf("status %q: ShowText render diverges from bootstrapshow.Render\n"+
				"--- ShowText ---\n%s\n--- shared ---\n%s",
				snap.Status, resp.GetOutput(), want.String())
		}
	}
}

// A `cli` reaching a daemon that never recorded an outcome (or a no-daemon
// unit build) must still get a rendered answer, not an empty body an operator
// would read as "nothing wrong".
func TestShowTextBootstrapImportWithNoHookStillRenders(t *testing.T) {
	s := NewServer("127.0.0.1:0", Config{
		Store: newConfigStore(t, t.TempDir()+"/xpf.conf"),
	})
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "bootstrap-import"})
	if err != nil {
		t.Fatalf("ShowText(bootstrap-import) with nil hook error = %v", err)
	}
	if !strings.Contains(resp.GetOutput(), "not-recorded") {
		t.Errorf("nil hook must render an explicit not-recorded state:\n%s", resp.GetOutput())
	}
}
