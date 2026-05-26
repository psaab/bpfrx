package frr

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeExecutor is a hand-rolled test double for the frrExecutor interface.
// Per-method response programming + per-method call counting. No external
// test framework dependencies.
type fakeExecutor struct {
	// vtyshResp returns the canned response for a given input command.
	// If the command is missing from the map, vtyshErr is returned.
	vtyshResp map[string]string
	vtyshErr  error

	// systemctlReloadErr is returned by SystemctlReload.
	systemctlReloadErr error

	// vtyshLoadResp / vtyshLoadErr are returned by VtyshLoad.
	vtyshLoadResp []byte
	vtyshLoadErr  error

	// Capture: most recent call args.
	lastVtyshCmd      string
	lastVtyshLoadConf string
	lastVtyshLoadCtx  context.Context
	systemctlCalls    int
	vtyshLoadCalls    int
	vtyshCalls        int
	lastSystemctlCtx  context.Context
}

func (f *fakeExecutor) Vtysh(command string) (string, error) {
	f.vtyshCalls++
	f.lastVtyshCmd = command
	if resp, ok := f.vtyshResp[command]; ok {
		return resp, nil
	}
	return "", f.vtyshErr
}

func (f *fakeExecutor) SystemctlReload(ctx context.Context) error {
	f.systemctlCalls++
	f.lastSystemctlCtx = ctx
	return f.systemctlReloadErr
}

func (f *fakeExecutor) VtyshLoad(ctx context.Context, conf string) ([]byte, error) {
	f.vtyshLoadCalls++
	f.lastVtyshLoadCtx = ctx
	f.lastVtyshLoadConf = conf
	return f.vtyshLoadResp, f.vtyshLoadErr
}

// TestExecVtyshUsesExecutor proves that Manager.ExecVtysh routes through
// the injected executor and returns its result verbatim. This is the
// archetype for AC#3 ("vtysh command execution is behind a narrow
// interface for tests").
func TestExecVtyshUsesExecutor(t *testing.T) {
	fake := &fakeExecutor{
		vtyshResp: map[string]string{"show whatever": "canned output"},
	}
	m := &Manager{exec: fake}
	out, err := m.ExecVtysh("show whatever")
	if err != nil {
		t.Fatalf("ExecVtysh: %v", err)
	}
	if out != "canned output" {
		t.Errorf("ExecVtysh: got %q, want %q", out, "canned output")
	}
	if fake.lastVtyshCmd != "show whatever" {
		t.Errorf("Vtysh called with %q, want %q", fake.lastVtyshCmd, "show whatever")
	}
}

// TestGetRIPRoutesUsesExecutor proves that a parsed Get* method also
// routes through the executor. Picks GetRIPRoutes because the parser is
// small and the inputs are easy to construct.
func TestGetRIPRoutesUsesExecutor(t *testing.T) {
	// FRR's "show ip rip" sample with two routes and a header line.
	canned := `Codes: R - RIP, C - connected, S - Static, O - OSPF, B - BGP
Network            Next Hop         Metric From            Tag Time
10.0.0.0/24        10.0.0.1         1      192.168.1.1     0   00:01:23
10.1.0.0/24        10.1.0.1         2      192.168.1.2     0   00:02:34
`
	fake := &fakeExecutor{
		vtyshResp: map[string]string{"show ip rip": canned},
	}
	m := &Manager{exec: fake}
	routes, err := m.GetRIPRoutes()
	if err != nil {
		t.Fatalf("GetRIPRoutes: %v", err)
	}
	if len(routes) < 2 {
		t.Fatalf("GetRIPRoutes: got %d routes, want at least 2", len(routes))
	}
	if routes[0].Network != "10.0.0.0/24" {
		t.Errorf("routes[0].Network = %q, want 10.0.0.0/24", routes[0].Network)
	}
	if fake.vtyshCalls != 1 {
		t.Errorf("Vtysh calls = %d, want 1", fake.vtyshCalls)
	}
}

// TestReloadUsesSystemctlHappyPath verifies that reload() calls
// SystemctlReload first and returns successfully when it succeeds — the
// VtyshLoad fallback must NOT be invoked.
func TestReloadUsesSystemctlHappyPath(t *testing.T) {
	fake := &fakeExecutor{
		systemctlReloadErr: nil, // happy path
	}
	m := &Manager{exec: fake, frrConf: "/tmp/test-frr.conf"}
	if err := m.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if fake.systemctlCalls != 1 {
		t.Errorf("SystemctlReload calls = %d, want 1", fake.systemctlCalls)
	}
	if fake.vtyshLoadCalls != 0 {
		t.Errorf("VtyshLoad calls = %d, want 0 on happy path", fake.vtyshLoadCalls)
	}
	if fake.lastSystemctlCtx == nil {
		t.Fatalf("SystemctlReload called with nil context — expected the 15s WithTimeout")
	}
	if _, ok := fake.lastSystemctlCtx.Deadline(); !ok {
		t.Errorf("SystemctlReload ctx has no deadline; expected the 15s reload timeout")
	}
}

// TestReloadFallsBackToVtyshLoad verifies that reload() falls through to
// VtyshLoad when systemctl reload returns an error.
func TestReloadFallsBackToVtyshLoad(t *testing.T) {
	fake := &fakeExecutor{
		systemctlReloadErr: errors.New("systemctl: unit frr not loaded"),
		vtyshLoadResp:      []byte(""),
		vtyshLoadErr:       nil,
	}
	m := &Manager{exec: fake, frrConf: "/tmp/test-frr.conf"}
	if err := m.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if fake.systemctlCalls != 1 {
		t.Errorf("SystemctlReload calls = %d, want 1", fake.systemctlCalls)
	}
	if fake.vtyshLoadCalls != 1 {
		t.Errorf("VtyshLoad calls = %d, want 1 (fallback)", fake.vtyshLoadCalls)
	}
	if fake.lastVtyshLoadConf != "/tmp/test-frr.conf" {
		t.Errorf("VtyshLoad conf = %q, want %q", fake.lastVtyshLoadConf, "/tmp/test-frr.conf")
	}
	if fake.lastVtyshLoadCtx == nil {
		t.Fatalf("VtyshLoad called with nil context — expected the 15s WithTimeout")
	}
	if _, ok := fake.lastVtyshLoadCtx.Deadline(); !ok {
		t.Errorf("VtyshLoad ctx has no deadline; expected the 15s reload timeout")
	}
}

// TestReloadFallbackErrorPropagated verifies that when both systemctl and
// vtysh -f fail, the error from VtyshLoad is wrapped with the captured
// output and returned.
func TestReloadFallbackErrorPropagated(t *testing.T) {
	fake := &fakeExecutor{
		systemctlReloadErr: errors.New("systemctl failed"),
		vtyshLoadResp:      []byte("syntax error at line 12"),
		vtyshLoadErr:       errors.New("exit status 1"),
	}
	m := &Manager{exec: fake, frrConf: "/tmp/test-frr.conf"}
	err := m.reload()
	if err == nil {
		t.Fatalf("reload: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "syntax error at line 12") {
		t.Errorf("reload error %q missing captured output", err.Error())
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("reload error %q missing underlying err", err.Error())
	}
}

// TestZeroValueManagerExecVtyshNoPanic verifies that a zero-value
// Manager — `var m frr.Manager` or `&Manager{}` — does NOT panic when
// ExecVtysh is called. The accessor returns realExecutor{} when m.exec
// is nil; the call may then fail because no vtysh binary is on PATH in
// CI, but it must not panic.
//
// Historical motivation: tests and ad-hoc callers in pkg/grpcapi /
// pkg/api have constructed literal Managers; the executor seam must not
// break that contract.
func TestZeroValueManagerExecVtyshNoPanic(t *testing.T) {
	var m Manager
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-value Manager.ExecVtysh panicked: %v", r)
		}
	}()
	// Don't assert on success — in CI there's likely no vtysh binary.
	// We just want to confirm no nil-deref via the accessor.
	_, _ = m.ExecVtysh("show version")
}
