package userspace

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// fakeCtrlMap is a programmable stand-in for the userspace_ctrl *ebpf.Map. It
// satisfies ctrlMapUpdater so the #5486 disable/fail-closed logic can be
// fault-injected without a privileged BPF map (the real-map link-cycle tests
// skip when memlock is unavailable).
type fakeCtrlMap struct {
	stored     userspaceCtrlValue
	haveStored bool

	// lookupErrs[i] (if non-nil) is returned by the i-th Lookup call.
	lookupErrs  []error
	lookupCalls int

	updateErr     error // returned by every Update when non-nil
	swallowUpdate bool  // Update returns nil but does NOT persist (silent no-op)
	updates       int
}

func (f *fakeCtrlMap) Lookup(key, valueOut interface{}) error {
	idx := f.lookupCalls
	f.lookupCalls++
	if idx < len(f.lookupErrs) && f.lookupErrs[idx] != nil {
		return f.lookupErrs[idx]
	}
	vp, ok := valueOut.(*userspaceCtrlValue)
	if !ok {
		return fmt.Errorf("fakeCtrlMap.Lookup: unexpected valueOut type %T", valueOut)
	}
	if !f.haveStored {
		return ebpf.ErrKeyNotExist
	}
	*vp = f.stored
	return nil
}

func (f *fakeCtrlMap) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	f.updates++
	if f.updateErr != nil {
		return f.updateErr
	}
	if f.swallowUpdate {
		return nil
	}
	v, ok := value.(userspaceCtrlValue)
	if !ok {
		return fmt.Errorf("fakeCtrlMap.Update: unexpected value type %T", value)
	}
	f.stored = v
	f.haveStored = true
	return nil
}

// (a) Lookup fault: the disable MUST still attempt a fail-closed (Enabled=0)
// write rather than silently bailing, and MUST return the error so a teardown
// caller learns the prior value was unreadable.
func TestDisableUserspaceCtrlLookupFaultWritesFailClosedAndReturnsError(t *testing.T) {
	fake := &fakeCtrlMap{lookupErrs: []error{errors.New("lookup boom")}}

	err := disableUserspaceCtrl(fake)
	if err == nil {
		t.Fatal("disableUserspaceCtrl returned nil on lookup fault, want error")
	}
	if fake.updates == 0 {
		t.Fatal("no ctrl Update attempted after lookup fault; fail-closed gate was not written")
	}
	if !fake.haveStored || fake.stored.Enabled != 0 {
		t.Fatalf("fail-closed ctrl row not written with Enabled=0: haveStored=%v stored=%+v", fake.haveStored, fake.stored)
	}
}

// (b) Update fault on the teardown path: the disable error MUST propagate and
// ALL bindings MUST be cleared (m.lastBindingIndices niled) so the XDP shim has
// no READY slot to redirect to before worker/UMEM teardown.
func TestDisableCtrlBeforeTeardownUpdateFaultClearsBindings(t *testing.T) {
	m := New()
	m.disableCtrlMapHook = &fakeCtrlMap{
		stored:     userspaceCtrlValue{Enabled: 1},
		haveStored: true,
		updateErr:  errors.New("update boom"),
	}
	m.lastBindingIndices = []uint32{1, 2, 3}

	err := m.disableCtrlBeforeTeardownLocked()
	if err == nil {
		t.Fatal("disableCtrlBeforeTeardownLocked returned nil on update fault, want error")
	}
	if m.lastBindingIndices != nil {
		t.Fatalf("lastBindingIndices = %v after fail-closed teardown, want nil (bindings must be cleared)", m.lastBindingIndices)
	}
}

// (c) Readback shows Enabled!=0: a silent write no-op (Update reports success
// but the row did not change) MUST be caught by the readback and returned as
// an error — otherwise a stale Enabled=1 strands transit redirecting to
// soon-dead XSK fds.
func TestDisableUserspaceCtrlReadbackMismatchReturnsError(t *testing.T) {
	fake := &fakeCtrlMap{
		stored:        userspaceCtrlValue{Enabled: 1},
		haveStored:    true,
		swallowUpdate: true, // Update "succeeds" but does not persist Enabled=0
	}

	err := disableUserspaceCtrl(fake)
	if err == nil {
		t.Fatal("disableUserspaceCtrl returned nil on readback mismatch, want error")
	}
	if !strings.Contains(err.Error(), "readback") {
		t.Fatalf("error = %v, want a readback-mismatch error", err)
	}
}

// Happy path: a successful disable sets Enabled=0, preserves the other ctrl
// fields byte-for-byte, and returns nil.
func TestDisableUserspaceCtrlHappyPathPreservesFieldsAndReturnsNil(t *testing.T) {
	fake := &fakeCtrlMap{
		stored:     userspaceCtrlValue{Enabled: 1, Flags: userspaceCtrlFlagStrict, Workers: 3, QueueCount: 3},
		haveStored: true,
	}

	if err := disableUserspaceCtrl(fake); err != nil {
		t.Fatalf("disableUserspaceCtrl happy path returned %v, want nil", err)
	}
	if fake.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d after disable, want 0", fake.stored.Enabled)
	}
	if fake.stored.Flags != userspaceCtrlFlagStrict || fake.stored.Workers != 3 || fake.stored.QueueCount != 3 {
		t.Fatalf("disable clobbered ctrl fields: %+v, want Flags/Workers/QueueCount preserved", fake.stored)
	}
}

// Happy-path teardown: a verified disable must NOT clear bindings (byte-for-byte
// with the pre-fix behavior — only a failed disable triggers the fail-closed
// binding clear).
func TestDisableCtrlBeforeTeardownSuccessKeepsBindings(t *testing.T) {
	m := New()
	m.disableCtrlMapHook = &fakeCtrlMap{stored: userspaceCtrlValue{Enabled: 1}, haveStored: true}
	m.lastBindingIndices = []uint32{7, 8}

	if err := m.disableCtrlBeforeTeardownLocked(); err != nil {
		t.Fatalf("disableCtrlBeforeTeardownLocked returned %v on success, want nil", err)
	}
	if len(m.lastBindingIndices) != 2 {
		t.Fatalf("lastBindingIndices = %v after successful disable, want preserved [7 8]", m.lastBindingIndices)
	}
}

// A missing ctrl map is itself a fail-closed-worthy anomaly during teardown:
// the disable returns an error and the teardown wrapper clears bindings.
func TestDisableCtrlBeforeTeardownMissingMapClearsBindings(t *testing.T) {
	m := New()
	// No disableCtrlMapHook and no loaded shim map -> ctrlMapForDisableLocked
	// returns nil.
	m.lastBindingIndices = []uint32{9}

	err := m.disableCtrlBeforeTeardownLocked()
	if err == nil {
		t.Fatal("disableCtrlBeforeTeardownLocked returned nil with no ctrl map, want error")
	}
	if m.lastBindingIndices != nil {
		t.Fatalf("lastBindingIndices = %v after missing-map teardown, want nil", m.lastBindingIndices)
	}
}
