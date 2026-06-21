package daemon

import (
	"errors"
	"fmt"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestCompileErrorMustAbortApply(t *testing.T) {
	if !compileErrorMustAbortApply(dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatal("scheduler protocol incompatibility must abort apply")
	}
	if !compileErrorMustAbortApply(fmt.Errorf("wrapped: %w", dpuserspace.ErrPolicySchedulerProtocolIncompatible)) {
		t.Fatal("wrapped scheduler protocol incompatibility must abort apply")
	}
	// #2138: the persistent-source-NAT protocol gate is the same required
	// gate class as the scheduler gate — it disarms the helper, so a commit
	// that hits it must abort (not promote a config against a dead dataplane).
	// Pre-fix this returned false: the persistent-SNAT sentinel was missing
	// from the abort set.
	if !compileErrorMustAbortApply(dpuserspace.ErrPersistentSourceNATProtocolIncompatible) {
		t.Fatal("persistent source NAT protocol incompatibility must abort apply")
	}
	if !compileErrorMustAbortApply(fmt.Errorf("publish userspace snapshot: %w", dpuserspace.ErrPersistentSourceNATProtocolIncompatible)) {
		t.Fatal("wrapped persistent source NAT protocol incompatibility must abort apply")
	}
	if compileErrorMustAbortApply(errors.New("compile failed for unrelated dataplane reason")) {
		t.Fatal("non-protocol compile failures must not abort apply")
	}
	if compileErrorMustAbortApply(nil) {
		t.Fatal("nil error must not abort apply")
	}
}
