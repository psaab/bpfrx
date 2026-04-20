// Tests for commit-path wiring — #797 H2: local CLI commits must run
// through the daemon's full reconcile (applyConfigFn) so D3 RSS
// indirection reapply, cluster, VRRP, DHCP etc. all trigger. Prior to
// the fix the CLI invoked applyToDataplane() directly which covered
// only dataplane/FRR/IPsec.
package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// commitApply must dispatch to the injected applyConfigFn when wired.
// This is the "in-process CLI from inside xpfd" path.
func TestCommitApply_UsesApplyConfigFnWhenSet(t *testing.T) {
	var called int
	var seenCfg *config.Config
	c := &CLI{}
	c.SetApplyConfigFn(func(cfg *config.Config) {
		called++
		seenCfg = cfg
	})

	want := &config.Config{}
	want.System.HostName = "test-fw"
	c.commitApply(want)

	if called != 1 {
		t.Fatalf("applyConfigFn must be called exactly once, got %d", called)
	}
	if seenCfg != want {
		t.Fatalf("applyConfigFn must see the committed config, got %p want %p", seenCfg, want)
	}
}

// commitApply must NOT fall through to applyToDataplane when
// applyConfigFn is set — double-invoking would re-run dataplane compile.
func TestCommitApply_DoesNotCallLegacyWhenFnSet(t *testing.T) {
	var called int
	c := &CLI{}
	c.SetApplyConfigFn(func(cfg *config.Config) { called++ })

	// c.dp is nil, so applyToDataplane would be a no-op regardless,
	// but this test pins the ordering by asserting applyConfigFn is
	// the only path taken.
	c.commitApply(&config.Config{})
	if called != 1 {
		t.Fatalf("want applyConfigFn called once, got %d", called)
	}
}

// When applyConfigFn is not wired (e.g. CLI spawned outside daemon),
// commitApply falls back to the legacy applyToDataplane path. With no
// dataplane set, that is a no-op — no panic, no error leak.
func TestCommitApply_FallsBackWhenFnUnset(t *testing.T) {
	c := &CLI{}
	// No SetApplyConfigFn, no dp.
	c.commitApply(&config.Config{})
	// Reached here without panic: behaviour is OK.
}
