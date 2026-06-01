// Package configstore: warnEqualFlowWorkerCap surfaces the #1733
// equal-flow worker-cap condition on the tolerant load / peer-sync
// paths.
//
// The commit-time strict validator (config.validateEqualFlowWorkerCapStrict)
// hard-rejects a config that enables CoS equal-flow-enforcement on more
// than config.MaxEqualFlowWorkers worker threads, because the v8 lease
// rotation silently fail-opens equal-flow above that count
// (rotate_epoch_v8.rs MAX_WORKERS_SCRATCH / publish_equal_flow_epoch_v8.rs
// fail_open(UnsampledActiveWorker)). To avoid blacking out an upgraded
// node's boot (Store.Load) or alarm-looping HA config sync
// (Store.SyncApply) on an already-persisted/peer-synced legacy config,
// those two paths compile leniently: the validator's error is downgraded
// to a cfg.Warnings entry instead of a hard reject (see
// Store.compileTreeLenient).
//
// This file emits the matching operator-facing journald WARN. The text is
// equal-flow-specific (NOT the retired-dataplane phrasing) and the
// remediation hint differs by caller: a local boot is fixed by a local
// `commit`, while a peer-synced config originates on the un-upgraded
// primary and must be fixed there.
package configstore

import (
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// warnEqualFlowWorkerCap logs a loud WARN for each #1733 equal-flow
// worker-cap warning carried on the leniently-compiled config. The
// warnings were appended by config.compileExpanded under the lenient
// flag; they are identified by the stable substring
// "equal-flow-enforcement is unsupported" emitted by
// validateEqualFlowWorkerCapStrict.
//
// caller selects the remediation phrasing (LoadCaller: fix locally;
// SyncCaller: fix the un-upgraded primary). Safe to call with a nil
// compiled config (no-op).
func warnEqualFlowWorkerCap(compiled *config.Config, caller retireRewriteCaller) {
	if compiled == nil {
		return
	}
	for _, w := range compiled.Warnings {
		if !strings.Contains(w, "equal-flow-enforcement is unsupported") {
			continue
		}
		slog.Warn(
			equalFlowWorkerCapWarnMessage(caller),
			"detail", w,
			"remediation", equalFlowWorkerCapRemediation(caller),
		)
	}
}

func equalFlowWorkerCapWarnMessage(caller retireRewriteCaller) string {
	switch caller {
	case SyncCaller:
		return "HA peer-synced config enables CoS equal-flow-enforcement above the supported worker cap; tolerating it (equal-flow silently disabled at runtime) so HA sync converges"
	default:
		return "persisted active-config enables CoS equal-flow-enforcement above the supported worker cap; tolerating it (equal-flow silently disabled at runtime) so the daemon boots"
	}
}

func equalFlowWorkerCapRemediation(caller retireRewriteCaller) string {
	switch caller {
	case SyncCaller:
		return "the un-upgraded primary is still pushing this config; on the primary, reduce system dataplane workers to <= the cap or remove equal-flow-enforcement, then `commit` so future sync rounds converge"
	default:
		return "reduce system dataplane workers to <= the cap or remove equal-flow-enforcement, then `commit`; the next candidate commit will be rejected until then"
	}
}
