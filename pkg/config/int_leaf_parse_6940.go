package config

import (
	"fmt"
	"strconv"
)

// parseIntLeaf parses a typed integer leaf, reporting a malformed value instead
// of silently yielding zero (#6940).
//
// THE DEFECT IT REPLACES. Thirteen leaves parsed as `x, _ = strconv.Atoi(v)`.
// `Atoi` returns 0 alongside its error, so a typo, a unit suffix, or a `${var}`
// that did not expand compiled to zero and the commit succeeded.
//
// "A wrong number" understates it. For five of the thirteen, ZERO IS THE
// DOCUMENTED SENTINEL for "not configured":
//
//	LeaseTime                   "seconds (0 = default)"
//	NTPThreshold                "0 = default"   (consumers gate on > 0)
//	TransferInterval            "0 = on commit only"
//	PrefixDelegatingPrefixLen   "0 = not set, send no length hint"
//	PrefixDelegatingSubPrefLen  "0 = advertise the delegated prefix as-is"
//
// So the malformed value does not land somewhere visibly wrong — it lands
// exactly where "the operator never wrote this leaf" lands, which is the one
// place nothing can distinguish it from. `TransferInterval` is the sharpest: a
// typo silently switches archival from periodic to on-commit-only.
//
// It is the same structure as the fixture rule that a probe must never use the
// value the bug falls back to, except here it is PRODUCTION whose fallback
// equals the sentinel.
//
// WHICH PATH THIS IS FOR. On the strict commit path the schema validator
// rejects a malformed integer before the compiler runs — measured for all
// thirteen leaves. So this warning is reachable only through
// `compileTreeLenient`, which `Store.Load` (disk boot) and `Store.SyncApply`
// (HA peer sync) use and which does not schema-validate at all.
//
// That is deliberate and it is why this WARNS rather than returning an error.
// The lenient path exists to accept input the strict path would reject; making
// it reject would refuse a persisted config on boot or fail an HA sync, which
// is a worse failure than the one being fixed (#1960 no-brick). Warn, do not
// rewrite silently, and do not reject.
//
// The warning reaches an operator: `cfg.Warnings` is logged by the daemon's
// `applyConfigLocked` as `slog.Warn("config validation", ...)` on the boot and
// sync applies, and is carried to the CLI in the commit response. It is not a
// diagnostic into a void.
func parseIntLeaf(warnings *[]string, path, raw string) (int, bool) {
	n, err := strconv.Atoi(raw)
	if err == nil {
		return n, true
	}
	if warnings != nil {
		*warnings = append(*warnings, fmt.Sprintf(
			"%s: %q is not an integer — the leaf is IGNORED (a strict commit "+
				"rejects this value; it survives here only because the tolerant "+
				"load / peer-sync path does not schema-validate). Before #6940 it "+
				"silently became 0, which for this leaf class is indistinguishable "+
				"from never having configured it", path, raw))
	}
	return 0, false
}
