package grpcapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// #9324 CENSUS, made permanent.
//
// The defect was a proto3 ZERO VALUE that is a real, privileged choice rather
// than an "unspecified" sentinel: `ConfigTarget { CANDIDATE = 0; }`, so an
// omitted target selected another session's uncommitted configuration on a
// PermView-priced RPC. That shape is general, so the whole enum set was
// censused rather than the one enum fixed.
//
// RESULT of the census at the time of #9324 — seven enums:
//
//	ConfigFormat                 HIERARCHICAL = 0             non-sentinel, BENIGN
//	ConfigTarget                 CANDIDATE = 0                non-sentinel, THE DEFECT
//	MonitorInterfaceSummaryMode  ..._COMBINED = 0             non-sentinel, BENIGN
//	ZoneCounterAvailability      ..._UNKNOWN = 0              sentinel
//	HostInboundAdmissionStatus   ..._NOT_COMPUTED = 0         sentinel
//	NATDeterministicDirection    ..._UNSPECIFIED = 0          sentinel
//	PeerFetchStatus              ..._UNSPECIFIED = 0          sentinel
//
// The two BENIGN verdicts were audited rather than assumed, because a benign
// verdict is the one nobody re-checks:
//
//   - ConfigFormat picks a RENDERER for whatever target was already chosen.
//     Every arm of ShowConfig's switch calls a *Redacted renderer, so no format
//     discloses more than another; the default renders hierarchical text, which
//     is Junos's own default rendering.
//   - MonitorInterfaceSummaryMode picks which counter columns to display. No
//     target, no privilege, no content difference.
//
// This cell keeps that census honest: a NEW enum whose zero value is not a
// sentinel must be added to the allowlist below with a reason, which is the
// moment to ask whether it is a ConfigTarget.
func TestProtoEnumZeroValuesAreSentinelsOrAllowlisted9324(t *testing.T) {
	src, err := os.ReadFile("../../proto/xpf/v1/xpf.proto")
	if err != nil {
		t.Fatalf("read proto: %v", err)
	}

	// A zero value that is a deliberate, audited non-sentinel. The comment is
	// the reason; adding a row without one is the thing this cell exists to
	// make somebody type.
	allowed := map[string]string{
		// Picks a renderer, not a target. Every arm is a *Redacted renderer.
		"ConfigFormat": "HIERARCHICAL",
		// Picks display columns. No target, no privilege.
		"MonitorInterfaceSummaryMode": "MONITOR_INTERFACE_SUMMARY_MODE_COMBINED",
		// ConfigTarget's zero is STILL CANDIDATE — renumbering it would be a
		// wire redefinition during a rolling upgrade. #9324 fixed it by PRICE
		// (reading a candidate costs PermConfig) and, on REST where absent is
		// distinguishable, by DEFAULT. If this row is ever removed because the
		// enum gained an UNSPECIFIED sentinel, the price must stay.
		"ConfigTarget": "CANDIDATE",
	}

	enumRe := regexp.MustCompile(`(?m)^enum\s+(\w+)\s*\{`)
	zeroRe := regexp.MustCompile(`(?m)^\s*(\w+)\s*=\s*0\s*;`)

	text := string(src)
	locs := enumRe.FindAllStringSubmatchIndex(text, -1)
	if len(locs) < 5 {
		// Positive control: a regex that stopped matching would report a
		// spotless enum set for a file full of them.
		t.Fatalf("found only %d enums in xpf.proto — the scan is broken, so its verdict is meaningless", len(locs))
	}

	seen := map[string]bool{}
	for _, loc := range locs {
		name := text[loc[2]:loc[3]]
		body := text[loc[1]:]
		if end := strings.Index(body, "\n}"); end >= 0 {
			body = body[:end]
		}
		m := zeroRe.FindStringSubmatch(body)
		if m == nil {
			t.Errorf("enum %s declares no `= 0;` value", name)
			continue
		}
		zero := m[1]
		seen[name] = true

		upper := strings.ToUpper(zero)
		isSentinel := strings.HasSuffix(upper, "UNSPECIFIED") ||
			strings.HasSuffix(upper, "UNKNOWN") ||
			strings.HasSuffix(upper, "NOT_COMPUTED")
		if isSentinel {
			continue
		}
		want, ok := allowed[name]
		if !ok {
			t.Errorf("enum %s has a NON-SENTINEL zero value %q and is not allowlisted.\n"+
				"proto3 cannot distinguish an omitted field from an explicit zero, so this value is what "+
				"every caller that omits the field gets. #9324 was exactly this shape: ConfigTarget's zero "+
				"is CANDIDATE, so a PermView caller that omitted the target read another session's "+
				"uncommitted config. Either give the enum an *_UNSPECIFIED zero, or add it to the "+
				"allowlist WITH the reason its default is safe.", name, zero)
			continue
		}
		if want != zero {
			t.Errorf("enum %s zero value changed from %q to %q — the allowlist entry records why the OLD "+
				"default was safe and no longer describes this one", name, want, zero)
		}
	}

	for name := range allowed {
		if !seen[name] {
			t.Errorf("allowlisted enum %s no longer exists in xpf.proto; drop the stale row", name)
		}
	}
}
