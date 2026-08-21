package daemon

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #5797. A Junos `system syslog host <h>` may carry several independent
// `<facility> <severity>` selectors, and Junos evaluates them INDEPENDENTLY:
// each facility keeps its own threshold. xpf folded every selector to the
// single most restrictive severity, so a selector naming a facility the
// destination's client never emits still filtered — or, with `none`, silenced —
// every record it did emit.
//
// These tests key on the facility the client actually STAMPS, which is the only
// facility any record it sends can carry. A selector resolving to a different
// code matches nothing here and must contribute nothing.

// TestSyslogSelector_ForeignFacilityDoesNotRestrict is the issue's headline
// example, verbatim:
//
//	host 192.0.2.10 { daemon info; authorization critical; }
//
// Junos forwards daemon records at info-or-higher. Before this fix the fold
// took critical (more restrictive than info) and the destination silently lost
// every daemon notice/info record the operator explicitly requested.
//
// RED-on-revert: restore the blind fold (merge every selector with
// MoreRestrictiveMinSeverity regardless of facility) and min becomes
// SyslogCritical, failing the threshold assertion, and both info/notice
// forwarding assertions fail.
func TestSyslogSelector_ForeignFacilityDoesNotRestrict(t *testing.T) {
	sel := []config.SyslogFacility{
		{Facility: "daemon", Severity: "info"},
		{Facility: "authorization", Severity: "critical"},
	}

	min := syslogHostMinSeverity(sel, logging.FacilityDaemon)
	if min != logging.SyslogInfo {
		t.Fatalf("min severity = %d, want %d (info — the daemon selector's own threshold)",
			min, logging.SyslogInfo)
	}

	c := &logging.SyslogClient{Facility: logging.FacilityDaemon, MinSeverity: min}
	for _, sev := range []int{logging.SyslogInfo, logging.SyslogNotice, logging.SyslogWarning, logging.SyslogCritical} {
		if !c.ShouldSend(sev) {
			t.Errorf("`daemon info; authorization critical` must forward severity %d — "+
				"the authorization selector cannot restrict daemon records", sev)
		}
	}
	if c.ShouldSend(logging.SyslogDebug) {
		t.Error("`daemon info` must NOT forward debug — the daemon threshold still applies")
	}
}

// TestSyslogSelector_ForeignNoneDoesNotSilence is the same defect at its worst
// magnitude. `none` outranks every other threshold in
// minSeverityRestrictRank, so under the blind fold ONE `none` selector on a
// facility this client never emits turned the whole destination off.
//
// RED-on-revert: with the blind fold, min == SeverityNone and ShouldSend
// returns false for every severity, so every forwarding assertion fails.
func TestSyslogSelector_ForeignNoneDoesNotSilence(t *testing.T) {
	sel := []config.SyslogFacility{
		{Facility: "daemon", Severity: "info"},
		{Facility: "authorization", Severity: "none"},
	}

	min := syslogHostMinSeverity(sel, logging.FacilityDaemon)
	if min == logging.SeverityNone {
		t.Fatalf("min severity = SeverityNone: an `authorization none` selector silenced the "+
			"whole destination, but this client stamps daemon (%d) and can never emit an "+
			"authorization record", logging.FacilityDaemon)
	}
	if min != logging.SyslogInfo {
		t.Fatalf("min severity = %d, want %d (info)", min, logging.SyslogInfo)
	}

	c := &logging.SyslogClient{Facility: logging.FacilityDaemon, MinSeverity: min}
	if !c.ShouldSend(logging.SyslogInfo) {
		t.Error("destination silenced: `daemon info` records must still forward")
	}
	if !c.ShouldSend(logging.SyslogEmergency) {
		t.Error("destination silenced: even emergency records stopped forwarding")
	}
}

// TestSyslogSelector_OwnFacilityNoneStillSilences is the negative control for
// the test above, and it is what keeps that fix from being a blanket
// "ignore none". A `none` naming the facility this client DOES stamp is an
// operator instruction to stop forwarding, and must be obeyed.
//
// Without this control, a fix that simply skipped every `none` would pass
// TestSyslogSelector_ForeignNoneDoesNotSilence while breaking the operator's
// actual off switch.
func TestSyslogSelector_OwnFacilityNoneStillSilences(t *testing.T) {
	min := syslogHostMinSeverity([]config.SyslogFacility{
		{Facility: "daemon", Severity: "none"},
	}, logging.FacilityDaemon)
	if min != logging.SeverityNone {
		t.Fatalf("min severity = %d, want SeverityNone (%d): `daemon none` on a daemon-stamping "+
			"client is the operator's off switch", min, logging.SeverityNone)
	}
	c := &logging.SyslogClient{Facility: logging.FacilityDaemon, MinSeverity: min}
	if c.ShouldSend(logging.SyslogEmergency) {
		t.Error("`daemon none` must forward nothing, not even emergency")
	}
}

// TestSyslogSelector_ExactWinsOverWildcard pins Junos more-specific-wins: when
// a host names both `any` and the client's own facility, the exact selector
// supplies the threshold. Otherwise `any critical; daemon info` would keep
// filtering daemon records at critical.
func TestSyslogSelector_ExactWinsOverWildcard(t *testing.T) {
	// Exact more PERMISSIVE than the wildcard — the direction a
	// most-restrictive fold gets wrong.
	if got := syslogHostMinSeverity([]config.SyslogFacility{
		{Facility: "any", Severity: "critical"},
		{Facility: "daemon", Severity: "info"},
	}, logging.FacilityDaemon); got != logging.SyslogInfo {
		t.Errorf("`any critical; daemon info` = %d, want %d (info — exact wins)", got, logging.SyslogInfo)
	}
	// Exact more RESTRICTIVE than the wildcard — exact still wins, so this is
	// not satisfiable by "always take the permissive one".
	if got := syslogHostMinSeverity([]config.SyslogFacility{
		{Facility: "any", Severity: "info"},
		{Facility: "daemon", Severity: "critical"},
	}, logging.FacilityDaemon); got != logging.SyslogCritical {
		t.Errorf("`any info; daemon critical` = %d, want %d (critical — exact wins)", got, logging.SyslogCritical)
	}
}

// TestSyslogSelector_WildcardAppliesWhenNoExact keeps the #5314 contract: with
// no selector naming the stamped facility, the `any` wildcard is the threshold.
// A fix that only honored exact matches would silently restore send-all here.
func TestSyslogSelector_WildcardAppliesWhenNoExact(t *testing.T) {
	got := syslogHostMinSeverity([]config.SyslogFacility{
		{Facility: "any", Severity: "critical"},
		{Facility: "authorization", Severity: "info"},
	}, logging.FacilityDaemon)
	if got != logging.SyslogCritical {
		t.Errorf("`any critical; authorization info` = %d, want %d (the wildcard applies)",
			got, logging.SyslogCritical)
	}
}

// TestSyslogSelector_UnmappedNameSharingLocal0Applies pins that the key is the
// numeric facility CODE, not the authored name. Every Junos name xpf's mapper
// does not know resolves to local0 (ParseFacility's fallback, warned about at
// the call site). A client that actually stamps local0 therefore DOES emit
// records those selectors match on the wire, so they must still constrain it.
//
// This is the boundary that stops the fix from being "ignore names I do not
// recognize", which would drop a real operator restriction.
func TestSyslogSelector_UnmappedNameSharingLocal0Applies(t *testing.T) {
	if logging.ParseFacility("authorization") != logging.FacilityLocal0 {
		t.Skip("mapper learned `authorization`; this boundary no longer exists")
	}
	got := syslogHostMinSeverity([]config.SyslogFacility{
		{Facility: "authorization", Severity: "critical"},
	}, logging.FacilityLocal0)
	if got != logging.SyslogCritical {
		t.Errorf("unmapped `authorization critical` on a local0-stamping client = %d, want %d: "+
			"the selector and the emitted record share local0 on the wire", got, logging.SyslogCritical)
	}
}

// TestApplySystemSyslogWarnsOnInapplicableSelector_5797 binds the operator
// signal for the residual. A selector naming a facility this host's client does
// not stamp now selects nothing — correct, and invisible. The operator asked
// for `authorization critical` and gets neither the records nor a complaint, so
// applySystemSyslog says so once per apply.
//
// The negative control matters more than the positive one here: the wildcard
// and the stamped facility are BOTH applicable and must stay quiet, or a
// correct single-selector config warns on every commit.
//
// RED-on-revert: delete the warn loop in applySystemSyslog and the positive
// subtest fails; widen it to every selector and the two controls fail.
func TestApplySystemSyslogWarnsOnInapplicableSelector_5797(t *testing.T) {
	apply := func(t *testing.T, sel []config.SyslogFacility) string {
		t.Helper()
		buf := captureRenderedWarnings(t)
		d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
		t.Cleanup(func() { d.slogHandler.SetClients(nil) })
		cfg := &config.Config{}
		cfg.System.Syslog = &config.SystemSyslogConfig{
			Hosts: []*config.SyslogHostConfig{{Address: "192.0.2.10", Facilities: sel}},
		}
		d.applySystemSyslog(cfg)
		return buf.String()
	}

	const marker = "selects nothing"

	t.Run("foreign facility warns", func(t *testing.T) {
		got := apply(t, []config.SyslogFacility{
			{Facility: "daemon", Severity: "info"},
			{Facility: "kern", Severity: "critical"},
		})
		if !strings.Contains(got, marker) {
			t.Errorf("a `kern critical` selector on a daemon-stamping host selects nothing and "+
				"said so nowhere; the operator sees neither the records nor a complaint. captured:\n%s", got)
		}
		if !strings.Contains(got, "kern") {
			t.Errorf("the warning must name the inapplicable selector. captured:\n%s", got)
		}
	})

	t.Run("stamped facility stays quiet", func(t *testing.T) {
		if got := apply(t, []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}); strings.Contains(got, marker) {
			t.Errorf("the selector that supplies the stamped facility IS applicable and must not "+
				"warn — a correct config would complain on every commit. captured:\n%s", got)
		}
	})

	t.Run("wildcard stays quiet", func(t *testing.T) {
		if got := apply(t, []config.SyslogFacility{{Facility: "any", Severity: "info"}}); strings.Contains(got, marker) {
			t.Errorf("`any` matches every record and is always applicable; warning about it is a "+
				"false alarm on the repo's own canonical fixture. captured:\n%s", got)
		}
	})
}
