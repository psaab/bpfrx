package daemon

// service_reload_debt_6800_test.go — #6800 RETRY-OWNER regression.
//
// The two managed-service-file appliers converge an on-disk configuration and
// then gate a RUNTIME reload on "did the on-disk set change". The gate is what
// keeps a steady-state commit from bouncing rsyslog/chrony — but it also erased
// the debt of a FAILED reload: the write half had already converged the files,
// so every later apply compared desired against the converged set, saw no
// change, skipped the reload, and the daemon kept serving the PREVIOUS ruleset
// until an unrelated syslog/NTP edit or a reboot.
//
// Every cell below reverts to green under exactly one reverted production
// line; the pairings (fires / does-not-fire, sources-leg / threshold-leg) are
// what stop the fix from becoming "reload on every commit" and what keep a
// compound mutation from masking half of itself.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// syslogDaemon6800 points the rsyslog drop-in reconcile at a temp dir and
// installs a restart spy. It returns the daemon, a pointer to the restart
// count, and a pointer to the error the spy returns (flip it between applies).
func syslogDaemon6800(t *testing.T) (d *Daemon, restarts *int, failWith *error) {
	t.Helper()

	dir := t.TempDir()
	origDir := rsyslogConfDir
	rsyslogConfDir = dir
	t.Cleanup(func() { rsyslogConfDir = origDir })

	var mu sync.Mutex
	n := 0
	var fail error
	origFn := rsyslogRestartFn
	rsyslogRestartFn = func() ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		return nil, fail
	}
	t.Cleanup(func() { rsyslogRestartFn = origFn })

	return &Daemon{}, &n, &fail
}

// syslogFileCfg6800 builds a config with one `system syslog file` destination.
func syslogFileCfg6800(name string) *config.Config {
	cfg := &config.Config{}
	cfg.System.Syslog = &config.SystemSyslogConfig{
		Files: []*config.SyslogFileConfig{
			{Name: name, Facility: "any", Severity: "info"},
		},
	}
	return cfg
}

// chronyDaemon6800 points the two managed chrony files at a temp dir and
// installs a reload spy that records the exact (sources, threshold) request it
// was issued. The returned outcome pointer decides what the spy reports back.
func chronyDaemon6800(t *testing.T) (d *Daemon, calls *[][2]bool, outcome *chronyReloadOutcome) {
	t.Helper()

	dir := t.TempDir()
	origSrc, origThr := chronySourcesPath, chronyThresholdPath
	chronySourcesPath = filepath.Join(dir, "xpf.sources")
	chronyThresholdPath = filepath.Join(dir, "xpf-threshold.conf")
	t.Cleanup(func() { chronySourcesPath, chronyThresholdPath = origSrc, origThr })

	var mu sync.Mutex
	var got [][2]bool
	var out chronyReloadOutcome
	origFn := chronyReloadFn
	chronyReloadFn = func(sources, threshold bool) chronyReloadOutcome {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, [2]bool{sources, threshold})
		return out
	}
	t.Cleanup(func() { chronyReloadFn = origFn })

	return &Daemon{}, &got, &out
}

// ntpCfg6800 builds a `system ntp` config with the given servers and threshold.
func ntpCfg6800(servers []string, threshold int) *config.Config {
	cfg := &config.Config{}
	cfg.System.NTPServers = servers
	if threshold > 0 {
		cfg.System.NTPThreshold = threshold
		cfg.System.NTPThresholdAction = "accept"
	}
	return cfg
}

// ---------------------------------------------------------------------------
// rsyslog: the debt is latched, discharged, and consulted by the next apply
// ---------------------------------------------------------------------------

// TestSyslogRestartOutcomeLatchesAndDischargesTheDebt6800 is the PAIRED
// outcome cell: the same apply, two restart results, opposite debt states.
//
// The FAILURE leg reds if noteRsyslogRestartResult is dropped from the apply
// path — the #6800 defect itself, which loses the only record that rsyslog
// never re-read the converged drop-ins.
//
// The SUCCESS leg reds if the note only ever LATCHES (`if err != nil { … =
// true }`) and never clears. Without the discharge the re-assert loop would
// bounce a healthy rsyslog every 30s forever after one transient failure —
// turning the retry owner into a new outage.
func TestSyslogRestartOutcomeLatchesAndDischargesTheDebt6800(t *testing.T) {
	d, restarts, failWith := syslogDaemon6800(t)
	cfg := syslogFileCfg6800("audit")

	*failWith = errors.New("simulated: Job for rsyslog.service failed")
	d.applySyslogFiles(cfg)
	if *restarts != 1 {
		t.Fatalf("setup: the first apply must issue the restart (writes a new "+
			"drop-in, so changed=true); got %d restarts", *restarts)
	}
	if !d.rsyslogRestartOwed() {
		t.Fatal("a FAILED `systemctl restart rsyslog` must latch the restart debt. " +
			"The drop-ins are already converged on disk, so the next apply's " +
			"`changed` flag is false and this debt is the ONLY record that " +
			"rsyslog is still serving the previous ruleset (#6800)")
	}

	*failWith = nil
	d.applySyslogFiles(cfg)
	if d.rsyslogRestartOwed() {
		t.Fatal("a SUCCESSFUL restart must DISCHARGE the debt — leaving it latched " +
			"makes the always-on re-assert bounce a healthy rsyslog every tick " +
			"forever (#6800)")
	}
}

// TestSteadyStateApplyRetriesTheOwedSyslogRestart6800 is the headline cell.
//
// Apply #1 writes the drop-in and its restart FAILS. Apply #2 presents the
// SAME config: the reconcile finds the files already converged and reports
// changed=false — which is precisely the state in which the pre-#6800 gate
// (`if changed`) skipped the restart and stranded rsyslog on the old ruleset.
// The retained debt must re-issue it.
//
// The fixture premise is guarded explicitly: a third reconcile against the
// identical desired set must report NO change, or apply #2 would have restarted
// for an ordinary content change and this cell would prove nothing.
func TestSteadyStateApplyRetriesTheOwedSyslogRestart6800(t *testing.T) {
	d, restarts, failWith := syslogDaemon6800(t)
	cfg := syslogFileCfg6800("audit")

	*failWith = errors.New("simulated restart failure")
	d.applySyslogFiles(cfg)

	// Premise: the drop-in set is now CONVERGED, so a further reconcile with
	// the same desired set is a no-op. Without this the cell could pass on a
	// content change rather than on the retained debt.
	desired := syslogDropinContents(cfg, "10-xpf-")
	if len(desired) == 0 {
		t.Fatal("fixture rendered ZERO drop-ins, so no apply could ever restart " +
			"rsyslog and every assertion here would be vacuous")
	}
	if reconcileSyslogDropins(rsyslogConfDir, "10-xpf-", desired) {
		t.Fatal("fixture premise broken: the drop-ins are not converged after the " +
			"first apply, so apply #2 would restart for a content change rather " +
			"than for the retained debt")
	}

	*failWith = nil
	before := *restarts
	d.applySyslogFiles(cfg)
	if *restarts != before+1 {
		t.Fatalf("a steady-state apply issued %d restarts (want %d): the managed "+
			"drop-ins converged on disk, so `changed` is false and only the "+
			"retained debt can re-drive the restart. Without it rsyslog keeps "+
			"serving the PREVIOUS ruleset — records still flowing to a removed "+
			"destination — until an unrelated syslog edit or a reboot (#6800)",
			*restarts-before, 1)
	}
	if d.rsyslogRestartOwed() {
		t.Fatal("the re-issued restart succeeded, so the debt must be discharged")
	}
}

// TestSteadyStateApplyWithNoDebtDoesNotRestartRsyslog6800 is the PAIRED
// negative, and it is what keeps the fix from being a regression of its own.
//
// An apply that changes nothing and owes nothing must NOT touch rsyslog. A
// gate widened to `if true` (or to something that never clears) would restart
// the logging pipeline on every single commit — the exact behaviour the
// `changed` gate exists to prevent.
func TestSteadyStateApplyWithNoDebtDoesNotRestartRsyslog6800(t *testing.T) {
	d, restarts, failWith := syslogDaemon6800(t)
	cfg := syslogFileCfg6800("audit")

	*failWith = nil
	d.applySyslogFiles(cfg) // converges + restarts once, successfully
	if *restarts != 1 {
		t.Fatalf("setup: want 1 restart from the first apply, got %d", *restarts)
	}

	d.applySyslogFiles(cfg)
	d.applySyslogFiles(cfg)
	if *restarts != 1 {
		t.Fatalf("a converged, debt-free apply restarted rsyslog (%d total, want 1) "+
			"— the `changed` gate must still suppress the steady state (#6800)",
			*restarts)
	}
}

// ---------------------------------------------------------------------------
// chrony: per-leg outcomes
// ---------------------------------------------------------------------------

// TestChronySourcesLegReportsItsOwnOutcome6800 is the PAIRED cell for the
// SOURCES leg of reloadChronyRuntime, driven through the real function.
//
// It is deliberately separate from the threshold cell: a compound mutation
// that broke both legs would be masked by a single combined cell, and the two
// legs drive different commands.
func TestChronySourcesLegReportsItsOwnOutcome6800(t *testing.T) {
	orig := chronyRunCmd
	t.Cleanup(func() { chronyRunCmd = orig })

	var seen []string
	fail := true
	chronyRunCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		seen = append(seen, name+" "+strings.Join(args, " "))
		if fail {
			return []byte("simulated"), errors.New("simulated chronyc failure")
		}
		return nil, nil
	}

	out := reloadChronyRuntime(true, false)
	if !out.sourcesFailed {
		t.Fatal("a failing `chronyc reload sources` must be REPORTED as a failed " +
			"sources leg. reconcileManagedFile has already written xpf.sources, " +
			"so the next apply computes changed=false against the converged file " +
			"and this outcome is the only thing that can carry the owed reload " +
			"forward (#6800)")
	}
	if out.thresholdFailed {
		t.Fatal("a sources-only request must never report a threshold failure — " +
			"the caller assigns the outcome straight onto the retained debt, so a " +
			"spurious threshold failure would latch a reload nobody asked for")
	}
	if len(seen) != 1 || !strings.HasPrefix(seen[0], "chronyc reload sources") {
		t.Fatalf("sources leg ran %v, want exactly [chronyc reload sources]", seen)
	}

	fail = false
	if out := reloadChronyRuntime(true, false); out.sourcesFailed {
		t.Fatal("a SUCCESSFUL sources reload must not report a failure — it would " +
			"latch a permanent debt and re-drive chronyc every 30s forever")
	}
}

// TestChronyThresholdLegReportsItsOwnOutcome6800 is the PAIRED cell for the
// THRESHOLD leg: it must report failure only after ALL FOUR fallback commands
// have failed, and must report success as soon as one of them works.
func TestChronyThresholdLegReportsItsOwnOutcome6800(t *testing.T) {
	orig := chronyRunCmd
	t.Cleanup(func() { chronyRunCmd = orig })

	failAll := true
	var attempts int
	chronyRunCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		attempts++
		if failAll || attempts < 2 {
			return []byte("simulated"), errors.New("simulated systemctl failure")
		}
		return nil, nil
	}

	out := reloadChronyRuntime(false, true)
	if !out.thresholdFailed {
		t.Fatal("every chrony reload/restart fallback failed, so the threshold leg " +
			"must be REPORTED as owed. xpf-threshold.conf is already on disk, so " +
			"the next apply sees changed=false and without this outcome the " +
			"running chrony keeps the previous logchange/maxchange (#6800)")
	}
	if out.sourcesFailed {
		t.Fatal("a threshold-only request must never report a sources failure")
	}
	if attempts != 4 {
		t.Fatalf("threshold leg made %d attempts, want all 4 fallbacks", attempts)
	}

	failAll = false
	attempts = 0
	if out := reloadChronyRuntime(false, true); out.thresholdFailed {
		t.Fatal("a fallback that SUCCEEDED must clear the threshold leg — reporting " +
			"failure anyway latches a permanent debt on a healthy chrony")
	}
}

// ---------------------------------------------------------------------------
// chrony: the debt is retained per-leg and REPLAYED, not re-derived
// ---------------------------------------------------------------------------

// TestOwedChronySourcesLegSurvivesAThresholdOnlyApply6800 binds the retained
// SOURCES leg.
//
// This is the "retain the exact owed request" property. Apply #1 changes only
// the sources file and its reload fails. Apply #2 changes only the THRESHOLD
// file. Re-deriving the request from apply #2's own change flags would issue
// (sources=false, threshold=true) and silently drop the sources debt — chrony
// would keep polling the OLD server set forever. The apply must fold the
// retained leg in.
func TestOwedChronySourcesLegSurvivesAThresholdOnlyApply6800(t *testing.T) {
	d, calls, outcome := chronyDaemon6800(t)

	*outcome = chronyReloadOutcome{sourcesFailed: true}
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 0))
	if len(*calls) != 1 || (*calls)[0] != [2]bool{true, false} {
		t.Fatalf("setup: apply #1 must request the sources leg only, got %v", *calls)
	}
	if s, th := d.chronyReloadOwed(); !s || th {
		t.Fatalf("setup: want debt (sources=true, threshold=false), got (%v, %v)", s, th)
	}

	// Apply #2: same servers (sources file converged), NEW threshold.
	*outcome = chronyReloadOutcome{}
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 120))
	if len(*calls) != 2 {
		t.Fatalf("apply #2 issued %d reloads, want 2", len(*calls))
	}
	if (*calls)[1] != [2]bool{true, true} {
		t.Fatalf("apply #2 requested %v, want [sources=true threshold=true]: the "+
			"owed SOURCES leg must be folded into the request. Re-deriving it "+
			"from this apply's own change flags drops it — the sources file is "+
			"already converged, so nothing else can see that chrony never "+
			"re-read it (#6800)", (*calls)[1])
	}
	if s, th := d.chronyReloadOwed(); s || th {
		t.Fatalf("both legs succeeded, so the debt must be discharged; got (%v, %v)", s, th)
	}
}

// TestOwedChronyThresholdLegSurvivesASourcesOnlyApply6800 is the SYMMETRIC
// cell for the THRESHOLD leg. Symmetry is where a compound mutation bites: a
// single cell covering one direction stays green when the other direction's
// fold is reverted.
func TestOwedChronyThresholdLegSurvivesASourcesOnlyApply6800(t *testing.T) {
	d, calls, outcome := chronyDaemon6800(t)

	*outcome = chronyReloadOutcome{thresholdFailed: true}
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 120))
	if len(*calls) != 1 || (*calls)[0] != [2]bool{true, true} {
		t.Fatalf("setup: apply #1 must request both legs, got %v", *calls)
	}
	if s, th := d.chronyReloadOwed(); s || !th {
		t.Fatalf("setup: want debt (sources=false, threshold=true), got (%v, %v)", s, th)
	}

	// Apply #2: NEW server list, same threshold (threshold file converged).
	*outcome = chronyReloadOutcome{}
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1", "10.0.0.2"}, 120))
	if len(*calls) != 2 {
		t.Fatalf("apply #2 issued %d reloads, want 2", len(*calls))
	}
	if (*calls)[1] != [2]bool{true, true} {
		t.Fatalf("apply #2 requested %v, want [sources=true threshold=true]: the "+
			"owed THRESHOLD leg must be folded into the request (#6800)",
			(*calls)[1])
	}
}

// TestSteadyStateNTPApplyRetriesTheOwedChronyReload6800 binds the ORDER of the
// fold against the early return.
//
// The two cells above both present an apply that changes SOMETHING, so they
// stay green even if the fold were placed after `if !sourcesChanged &&
// !thresholdChanged { return }`. This one presents the identical config twice:
// both files are converged, both change flags are false, and the early return
// is the thing that would swallow the retry.
func TestSteadyStateNTPApplyRetriesTheOwedChronyReload6800(t *testing.T) {
	d, calls, outcome := chronyDaemon6800(t)
	cfg := ntpCfg6800([]string{"10.0.0.1"}, 120)

	*outcome = chronyReloadOutcome{sourcesFailed: true, thresholdFailed: true}
	d.applySystemNTP(cfg)
	if len(*calls) != 1 {
		t.Fatalf("setup: want 1 reload from the first apply, got %d", len(*calls))
	}

	*outcome = chronyReloadOutcome{}
	d.applySystemNTP(cfg)
	if len(*calls) != 2 {
		t.Fatalf("a steady-state apply issued %d reloads, want 2: both managed "+
			"chrony files are converged so both change flags are false, and only "+
			"the retained debt — folded in BEFORE the no-change early return — "+
			"can re-drive the reload (#6800)", len(*calls))
	}
	if (*calls)[1] != [2]bool{true, true} {
		t.Fatalf("the retry requested %v, want both owed legs replayed", (*calls)[1])
	}
	if s, th := d.chronyReloadOwed(); s || th {
		t.Fatalf("the retry succeeded, so the debt must be discharged; got (%v, %v)", s, th)
	}
}

// TestSteadyStateNTPApplyWithNoDebtDoesNotReload6800 is the PAIRED negative:
// a converged, debt-free apply must leave chrony alone. `systemctl restart
// chrony` is one of the fallbacks, so a gate that fired every commit would
// periodically bounce time sync.
func TestSteadyStateNTPApplyWithNoDebtDoesNotReload6800(t *testing.T) {
	d, calls, outcome := chronyDaemon6800(t)
	cfg := ntpCfg6800([]string{"10.0.0.1"}, 120)

	*outcome = chronyReloadOutcome{}
	d.applySystemNTP(cfg)
	if len(*calls) != 1 {
		t.Fatalf("setup: want 1 reload from the first apply, got %d", len(*calls))
	}

	d.applySystemNTP(cfg)
	d.applySystemNTP(cfg)
	if len(*calls) != 1 {
		t.Fatalf("a converged, debt-free apply reloaded chrony (%d total, want 1) "+
			"— the change gate must still suppress the steady state (#6800)",
			len(*calls))
	}
}

// TestSteadyStateDisabledNTPApplyRetriesTheOwedChronyReload6800 binds the fold
// on the `system processes ntp disable` branch, which has its own copy of it.
//
// The sequence is the ordinary one for a disabled NTP stanza: the first apply
// after the operator disables NTP REMOVES the two managed files (changed=true)
// and its reload fails; every later apply finds them already absent, so both
// change flags are false. Without the fold on this branch the owed reload is
// dropped and chrony keeps the removed sources loaded — the deleted-destination
// shape #5111 fixed for rsyslog, reached through the reload instead of the file.
func TestSteadyStateDisabledNTPApplyRetriesTheOwedChronyReload6800(t *testing.T) {
	d, calls, outcome := chronyDaemon6800(t)

	// Seed the files a previously-enabled apply would have left behind.
	if err := os.WriteFile(chronySourcesPath, []byte("server 10.0.0.1 iburst\n"), 0644); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	if err := os.WriteFile(chronyThresholdPath, []byte("logchange 120\n"), 0644); err != nil {
		t.Fatalf("seed threshold: %v", err)
	}

	cfg := ntpCfg6800(nil, 0)
	cfg.System.DisabledProcesses = []string{"ntp"}

	*outcome = chronyReloadOutcome{sourcesFailed: true, thresholdFailed: true}
	d.applySystemNTP(cfg)
	if len(*calls) != 1 || (*calls)[0] != [2]bool{true, true} {
		t.Fatalf("setup: the disabling apply must remove both files and request "+
			"both legs, got %v", *calls)
	}
	if _, err := os.Stat(chronySourcesPath); !os.IsNotExist(err) {
		t.Fatalf("setup: the managed sources file must be removed, stat err = %v", err)
	}

	*outcome = chronyReloadOutcome{}
	d.applySystemNTP(cfg)
	if len(*calls) != 2 {
		t.Fatalf("a steady-state DISABLED apply issued %d reloads, want 2: the "+
			"managed files are already gone so both change flags are false, and "+
			"only the retained debt can re-drive the reload that tells chrony to "+
			"drop the removed sources (#6800)", len(*calls))
	}
	if (*calls)[1] != [2]bool{true, true} {
		t.Fatalf("the retry requested %v, want both owed legs replayed", (*calls)[1])
	}

	// PAIRED negative: now that the debt is discharged, a further disabled apply
	// must not touch chrony at all.
	d.applySystemNTP(cfg)
	if len(*calls) != 2 {
		t.Fatalf("a converged, debt-free DISABLED apply reloaded chrony (%d total, "+
			"want 2) — the change gate must still suppress the steady state", len(*calls))
	}
}

// ---------------------------------------------------------------------------
// the always-on re-assert loop
// ---------------------------------------------------------------------------

// TestReassertRedrivesOwedReloadsAndDischargesThem6800 binds the loop BODY for
// both services at once, with the paired no-op cell below.
//
// This is the half that matters most on a real box: a boot-time apply whose
// restart failed has NO further apply coming. Nothing else on the daemon
// re-drives either reload, so without this loop the recovery window is "until
// the operator next edits syslog or NTP" — potentially never.
func TestReassertRedrivesOwedReloadsAndDischargesThem6800(t *testing.T) {
	d, restarts, failWith := syslogDaemon6800(t)
	chronyD, calls, outcome := chronyDaemon6800(t)
	_ = chronyD // the chrony seams are package-level; drive them through d
	d.applySem = semaphore.NewWeighted(1)

	// Latch both debts through the apply path, so the fixture owes exactly what
	// a failed apply would owe.
	*failWith = errors.New("simulated restart failure")
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	*outcome = chronyReloadOutcome{sourcesFailed: true}
	d.applySystemNTP(ntpCfg6800([]string{"10.0.0.1"}, 0))
	if !d.serviceReloadDebtOutstanding() {
		t.Fatal("setup: both debts must be outstanding before the re-assert")
	}
	restartsAfterApply, callsAfterApply := *restarts, len(*calls)

	*failWith = nil
	*outcome = chronyReloadOutcome{}
	d.reassertServiceReloadDebtOnce(context.Background())

	if *restarts != restartsAfterApply+1 {
		t.Fatalf("the re-assert issued %d rsyslog restarts, want 1 — a boot-time "+
			"apply whose restart failed has no further apply coming, so this loop "+
			"is the only retry owner (#6800)", *restarts-restartsAfterApply)
	}
	if len(*calls) != callsAfterApply+1 {
		t.Fatalf("the re-assert issued %d chrony reloads, want 1", len(*calls)-callsAfterApply)
	}
	if got := (*calls)[len(*calls)-1]; got != [2]bool{true, false} {
		t.Fatalf("the re-assert requested %v, want [sources=true threshold=false]: "+
			"it must REPLAY the exact owed leg, not re-derive a request. Reloading "+
			"the threshold too would gratuitously `systemctl restart chrony` for a "+
			"leg that never failed (#6800)", got)
	}
	if d.serviceReloadDebtOutstanding() {
		t.Fatal("a successful re-assert must discharge the debt, or the loop " +
			"re-drives forever")
	}
}

// TestReassertIsANoOpWhenNothingIsOwed6800 is the PAIRED negative for the
// loop: with no debt it must not touch either service. An always-on loop that
// reloaded unconditionally would bounce rsyslog and chrony every 30s on a
// perfectly healthy firewall.
func TestReassertIsANoOpWhenNothingIsOwed6800(t *testing.T) {
	d, restarts, _ := syslogDaemon6800(t)
	_, calls, _ := chronyDaemon6800(t)
	d.applySem = semaphore.NewWeighted(1)

	if d.serviceReloadDebtOutstanding() {
		t.Fatal("setup: a fresh daemon must owe nothing")
	}
	d.reassertServiceReloadDebtOnce(context.Background())

	if *restarts != 0 || len(*calls) != 0 {
		t.Fatalf("a debt-free re-assert touched the services (%d rsyslog restarts, "+
			"%d chrony reloads, want 0/0) — a 30s unconditional bounce of the "+
			"logging and time-sync pipelines would be worse than the bug (#6800)",
			*restarts, len(*calls))
	}
}

// TestReassertRechecksTheDebtInsideTheSemaphore6800 binds the INNER gate.
//
// The check before applySem is only an optimisation: it avoids queueing behind
// a commit for nothing. The inner one is the correctness gate — a tick that
// blocked behind an in-flight commit may find the commit ALREADY re-issued the
// reload and discharged the debt, and restarting rsyslog again then is a
// gratuitous bounce of a healthy logging pipeline.
//
// The mutation that survives without this cell removes only the inner re-read;
// the outer check still short-circuits the quiet case, so
// TestReassertIsANoOpWhenNothingIsOwed6800 stays green.
func TestReassertRechecksTheDebtInsideTheSemaphore6800(t *testing.T) {
	d, restarts, failWith := syslogDaemon6800(t)
	d.applySem = semaphore.NewWeighted(1)

	*failWith = errors.New("simulated restart failure")
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	if !d.rsyslogRestartOwed() {
		t.Fatal("setup: the restart debt must be outstanding")
	}
	before := *restarts

	// Hold applySem, as an in-flight commit would.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		d.reassertServiceReloadDebtOnce(context.Background())
		close(done)
	}()
	<-started

	// The tick is now blocked on the semaphore (or about to be). Simulate the
	// commit having re-issued the restart successfully, then let the tick in.
	d.noteRsyslogRestartResult(nil)
	d.applySem.Release(1)
	<-done

	if *restarts != before {
		t.Fatalf("the re-assert restarted rsyslog %d times after the commit it "+
			"queued behind had already discharged the debt, want 0 — re-reading "+
			"the debt INSIDE the semaphore is what stops a gratuitous bounce of a "+
			"healthy logging pipeline (#6800)", *restarts-before)
	}
}

// TestReassertWaitsForTheApplySemaphore6800 binds the applySem ACQUISITION,
// which the inner-gate cell above cannot: that one still passes if the
// semaphore is never taken and the tick simply runs earlier.
//
// The semaphore is held by a "commit" that never releases, and the tick is
// given a short-lived context. Correct code blocks in Acquire until the context
// expires and then declines to reload at all. Dropping the Acquire makes the
// tick fire a `systemctl restart rsyslog` straight into the middle of a commit
// — reconcileSyslogDropins is mid-way through removing and rewriting
// /etc/rsyslog.d/10-xpf-*, so the restart would load a HALF-CONVERGED drop-in
// set and then latch a success for it (#4001, #6800).
func TestReassertWaitsForTheApplySemaphore6800(t *testing.T) {
	d, restarts, failWith := syslogDaemon6800(t)
	d.applySem = semaphore.NewWeighted(1)

	*failWith = errors.New("simulated restart failure")
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	if !d.rsyslogRestartOwed() {
		t.Fatal("setup: the restart debt must be outstanding")
	}
	before := *restarts

	// A commit takes the semaphore and does not give it back.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	d.reassertServiceReloadDebtOnce(ctx)

	if *restarts != before {
		t.Fatalf("the re-assert restarted rsyslog %d times while a commit held "+
			"applySem, want 0 — it must queue behind the in-flight apply, or the "+
			"restart can load a half-converged drop-in set and latch a success "+
			"for it (#4001, #6800)", *restarts-before)
	}
	if !d.rsyslogRestartOwed() {
		t.Fatal("a re-assert that never ran must leave the debt outstanding")
	}
}

// TestServiceReloadDebtLoopTicks6800 binds the loop plumbing: the ticker
// actually drives the re-assert, and the loop stops on context cancellation.
//
// Separate from the source check below because they fail for different
// reasons: this reds if the loop is wired to the wrong function or never
// ticks; the source check reds if Run never starts it.
func TestServiceReloadDebtLoopTicks6800(t *testing.T) {
	d, restarts, failWith := syslogDaemon6800(t)
	d.applySem = semaphore.NewWeighted(1)

	orig := serviceReloadDebtReassertInterval
	serviceReloadDebtReassertInterval = 5 * time.Millisecond
	t.Cleanup(func() { serviceReloadDebtReassertInterval = orig })

	*failWith = errors.New("simulated restart failure")
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	before := *restarts

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() { d.serviceReloadDebtReassertLoop(ctx); close(loopDone) }()

	deadline := time.Now().Add(5 * time.Second)
	for *restarts <= before {
		if time.Now().After(deadline) {
			cancel()
			<-loopDone
			t.Fatal("the re-assert loop never re-drove the owed rsyslog restart — " +
				"nothing else on the daemon retries it (#6800)")
		}
		time.Sleep(2 * time.Millisecond)
	}

	cancel()
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("serviceReloadDebtReassertLoop did not return on context cancellation")
	}
}

// TestRunStartsTheServiceReloadDebtReassertLoop6800 binds the WIRING.
//
// Every cell above stays green if Run never starts the loop — which IS half the
// bug: a boot apply whose reload failed has no further apply coming, so with no
// loop the debt sits latched and nothing ever pays it. It is a source check
// because pkg/daemon has no seam that observes Run's goroutine set, and a cell
// that started Run for real would need the whole daemon bring-up.
//
// The start must also be UNCONDITIONAL. Nesting it under another feature's
// guard (the `!d.opts.NoDataplane` block, say) would skip the retry owner on
// exactly the deployments that use it — the reload debt has nothing to do with
// the dataplane.
//
// Comments are stripped before matching: the comment introducing the start
// names the function, and a gate satisfiable by its own documentation proves
// nothing.
func TestRunStartsTheServiceReloadDebtReassertLoop6800(t *testing.T) {
	src, err := os.ReadFile("daemon_run.go")
	if err != nil {
		t.Fatalf("read daemon_run.go: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			code.WriteString("\n")
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	body := code.String()

	const start = "d.serviceReloadDebtReassertLoop(ctx)"
	at := strings.Index(body, start)
	if at < 0 {
		t.Fatal("Run never starts serviceReloadDebtReassertLoop — a managed-service " +
			"reload that failed at boot has no further apply coming, so the debt " +
			"stays latched and rsyslog/chrony keep serving the previous ruleset " +
			"until an operator happens to edit syslog or NTP (#6800)")
	}
	lineStart := strings.LastIndex(body[:at], "\n") + 1
	indent := 0
	for _, r := range body[lineStart:at] {
		if r == '\t' {
			indent++
		}
	}
	if indent != 2 {
		t.Fatalf("serviceReloadDebtReassertLoop is started at indent %d, want 2 (the "+
			"goroutine body inside an unconditional wg.Add block) — a start nested "+
			"under another feature's conditional would skip the retry owner on "+
			"configs that do not use that feature", indent)
	}
}
