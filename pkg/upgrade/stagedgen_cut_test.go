package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

// TestCut_ReadsPinnedGenerationNotTornStaged is the #1981 acceptance pin: a cut
// reads the PINNED, published staged generation, NEVER live staged/. We publish
// a CLEAN generation, then tear live staged/ to a half-unpacked mix, then drive
// a full cut and assert versions/<ver> holds the CLEAN bytes — proving the cut
// never read the torn live tree.
//
// Non-tautological by construction: the COUNTER-FACTUAL below drives the
// pre-fix behavior (copyStaged reading live staged/, modeled by an empty
// SourceGeneration legacy cut) against the SAME torn staged/ and shows it
// publishes the TORN bytes. So the assertion only passes because the cut is
// pinned to the generation, not because the torn write was inert.
func TestCut_ReadsPinnedGenerationNotTornStaged(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs) // publishes a clean gen of version 2.0.0
	seedInitialCurrent(t, r, cfg, "1.0.0")

	// Tear live staged/: replace the lockstep dataplane binary with a
	// half-unpacked payload, as dpkg would mid-unpack. The CLEAN bytes were
	// already captured in the published generation by testEnv's publish.
	tornPath := filepath.Join(cfg.StagedDir, "xpf-userspace-dp")
	if err := os.WriteFile(tornPath, []byte("TORN-half-unpacked-dp"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("cut: %v", err)
	}

	// The committed version dir must hold the CLEAN published bytes, not the
	// torn live staged/ bytes.
	got, err := os.ReadFile(filepath.Join(cfg.VersionsDir, "2.0.0", "xpf-userspace-dp"))
	if err != nil {
		t.Fatalf("read committed binary: %v", err)
	}
	if string(got) != "binary-xpf-userspace-dp-2.0.0" {
		t.Fatalf("cut consumed the TORN live staged/ bytes, not the pinned generation: %q", got)
	}

	// The version dir must carry a .srcgen stamp naming a valid generation.
	stamp, serr := os.ReadFile(filepath.Join(cfg.VersionsDir, "2.0.0", stagedgen.SrcGenFile))
	if serr != nil {
		t.Fatalf("version dir missing .srcgen stamp: %v", serr)
	}
	if !stagedgen.ValidGenID(strings.TrimSpace(string(stamp))) {
		t.Fatalf(".srcgen does not name a valid generation: %q", stamp)
	}
}

// TestCut_CounterFactual_LegacyReadsTornStaged is the counter-factual that pins
// the test above: with an empty SourceGeneration (the pre-#1981 legacy path
// that reads live staged/), copyStaged DOES consume the torn bytes. This proves
// the fixed path's clean read is the fix, not an inert torn write.
func TestCut_CounterFactual_LegacyReadsTornStaged(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)

	// Tear live staged/.
	tornPath := filepath.Join(cfg.StagedDir, "xpf-userspace-dp")
	if err := os.WriteFile(tornPath, []byte("TORN-half-unpacked-dp"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Drive copyStaged directly with an empty SourceGeneration (legacy path).
	j := &Journal{TargetVersion: "2.0.0", State: StateStaged} // SourceGeneration == ""
	if err := r.copyStaged(j); err != nil {
		t.Fatalf("legacy copyStaged: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(cfg.VersionsDir, "2.0.0", "xpf-userspace-dp"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "TORN-half-unpacked-dp" {
		t.Fatalf("counter-factual did NOT read the torn live staged/ (got %q) — the "+
			"regression test is tautological", got)
	}
	// The legacy path must NOT stamp a .srcgen (so a later resume recognizes it
	// as a pre-#1981 dir).
	if _, serr := os.Stat(filepath.Join(cfg.VersionsDir, "2.0.0", stagedgen.SrcGenFile)); !os.IsNotExist(serr) {
		t.Errorf("legacy copyStaged stamped a .srcgen; want none on the empty-generation path")
	}
}

// TestCut_NoSourceGenerationRefusesAtInit pins plan §7.2: a fresh cut with NO
// published generation refuses at INIT — no journal written, no DB snapshot
// taken, daemon untouched.
func TestCut_NoSourceGenerationRefusesAtInit(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	// Remove the published generation so current-gen is absent.
	if err := os.RemoveAll(cfg.StagedGenDir); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected a no-source refusal")
	}
	if !strings.Contains(err.Error(), "no published staged generation") {
		t.Fatalf("error is not a no-source refusal: %v", err)
	}
	// No journal written.
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Errorf("journal written on a no-source refusal: %v", serr)
	}
	// No DB snapshot taken.
	if matches, _ := filepath.Glob(filepath.Join(cfg.VersionsDir, ".*.dbsnap")); len(matches) != 0 {
		t.Errorf("DB snapshot taken on a no-source refusal: %v", matches)
	}
	// No live mutation.
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" {
			t.Errorf("live mutation %q on a no-source refusal", c)
		}
	}
	// current still points at the seeded prior version.
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "1.0.0" {
		t.Errorf("current moved off 1.0.0 on a no-source refusal: %q", cur)
	}
}

// TestCut_SameVersionDifferentGenerationRecopies pins plan §7.8 (B-P3b OPT1):
// a same-version re-stage with NEW bytes (a new generation) re-copies into a
// STALE non-live versions/<ver> instead of skipping it. Counter-factual: a
// version-only skip would ship the stale bytes.
func TestCut_SameVersionDifferentGenerationRecopies(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	// Stage a STALE versions/2.0.0 from generation g1 (bytes "stale"), as a
	// prior abandoned attempt would leave. It is NOT current (1.0.0 is) and not
	// the rollback target, so it is a stale non-live dir.
	staleDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	if err := os.MkdirAll(staleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, b := range managedBins {
		if err := os.WriteFile(filepath.Join(staleDir, b), []byte("stale-"+b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(staleDir, stagedgen.SrcGenFile), []byte("g1-stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The current published generation (from testEnv) holds the FRESH 2.0.0
	// bytes ("binary-..."), with a DIFFERENT genid than the stale "g1-stale".
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("cut: %v", err)
	}

	// The committed version dir must hold the FRESH published bytes (recopied),
	// not the stale ones — proving the generation-aware skip recopied.
	got, err := os.ReadFile(filepath.Join(cfg.VersionsDir, "2.0.0", "xpfd"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary-xpfd-2.0.0" {
		t.Fatalf("cut shipped STALE bytes (version-only skip): %q", got)
	}
}

// TestCut_SameVersionDifferentGenerationRefusesOnLive pins B-P3b OPT1's refusal
// arm: a same-version-different-generation cut REFUSES when versions/<ver> is
// the LIVE current target (cannot safely mutate a live version dir mid-cut).
func TestCut_SameVersionDifferentGenerationRefusesOnLive(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	// Seed 2.0.0 as the LIVE current with a DIFFERENT-generation stamp so the
	// cut's pinned generation differs from the live dir's.
	seedInitialCurrent(t, r, cfg, "2.0.0")
	liveStamp := filepath.Join(cfg.VersionsDir, "2.0.0", stagedgen.SrcGenFile)
	if err := os.WriteFile(liveStamp, []byte("g-old-live\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected a refusal to replace the live version dir")
	}
	if !strings.Contains(err.Error(), "cannot replace the live/rollback version dir") {
		t.Fatalf("error is not the live-dir replacement refusal: %v", err)
	}
	// No live mutation (pure pre-PREFLIGHT refusal).
	for _, c := range fs.calls {
		if c == "stop" || c == "dropin" {
			t.Errorf("live mutation %q on a live-dir replacement refusal", c)
		}
	}
}

// TestCut_GCProtectsInFlightSourceGeneration pins plan §7.7 (GC-vs-resume) at
// the cut level: a cut journaled with a pinned SourceGeneration must keep that
// generation across a GC even when newer generations have been published and
// the pinned one has fallen outside the N=2 retention window — so a resume can
// still find its source.
func TestCut_GCProtectsInFlightSourceGeneration(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	sg := r.stagedGenConfig()
	// The cut pins g0 (current-gen at INIT) — model an in-flight journal.
	g0, err := sg.ResolveCurrent()
	if err != nil || g0 == "" {
		t.Fatalf("resolve pinned generation: %v (%q)", err, g0)
	}
	j := &Journal{TargetVersion: "2.0.0", PreviousVersion: "1.0.0",
		State: StateCopied, SourceGeneration: g0}

	// Newer generations are published (a concurrent upgrade), advancing
	// current-gen so g0 falls outside the N=2 retention window.
	for i := 0; i < 2; i++ {
		if _, perr := sg.Publish(); perr != nil {
			t.Fatal(perr)
		}
	}

	// The cut's GC (journal-protected) must keep g0.
	if gcErr := r.gc(j); gcErr != nil {
		t.Fatalf("gc: %v", gcErr)
	}
	if _, serr := os.Stat(sg.GenDir(g0)); serr != nil {
		t.Fatalf("GC deleted the in-flight (journal-pinned) source generation %s: %v", g0, serr)
	}

	// Counter-factual: an unprotected GC (empty SourceGeneration) reaps g0.
	jUnprotected := &Journal{TargetVersion: "2.0.0", PreviousVersion: "1.0.0", State: StateCopied}
	if gcErr := r.gc(jUnprotected); gcErr != nil {
		t.Fatal(gcErr)
	}
	if _, serr := os.Stat(sg.GenDir(g0)); serr == nil {
		t.Fatal("g0 survived an unprotected GC — the protection test is tautological")
	}
}

// TestCut_AbortedUnpackLeavesPriorGenerationValid pins plan §7.4: a failed/
// aborted unpack simply does NOT publish a new generation; the PRIOR
// generation stays valid and a cut from it succeeds. This is the test that
// would FAIL under Option A (a stranded sentinel permanently wedges the host)
// — Option B has the permanent-wedge class structurally absent.
func TestCut_AbortedUnpackLeavesPriorGenerationValid(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs) // publishes the GOOD generation of version 2.0.0
	seedInitialCurrent(t, r, cfg, "1.0.0")

	sg := r.stagedGenConfig()
	priorGen, _ := sg.ResolveCurrent()

	// Model an aborted unpack: dpkg started rewriting staged/ (it is now torn)
	// but the postinst NEVER published a new generation. current-gen still
	// names the prior good generation.
	if err := os.WriteFile(filepath.Join(cfg.StagedDir, "xpfd"), []byte("TORN-aborted-unpack"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A cut still succeeds, reading the PRIOR valid generation — no
	// permanent-wedge, no torn read.
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("cut after an aborted unpack should succeed from the prior generation: %v", err)
	}
	if cur, _ := sg.ResolveCurrent(); cur != priorGen {
		t.Fatalf("current-gen moved to %q; an aborted unpack must leave the prior %q", cur, priorGen)
	}
	got, _ := os.ReadFile(filepath.Join(cfg.VersionsDir, "2.0.0", "xpfd"))
	if string(got) != "binary-xpfd-2.0.0" {
		t.Fatalf("cut consumed torn aborted-unpack bytes: %q", got)
	}
}

// TestCut_ResumePinnedGenerationAfterCurrentGenAdvances pins B-P3: a resuming
// cut keeps reading its ORIGINALLY-pinned generation even if a concurrent
// publish has advanced current-gen — the resume must not silently switch
// sources mid-cut.
func TestCut_ResumePinnedGenerationAfterCurrentGenAdvances(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	sg := r.stagedGenConfig()
	g0, _ := sg.ResolveCurrent()

	// Model a crash at StateCopied: journal the pinned state directly (a real
	// run that crashed after COPY would leave exactly this).
	jCopied := &Journal{TargetVersion: "2.0.0", PreviousVersion: "1.0.0",
		State: StateCopied, SourceGeneration: g0}
	// Stamp the copied dir with g0 so the resume's copyStaged sees a true
	// same-generation resume (skip).
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-2.0.0")
	}
	if err := os.WriteFile(filepath.Join(verDir, stagedgen.SrcGenFile), []byte(g0+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.saveJournal(jCopied); err != nil {
		t.Fatal(err)
	}

	// A concurrent publish advances current-gen to a NEW generation.
	gNew, err := sg.Publish()
	if err != nil {
		t.Fatal(err)
	}
	if gNew == g0 {
		t.Fatal("publish did not advance the generation")
	}

	// Resume the cut. It must keep g0 (the journal pin), NOT switch to gNew.
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("resume cut: %v", err)
	}
	// The committed version dir's stamp must still name g0 (the resume kept its
	// pinned source, did not recopy from gNew).
	stamp, _ := os.ReadFile(filepath.Join(verDir, stagedgen.SrcGenFile))
	if strings.TrimSpace(string(stamp)) != g0 {
		t.Fatalf("resume switched source generation to %q; must keep the pinned %q", stamp, g0)
	}
}
