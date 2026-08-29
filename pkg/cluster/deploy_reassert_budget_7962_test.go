package cluster

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// #7962: the post-deploy reassert's budget must cover the degraded-promotion
// fallback it depends on.
//
// THE DEFECT THIS GUARDS was not "30 is too small a number". It was that the
// budget was chosen with no reference to the thing it waits for, so the two
// could drift independently — and they had. The reassert allowed
// TRIES*DELAY = 30s while `DefaultDegradedPromoteTimeout` is 120s, and on an
// idle cluster that fallback is the ONLY path to convergence: XSK liveness
// cannot self-prove on the node the reassert checks, because
// `shouldAutoProveIdleStandbyXSKLocked` requires `!hasActiveDataRGLocked()` and
// node0 holds RG1.
//
// So the gate could not pass on a restarted idle cluster unless traffic
// happened to flow inside its window. Both its passes and its failures were
// timing artifacts, and the failures were indistinguishable from an HA
// regression in whatever branch deployed next (#7688, #7939).
//
// Raising 30 to a bigger number would have fixed the instance and left the
// class: the next change to either side reopens it silently. This test is the
// coupling. It reads the shell default out of the deploy library and fails if
// either side moves such that the budget no longer covers the fallback — so
// changing one tells you about the other.
func TestDeployReassertBudgetExceedsDegradedFallback7962(t *testing.T) {
	const libPath = "../../test/incus/deploy-lib.sh"
	src, err := os.ReadFile(libPath)
	if err != nil {
		t.Fatalf("read %s: %v — this test is the only thing coupling the deploy "+
			"budget to the fallback timeout; if the file moved, move this with it", libPath, err)
	}

	re := regexp.MustCompile(`DEPLOY_REASSERT_FALLBACK_BUDGET_S="\$\{DEPLOY_REASSERT_FALLBACK_BUDGET_S:-(\d+)\}"`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatal("could not find DEPLOY_REASSERT_FALLBACK_BUDGET_S's default in " +
			"deploy-lib.sh. If it was renamed or restructured, this test stopped " +
			"guarding the coupling it exists for — update the pattern rather than " +
			"deleting the test (#7962)")
	}
	budgetSecs, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("unparseable budget %q: %v", m[1], err)
	}
	budget := time.Duration(budgetSecs) * time.Second

	if budget <= DefaultDegradedPromoteTimeout {
		t.Errorf("the deploy reassert's fallback budget is %s but the degraded-promotion "+
			"fallback it waits for takes %s. On an idle cluster that fallback is the "+
			"ONLY path to convergence, so the gate fails BY CONSTRUCTION and its "+
			"failure is indistinguishable from a real HA regression — which is the "+
			"defect #7962 was filed for. Raise the budget, or lower the fallback, but "+
			"they must not be chosen independently.",
			budget, DefaultDegradedPromoteTimeout)
	}

	// Anti-vacuity: a budget absurdly larger than the fallback would satisfy the
	// check above while making every genuinely failing deploy pay for it. The
	// margin is meant to absorb election and status-read latency, not to be a
	// second, invisible timeout.
	if budget > DefaultDegradedPromoteTimeout*3 {
		t.Errorf("the budget %s is more than 3x the %s fallback. That is no longer a "+
			"margin, it is an independent timeout — and every failing deploy pays it "+
			"before reporting (#7962)", budget, DefaultDegradedPromoteTimeout)
	}
}
