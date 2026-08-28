package refactoraudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #6899 (C180-021): docs/afxdp-packet-processing.md asserted that the SHIM drops
// non-SYN TCP without a live `userspace_sessions` entry. That described the
// RETIRED eBPF pipeline. The shim redirects every session miss to the userspace
// dataplane ("Let all session misses through to the userspace dataplane" —
// userspace-xdp/src/lib.rs) and the guard now lives there, where the action
// differs BY DISPOSITION: transit drops a bare RST/FIN (#4400/#4539), while
// host-inbound LocalDelivery declines only to CACHE and still delivers the
// packet to the local stack.
//
// An operator reading the old text would expect a drop where the packet is
// delivered — a wrong answer, not a missing one.
//
// WHAT THIS GUARD CAN AND CANNOT DO, stated so nobody over-reads it. It catches
// a LITERAL reintroduction of the retired sentence, which is what a revert or a
// copy-paste from git history produces. It is defeated by a paraphrase, and no
// string check can do better. The behavioural claims the rewritten text makes
// are not guarded here at all — they are covered by their own cells in
// userspace-dp (`bare_rst_fin_session_miss_does_not_cache_local_delivery`,
// `non_handshake_tcp_session_miss_does_not_cache_local_delivery`), which is the
// right place for them and the reason this file asserts only the negation.
func TestAfxdpDocDoesNotClaimShimDropsNonSYN6899(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "docs", "afxdp-packet-processing.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// Normalise whitespace so the check is WRAP-insensitive: the retired claim
	// spanned two lines, and a `strings.Contains` against the raw bytes would
	// miss it the moment someone re-flowed the paragraph.
	flat := strings.Join(strings.Fields(string(raw)), " ")

	const retired = "Non-SYN TCP without a live entry in `userspace_sessions` BPF map is dropped"
	if strings.Contains(flat, retired) {
		t.Fatalf("docs/afxdp-packet-processing.md has reacquired the retired #6899 claim "+
			"%q. The shim does not decide a session miss — it redirects to the userspace "+
			"dataplane, and host-inbound LocalDelivery DELIVERS the packet while declining "+
			"to cache it. The old wording tells an operator to expect a drop that does not "+
			"happen.", retired)
	}

	// And the replacement must actually carry the distinction the old text
	// lost. Without this the guard is satisfied by DELETING the item entirely,
	// which would remove a wrong answer by removing the answer.
	for _, want := range []string{
		"Let all session misses through to the userspace dataplane",
		"differs by disposition",
		"does NOT drop",
	} {
		if !strings.Contains(flat, want) {
			t.Fatalf("the rewritten session-miss item is missing %q — the retired claim was "+
				"removed without the corrected behaviour replacing it", want)
		}
	}
}
