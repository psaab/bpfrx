package dhcpserver

// Kea Lease File Cleanup (LFC) file-set naming + read order (#5796).
//
// Kea's memfile backend never rewrites the lease file in place between LFC
// compactions — every renewal / release / decline / expiry-reclaim is APPENDED
// — and it periodically runs kea-lfc to compact the log. During AND after a
// cleanup the live lease set is NOT the current file alone; it spans Kea's LFC
// file set. Reading only the current file loses every lease that currently
// lives in the previous or input file: right after LFC rotates the current
// file, that file is a fresh (often header-only) append log while the active
// leases sit in the compacted previous file. A header-only current file must
// therefore never by itself authorize the destructive DDNS trusted-empty diff.
//
// File naming is authoritative from Kea source
// (src/lib/dhcpsrv/memfile_lease_mgr.cc, appendSuffix / LFCFileType) for a
// current lease file <f>:
//
//	<f>            CURRENT  — the live append log the server writes now.
//	<f>.1          INPUT    — the current file the server MOVES ASIDE at the
//	                          START of a cleanup; kea-lfc reads it. Present only
//	                          while a cleanup is in progress (or left behind by a
//	                          crashed cleanup).
//	<f>.2          PREVIOUS — the COMPACTED result of the last COMPLETED cleanup
//	                          (one row per active lease). Present once any LFC
//	                          has run.
//	<f>.output     kea-lfc's temporary compaction output.
//	<f>.completed  kea-lfc's finish marker.
//	<f>.pid        kea-lfc's pid file.
//
// The .output/.completed/.pid files hold no lease union we must read and are
// ignored. NOTE the suffix mapping: .1 is INPUT and .2 is PREVIOUS — so the
// CHRONOLOGICAL read order (oldest → newest) is .2 → .1 → current, i.e. the
// previous-compacted snapshot first, then the input file, then the current
// append log.
//
// keaLFCLeaseFilePaths returns the candidate paths in that chronological order.
// A reader that OPENS each in turn (treating a missing file as simply absent —
// skip, not an error) and replays the rows through the SAME append-only,
// last-row-wins dedup the single-file parsers already use gets Kea's own final
// disposition per lease key: a newer row in INPUT or CURRENT supersedes an older
// row in PREVIOUS, and a release/expiry row still tombstones a lease that a
// later re-allocation can reclaim. On a steady-state box with no LFC in progress
// (.1/.2 absent) the set collapses to exactly the current file, so behavior is
// byte-identical to the pre-#5796 single-file read.
func keaLFCLeaseFilePaths(current string) []string {
	return []string{current + ".2", current + ".1", current}
}
