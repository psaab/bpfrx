// libbpf fd pinning + pinned degraded-path stats reader.
//
// Pure code motion out of `bpf_map/mod.rs` (#2003): the RAII wrapper that
// opens a pinned BPF object by sysfs path (`bpf_obj_get`) and closes the
// fd on drop, plus the debug-gated reader for the pinned
// `userspace_fallback_stats` map, now live here. These are the only
// items that talk to the bpffs pin paths directly.
//
// Behaviour-preserving: `OwnedFd::open_bpf_map` keeps the same
// `CString`/`bpf_obj_get`/`last_os_error` contract, `Drop` still closes
// the fd, and `read_degraded_path_stats` keeps the same 16-slot scan and
// debug-log gating. The pin-path constant and reason-name table move with
// the reader. The orchestrator and tests resolve these via the `bpf_map`
// re-export, exactly as before.
//
// Precedent: the sibling `publish_conntrack.rs` split (#1356).

use super::*;

pub(in crate::afxdp) struct OwnedFd {
    pub(in crate::afxdp) fd: c_int,
}

impl OwnedFd {
    pub(in crate::afxdp) fn open_bpf_map(path: &str) -> io::Result<Self> {
        let path = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid map path"))?;
        let fd = unsafe { libbpf_sys::bpf_obj_get(path.as_ptr()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.fd) };
    }
}

// The pinned map path keeps the historical "fallback" spelling for
// mixed-version shim compatibility. Operator-facing names use
// degraded-path terminology.
//
// #1776: the only production reader (the per-second degraded-path
// dump in worker/loop_body/debug_report.rs) is debug-log-gated, so
// these items are cfg-gated to match (REASON_NAMES is also asserted
// by unit tests, hence `any(test, ...)`).
#[cfg(feature = "debug-log")]
pub(in crate::afxdp) const DEGRADED_PATH_STATS_PIN_PATH: &str =
    "/sys/fs/bpf/xpf/userspace_fallback_stats";
#[cfg(any(test, feature = "debug-log"))]
pub(in crate::afxdp) const DEGRADED_PATH_REASON_NAMES: &[&str] = &[
    "ctrl_disabled",            // 0
    "parse_fail",               // 1
    "binding_missing",          // 2
    "binding_not_ready",        // 3
    "heartbeat_missing",        // 4
    "heartbeat_stale",          // 5
    "icmp",                     // 6
    "early_filter",             // 7
    "adjust_meta",              // 8
    "meta_bounds",              // 9
    "redirect_err",             // 10
    "interface_nat_no_session", // 11
    "no_session",               // 12
    "strict_drop",              // 13
    "pass_to_kernel",           // 14
    "transit_drop",             // 15
];

#[cfg(feature = "debug-log")]
pub(in crate::afxdp) fn read_degraded_path_stats() -> Option<Vec<(String, u64)>> {
    let fd = OwnedFd::open_bpf_map(DEGRADED_PATH_STATS_PIN_PATH).ok()?;
    let mut result = Vec::new();
    for idx in 0u32..16 {
        let mut value = 0u64;
        let rc = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                fd.fd,
                (&idx as *const u32).cast::<c_void>(),
                (&mut value as *mut u64).cast::<c_void>(),
            )
        };
        if rc == 0 && value > 0 {
            let name = DEGRADED_PATH_REASON_NAMES
                .get(idx as usize)
                .copied()
                .unwrap_or("unknown");
            result.push((name.to_string(), value));
        }
    }
    Some(result)
}
