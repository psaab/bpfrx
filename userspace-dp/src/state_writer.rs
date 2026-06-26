use io_uring::IoUring;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

/// Durability seam: fsync a [`File`]. Indirected through a function pointer so
/// crash-safety unit tests can record calls (and so a test FAILS if the fsync
/// is removed from the durable finalizer). Production always uses
/// [`real_sync_all`].
#[cfg(test)]
type SyncAllFn = fn(&File) -> io::Result<()>;

fn real_sync_all(f: &File) -> io::Result<()> {
    f.sync_all()
}

#[cfg(test)]
thread_local! {
    static SYNC_ALL_HOOK: std::cell::Cell<SyncAllFn> = const { std::cell::Cell::new(real_sync_all) };
}

#[cfg(test)]
fn sync_all(f: &File) -> io::Result<()> {
    SYNC_ALL_HOOK.with(|h| (h.get())(f))
}

#[cfg(not(test))]
#[inline]
fn sync_all(f: &File) -> io::Result<()> {
    real_sync_all(f)
}

/// A writer's *process instance* identity: its pid PLUS its process start time
/// (`/proc/<pid>/stat` field 22, clock ticks since boot). The pid alone is NOT
/// a stable identity across a crash — Linux recycles pids, so after the helper
/// crashes an unrelated process can be assigned the crashed writer's pid before
/// the next helper starts. Pairing the pid with the start time disambiguates a
/// genuinely-live original writer from a reused-pid impostor: the start time of
/// the original process can never be reproduced by a later process on the same
/// pid (the start-time monotonically advances with each fork). This is the
/// identity embedded in temp names and checked by the orphan sweep (#2957).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcInstance {
    pid: u32,
    /// Process start time in clock ticks since boot (`/proc/<pid>/stat` field
    /// 22). 0 is a sentinel meaning "unknown" — used only when the start time
    /// could not be read, and is never matched against a live process (an
    /// unknown-start-time temp is treated as orphaned once its pid is dead).
    start_time: u64,
}

/// Read the process start time (clock ticks since boot) from `/proc/<pid>/stat`
/// field 22. The stat line is `pid (comm) state ...` where `comm` can itself
/// contain spaces and parentheses, so we split AFTER the last ')' to skip the
/// comm field, then count whitespace-separated fields. After the last ')' the
/// next field is `state` (field 3), so field 22 (starttime) is index 19 in the
/// post-comm split. Returns `None` if the process is gone or the stat is
/// unparseable.
fn real_proc_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat")).ok()?;
    // `comm` is wrapped in parentheses and may contain ')' itself; the kernel
    // guarantees the FINAL ')' terminates comm. Everything after it is a clean
    // whitespace-separated field list starting at `state` (field 3).
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // Fields after comm, 0-indexed: 0=state(3) ... 19=starttime(22).
    after_comm.split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// Start-time seam: indirected through a function pointer so the orphan-temp
/// sweep's PID-reuse handling can be tested deterministically (a test can make
/// a still-live pid report a DIFFERENT start time than the one embedded in a
/// stale temp, simulating pid reuse, without spawning real processes). A test
/// FAILS if the start-time match is removed from the liveness gate. Production
/// always uses [`real_proc_start_time`].
#[cfg(test)]
type StartTimeFn = fn(u32) -> Option<u64>;

#[cfg(test)]
thread_local! {
    static START_TIME_HOOK: std::cell::Cell<StartTimeFn> =
        const { std::cell::Cell::new(real_proc_start_time) };
}

/// Single seam through which all liveness start-time lookups route, so a test
/// can fake a pid's current start time (simulating PID reuse) and so the gate
/// below is exercised against that fake rather than real `/proc`.
#[cfg(test)]
fn lookup_start_time(pid: u32) -> Option<u64> {
    START_TIME_HOOK.with(|h| (h.get())(pid))
}

#[cfg(not(test))]
#[inline]
fn lookup_start_time(pid: u32) -> Option<u64> {
    real_proc_start_time(pid)
}

/// This process's own instance identity (pid + start time), computed once. Used
/// both to name our temps and to short-circuit the sweep's liveness check for
/// our own in-flight temps regardless of any `/proc` visibility quirk. Reads the
/// real start time (never the test seam) — our own identity is fixed.
fn self_instance() -> ProcInstance {
    use std::sync::OnceLock;
    static SELF: OnceLock<ProcInstance> = OnceLock::new();
    *SELF.get_or_init(|| {
        let pid = std::process::id();
        ProcInstance {
            pid,
            start_time: real_proc_start_time(pid).unwrap_or(0),
        }
    })
}

/// A writer instance is "alive" only if a process with the embedded pid exists
/// AND its current start time matches the embedded start time (#2957). This is
/// the concurrency-safety gate for the orphan sweep (#2714): the
/// unique-per-write temp scheme leaks `<dest>.<pid>_<starttime>.<seq>.tmp` on a
/// crash between create and rename, but a naive glob-sweep would re-introduce
/// the #2705 cross-writer hazard by deleting a still-live OTHER writer's
/// in-flight temp. Matching on pid alone is unsafe: after a crash Linux can
/// recycle the pid, and a bare-pid check would then preserve the dead writer's
/// orphan as if a live process still held it, pinning crash debris for the rest
/// of the helper's lifetime. Requiring the start time to match too means a
/// reused pid (different start time) is correctly treated as a dead instance
/// and its orphan is swept, while a genuinely-live writer (pid AND start time
/// match) is always preserved.
fn instance_is_alive(inst: ProcInstance) -> bool {
    // The writer's own process is always alive; never treat its in-flight temps
    // as orphans regardless of /proc visibility quirks or start-time read races.
    // The shortcut MUST match the FULL instance (pid AND start time), not the
    // bare pid: after our predecessor crashed, Linux can recycle its pid as OUR
    // pid. A stale orphan then embeds (our pid, the predecessor's start time).
    // A bare-pid shortcut would preserve that recycled-pid debris forever — the
    // exact PID-reuse hazard #2957 closed, re-opened for the one pid that equals
    // ours (#3009). Comparing the whole instance preserves only our genuine
    // in-flight temp (pid AND start time match) and lets the normal path below
    // sweep a recycled-pid orphan (same pid, different embedded start time).
    if inst == self_instance() {
        return true;
    }
    match lookup_start_time(inst.pid) {
        // pid exists; preserve ONLY if it is the SAME process instance. A temp
        // whose embedded start time is the "unknown" sentinel (0) can never
        // match a real start time, so it is treated as orphaned once we reach
        // here (its original owner is gone — a live owner would carry its real
        // start time). PID reuse (live pid, different start time) -> not alive.
        Some(now) => now == inst.start_time && inst.start_time != 0,
        // No such process -> the writer is gone, the temp is a true orphan.
        None => false,
    }
}

enum WriteMode {
    IoUring(IoUring),
    SyncFallback,
}

struct WriteRequest {
    path: String,
    data: Vec<u8>,
    resp: mpsc::Sender<Result<(), String>>,
}

#[derive(Clone, Debug, Default)]
pub struct WriterStatus {
    pub active: bool,
    pub mode: String,
    pub last_error: String,
}

pub struct StateWriter {
    tx: mpsc::Sender<WriteRequest>,
    active: Arc<AtomicBool>,
    mode: Arc<Mutex<String>>,
    last_error: Arc<Mutex<String>>,
}

impl StateWriter {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<WriteRequest>();
        let active = Arc::new(AtomicBool::new(false));
        let mode = Arc::new(Mutex::new(String::from("sync")));
        let last_error = Arc::new(Mutex::new(String::new()));

        let active_bg = active.clone();
        let mode_bg = mode.clone();
        let last_error_bg = last_error.clone();
        thread::Builder::new()
            .name("xpf-state-writer".to_string())
            .spawn(move || {
                let mut write_mode = match IoUring::new(8) {
                    Ok(ring) => {
                        active_bg.store(true, Ordering::Relaxed);
                        if let Ok(mut m) = mode_bg.lock() {
                            *m = "io_uring".to_string();
                        }
                        WriteMode::IoUring(ring)
                    }
                    Err(err) => {
                        if let Ok(mut m) = mode_bg.lock() {
                            *m = "sync".to_string();
                        }
                        if let Ok(mut last) = last_error_bg.lock() {
                            *last = format!("io_uring unavailable: {err}");
                        }
                        WriteMode::SyncFallback
                    }
                };

                // Destinations whose stale-orphan sweep has already run this
                // process lifetime. The sweep removes `<dest>.<pid>.<seq>.tmp`
                // leaked by a crash between create and rename (#2714); running
                // it once per distinct destination keeps it off the per-write
                // hot path while still cleaning up at process start.
                let mut swept: HashSet<String> = HashSet::new();

                while let Ok(req) = rx.recv() {
                    if swept.insert(req.path.clone()) {
                        sweep_stale_temps(&req.path);
                    }
                    let outcome = persist_with_mode(&mut write_mode, &req.path, &req.data);
                    let result = apply_outcome(
                        outcome,
                        &mut write_mode,
                        &active_bg,
                        &mode_bg,
                        &last_error_bg,
                    );
                    let _ = req.resp.send(result);
                }
            })
            .expect("start state writer thread");

        Self {
            tx,
            active,
            mode,
            last_error,
        }
    }

    pub fn persist(&self, path: &str, data: Vec<u8>) -> Result<(), String> {
        let (resp_tx, resp_rx) = mpsc::channel();
        self.tx
            .send(WriteRequest {
                path: path.to_string(),
                data,
                resp: resp_tx,
            })
            .map_err(|e| format!("queue state write: {e}"))?;
        resp_rx
            .recv()
            .map_err(|e| format!("state writer response: {e}"))?
    }

    pub fn status(&self) -> WriterStatus {
        WriterStatus {
            active: self.active.load(Ordering::Relaxed),
            mode: self.mode.lock().map(|m| m.clone()).unwrap_or_default(),
            last_error: self
                .last_error
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
        }
    }
}

/// Result of one persistence attempt, carrying the I/O outcome plus whether the
/// io_uring transport failed on this write. The writer loop uses `io_uring_failed`
/// to decide whether to demote `WriteMode` to sync for the rest of its lifetime
/// (#2958): a runtime ring failure that fell back to a successful sync write must
/// still flip the reported mode and stop future ring submissions.
struct PersistOutcome {
    result: Result<(), String>,
    /// The io_uring transport failed on this write (regardless of whether the
    /// sync fallback then succeeded). Always false when already in sync mode.
    io_uring_failed: bool,
    /// The io_uring error that triggered the demotion, recorded as `last_error`
    /// even when the sync fallback succeeded so the demotion cause is visible.
    demotion_cause: Option<String>,
}

fn persist_with_mode(mode: &mut WriteMode, path: &str, data: &[u8]) -> PersistOutcome {
    match mode {
        WriteMode::IoUring(ring) => match persist_with_io_uring(ring, path, data) {
            Ok(()) => PersistOutcome {
                result: Ok(()),
                io_uring_failed: false,
                demotion_cause: None,
            },
            Err(ring_err) => {
                // io_uring failed at runtime. Fall back to a sync write for THIS
                // request, but flag the failure so the writer loop demotes the
                // mode persistently (status + no future ring attempts).
                let cause = format!("io_uring write failed, demoting to sync: {ring_err}");
                let result = persist_sync(path, data)
                    .map_err(|sync_err| format!("{ring_err}; {sync_err}"));
                PersistOutcome {
                    result,
                    io_uring_failed: true,
                    demotion_cause: Some(cause),
                }
            }
        },
        WriteMode::SyncFallback => PersistOutcome {
            result: persist_sync(path, data),
            io_uring_failed: false,
            demotion_cause: None,
        },
    }
}

/// Apply a [`PersistOutcome`] to the writer's shared state and return the
/// caller-visible result. This is the runtime-demotion chokepoint (#2958):
///
/// * On an io_uring transport failure (`io_uring_failed`), if we are still in
///   io_uring mode, demote `*mode` to [`WriteMode::SyncFallback`] PERMANENTLY
///   (no cooldown retry — avoids flapping) and flip the reported status:
///   `active=false`, `mode="sync"`. Every subsequent write then takes the sync
///   branch directly, never re-submitting to the broken ring, and the status
///   path stops claiming io_uring is active.
/// * `last_error` is set to the write error when the write failed, or to the
///   demotion cause when the sync fallback succeeded (so an operator can see
///   why the writer left io_uring even on a "successful" write).
///
/// Extracting this from the writer-thread loop lets a unit test drive the exact
/// demotion logic on the test thread (fail-on-revert): remove the demotion and
/// the mode stays io_uring, turning the test RED.
fn apply_outcome(
    outcome: PersistOutcome,
    mode: &mut WriteMode,
    active: &AtomicBool,
    mode_str: &Mutex<String>,
    last_error: &Mutex<String>,
) -> Result<(), String> {
    if outcome.io_uring_failed && matches!(mode, WriteMode::IoUring(_)) {
        *mode = WriteMode::SyncFallback;
        active.store(false, Ordering::Relaxed);
        if let Ok(mut m) = mode_str.lock() {
            *m = "sync".to_string();
        }
    }
    match &outcome.result {
        Err(err) => {
            if let Ok(mut last) = last_error.lock() {
                *last = err.clone();
            }
        }
        Ok(()) => {
            // The write itself succeeded. If io_uring failed and we fell back to
            // sync, surface the demotion cause so the transition is observable
            // even without a failed write.
            if outcome.io_uring_failed {
                if let (Ok(mut last), Some(cause)) =
                    (last_error.lock(), outcome.demotion_cause.as_ref())
                {
                    *last = cause.clone();
                }
            }
        }
    }
    outcome.result
}

fn persist_with_io_uring(ring: &mut IoUring, path: &str, data: &[u8]) -> Result<(), String> {
    // Each write gets a PRIVATE temp path (pid + monotonic counter), created
    // with O_EXCL so two concurrent writers — even different helper processes
    // racing the same destination during a restart/upgrade handover — can never
    // open, truncate, or write the SAME temp file. The atomic rename then
    // publishes onto `path` (last-writer-wins on the final file is acceptable;
    // crossed bytes under a successful rename are not, #2705).
    let tmp = temporary_path(path);
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| format!("open temp state file {}: {e}", tmp.display()))?;
    let result = (|| {
        write_all_with_ring(ring, file.as_raw_fd(), data)?;
        finalize_durably(&file, &tmp, path)
    })();
    cleanup_on_error(&tmp, result)
}

fn persist_sync(path: &str, data: &[u8]) -> Result<(), String> {
    // See persist_with_io_uring: O_EXCL unique temp, atomic rename publish.
    let tmp = temporary_path(path);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| format!("open temp state file {}: {e}", tmp.display()))?;
    let result = (|| {
        {
            use io::Write;
            file.write_all(data)
                .map_err(|e| format!("write temp state file {}: {e}", tmp.display()))?;
        }
        finalize_durably(&file, &tmp, path)
    })();
    cleanup_on_error(&tmp, result)
}

/// On a failed write the unique temp is never renamed into place, so it would
/// leak. Remove it (best-effort) and propagate the original error. On success
/// the rename already consumed the temp, so there is nothing to clean up.
fn cleanup_on_error(tmp: &Path, result: Result<(), String>) -> Result<(), String> {
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

/// Shared crash-safe finalizer for both write transports (io_uring and the
/// sync fallback). The temp file's data must already be fully written. Applies
/// the same durability contract regardless of how the bytes got there:
///   1. fsync the temp file so its data + metadata reach stable storage,
///   2. atomically rename it onto the destination,
///   3. fsync the parent directory so the rename itself survives power loss.
///
/// Without (1) the file can be empty/torn after a crash; without (3) the rename
/// (the dirent change) can be lost even though the file data is durable. Both
/// modes go through here so neither can drift from this contract.
fn finalize_durably(file: &File, tmp: &Path, dest: &str) -> Result<(), String> {
    sync_all(file).map_err(|e| format!("sync temp state file {}: {e}", tmp.display()))?;
    fs::rename(tmp, dest).map_err(|e| format!("rename {} -> {dest}: {e}", tmp.display()))?;
    sync_parent_dir(dest)?;
    Ok(())
}

/// fsync the directory that contains `dest` so the rename's dirent update is
/// durable. A missing parent (path has no directory component) is treated as
/// the current directory.
fn sync_parent_dir(dest: &str) -> Result<(), String> {
    let parent = Path::new(dest).parent().filter(|p| !p.as_os_str().is_empty());
    let dir = match parent {
        Some(p) => p,
        None => Path::new("."),
    };
    let dir_file =
        File::open(dir).map_err(|e| format!("open parent dir {} for fsync: {e}", dir.display()))?;
    sync_all(&dir_file).map_err(|e| format!("fsync parent dir {}: {e}", dir.display()))?;
    Ok(())
}

fn write_all_with_ring(ring: &mut IoUring, fd: i32, data: &[u8]) -> Result<(), String> {
    // Positioned write to the temp state file. The shared loop retries the wait
    // on EINTR rather than abandoning an in-flight SQE, matches the completion
    // by user_data so a stale CQE cannot corrupt the file offset, and returns
    // only after the matching CQE is reaped so `data` outlives every kernel
    // reference (#2297).
    // The state writer is a positioned (byte-stream) write with no synchronous
    // fallback, so it does not consume the `WriteError` retry-safety
    // classification (#2477) — collapse it to the error message.
    crate::io_uring_write::write_all_to_fd(ring, fd, data, true, "state")
        .map_err(|e| e.to_string())
}

/// Process-global monotonic counter that makes every temp path produced by this
/// process unique, even for back-to-back writes to the same destination.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Build a PRIVATE temp path for one write:
/// `<dest>.<pid>_<starttime>.<seq>.tmp`. The pid+start-time pair is this
/// process's stable *instance* identity (`<pid>_<starttime>`, joined by `_` so
/// it stays a single dot-component) — it isolates separate helper processes
/// (restart/upgrade handover) AND, unlike a bare pid, lets the orphan sweep tell
/// a genuinely-live writer from a reused-pid impostor after a crash (#2957). The
/// per-process monotonic counter isolates concurrent or rapid in-process writes.
/// Two distinct writers therefore never name — and so never open/truncate/write
/// — the same temp file, which is what previously let a successful rename
/// publish crossed bytes (#2705). The destination's own extension is preserved
/// in the stem so the temp stays a recognizable sibling.
fn temporary_path(path: &str) -> PathBuf {
    let me = self_instance();
    let pid = me.pid;
    let start = me.start_time;
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut tmp = PathBuf::from(path);
    let suffix = tmp
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!("{ext}.{pid}_{start}.{seq}.tmp"))
        .unwrap_or_else(|| format!("{pid}_{start}.{seq}.tmp"));
    tmp.set_extension(suffix);
    tmp
}

/// Parse the embedded writer-instance (pid + start time) out of a temp file
/// NAME (not a full path) produced by [`temporary_path`]. The format is
/// `<stem>[.<ext>].<pid>_<starttime>.<seq>.tmp`, so after stripping the trailing
/// `.tmp` the last two dot-components are `<pid>_<starttime>` and `<seq>`. The
/// instance component is itself `<pid>_<starttime>` (joined by `_`). Returns
/// `None` if `name` does not match that shape — a foreign file that merely ends
/// in `.tmp`, or a legacy bare-`<pid>.<seq>` temp from before #2957, is left
/// untouched (a legacy temp lacking a start time can't be safely PID-reuse
/// disambiguated, so it is not a sweep candidate under the new scheme).
fn instance_from_temp_name(name: &str) -> Option<ProcInstance> {
    let body = name.strip_suffix(".tmp")?;
    let mut parts = body.rsplitn(3, '.');
    let seq: &str = parts.next()?; // trailing <seq>
    let inst_str = parts.next()?; // <pid>_<starttime> immediately before <seq>
    let stem = parts.next()?; // at least one leading stem component must exist
    if stem.is_empty() {
        return None;
    }
    // The seq component must be all-digits to be one of our temps.
    if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // The instance component must be exactly `<pid>_<starttime>`, both numeric.
    let (pid_str, start_str) = inst_str.split_once('_')?;
    if pid_str.is_empty() || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if start_str.is_empty() || !start_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(ProcInstance {
        pid: pid_str.parse::<u32>().ok()?,
        start_time: start_str.parse::<u64>().ok()?,
    })
}

/// Best-effort removal of stale `<dest>.<pid>_<starttime>.<seq>.tmp` orphans
/// left in `dest`'s directory by a crash between temp create and atomic rename
/// (#2714).
///
/// Concurrency safety (the #2705 hazard): a unique-per-write temp belonging to a
/// DIFFERENT, still-running writer (e.g. a replacement helper started before the
/// old one fully exits) must NEVER be removed — deleting its in-flight temp
/// would break its atomic write. This sweep therefore removes a candidate ONLY
/// when its embedded writer *instance* (pid + process start time) is no longer
/// live. Keying on the pid alone is unsafe: after a crash Linux can recycle the
/// dead writer's pid, and a bare-pid liveness check would then preserve the
/// stale orphan as if a live writer held it, pinning crash debris indefinitely
/// (#2957). Matching the start time too means a reused pid is correctly seen as
/// a dead instance. The current process's own pid is always treated as alive,
/// so this never races our own writes.
///
/// Scoped to siblings of `dest` whose name starts with `dest`'s file name plus a
/// dot, so it cannot touch unrelated files or temps for other destinations in
/// the same directory. Fail-safe: any error (unreadable dir, racey unlink) is
/// swallowed so a sweep failure can never break the subsequent write.
fn sweep_stale_temps(dest: &str) {
    let dest_path = Path::new(dest);
    let dir = match dest_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(p) => p,
        None => Path::new("."),
    };
    let dest_name = match dest_path.file_name().and_then(|n| n.to_str()) {
        Some(n) if !n.is_empty() => n,
        _ => return,
    };
    // Our temps for this destination are named
    // `<dest_name>.<pid>_<starttime>.<seq>.tmp`.
    let prefix = format!("{dest_name}.");

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // dir may not exist yet on first write — nothing to sweep
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };
        if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
            continue;
        }
        let inst = match instance_from_temp_name(name) {
            Some(i) => i,
            None => continue, // not one of our `<pid>_<starttime>.<seq>.tmp` temps
        };
        if instance_is_alive(inst) {
            continue; // a live writer (possibly another helper) may still hold it
        }
        let victim = entry.path();
        match fs::remove_file(&victim) {
            Ok(()) => eprintln!(
                "xpf-state-writer: swept stale orphan temp {} (dead instance pid {} start {})",
                victim.display(),
                inst.pid,
                inst.start_time
            ),
            Err(_) => { /* best-effort: raced unlink or perms — ignore */ }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    thread_local! {
        static SYNC_CALLS: AtomicUsize = const { AtomicUsize::new(0) };
        // 1-based index of the fsync call to fail; 0 = never fail.
        static SYNC_FAIL_AT: AtomicUsize = const { AtomicUsize::new(0) };
        // Records, per sync_all call, whether the synced fd was a directory.
        static SYNC_WAS_DIR: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
    }

    fn fd_is_dir(f: &File) -> bool {
        f.metadata().map(|m| m.is_dir()).unwrap_or(false)
    }

    /// Test hook: counts every fsync, records whether each was a directory fd,
    /// and optionally fails one specific call (1-based) for fault injection.
    fn recording_sync(f: &File) -> io::Result<()> {
        let this_call = SYNC_CALLS.with(|c| c.fetch_add(1, AtomicOrdering::Relaxed) + 1);
        SYNC_WAS_DIR.with(|v| v.borrow_mut().push(fd_is_dir(f)));
        let fail_at = SYNC_FAIL_AT.with(|r| r.load(AtomicOrdering::Relaxed));
        if fail_at != 0 && this_call == fail_at {
            return Err(io::Error::new(io::ErrorKind::Other, "injected fsync failure"));
        }
        real_sync_all(f)
    }

    struct SyncGuard;
    impl SyncGuard {
        fn install() -> Self {
            SYNC_CALLS.with(|c| c.store(0, AtomicOrdering::Relaxed));
            SYNC_FAIL_AT.with(|r| r.store(0, AtomicOrdering::Relaxed));
            SYNC_WAS_DIR.with(|v| v.borrow_mut().clear());
            SYNC_ALL_HOOK.with(|h| h.set(recording_sync));
            SyncGuard
        }
        fn calls(&self) -> usize {
            SYNC_CALLS.with(|c| c.load(AtomicOrdering::Relaxed))
        }
        fn dir_syncs(&self) -> usize {
            SYNC_WAS_DIR.with(|v| v.borrow().iter().filter(|&&d| d).count())
        }
        /// Make the `n`th fsync (1-based) fail.
        fn fail_at(&self, n: usize) {
            SYNC_FAIL_AT.with(|r| r.store(n, AtomicOrdering::Relaxed));
        }
    }
    impl Drop for SyncGuard {
        fn drop(&mut self) {
            SYNC_ALL_HOOK.with(|h| h.set(real_sync_all));
        }
    }

    thread_local! {
        // Pids the test has marked DEAD (no live process at all); the
        // start-time hook reports None for these, so the instance liveness gate
        // sees a true orphan. Deterministic, no real processes spawned.
        static DEAD_PIDS: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
        // Pids that are LIVE but with a (pid -> current start time) mapping. The
        // start-time hook returns this value, letting a test simulate PID reuse:
        // a still-live pid whose CURRENT start time differs from the one
        // embedded in a stale temp. Any pid not listed and not dead falls back
        // to a default "alive, matching" start time so legacy tests stay simple.
        static LIVE_START_TIMES: RefCell<Vec<(u32, u64)>> = const { RefCell::new(Vec::new()) };
    }

    /// Deterministic start-time hook driven by the test tables above. A dead pid
    /// reports None (no process); a pid with an explicit live start time reports
    /// it; any other pid reports a sentinel matching start time so a plain
    /// "(pid, start) embedded == live" temp is preserved without per-test setup.
    const TEST_DEFAULT_START_TIME: u64 = 9_000_000;
    fn test_proc_start_time(pid: u32) -> Option<u64> {
        if DEAD_PIDS.with(|d| d.borrow().contains(&pid)) {
            return None;
        }
        if let Some((_, st)) =
            LIVE_START_TIMES.with(|m| m.borrow().iter().find(|(p, _)| *p == pid).copied())
        {
            return Some(st);
        }
        Some(TEST_DEFAULT_START_TIME)
    }

    /// Installs deterministic liveness hooks (real instance check over a faked
    /// start-time source) for the orphan sweep and lets the test declare
    /// specific pids dead or alive-with-a-given-start-time (PID reuse).
    /// Restores the real checks on drop.
    struct PidGuard;
    impl PidGuard {
        fn install() -> Self {
            DEAD_PIDS.with(|d| d.borrow_mut().clear());
            LIVE_START_TIMES.with(|m| m.borrow_mut().clear());
            // Drive the production instance gate (instance_is_alive) through the
            // faked start-time source, so the test exercises the REAL pid+start
            // matching logic rather than a stubbed verdict.
            START_TIME_HOOK.with(|h| h.set(test_proc_start_time));
            PidGuard
        }
        fn mark_dead(&self, pid: u32) {
            DEAD_PIDS.with(|d| d.borrow_mut().push(pid));
        }
        /// Mark `pid` as LIVE but currently running with `start_time` — used to
        /// simulate PID reuse (a stale temp embeds a DIFFERENT start time).
        fn mark_live_with_start(&self, pid: u32, start_time: u64) {
            LIVE_START_TIMES.with(|m| m.borrow_mut().push((pid, start_time)));
        }
        /// The matching start time a temp must embed for a default-live pid to
        /// be preserved.
        fn matching_start() -> u64 {
            TEST_DEFAULT_START_TIME
        }
    }
    impl Drop for PidGuard {
        fn drop(&mut self) {
            START_TIME_HOOK.with(|h| h.set(real_proc_start_time));
        }
    }

    fn tmpdir() -> PathBuf {
        let base = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let unique = format!(
            "xpf-state-writer-test-{}-{:?}",
            std::process::id(),
            thread::current().id()
        );
        let dir = base.join(unique);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    // The durability contract that both modes must honor: exactly the file
    // fsync + the parent-directory fsync. If either fsync is deleted from
    // finalize_durably, these counts drop and the test fails (#2147 / #1968:
    // a durability test must fail if the durable effect is removed).
    const EXPECTED_FSYNCS_PER_PERSIST: usize = 2; // temp file + parent dir
    const EXPECTED_DIR_FSYNCS_PER_PERSIST: usize = 1; // parent dir

    #[test]
    fn fallback_persist_fsyncs_file_and_parent_dir() {
        let dir = tmpdir();
        let path = dir.join("state.json");
        let path_str = path.to_str().unwrap();
        let guard = SyncGuard::install();

        persist_sync(path_str, b"hello durable fallback").expect("fallback persist");

        assert_eq!(
            guard.calls(),
            EXPECTED_FSYNCS_PER_PERSIST,
            "fallback path must fsync the temp file AND the parent dir"
        );
        assert_eq!(
            guard.dir_syncs(),
            EXPECTED_DIR_FSYNCS_PER_PERSIST,
            "fallback path must fsync the parent directory after rename"
        );
        assert_eq!(fs::read(&path).unwrap(), b"hello durable fallback");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_durably_fsyncs_file_and_parent_dir() {
        // Drive the shared finalizer directly so the test pins the contract
        // both transports route through, independent of write mechanism.
        let dir = tmpdir();
        let dest = dir.join("snap.json");
        let dest_str = dest.to_str().unwrap();
        let tmp = temporary_path(dest_str);
        let guard = SyncGuard::install();

        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .unwrap();
        {
            use io::Write;
            (&file).write_all(b"payload").unwrap();
        }
        finalize_durably(&file, &tmp, dest_str).expect("finalize");

        assert_eq!(guard.calls(), EXPECTED_FSYNCS_PER_PERSIST);
        assert_eq!(guard.dir_syncs(), EXPECTED_DIR_FSYNCS_PER_PERSIST);
        assert!(!tmp.exists(), "temp file must be renamed away");
        assert_eq!(fs::read(&dest).unwrap(), b"payload");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_fsync_failure_is_propagated_and_does_not_rename() {
        // First fsync is the temp file. If it fails, the rename must NOT run —
        // the destination must keep its prior contents.
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap();
        fs::write(&dest, b"previous-good").unwrap();

        let guard = SyncGuard::install();
        guard.fail_at(1); // 1st fsync = temp file

        let err = persist_sync(dest_str, b"new-data").expect_err("file fsync should fail");
        assert!(err.contains("sync temp state file"), "unexpected error: {err}");
        assert_eq!(
            fs::read(&dest).unwrap(),
            b"previous-good",
            "destination must be untouched when the temp-file fsync fails"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn temporary_path_is_unique_per_call_for_same_dest() {
        // The core #2705 invariant: two writes targeting the SAME destination
        // must get DISTINCT temp paths so they can never open/truncate/write the
        // same temp file and publish crossed bytes under a successful rename.
        // With the old deterministic `<dest>.tmp` both calls returned the same
        // path and this assertion goes RED (fail-on-revert).
        let dest = "/tmp/xpf-state-uniq/state.json";
        let a = temporary_path(dest);
        let b = temporary_path(dest);
        assert_ne!(
            a, b,
            "two writes to the same dest must use distinct temp paths (got {a:?} twice)"
        );
        // Still a recognizable sibling of the destination, in the same dir.
        assert_eq!(a.parent(), Path::new(dest).parent());
        assert_eq!(b.parent(), Path::new(dest).parent());
        for p in [&a, &b] {
            let name = p.file_name().unwrap().to_str().unwrap();
            assert!(name.starts_with("state.json."), "unexpected temp name: {name}");
            assert!(name.ends_with(".tmp"), "unexpected temp name: {name}");
        }
        // Extension-less destinations also get a unique temp.
        let c = temporary_path("/tmp/xpf-state-uniq/state");
        let d = temporary_path("/tmp/xpf-state-uniq/state");
        assert_ne!(c, d, "extension-less dest must also get unique temp paths");
    }

    #[test]
    fn two_concurrent_writers_never_publish_crossed_bytes() {
        // Simulate two writers (two logical "processes"/instances) racing the
        // same destination. Each writes a distinct, self-describing payload many
        // times. Because every write uses a private O_EXCL temp + atomic rename,
        // the destination must ALWAYS contain exactly one writer's COMPLETE
        // payload — never a mix. With a shared deterministic temp, the open(+
        // truncate)/write/rename sequences could interleave and publish crossed
        // bytes; here that is impossible.
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap().to_string();

        // Two payloads of equal length, each internally consistent.
        let payload_a = vec![b'A'; 64 * 1024];
        let payload_b = vec![b'B'; 64 * 1024];

        let iters = 200usize;
        let d_a = dest_str.clone();
        let p_a = payload_a.clone();
        let d_b = dest_str.clone();
        let p_b = payload_b.clone();

        let h_a = thread::spawn(move || {
            for _ in 0..iters {
                persist_sync(&d_a, &p_a).expect("writer A persist");
            }
        });
        let h_b = thread::spawn(move || {
            for _ in 0..iters {
                persist_sync(&d_b, &p_b).expect("writer B persist");
            }
        });
        h_a.join().unwrap();
        h_b.join().unwrap();

        // The final file must be exactly one writer's complete payload.
        let final_bytes = fs::read(&dest).unwrap();
        assert!(
            final_bytes == payload_a || final_bytes == payload_b,
            "final file is neither complete payload (len={}, first byte={:?}) — crossed bytes",
            final_bytes.len(),
            final_bytes.first()
        );

        // No private temp files leaked: only the destination should remain.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "state.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files leaked after concurrent writes: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_write_cleans_up_its_unique_temp() {
        // A unique temp is never renamed on failure, so it must be removed or it
        // would accumulate. Inject a temp-file fsync failure and assert no temp
        // sibling is left behind in the directory.
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap();

        let guard = SyncGuard::install();
        guard.fail_at(1); // temp-file fsync fails -> no rename, temp must be cleaned

        let err = persist_sync(dest_str, b"doomed").expect_err("write should fail");
        assert!(err.contains("sync temp state file"), "unexpected error: {err}");

        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            leftovers.is_empty(),
            "failed write must clean up its unique temp; found: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_dir_fsync_failure_is_propagated() {
        // Let the file fsync succeed but fail the directory fsync (the 2nd
        // call). The error must surface so a caller never believes a snapshot
        // is durable when the rename may be lost on power loss.
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap();

        let guard = SyncGuard::install();
        guard.fail_at(2); // 2nd fsync = parent dir

        let err = persist_sync(dest_str, b"data").expect_err("parent dir fsync should fail");
        assert!(err.contains("fsync parent dir"), "unexpected error: {err}");
        // Both fsyncs were attempted (file succeeded, dir failed) -> 2 calls.
        assert_eq!(guard.calls(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn instance_from_temp_name_parses_our_format_only() {
        // `<stem>.<pid>_<start>.<seq>.tmp` and `<stem>.<ext>.<pid>_<start>.<seq>.tmp`.
        assert_eq!(
            instance_from_temp_name("state.1234_777.0.tmp"),
            Some(ProcInstance {
                pid: 1234,
                start_time: 777
            })
        );
        assert_eq!(
            instance_from_temp_name("state.json.999_42.7.tmp"),
            Some(ProcInstance {
                pid: 999,
                start_time: 42
            })
        );
        // Foreign / non-matching names must NOT be parsed (so they are skipped).
        assert_eq!(instance_from_temp_name("state.json"), None);
        assert_eq!(instance_from_temp_name("state.tmp"), None); // no inst.seq
        assert_eq!(instance_from_temp_name("state.0.tmp"), None); // only one comp
        // Legacy bare-pid temps (no `_<starttime>`) are no longer ours (#2957).
        assert_eq!(instance_from_temp_name("state.1234.0.tmp"), None);
        assert_eq!(instance_from_temp_name("state.json.999.42.tmp"), None);
        // Instance component malformed.
        assert_eq!(instance_from_temp_name("state.abc_777.0.tmp"), None); // pid not numeric
        assert_eq!(instance_from_temp_name("state.1234_abc.0.tmp"), None); // start not numeric
        assert_eq!(instance_from_temp_name("state.1234_.0.tmp"), None); // empty start
        assert_eq!(instance_from_temp_name("state._777.0.tmp"), None); // empty pid
        assert_eq!(instance_from_temp_name("state.1234.def.tmp"), None); // seq not numeric (and no _)
        assert_eq!(instance_from_temp_name(".1234_777.0.tmp"), None); // empty stem
    }

    // Fail-on-revert (#2714): a dead-pid orphan must be swept while a live
    // writer's in-flight temp (and unrelated files) are preserved. Reverting the
    // sweep (sweep_stale_temps a no-op) leaves the orphan and fails this test.
    #[test]
    fn sweep_removes_dead_pid_orphan_preserves_live_and_foreign() {
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap();
        let st = PidGuard::matching_start();

        // Orphan from a CRASHED writer (dead pid) — must be removed.
        let dead_pid = 4242u32;
        let dead_orphan = dir.join(format!("state.json.{dead_pid}_{st}.7.tmp"));
        fs::write(&dead_orphan, b"crashed mid-write").unwrap();

        // In-flight temp of a LIVE other writer (#2705 hazard) — must survive.
        let live_pid = 5151u32;
        let live_temp = dir.join(format!("state.json.{live_pid}_{st}.3.tmp"));
        fs::write(&live_temp, b"another writer in flight").unwrap();

        // A temp for a DIFFERENT destination, dead pid — out of scope, survives.
        let other_dest_temp = dir.join(format!("other.json.{dead_pid}_{st}.1.tmp"));
        fs::write(&other_dest_temp, b"other dest").unwrap();

        // A foreign .tmp not matching our instance format — survives.
        let foreign = dir.join("state.json.backup.tmp");
        fs::write(&foreign, b"foreign").unwrap();

        // A LEGACY bare-pid temp (pre-#2957, no `_<starttime>`) — not ours under
        // the new scheme, so it is left untouched.
        let legacy = dir.join(format!("state.json.{dead_pid}.9.tmp"));
        fs::write(&legacy, b"legacy bare-pid temp").unwrap();

        // An existing published destination — never a sweep candidate.
        fs::write(&dest, b"existing good state").unwrap();

        let pids = PidGuard::install();
        pids.mark_dead(dead_pid); // live_pid stays alive (default matching start)

        sweep_stale_temps(dest_str);

        assert!(
            !dead_orphan.exists(),
            "dead-pid orphan must be swept (revert -> still present, RED)"
        );
        assert!(
            live_temp.exists(),
            "a live writer's in-flight temp must be preserved (#2705)"
        );
        assert!(
            other_dest_temp.exists(),
            "a temp for a different destination must be out of scope"
        );
        assert!(
            foreign.exists(),
            "a non-format foreign .tmp must be preserved"
        );
        assert!(
            legacy.exists(),
            "a legacy bare-pid temp is not a candidate under the instance scheme"
        );
        assert!(
            dest.exists(),
            "the published destination must never be touched"
        );
        assert_eq!(fs::read(&dest).unwrap(), b"existing good state");

        let _ = fs::remove_dir_all(&dir);
    }

    // Fail-on-revert (#2957): the orphan-temp identity must be pid + process
    // START TIME, not the bare pid. A stale temp left by a CRASHED writer whose
    // pid has since been REUSED by an unrelated live process must STILL be
    // swept — the reused process's start time differs from the one embedded in
    // the orphan's name. With the old bare-pid keying (`pid_is_alive(pid)`),
    // `/proc/<reused-pid>` exists so the sweep PRESERVES the orphan forever;
    // this test then goes RED (orphan still present). A genuinely-live writer
    // (pid AND start time match) is still preserved.
    #[test]
    fn sweep_removes_orphan_whose_pid_was_reused_by_another_process() {
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap();

        // The crashed writer ran as pid 7000 with start time 100. Its orphan
        // temp encodes that exact instance.
        let crashed_pid = 7000u32;
        let crashed_start = 100u64;
        let reuse_orphan = dir.join(format!("state.json.{crashed_pid}_{crashed_start}.5.tmp"));
        fs::write(&reuse_orphan, b"crashed, pid later reused").unwrap();

        // A genuinely-live writer (pid 8000, start 200) — its in-flight temp
        // encodes its real, currently-running instance and must survive.
        let live_pid = 8000u32;
        let live_start = 200u64;
        let live_temp = dir.join(format!("state.json.{live_pid}_{live_start}.2.tmp"));
        fs::write(&live_temp, b"live writer in flight").unwrap();

        let pids = PidGuard::install();
        // pid 7000 is LIVE again (reused) but now started at a DIFFERENT time
        // (999) than the orphan's embedded start (100) — the impostor.
        pids.mark_live_with_start(crashed_pid, 999);
        // pid 8000 is live with the SAME start time its temp embeds.
        pids.mark_live_with_start(live_pid, live_start);

        sweep_stale_temps(dest_str);

        assert!(
            !reuse_orphan.exists(),
            "orphan whose pid was reused (different start time) must be swept \
             (bare-pid keying preserves it -> RED)"
        );
        assert!(
            live_temp.exists(),
            "a genuinely-live writer's temp (pid+start match) must be preserved"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // Fail-on-revert (#3009): the self-process shortcut in `instance_is_alive`
    // must match the FULL instance (pid AND start time), not the bare pid. The
    // #2957 PID-reuse fix left a residual: if a crashed writer's pid is recycled
    // as the CURRENT helper's pid, the orphan temp embeds (our pid, the dead
    // writer's start time). A bare-pid self-shortcut returns `true` for it and
    // pins the dead writer's debris for the rest of our lifetime — exactly the
    // PID-reuse hazard #2957 set out to close, for the one pid equal to ours.
    //
    // This test drives the real `instance_is_alive`/sweep gate:
    //   * a recycled-pid orphan (pid == OUR pid, but a DIFFERENT embedded start
    //     time) MUST be swept;
    //   * our OWN genuine in-flight temp (pid AND start time == self) MUST be
    //     preserved.
    // With the bare-pid shortcut (`inst.pid == self_instance().pid`) the orphan
    // is preserved and the first assertion goes RED.
    #[test]
    fn sweep_removes_self_pid_orphan_with_mismatched_start_time() {
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap();

        let me = self_instance();

        // A crashed predecessor whose pid Linux later recycled as ours: the
        // orphan embeds OUR pid but the predecessor's start time. Guard against
        // the (vanishingly unlikely) case where our real start time is 0 or
        // collides with the chosen impostor value.
        let impostor_start = if me.start_time == 0 { 1 } else { 0 };
        let recycled_orphan =
            dir.join(format!("state.json.{}_{impostor_start}.5.tmp", me.pid));
        fs::write(&recycled_orphan, b"crashed predecessor, our pid recycled").unwrap();

        // Our OWN in-flight temp: pid AND start time match self exactly.
        let self_temp =
            dir.join(format!("state.json.{}_{}.2.tmp", me.pid, me.start_time));
        fs::write(&self_temp, b"our genuine in-flight write").unwrap();

        let pids = PidGuard::install();
        // Our pid is, of course, LIVE — and `/proc` reports OUR real start time.
        // The recycled orphan's embedded start (impostor_start) therefore does
        // not match, so the normal (pid,start) gate must sweep it; our own temp
        // (start == me.start_time) must survive.
        pids.mark_live_with_start(me.pid, me.start_time);

        sweep_stale_temps(dest_str);

        assert!(
            !recycled_orphan.exists(),
            "an orphan with OUR pid but a mismatched start time must be swept \
             (bare-pid self-shortcut preserves it -> RED)"
        );
        assert!(
            self_temp.exists(),
            "our own in-flight temp (pid+start match self) must be preserved"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_sweeps_stale_orphan_before_write() {
        // End-to-end through persist_sync's caller-visible effect: pre-seed a
        // dead-pid orphan, then drive a real write; the sweep that the writer
        // runs once per destination must have removed the orphan, leaving only
        // the freshly published destination.
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap();

        let dead_pid = 31337u32;
        let dead_start = PidGuard::matching_start();
        let orphan = dir.join(format!("state.json.{dead_pid}_{dead_start}.0.tmp"));
        fs::write(&orphan, b"leaked").unwrap();

        let pids = PidGuard::install();
        pids.mark_dead(dead_pid);

        // Mirror the writer-thread contract: sweep once for this destination,
        // then persist.
        sweep_stale_temps(dest_str);
        persist_sync(dest_str, b"fresh state").expect("persist");

        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            leftovers,
            vec!["state.json".to_string()],
            "only the published destination should remain after sweep+write"
        );
        assert_eq!(fs::read(&dest).unwrap(), b"fresh state");
        let _ = fs::remove_dir_all(&dir);
    }

    // Fail-on-revert (#2958): a RUNTIME io_uring write failure must DEMOTE the
    // writer to sync — permanently — so (a) the reported mode flips to "sync"
    // and active=false, (b) the demotion cause is recorded as last_error, and
    // (c) every subsequent write takes the sync branch and never re-submits to
    // the broken ring. Reverting the demotion (leaving *mode = IoUring) makes
    // the post-failure assertions RED: the mode stays IoUring and a later write
    // still reports io_uring_failed=true.
    #[test]
    fn runtime_io_uring_failure_demotes_to_sync_permanently() {
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap().to_string();

        // Construct a writer in io_uring mode. If the kernel cannot provide a
        // ring (older CI), the demotion path is unreachable, so skip rather than
        // give a false pass — production always starts in io_uring when a ring
        // is available, which is the scenario this regression guards.
        let ring = match IoUring::new(8) {
            Ok(r) => r,
            Err(_) => {
                eprintln!("io_uring unavailable on this kernel; skipping demotion test");
                return;
            }
        };
        let mut mode = WriteMode::IoUring(ring);

        // Mirror the StateWriter startup state: active + mode reflect io_uring.
        let active = AtomicBool::new(true);
        let mode_str = Mutex::new(String::from("io_uring"));
        let last_error = Mutex::new(String::new());

        // Simulate the writer loop receiving an io_uring transport failure whose
        // sync fallback succeeded — exactly what persist_with_mode produces on a
        // runtime ring failure.
        let demotion_cause = "io_uring write failed, demoting to sync: injected".to_string();
        let outcome = PersistOutcome {
            result: Ok(()),
            io_uring_failed: true,
            demotion_cause: Some(demotion_cause.clone()),
        };
        let res = apply_outcome(outcome, &mut mode, &active, &mode_str, &last_error);
        assert!(res.is_ok(), "sync fallback succeeded, write must report Ok");

        // (a) mode demoted.
        assert!(
            matches!(mode, WriteMode::SyncFallback),
            "runtime io_uring failure must demote WriteMode to SyncFallback"
        );
        // (b) reported status reflects sync.
        assert!(
            !active.load(Ordering::Relaxed),
            "status.active must be false after demotion"
        );
        assert_eq!(
            *mode_str.lock().unwrap(),
            "sync",
            "status.mode must report sync after demotion"
        );
        assert_eq!(
            *last_error.lock().unwrap(),
            demotion_cause,
            "last_error must record the demotion cause"
        );

        // (c) no further io_uring attempts: a subsequent write now goes through
        // the sync branch (io_uring_failed=false) and actually persists. With
        // the demotion reverted, `mode` would still be IoUring here and this
        // write would route through the ring.
        let next = persist_with_mode(&mut mode, &dest_str, b"after demotion");
        assert!(next.result.is_ok(), "post-demotion write must succeed");
        assert!(
            !next.io_uring_failed,
            "post-demotion write must NOT touch io_uring (must take the sync branch)"
        );
        assert!(
            matches!(mode, WriteMode::SyncFallback),
            "mode must stay sync for the writer's lifetime (no flapping)"
        );
        assert_eq!(fs::read(&dest).unwrap(), b"after demotion");

        let _ = fs::remove_dir_all(&dir);
    }
}
