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

/// Liveness seam: report whether `pid` is a live process. Indirected through a
/// function pointer so the orphan-temp sweep can be tested deterministically
/// (a test marks specific pids dead/alive without spawning real processes) and
/// so a test FAILS if the dead-pid gate is removed. Production always uses
/// [`real_pid_is_alive`].
#[cfg(test)]
type PidAliveFn = fn(u32) -> bool;

/// A pid is "alive" if `/proc/<pid>` exists. This is the concurrency-safety
/// gate for the orphan sweep (#2714): the unique-per-write temp scheme leaks
/// `<dest>.<pid>.<seq>.tmp` on a crash between create and rename, but a naive
/// glob-sweep would re-introduce the #2705 cross-writer hazard by deleting a
/// still-live OTHER writer's in-flight temp. Removing only temps whose embedded
/// pid is no longer running preserves any concurrent live writer's temp.
fn real_pid_is_alive(pid: u32) -> bool {
    // The writer's own process is always alive; never treat its in-flight temps
    // as orphans regardless of /proc visibility quirks.
    if pid == std::process::id() {
        return true;
    }
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(test)]
thread_local! {
    static PID_ALIVE_HOOK: std::cell::Cell<PidAliveFn> =
        const { std::cell::Cell::new(real_pid_is_alive) };
}

#[cfg(test)]
fn pid_is_alive(pid: u32) -> bool {
    PID_ALIVE_HOOK.with(|h| (h.get())(pid))
}

#[cfg(not(test))]
#[inline]
fn pid_is_alive(pid: u32) -> bool {
    real_pid_is_alive(pid)
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
                    let result = persist_with_mode(&mut write_mode, &req.path, &req.data);
                    if let Err(err) = &result {
                        if let Ok(mut last) = last_error_bg.lock() {
                            *last = err.clone();
                        }
                    }
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

fn persist_with_mode(mode: &mut WriteMode, path: &str, data: &[u8]) -> Result<(), String> {
    match mode {
        WriteMode::IoUring(ring) => persist_with_io_uring(ring, path, data).or_else(|err| {
            persist_sync(path, data).map_err(|sync_err| format!("{err}; {sync_err}"))
        }),
        WriteMode::SyncFallback => persist_sync(path, data),
    }
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

/// Build a PRIVATE temp path for one write: `<dest>.<pid>.<seq>.tmp`. The pid
/// isolates separate helper processes (restart/upgrade handover) and the
/// per-process monotonic counter isolates concurrent or rapid in-process writes.
/// Two distinct writers therefore never name — and so never open/truncate/write
/// — the same temp file, which is what previously let a successful rename
/// publish crossed bytes (#2705). The destination's own extension is preserved
/// in the stem so the temp stays a recognizable sibling.
fn temporary_path(path: &str) -> PathBuf {
    let pid = std::process::id();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut tmp = PathBuf::from(path);
    let suffix = tmp
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!("{ext}.{pid}.{seq}.tmp"))
        .unwrap_or_else(|| format!("{pid}.{seq}.tmp"));
    tmp.set_extension(suffix);
    tmp
}

/// Parse the embedded pid out of a temp file NAME (not a full path) produced by
/// [`temporary_path`]. The format is `<stem>[.<ext>].<pid>.<seq>.tmp`, so after
/// stripping the trailing `.tmp` the last two dot-components are `<pid>.<seq>`
/// (pid second-to-last, seq last). Returns `None` if `name` does not match that
/// shape — a foreign file that merely ends in `.tmp` is left untouched.
fn pid_from_temp_name(name: &str) -> Option<u32> {
    let body = name.strip_suffix(".tmp")?;
    let mut parts = body.rsplitn(3, '.');
    let _seq: &str = parts.next()?; // trailing <seq>
    let pid_str = parts.next()?; // <pid> immediately before <seq>
    let stem = parts.next()?; // at least one leading stem component must exist
    if stem.is_empty() {
        return None;
    }
    // Both the seq and pid components must be all-digits to be one of our temps.
    if !_seq.bytes().all(|b| b.is_ascii_digit()) || _seq.is_empty() {
        return None;
    }
    if pid_str.is_empty() || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid_str.parse::<u32>().ok()
}

/// Best-effort removal of stale `<dest>.<pid>.<seq>.tmp` orphans left in `dest`'s
/// directory by a crash between temp create and atomic rename (#2714).
///
/// Concurrency safety (the #2705 hazard): a unique-per-write temp belonging to a
/// DIFFERENT, still-running writer (e.g. a replacement helper started before the
/// old one fully exits) must NEVER be removed — deleting its in-flight temp
/// would break its atomic write. This sweep therefore removes a candidate ONLY
/// when its embedded pid is no longer a live process. The current process's own
/// pid is always treated as alive, so this never races our own writes.
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
    // Our temps for this destination are named `<dest_name>.<pid>.<seq>.tmp`.
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
        let pid = match pid_from_temp_name(name) {
            Some(p) => p,
            None => continue, // not one of our `<pid>.<seq>.tmp` temps
        };
        if pid_is_alive(pid) {
            continue; // a live writer (possibly another helper) may still hold it
        }
        let victim = entry.path();
        match fs::remove_file(&victim) {
            Ok(()) => eprintln!(
                "xpf-state-writer: swept stale orphan temp {} (dead pid {pid})",
                victim.display()
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
        // Pids the test has marked DEAD; the live-check hook reports any pid in
        // this set as not-alive and everything else as alive. Deterministic, no
        // real processes spawned.
        static DEAD_PIDS: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    }

    fn test_pid_is_alive(pid: u32) -> bool {
        DEAD_PIDS.with(|d| !d.borrow().contains(&pid))
    }

    /// Installs a deterministic pid-liveness hook for the orphan sweep and lets
    /// the test declare specific pids dead. Restores the real check on drop.
    struct PidGuard;
    impl PidGuard {
        fn install() -> Self {
            DEAD_PIDS.with(|d| d.borrow_mut().clear());
            PID_ALIVE_HOOK.with(|h| h.set(test_pid_is_alive));
            PidGuard
        }
        fn mark_dead(&self, pid: u32) {
            DEAD_PIDS.with(|d| d.borrow_mut().push(pid));
        }
    }
    impl Drop for PidGuard {
        fn drop(&mut self) {
            PID_ALIVE_HOOK.with(|h| h.set(real_pid_is_alive));
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
    fn pid_from_temp_name_parses_our_format_only() {
        // `<stem>.<pid>.<seq>.tmp` and `<stem>.<ext>.<pid>.<seq>.tmp`.
        assert_eq!(pid_from_temp_name("state.1234.0.tmp"), Some(1234));
        assert_eq!(pid_from_temp_name("state.json.999.42.tmp"), Some(999));
        // Foreign / non-matching names must NOT be parsed (so they are skipped).
        assert_eq!(pid_from_temp_name("state.json"), None);
        assert_eq!(pid_from_temp_name("state.tmp"), None); // no pid.seq
        assert_eq!(pid_from_temp_name("state.0.tmp"), None); // only one number
        assert_eq!(pid_from_temp_name("state.abc.0.tmp"), None); // pid not numeric
        assert_eq!(pid_from_temp_name("state.1.def.tmp"), None); // seq not numeric
        assert_eq!(pid_from_temp_name(".1234.0.tmp"), None); // empty stem
    }

    // Fail-on-revert (#2714): a dead-pid orphan must be swept while a live
    // writer's in-flight temp (and unrelated files) are preserved. Reverting the
    // sweep (sweep_stale_temps a no-op) leaves the orphan and fails this test.
    #[test]
    fn sweep_removes_dead_pid_orphan_preserves_live_and_foreign() {
        let dir = tmpdir();
        let dest = dir.join("state.json");
        let dest_str = dest.to_str().unwrap();

        // Orphan from a CRASHED writer (dead pid) — must be removed.
        let dead_pid = 4242u32;
        let dead_orphan = dir.join(format!("state.json.{dead_pid}.7.tmp"));
        fs::write(&dead_orphan, b"crashed mid-write").unwrap();

        // In-flight temp of a LIVE other writer (#2705 hazard) — must survive.
        let live_pid = 5151u32;
        let live_temp = dir.join(format!("state.json.{live_pid}.3.tmp"));
        fs::write(&live_temp, b"another writer in flight").unwrap();

        // A temp for a DIFFERENT destination, dead pid — out of scope, survives.
        let other_dest_temp = dir.join(format!("other.json.{dead_pid}.1.tmp"));
        fs::write(&other_dest_temp, b"other dest").unwrap();

        // A foreign .tmp not matching our pid.seq format — survives.
        let foreign = dir.join("state.json.backup.tmp");
        fs::write(&foreign, b"foreign").unwrap();

        // An existing published destination — never a sweep candidate.
        fs::write(&dest, b"existing good state").unwrap();

        let pids = PidGuard::install();
        pids.mark_dead(dead_pid); // live_pid stays alive

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
            dest.exists(),
            "the published destination must never be touched"
        );
        assert_eq!(fs::read(&dest).unwrap(), b"existing good state");

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
        let orphan = dir.join(format!("state.json.{dead_pid}.0.tmp"));
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
}
