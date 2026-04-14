use io_uring::{IoUring, opcode, types};
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

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

                while let Ok(req) = rx.recv() {
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
    let tmp = temporary_path(path);
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| format!("open temp state file {}: {e}", tmp.display()))?;
    write_all_with_ring(ring, file.as_raw_fd(), data)?;
    file.sync_all()
        .map_err(|e| format!("sync temp state file {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path))?;
    Ok(())
}

fn persist_sync(path: &str, data: &[u8]) -> Result<(), String> {
    let tmp = temporary_path(path);
    fs::write(&tmp, data).map_err(|e| format!("write temp state file {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path))?;
    Ok(())
}

fn write_all_with_ring(ring: &mut IoUring, fd: i32, data: &[u8]) -> Result<(), String> {
    let mut offset = 0usize;
    while offset < data.len() {
        let entry = opcode::Write::new(
            types::Fd(fd),
            unsafe { data.as_ptr().add(offset) },
            (data.len() - offset) as _,
        )
        .offset(offset as _)
        .build()
        .user_data(1);
        unsafe {
            ring.submission()
                .push(&entry)
                .map_err(|_| "submit queue full".to_string())?;
        }
        ring.submit_and_wait(1)
            .map_err(|e| format!("submit io_uring write: {e}"))?;
        let mut completion = ring.completion();
        let cqe = completion
            .next()
            .ok_or_else(|| "missing io_uring completion".to_string())?;
        let res = cqe.result();
        if res < 0 {
            return Err(format!(
                "io_uring write failed: {}",
                io::Error::from_raw_os_error(-res)
            ));
        }
        if res == 0 {
            return Err("io_uring short write: 0".to_string());
        }
        offset += res as usize;
    }
    Ok(())
}

fn temporary_path(path: &str) -> PathBuf {
    let mut tmp = PathBuf::from(path);
    let ext = tmp
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!("{ext}.tmp"))
        .unwrap_or_else(|| "tmp".to_string());
    tmp.set_extension(ext);
    tmp
}
