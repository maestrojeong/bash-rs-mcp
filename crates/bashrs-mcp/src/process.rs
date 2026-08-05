//! Background bash process registry.
//!
//! This is the *actual* state this server exists to hold — deliberately
//! decoupled from the MCP transport/session. A `BashProc` is created by
//! `bash_run`/`bash_watch`, addressed by its `bash_id` from then on, and
//! outlives whatever MCP request created it. Nothing here reads or writes
//! anything session-shaped; the only access control is the capability-derived
//! `owner` string stored on the proc and checked by every subsequent call.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rand::RngCore;
use regex::Regex;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

pub const MAX_LIVE_BYTES: usize = 256 * 1024;
const DEFAULT_WATCH_TIMEOUT_SECONDS: u64 = 3600;
pub const MAX_WATCH_TIMEOUT_SECONDS: u64 = 24 * 3600;
const SIGTERM_GRACE: Duration = Duration::from_secs(5);

pub fn new_bash_id() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("bash_{}", hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// One captured stream (stdout or stderr). Keeps a bounded live window in
/// memory plus a best-effort append-only spill file with the complete bytes,
/// mirroring the TS server's head+tail preview / full-spill-on-disk split.
pub struct OutputStream {
    live: Vec<u8>,
    live_start: u64,
    total: u64,
    spill: Option<std::fs::File>,
    pub spill_path: Option<std::path::PathBuf>,
}

pub struct ReadResult {
    pub text: String,
    pub next_cursor: u64,
    pub dropped_bytes: u64,
}

impl OutputStream {
    fn new(spill_path: Option<std::path::PathBuf>) -> Self {
        let spill = spill_path.as_ref().and_then(|path| {
            std::fs::File::options()
                .create(true)
                .append(true)
                .open(path)
                .ok()
        });
        Self {
            live: Vec::new(),
            live_start: 0,
            total: 0,
            spill,
            spill_path,
        }
    }

    fn push(&mut self, data: &[u8]) {
        if let Some(file) = self.spill.as_mut() {
            use std::io::Write;
            let _ = file.write_all(data); // best-effort; the live window is authoritative for recent reads
        }
        self.live.extend_from_slice(data);
        self.total += data.len() as u64;
        if self.live.len() > MAX_LIVE_BYTES {
            let excess = self.live.len() - MAX_LIVE_BYTES;
            self.live.drain(0..excess);
            self.live_start += excess as u64;
        }
    }

    pub fn read_since(&self, cursor: u64) -> ReadResult {
        if cursor < self.live_start {
            ReadResult {
                text: String::from_utf8_lossy(&self.live).into_owned(),
                next_cursor: self.live_start + self.live.len() as u64,
                dropped_bytes: self.live_start - cursor,
            }
        } else {
            let offset = (cursor - self.live_start) as usize;
            let slice = self.live.get(offset..).unwrap_or(&[]);
            ReadResult {
                text: String::from_utf8_lossy(slice).into_owned(),
                next_cursor: self.total,
                dropped_bytes: 0,
            }
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.total
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WatchTarget {
    Stdout,
    Stderr,
    Both,
}

struct WatchState {
    regex: Regex,
    target: WatchTarget,
    stdout_carry: String,
    stderr_carry: String,
}

pub struct BashProc {
    pub id: String,
    pub owner: String,
    pub command: String,
    pub started_at: Instant,
    pub stdout: Mutex<OutputStream>,
    pub stderr: Mutex<OutputStream>,
    pub exited: AtomicBool,
    pub exit_code: StdMutex<Option<i32>>,
    pub watch_matched_line: StdMutex<Option<String>>,
    pid: i32,
}

/// Read cursors live outside `BashProc` (in the registry handle) because
/// tool calls are not required to be concurrent for the same `bash_id` —
/// mirrors the TS server's single-reader assumption for
/// `background_bash_output`.
pub struct ProcHandle {
    pub proc: Arc<BashProc>,
    pub stdout_cursor: StdMutex<u64>,
    pub stderr_cursor: StdMutex<u64>,
}

pub struct Registry {
    procs: Mutex<HashMap<String, Arc<ProcHandle>>>,
    spill_root: std::path::PathBuf,
}

pub struct WatchRequest {
    pub pattern: String,
    pub target: WatchTarget,
    pub timeout_seconds: Option<u64>,
}

pub enum SpawnError {
    InvalidRegex(String),
    Io(String),
}

impl Registry {
    pub fn new(spill_root: std::path::PathBuf) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&spill_root);
        Arc::new(Self {
            procs: Mutex::new(HashMap::new()),
            spill_root,
        })
    }

    pub async fn spawn(
        self: &Arc<Self>,
        owner: &str,
        command: String,
        cwd: Option<String>,
        watch: Option<WatchRequest>,
    ) -> Result<String, SpawnError> {
        let watch_state = match watch.as_ref() {
            Some(w) => Some(
                Regex::new(&w.pattern).map_err(|e| SpawnError::InvalidRegex(e.to_string()))?,
            ),
            None => None,
        };

        let id = new_bash_id();
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg(&command);
        if let Some(dir) = cwd.as_ref() {
            cmd.current_dir(dir);
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.as_std_mut().process_group(0); // own process group, mirrors `detached: true` + kill(-pgid)
        }

        let mut child: Child = cmd.spawn().map_err(|e| SpawnError::Io(e.to_string()))?;
        let pid = child.id().unwrap_or(0) as i32;
        let stdout = child.stdout.take().expect("piped");
        let stderr = child.stderr.take().expect("piped");

        let spill_dir = self.spill_root.join(&id);
        let _ = std::fs::create_dir_all(&spill_dir);

        let handle = Arc::new(ProcHandle {
            proc: Arc::new(BashProc {
                id: id.clone(),
                owner: owner.to_string(),
                command,
                started_at: Instant::now(),
                stdout: Mutex::new(OutputStream::new(Some(spill_dir.join("stdout.log")))),
                stderr: Mutex::new(OutputStream::new(Some(spill_dir.join("stderr.log")))),
                exited: AtomicBool::new(false),
                exit_code: StdMutex::new(None),
                watch_matched_line: StdMutex::new(None),
                pid,
            }),
            stdout_cursor: StdMutex::new(0),
            stderr_cursor: StdMutex::new(0),
        });

        self.procs.lock().await.insert(id.clone(), handle.clone());

        let proc = handle.proc.clone();
        let watch_target = watch.as_ref().map(|w| w.target).unwrap_or(WatchTarget::Both);
        let timeout = Duration::from_secs(
            watch
                .as_ref()
                .and_then(|w| w.timeout_seconds)
                .unwrap_or(DEFAULT_WATCH_TIMEOUT_SECONDS)
                .min(MAX_WATCH_TIMEOUT_SECONDS),
        );

        let mut watch_state = watch_state.map(|regex| WatchState {
            regex,
            target: watch_target,
            stdout_carry: String::new(),
            stderr_carry: String::new(),
        });

        let registry = self.clone();
        tokio::spawn(async move {
            let stdout_proc = proc.clone();
            let stderr_proc = proc.clone();

            let matched: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
            let matched_stdout = matched.clone();
            let matched_stderr = matched.clone();

            // Streams are read independently; watch matching (if any) is
            // checked line-by-line on whichever stream(s) `target` selects.
            let regex_ref: Option<Regex> = watch_state.as_ref().map(|w| w.regex.clone());
            let regex_stdout = regex_ref.clone();
            let regex_stderr = regex_ref;

            let stdout_task = tokio::spawn(async move {
                let mut reader = BufReader::new(stdout);
                let mut carry = String::new();
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            stdout_proc.stdout.lock().await.push(&buf[..n]);
                            if let Some(re) = regex_stdout.as_ref() {
                                if matched_stdout.lock().unwrap().is_none()
                                    && matches!(watch_target, WatchTarget::Stdout | WatchTarget::Both)
                                {
                                    if let Some(line) =
                                        scan_lines(&mut carry, &buf[..n], re)
                                    {
                                        *matched_stdout.lock().unwrap() = Some(line);
                                    }
                                }
                            }
                        }
                    }
                }
            });

            let stderr_task = tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                let mut carry = String::new();
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            stderr_proc.stderr.lock().await.push(&buf[..n]);
                            if let Some(re) = regex_stderr.as_ref() {
                                if matched_stderr.lock().unwrap().is_none()
                                    && matches!(watch_target, WatchTarget::Stderr | WatchTarget::Both)
                                {
                                    if let Some(line) =
                                        scan_lines(&mut carry, &buf[..n], re)
                                    {
                                        *matched_stderr.lock().unwrap() = Some(line);
                                    }
                                }
                            }
                        }
                    }
                }
            });

            let wait_child = async {
                let _ = child.wait().await;
            };

            if watch_state.is_some() {
                tokio::select! {
                    _ = wait_child => {}
                    _ = tokio::time::sleep(timeout) => {}
                    _ = async {
                        loop {
                            if matched.lock().unwrap().is_some() { break; }
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    } => {
                        // matched: terminate the process, matching TS's
                        // handleWatchMatch (stop as soon as the line appears).
                        signal_pid(proc.pid, libc_sigterm());
                    }
                }
            } else {
                wait_child.await;
            }

            let _ = stdout_task.await;
            let _ = stderr_task.await;
            let exit_code = child.wait().await.ok().and_then(|s| s.code());
            *proc.exit_code.lock().unwrap() = exit_code;
            proc.exited.store(true, Ordering::SeqCst);
            if let Some(line) = matched.lock().unwrap().take() {
                *proc.watch_matched_line.lock().unwrap() = Some(line);
            }
            let _ = watch_state.take();
            drop(registry); // keep registry alive for the duration of this task
        });

        Ok(id)
    }

    pub async fn get(&self, id: &str) -> Option<Arc<ProcHandle>> {
        self.procs.lock().await.get(id).cloned()
    }

    pub async fn kill(&self, id: &str) -> Option<bool> {
        let handle = self.get(id).await?;
        if handle.proc.exited.load(Ordering::SeqCst) {
            return Some(false);
        }
        signal_pid(handle.proc.pid, libc_sigterm());
        let proc = handle.proc.clone();
        tokio::spawn(async move {
            tokio::time::sleep(SIGTERM_GRACE).await;
            if !proc.exited.load(Ordering::SeqCst) {
                signal_pid(proc.pid, libc_sigkill());
            }
        });
        Some(true)
    }
}

fn scan_lines(carry: &mut String, chunk: &[u8], regex: &Regex) -> Option<String> {
    carry.push_str(&String::from_utf8_lossy(chunk));
    let mut lines: Vec<String> = carry.split('\n').map(|s| s.to_string()).collect();
    *carry = lines.pop().unwrap_or_default();
    for line in lines {
        if regex.is_match(&line) {
            return Some(line);
        }
    }
    None
}

#[cfg(unix)]
fn signal_pid(pid: i32, signal: i32) {
    if pid <= 0 {
        return;
    }
    unsafe {
        libc::kill(-pid, signal); // negative pid = whole process group (see process_group(0) above)
    }
}

#[cfg(not(unix))]
fn signal_pid(_pid: i32, _signal: i32) {}

#[cfg(unix)]
fn libc_sigterm() -> i32 {
    libc::SIGTERM
}
#[cfg(unix)]
fn libc_sigkill() -> i32 {
    libc::SIGKILL
}
#[cfg(not(unix))]
fn libc_sigterm() -> i32 {
    15
}
#[cfg(not(unix))]
fn libc_sigkill() -> i32 {
    9
}
