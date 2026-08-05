//! Background bash process registry.
//!
//! This is the *actual* state this server exists to hold — deliberately
//! decoupled from the MCP transport/session. A `BashProc` is created by
//! `background_bash_run`/`background_bash_watch`, addressed by its `bash_id` from then on, and
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

use crate::journal::{self, JobMeta, JobResult};

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
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WatchTarget {
    Stdout,
    Stderr,
    Both,
}

pub struct BashProc {
    pub id: String,
    pub owner: String,
    /// Kept for a future introspection/`bash_list` tool.
    #[allow(dead_code)]
    pub command: String,
    /// Kept for a future introspection/`bash_list` tool.
    #[allow(dead_code)]
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
            Some(w) => {
                Some(Regex::new(&w.pattern).map_err(|e| SpawnError::InvalidRegex(e.to_string()))?)
            }
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

        // Written before the job can possibly finish, so a crash right after
        // this point still leaves enough on disk for `recover()` to find the
        // orphan on the next startup — see journal.rs.
        journal::write_meta(
            &spill_dir,
            &JobMeta {
                bash_id: id.clone(),
                owner: owner.to_string(),
                command: command.clone(),
                cwd: cwd.clone(),
                pid,
                started_at_ms: journal::now_ms(),
            },
        );

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
        let watch_target = watch
            .as_ref()
            .map(|w| w.target)
            .unwrap_or(WatchTarget::Both);
        let timeout = Duration::from_secs(
            watch
                .as_ref()
                .and_then(|w| w.timeout_seconds)
                .unwrap_or(DEFAULT_WATCH_TIMEOUT_SECONDS)
                .min(MAX_WATCH_TIMEOUT_SECONDS),
        );

        let registry = self.clone();
        tokio::spawn(async move {
            let stdout_proc = proc.clone();
            let stderr_proc = proc.clone();

            let matched: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
            let matched_stdout = matched.clone();
            let matched_stderr = matched.clone();

            // Streams are read independently; watch matching (if any) is
            // checked line-by-line on whichever stream(s) `watch_target` selects.
            let regex_stdout = watch_state.clone();
            let regex_stderr = watch_state.clone();

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
                                    && matches!(
                                        watch_target,
                                        WatchTarget::Stdout | WatchTarget::Both
                                    )
                                {
                                    if let Some(line) = scan_lines(&mut carry, &buf[..n], re) {
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
                                    && matches!(
                                        watch_target,
                                        WatchTarget::Stderr | WatchTarget::Both
                                    )
                                {
                                    if let Some(line) = scan_lines(&mut carry, &buf[..n], re) {
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
            let matched_line = matched.lock().unwrap().take();
            if let Some(line) = matched_line.clone() {
                *proc.watch_matched_line.lock().unwrap() = Some(line);
            }
            journal::write_result(
                &registry.spill_root.join(&proc.id),
                &JobResult {
                    bash_id: proc.id.clone(),
                    owner: proc.owner.clone(),
                    exit_code,
                    finished_at_ms: journal::now_ms(),
                    matched_line,
                    unknown: false,
                },
            );
        });

        Ok(id)
    }

    pub async fn get(&self, id: &str) -> Option<Arc<ProcHandle>> {
        self.procs.lock().await.get(id).cloned()
    }

    /// Call once at startup, before serving any request. Scans for jobs a
    /// *previous* instance of this daemon started and never finished
    /// watching — `meta.json` on disk with no matching `result.json` yet.
    ///
    /// Those jobs are not reattached into this process's in-memory registry:
    /// `background_bash_output`/`background_bash_kill` genuinely can't work on them anymore (this
    /// process is not their real parent — the OS reparented them when the
    /// old daemon died — so there is no `wait()` to observe their real exit
    /// code, only `kill(pid, 0)` polling to notice when they're gone).
    ///
    /// What *does* still work: the completion signal. Once the orphan exits
    /// (observed via polling), a `result.json` is written with
    /// `unknown: true` so a caller watching the spill root for completions
    /// (see journal.rs) is not left waiting forever for a job the old
    /// instance already lost track of.
    pub async fn recover(self: &Arc<Self>) {
        let Ok(entries) = std::fs::read_dir(&self.spill_root) else {
            return;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() || journal::result_exists(&dir) {
                continue;
            }
            let Some(meta) = journal::read_meta(&dir) else {
                continue;
            };
            tracing::warn!(
                bash_id = %meta.bash_id,
                pid = meta.pid,
                "recover: orphaned job from a previous instance — watching for exit; \
                 its live output/kill are unavailable now"
            );
            let spill_root = self.spill_root.clone();
            tokio::spawn(async move {
                while pid_alive(meta.pid) {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                journal::write_result(
                    &spill_root.join(&meta.bash_id),
                    &JobResult {
                        bash_id: meta.bash_id.clone(),
                        owner: meta.owner.clone(),
                        exit_code: None,
                        finished_at_ms: journal::now_ms(),
                        matched_line: None,
                        unknown: true,
                    },
                );
                tracing::info!(bash_id = %meta.bash_id, "recover: orphaned job finished");
            });
        }
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
    lines.into_iter().find(|line| regex.is_match(line))
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

/// `kill(pid, 0)`: sends no signal, just checks whether `pid` still exists
/// and is ours to signal. Used only by `Registry::recover` — it cannot
/// `wait()` an orphan it didn't fork, so this poll is the only exit signal
/// available to it.
#[cfg(unix)]
fn pid_alive(pid: i32) -> bool {
    pid > 0 && unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(not(unix))]
fn pid_alive(_pid: i32) -> bool {
    false
}

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
