//! On-disk completion notifications.
//!
//! This is the extensible integration point instead of an exec'd hook: every
//! job gets a `meta.json` (written at spawn) and a `result.json` (written on
//! completion) inside its own spill directory, alongside `stdout.log` /
//! `stderr.log`. A caller (negotium, clawgram, anything) watches
//! `{spill_root}/*/result.json` the same way it already watches its own
//! outbox/inbox directories — `fs.watch` + a fallback poll, exactly the
//! at-least-once pattern negotium's `runtime/inbox.ts` already uses — reads
//! `owner` to figure out where the completion belongs, and deletes (or
//! renames) the file once delivered. bash-rs never reads these back and
//! never deletes them; it only ever appends new job directories.
//!
//! This also means bash-rs itself never has to exec anything or know a
//! single thing about the caller's runtime — the contract is purely file
//! shapes, so any project can consume it without linking against negotium.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobMeta {
    pub bash_id: String,
    pub owner: String,
    pub command: String,
    pub cwd: Option<String>,
    pub pid: i32,
    pub started_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub bash_id: String,
    pub owner: String,
    pub exit_code: Option<i32>,
    pub finished_at_ms: u64,
    pub matched_line: Option<String>,
    /// True when the exit code could not be observed — the job was still
    /// running when a *previous* bash-rs instance died and this one
    /// inherited an orphan it is not the real parent of, so `wait()` is
    /// unavailable to it (see `process::Registry::recover`). The consumer
    /// still gets a completion signal; it just can't know how the job
    /// exited.
    pub unknown: bool,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) {
    let Ok(body) = serde_json::to_vec_pretty(value) else {
        return;
    };
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp")
    ));
    // Write-then-rename: a reader watching this directory never observes a
    // partially-written file, and a crash between the two steps just leaves
    // an inert `.tmp` file instead of a corrupt `meta.json`/`result.json`.
    if std::fs::write(&tmp, &body).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

pub fn write_meta(dir: &Path, meta: &JobMeta) {
    atomic_write_json(&dir.join("meta.json"), meta);
}

pub fn write_result(dir: &Path, result: &JobResult) {
    atomic_write_json(&dir.join("result.json"), result);
}

pub fn read_meta(dir: &Path) -> Option<JobMeta> {
    let bytes = std::fs::read(dir.join("meta.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn result_exists(dir: &Path) -> bool {
    dir.join("result.json").exists()
}
