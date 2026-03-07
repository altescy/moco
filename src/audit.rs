use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditLogError {
    #[error("failed to open audit log file: {0}")]
    Open(#[from] std::io::Error),
    #[error("failed to serialize audit event: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct AuditLogger {
    path: std::path::PathBuf,
    max_bytes: u64,
    max_files: usize,
    state: Mutex<AuditState>,
}

#[derive(Debug)]
struct AuditState {
    file: std::fs::File,
    current_size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp_ms: u128,
    pub request_id: u64,
    pub phase: String,
    pub tool: String,
    pub status: String,
    pub findings: usize,
    pub reasons: usize,
    pub reason_hashes: Vec<String>,
}

impl AuditLogger {
    pub fn new(path: &Path, max_bytes: u64, max_files: usize) -> Result<Self, AuditLogError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let current_size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            max_bytes,
            max_files: max_files.max(1),
            state: Mutex::new(AuditState { file, current_size }),
        })
    }

    pub fn log(&self, event: AuditEvent) -> Result<(), AuditLogError> {
        let serialized = serde_json::to_vec(&event)?;
        let line_size = serialized.len() as u64 + 1;

        let mut state = self.state.lock().expect("audit logger mutex poisoned");
        if self.max_bytes > 0 && state.current_size.saturating_add(line_size) > self.max_bytes {
            self.rotate_locked(&mut state)?;
        }

        state.file.write_all(&serialized)?;
        state.file.write_all(b"\n")?;
        state.file.flush()?;
        state.current_size = state.current_size.saturating_add(line_size);
        Ok(())
    }

    fn rotate_locked(&self, state: &mut AuditState) -> Result<(), AuditLogError> {
        for i in (1..=self.max_files).rev() {
            let src = self.path.with_extension(format!("jsonl.{i}"));
            if i == self.max_files {
                if src.exists() {
                    fs::remove_file(src)?;
                }
                continue;
            }

            if src.exists() {
                let dst = self.path.with_extension(format!("jsonl.{}", i + 1));
                fs::rename(src, dst)?;
            }
        }

        if self.path.exists() {
            let first = self.path.with_extension("jsonl.1");
            fs::rename(&self.path, first)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        state.file = file;
        state.current_size = 0;
        Ok(())
    }
}

#[must_use]
pub fn now_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

#[must_use]
pub fn hash_reason(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
