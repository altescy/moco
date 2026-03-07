use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditLogError {
    #[error("failed to open audit db: {0}")]
    Open(#[from] rusqlite::Error),
    #[error("failed to initialize audit db schema: {0}")]
    InitSchema(rusqlite::Error),
    #[error("failed to create audit db directory: {0}")]
    CreateDir(#[from] std::io::Error),
    #[error("failed to serialize audit event: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct AuditLogger {
    path: PathBuf,
    state: Mutex<()>,
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

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub timestamp_ms: i64,
    pub request_id: i64,
    pub phase: String,
    pub tool: String,
    pub status: String,
    pub findings: i64,
    pub reasons: i64,
    pub reason_hashes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditSummary {
    pub total_events: i64,
    pub by_status: Vec<(String, i64)>,
    pub by_phase: Vec<(String, i64)>,
    pub top_tools: Vec<(String, i64)>,
}

impl AuditLogger {
    pub fn new(path: &Path) -> Result<Self, AuditLogError> {
        let logger = Self {
            path: path.to_path_buf(),
            state: Mutex::new(()),
        };
        logger.ensure_db_ready()?;
        Ok(logger)
    }

    pub fn log(&self, event: AuditEvent) -> Result<(), AuditLogError> {
        let _guard = self.state.lock().expect("audit logger mutex poisoned");
        let conn = self.open_connection()?;
        let reason_hashes = serde_json::to_string(&event.reason_hashes)?;
        conn.execute(
            "INSERT INTO audit_events (timestamp_ms, request_id, phase, tool, status, findings, reasons, reason_hashes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.timestamp_ms as i64,
                event.request_id as i64,
                event.phase,
                event.tool,
                event.status,
                event.findings as i64,
                event.reasons as i64,
                reason_hashes,
            ],
        )?;
        Ok(())
    }

    pub fn recent_entries(&self, limit: usize) -> Result<Vec<AuditLogEntry>, AuditLogError> {
        let safe_limit = limit.max(1) as i64;
        let conn = self.open_connection()?;
        let mut stmt = conn.prepare(
            "SELECT timestamp_ms, request_id, phase, tool, status, findings, reasons, reason_hashes
             FROM audit_events
             ORDER BY id DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map([safe_limit], |row| {
            let raw_reason_hashes: String = row.get(7)?;
            let reason_hashes =
                serde_json::from_str::<Vec<String>>(&raw_reason_hashes).unwrap_or_default();

            Ok(AuditLogEntry {
                timestamp_ms: row.get(0)?,
                request_id: row.get(1)?,
                phase: row.get(2)?,
                tool: row.get(3)?,
                status: row.get(4)?,
                findings: row.get(5)?,
                reasons: row.get(6)?,
                reason_hashes,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn summarize(&self, top_tools: usize) -> Result<AuditSummary, AuditLogError> {
        let conn = self.open_connection()?;
        let total_events =
            conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))?;

        let by_status = grouped_counts(&conn, "status", 32)?;
        let by_phase = grouped_counts(&conn, "phase", 32)?;
        let top_tools = grouped_counts(&conn, "tool", top_tools.max(1))?;

        Ok(AuditSummary {
            total_events,
            by_status,
            by_phase,
            top_tools,
        })
    }

    fn ensure_db_ready(&self) -> Result<(), AuditLogError> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }

        let conn = self.open_connection()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ms INTEGER NOT NULL,
                request_id INTEGER NOT NULL,
                phase TEXT NOT NULL,
                tool TEXT NOT NULL,
                status TEXT NOT NULL,
                findings INTEGER NOT NULL,
                reasons INTEGER NOT NULL,
                reason_hashes TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp_ms);
             CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_events(status);
             CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events(tool);",
        )
        .map_err(AuditLogError::InitSchema)
    }

    fn open_connection(&self) -> Result<Connection, AuditLogError> {
        Connection::open(&self.path).map_err(AuditLogError::Open)
    }
}

fn grouped_counts(
    conn: &Connection,
    column: &str,
    limit: usize,
) -> Result<Vec<(String, i64)>, AuditLogError> {
    let query = format!(
        "SELECT {column}, COUNT(*) AS c
         FROM audit_events
         GROUP BY {column}
         ORDER BY c DESC, {column} ASC
         LIMIT ?1"
    );
    let mut stmt = conn.prepare(&query)?;
    let rows = stmt.query_map([limit as i64], |row| Ok((row.get(0)?, row.get(1)?)))?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
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
