//! Append-only audit log (JSON Lines). Records what happened, never secret values.

use std::io::Write;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::approval::Decision;
use crate::config::{self, Paths};

const ROTATE_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Event {
    pub ts: DateTime<Utc>,
    pub event: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    /// Command line, URL or path — with placeholders, never values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redactions: Option<usize>,
}

impl Event {
    pub fn new(event: &'static str) -> Self {
        Self {
            ts: Utc::now(),
            event,
            secrets: Vec::new(),
            action: None,
            approval: None,
            outcome: None,
            redactions: None,
        }
    }
}

/// Best effort: failures are logged, never fatal.
pub fn record(paths: &Paths, event: &Event) {
    if let Err(e) = try_record(paths, event) {
        tracing::warn!("could not write audit log: {e:#}");
    }
}

fn try_record(paths: &Paths, event: &Event) -> Result<()> {
    paths.ensure()?;
    let path = paths.audit_file();
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > ROTATE_BYTES) {
        let _ = std::fs::rename(&path, path.with_extension("jsonl.1"));
    }
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    config::restrict_file(&path)?;
    file.write_all(&line)?;
    Ok(())
}

/// The last `n` lines of the log.
pub fn tail(paths: &Paths, n: usize) -> Result<Vec<String>> {
    let text = match std::fs::read_to_string(paths.audit_file()) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    Ok(lines[lines.len().saturating_sub(n)..].to_vec())
}
