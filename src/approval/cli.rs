//! Approval from another terminal (`keymitt approve <id>`).
//!
//! This is a *weak* method: any process running as you could write the
//! decision file. It exists for headless machines and is only used when the
//! policy allows weak approval.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{Outcome, Request};
use crate::config::{self, Paths};

#[derive(Debug, Serialize, Deserialize)]
pub struct Pending {
    #[serde(flatten)]
    pub request: Request,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
}

fn request_path(paths: &Paths, id: &str) -> PathBuf {
    paths.pending_dir().join(format!("{id}.json"))
}

fn decision_path(paths: &Paths, id: &str) -> PathBuf {
    paths.pending_dir().join(format!("{id}.decision"))
}

/// Creates a new file without following an existing path (or a planted symlink).
fn write_new(path: &std::path::Path, content: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).with_context(|| format!("creating {}", path.display()))?;
    std::io::Write::write_all(&mut file, content)?;
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.chars().all(|c| c.is_ascii_alphanumeric())
}

pub(crate) fn request(paths: &Paths, req: &Request, timeout: Duration) -> Outcome {
    match wait_for_decision(paths, req, timeout) {
        Ok(outcome) => outcome,
        Err(e) => Outcome::Unavailable(format!("{e:#}")),
    }
}

fn wait_for_decision(paths: &Paths, req: &Request, timeout: Duration) -> Result<Outcome> {
    let dir = paths.pending_dir();
    std::fs::create_dir_all(&dir)?;
    config::restrict_dir(&dir)?;
    let now = Utc::now();
    let pending = Pending {
        request: req.clone(),
        created: now,
        expires: now + chrono::Duration::from_std(timeout).unwrap_or(chrono::Duration::seconds(120)),
    };
    let req_file = request_path(paths, &req.id);
    write_new(&req_file, &serde_json::to_vec_pretty(&pending)?)?;
    eprintln!(
        "keymitt: approval needed for request {id}: {summary}\n  approve from a terminal: keymitt approve {id}   (or: keymitt deny {id})",
        id = req.id,
        summary = req.summary
    );

    let decision_file = decision_path(paths, &req.id);
    let deadline = std::time::Instant::now() + timeout;
    let outcome = loop {
        if let Ok(text) = std::fs::read_to_string(&decision_file) {
            break if text.trim() == "approve" {
                Outcome::Approved
            } else {
                Outcome::Denied("denied with `keymitt deny`".into())
            };
        }
        if std::time::Instant::now() >= deadline {
            break Outcome::Denied("timed out waiting for `keymitt approve`".into());
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    let _ = std::fs::remove_file(&req_file);
    let _ = std::fs::remove_file(&decision_file);
    Ok(outcome)
}

/// Pending requests that have not expired.
pub fn list(paths: &Paths) -> Result<Vec<Pending>> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(paths.pending_dir()) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Ok(pending) = serde_json::from_str::<Pending>(&text) else { continue };
        if pending.expires > Utc::now() {
            out.push(pending);
        }
    }
    out.sort_by_key(|p| p.created);
    Ok(out)
}

pub fn load(paths: &Paths, id: &str) -> Result<Pending> {
    if !valid_id(id) {
        bail!("invalid request id {id:?}");
    }
    let text = std::fs::read_to_string(request_path(paths, id)).with_context(|| format!("no pending request {id}"))?;
    let pending: Pending = serde_json::from_str(&text)?;
    if pending.expires <= Utc::now() {
        bail!("request {id} has expired");
    }
    Ok(pending)
}

pub fn decide(paths: &Paths, id: &str, approve: bool) -> Result<()> {
    load(paths, id)?;
    write_new(&decision_path(paths, id), if approve { b"approve" } else { b"deny" })
}
