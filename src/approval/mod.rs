//! Human approval, out of band from the AI agent.
//!
//! "Strong" methods authenticate the person (Touch ID or the login password
//! on macOS, Windows Hello, polkit on Linux). "Weak" methods only ask for a
//! click or a typed confirmation and are used only when strong ones are
//! unavailable and the policy allows it.

pub mod cli;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::Paths;
use crate::policy::{ApprovalMethod, ApprovalSettings};

/// What the human is asked to approve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    /// The secrets involved.
    pub secrets: Vec<String>,
    /// One-line description of what will happen, shown in dialogs.
    pub summary: String,
    /// Full details (command line, working directory, URL...).
    pub detail: String,
}

/// Longest prompt keymitt will show. Longer requests are refused rather than
/// truncated, so nothing the agent sends can hide past the end of the dialog.
pub const MAX_PROMPT_CHARS: usize = 700;

impl Request {
    /// Control characters, bidi overrides and other invisible characters in
    /// either text are made visible, so the agent cannot disguise the request.
    pub fn new(secrets: Vec<String>, summary: String, detail: String) -> Self {
        Self { id: short_id(), secrets, summary: printable(&summary), detail: printable(&detail) }
    }

    /// Text for dialogs: the summary first, then the details.
    pub fn reason(&self) -> String {
        format!("{} | {}", self.summary, self.detail)
    }

    /// Fails if the prompt would be too long to show in full.
    pub fn check_length(&self) -> anyhow::Result<()> {
        let n = self.reason().chars().count();
        if n > MAX_PROMPT_CHARS {
            anyhow::bail!(
                "this request is too long to show in full in the approval prompt ({n} > {MAX_PROMPT_CHARS} characters). \
                 Shorten the arguments, stdin, headers or file contents"
            );
        }
        Ok(())
    }
}

/// Escapes characters that could change how text looks: control characters
/// (including newlines and terminal escapes), bidi overrides and zero-width characters.
pub fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let invisible = c.is_control()
            || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}');
        if invisible {
            match c {
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                _ => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub approved: bool,
    pub method: &'static str,
    pub strong: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// How long the decision took. A human needs at least a second or so;
    /// near-zero values on a prompting method deserve a closer look.
    pub elapsed_ms: u64,
}

impl Decision {
    pub fn approved(method: &'static str, strong: bool) -> Self {
        Self { approved: true, method, strong, note: None, elapsed_ms: 0 }
    }
    pub fn denied(method: &'static str, strong: bool, note: impl Into<String>) -> Self {
        Self { approved: false, method, strong, note: Some(note.into()), elapsed_ms: 0 }
    }
}

/// Result of a single approval mechanism.
pub(crate) enum Outcome {
    Approved,
    /// The person (or the system on their behalf) said no. Never fall back.
    Denied(String),
    /// The mechanism cannot be used here. Falling back is allowed.
    Unavailable(String),
}

pub struct Approver {
    settings: ApprovalSettings,
    paths: Paths,
}

impl Approver {
    pub fn new(settings: ApprovalSettings, paths: Paths) -> Self {
        Self { settings, paths }
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.settings.timeout_secs.max(1))
    }

    /// Blocks until the human decides or the timeout passes.
    /// With `require_strong`, weak methods are never used.
    pub fn request(&self, req: &Request, require_strong: bool) -> Decision {
        let started = std::time::Instant::now();
        let mut decision = self.decide(req, require_strong);
        decision.elapsed_ms = started.elapsed().as_millis() as u64;
        decision
    }

    fn decide(&self, req: &Request, require_strong: bool) -> Decision {
        #[cfg(feature = "testing")]
        if let Ok(answer) = std::env::var("KEYMITT_TEST_APPROVER") {
            return match answer.as_str() {
                "approve" => Decision::approved("test", true),
                _ => Decision::denied("test", true, "denied by KEYMITT_TEST_APPROVER"),
            };
        }

        let allow_weak = self.settings.allow_weak && !require_strong;
        let timeout = self.timeout();

        if self.settings.method == ApprovalMethod::Cli {
            if !allow_weak {
                return Decision::denied(
                    "cli",
                    false,
                    "CLI approval is a weak method and this action requires strong approval",
                );
            }
            return weak_decision("cli", cli::request(&self.paths, req, timeout));
        }

        let unavailable = match strong(req, timeout) {
            (method, Outcome::Approved) => return Decision::approved(method, true),
            (method, Outcome::Denied(why)) => return Decision::denied(method, true, why),
            (_, Outcome::Unavailable(why)) => why,
        };

        if self.settings.method == ApprovalMethod::Native || !allow_weak {
            return Decision::denied("none", false, format!("no strong approval method is available: {unavailable}"));
        }
        tracing::warn!("strong approval unavailable ({unavailable}); falling back to a weak method");
        if let Some((method, outcome)) = weak_dialog(req, timeout) {
            if !matches!(outcome, Outcome::Unavailable(_)) {
                return weak_decision(method, outcome);
            }
        }
        weak_decision("cli", cli::request(&self.paths, req, timeout))
    }

    /// Describes which methods would be used, for `keymitt doctor`.
    pub fn describe(&self) -> String {
        let strong = strong_method_name();
        match self.settings.method {
            ApprovalMethod::Cli => "cli (weak: `keymitt approve <id>` from another terminal)".into(),
            ApprovalMethod::Native => format!("{strong} only"),
            ApprovalMethod::Auto if self.settings.allow_weak => {
                format!("{strong}; if unavailable: {} then cli", weak_dialog_name())
            }
            ApprovalMethod::Auto => format!("{strong} only (allow_weak = false)"),
        }
    }
}

fn weak_decision(method: &'static str, outcome: Outcome) -> Decision {
    match outcome {
        Outcome::Approved => Decision::approved(method, false),
        Outcome::Denied(why) | Outcome::Unavailable(why) => Decision::denied(method, false, why),
    }
}

#[cfg(target_os = "macos")]
fn strong(req: &Request, timeout: Duration) -> (&'static str, Outcome) {
    ("touch-id/password", macos::authenticate(&req.reason(), timeout))
}

#[cfg(windows)]
fn strong(req: &Request, timeout: Duration) -> (&'static str, Outcome) {
    ("windows-hello", windows::hello(&req.reason(), timeout))
}

#[cfg(target_os = "linux")]
fn strong(req: &Request, timeout: Duration) -> (&'static str, Outcome) {
    ("polkit", linux::polkit(&req.reason(), timeout))
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn strong(_req: &Request, _timeout: Duration) -> (&'static str, Outcome) {
    ("none", Outcome::Unavailable("no strong approval method on this platform".into()))
}

fn strong_method_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Touch ID / login password (LocalAuthentication)"
    } else if cfg!(windows) {
        "Windows Hello"
    } else if cfg!(target_os = "linux") {
        "polkit (requires `keymitt setup polkit`)"
    } else {
        "none"
    }
}

#[cfg(windows)]
fn weak_dialog(req: &Request, timeout: Duration) -> Option<(&'static str, Outcome)> {
    Some(("message-box", windows::message_box("keymitt: approve secret use?", &req.reason(), timeout)))
}

#[cfg(target_os = "linux")]
fn weak_dialog(req: &Request, timeout: Duration) -> Option<(&'static str, Outcome)> {
    linux::dialog("keymitt: approve secret use?", &req.reason(), timeout)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn weak_dialog(_req: &Request, _timeout: Duration) -> Option<(&'static str, Outcome)> {
    None
}

fn weak_dialog_name() -> &'static str {
    if cfg!(windows) {
        "a Yes/No message box"
    } else if cfg!(target_os = "linux") {
        "a zenity/kdialog question"
    } else {
        "(no dialog)"
    }
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_escapes_invisible_characters() {
        assert_eq!(printable("a\nb\x1b[2Jc"), "a\\nb\\u{001b}[2Jc");
        assert_eq!(printable("evil\u{202E}gnp.exe"), "evil\\u{202e}gnp.exe");
        assert_eq!(printable("plain text ü"), "plain text ü");
    }

    #[test]
    fn long_requests_are_refused() {
        let r = Request::new(vec!["s".into()], "use s".into(), "x".repeat(MAX_PROMPT_CHARS));
        assert!(r.check_length().is_err());
        let r = Request::new(vec!["s".into()], "use s".into(), "short".into());
        assert!(r.check_length().is_ok());
    }
}
