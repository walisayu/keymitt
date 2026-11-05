//! polkit (strong) and zenity/kdialog (weak) approval on Linux.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::Outcome;

pub const ACTION_ID: &str = "dev.keymitt.approve";
pub const POLICY_PATH: &str = "/usr/share/polkit-1/actions/dev.keymitt.approve.policy";
pub const POLICY_XML: &str = include_str!("../../packaging/linux/dev.keymitt.approve.policy");

/// Runs a command, killing it after `timeout`. Returns the exit code, or None on timeout.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<Option<i32>, String> {
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(Some(status.code().unwrap_or(-1)));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `pid,start-time,uid` for this process, as pkcheck expects.
fn process_subject() -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|e| e.to_string())?;
    // Fields after the parenthesised command name; start time is field 22 overall.
    let rest = stat.rsplit_once(") ").map(|(_, r)| r).ok_or("unexpected /proc/self/stat")?;
    let start = rest.split_whitespace().nth(19).ok_or("unexpected /proc/self/stat")?;
    let uid = std::fs::metadata("/proc/self").map_err(|e| e.to_string())?.uid();
    Ok(format!("{},{start},{uid}", std::process::id()))
}

/// polkit's own dialog can only show the fixed message from the action file, so
/// the details go into a desktop notification shown just before it (best effort).
fn notify(reason: &str) {
    let has_display = ["DISPLAY", "WAYLAND_DISPLAY"].iter().any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()));
    if !has_display {
        return;
    }
    if let Ok(notify_send) = crate::exec::find_on_path("notify-send") {
        let _ = Command::new(notify_send)
            .args(["--app-name=keymitt", "--urgency=critical", "keymitt: approval requested", &escape_markup(reason)])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

pub(crate) fn polkit(reason: &str, timeout: Duration) -> Outcome {
    if !Path::new(POLICY_PATH).exists() {
        return Outcome::Unavailable("the keymitt polkit action is not installed (see `keymitt setup polkit`)".into());
    }
    let Ok(pkcheck) = crate::exec::find_on_path("pkcheck") else {
        return Outcome::Unavailable("pkcheck not found".into());
    };
    let subject = match process_subject() {
        Ok(s) => s,
        Err(e) => return Outcome::Unavailable(e),
    };
    notify(reason);
    let mut cmd = Command::new(pkcheck);
    cmd.args(["--action-id", ACTION_ID, "--process", &subject, "--allow-user-interaction"]);
    match run_with_timeout(&mut cmd, timeout) {
        Ok(Some(0)) => Outcome::Approved,
        // 1: not authorized, 2: challenge failed, 3: dismissed.
        Ok(Some(code @ 1..=3)) => Outcome::Denied(format!("polkit did not authorize (exit {code})")),
        Ok(Some(code)) => Outcome::Unavailable(format!("pkcheck failed (exit {code}); is a polkit agent running?")),
        Ok(None) => Outcome::Denied("timed out waiting for polkit".into()),
        Err(e) => Outcome::Unavailable(e),
    }
}

fn escape_markup(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub(crate) fn dialog(title: &str, text: &str, timeout: Duration) -> Option<(&'static str, Outcome)> {
    let has_display = ["DISPLAY", "WAYLAND_DISPLAY"].iter().any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()));
    if !has_display {
        return None;
    }
    if let Ok(zenity) = crate::exec::find_on_path("zenity") {
        let mut cmd = Command::new(zenity);
        cmd.args(["--question", "--title", title, "--text", &escape_markup(text)]).args([
            "--ok-label",
            "Allow",
            "--cancel-label",
            "Deny",
        ]);
        return Some((
            "zenity",
            match run_with_timeout(&mut cmd, timeout) {
                Ok(Some(0)) => Outcome::Approved,
                Ok(Some(_)) | Ok(None) => Outcome::Denied("declined or timed out".into()),
                Err(e) => Outcome::Unavailable(e),
            },
        ));
    }
    if let Ok(kdialog) = crate::exec::find_on_path("kdialog") {
        let mut cmd = Command::new(kdialog);
        cmd.args(["--title", title, "--yesno", text]);
        return Some((
            "kdialog",
            match run_with_timeout(&mut cmd, timeout) {
                Ok(Some(0)) => Outcome::Approved,
                Ok(Some(_)) | Ok(None) => Outcome::Denied("declined or timed out".into()),
                Err(e) => Outcome::Unavailable(e),
            },
        ));
    }
    None
}
