//! Windows Hello (PIN, fingerprint or face), with a message box as the weak fallback.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, MessageBoxW,
};
use windows_core::{HSTRING, PCWSTR};
use windows_future::{AsyncStatus, IAsyncOperation};

use super::Outcome;

/// Polls a WinRT async operation so it can be abandoned after `timeout`.
fn wait<T: windows_core::RuntimeType + 'static>(
    op: &IAsyncOperation<T>,
    timeout: Duration,
) -> Result<Option<T>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = op.Status().map_err(|e| e.to_string())?;
        if status == AsyncStatus::Completed {
            return op.GetResults().map(Some).map_err(|e| e.to_string());
        }
        if status == AsyncStatus::Canceled {
            return Ok(None);
        }
        if status != AsyncStatus::Started {
            return Err(op.GetResults().err().map(|e| e.to_string()).unwrap_or_else(|| "operation failed".into()));
        }
        if Instant::now() >= deadline {
            let _ = op.Cancel();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(crate) fn hello(reason: &str, timeout: Duration) -> Outcome {
    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .map_err(|e| e.to_string())
        .and_then(|op| wait(&op, Duration::from_secs(10)));
    match availability {
        Ok(Some(a)) if a == UserConsentVerifierAvailability::Available => {}
        Ok(Some(a)) => return Outcome::Unavailable(format!("Windows Hello is not set up (availability {})", a.0)),
        Ok(None) => return Outcome::Unavailable("timed out checking Windows Hello".into()),
        Err(e) => return Outcome::Unavailable(e),
    }

    let message = HSTRING::from(reason);
    // Desktop apps must parent the prompt to a window; use whatever is in front.
    // SAFETY: plain Win32/WinRT calls with valid arguments.
    let op = unsafe {
        let mut hwnd = GetForegroundWindow();
        if hwnd.is_invalid() {
            hwnd = GetConsoleWindow();
        }
        windows_core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>().and_then(|interop| {
            interop.RequestVerificationForWindowAsync::<IAsyncOperation<UserConsentVerificationResult>>(hwnd, &message)
        })
    };
    let op = match op {
        Ok(op) => op,
        Err(_) => match UserConsentVerifier::RequestVerificationAsync(&message) {
            Ok(op) => op,
            Err(e) => return Outcome::Unavailable(e.to_string()),
        },
    };

    match wait(&op, timeout) {
        Ok(Some(r)) if r == UserConsentVerificationResult::Verified => Outcome::Approved,
        Ok(Some(r))
            if r == UserConsentVerificationResult::DeviceNotPresent
                || r == UserConsentVerificationResult::NotConfiguredForUser
                || r == UserConsentVerificationResult::DisabledByPolicy =>
        {
            Outcome::Unavailable(format!("Windows Hello unavailable (result {})", r.0))
        }
        Ok(Some(r)) if r == UserConsentVerificationResult::Canceled => Outcome::Denied("canceled".into()),
        Ok(Some(r)) => Outcome::Denied(format!("Windows Hello did not verify (result {})", r.0)),
        Ok(None) => Outcome::Denied("timed out waiting for Windows Hello".into()),
        Err(e) => Outcome::Unavailable(e),
    }
}

pub(crate) fn message_box(title: &str, text: &str, timeout: Duration) -> Outcome {
    let (tx, rx) = mpsc::channel();
    let (title, text) = (HSTRING::from(title), HSTRING::from(text));
    std::thread::spawn(move || {
        // SAFETY: both strings outlive the call.
        let answer = unsafe {
            MessageBoxW(
                None,
                PCWSTR(text.as_ptr()),
                PCWSTR(title.as_ptr()),
                MB_YESNO | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND | MB_DEFBUTTON2,
            )
        };
        let _ = tx.send(answer == IDYES);
    });
    match rx.recv_timeout(timeout) {
        Ok(true) => Outcome::Approved,
        Ok(false) => Outcome::Denied("declined".into()),
        Err(_) => Outcome::Denied("timed out waiting for the message box".into()),
    }
}
