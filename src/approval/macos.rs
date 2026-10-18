//! Touch ID, Apple Watch or the login password via LocalAuthentication.

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use super::Outcome;

// LAError codes that mean "cannot ask here" rather than "the person said no".
const LA_ERROR_PASSCODE_NOT_SET: isize = -5;
const LA_ERROR_NOT_INTERACTIVE: isize = -1004;

pub(crate) fn authenticate(reason: &str, timeout: Duration) -> Outcome {
    // SAFETY: plain Objective-C object creation and method calls on a
    // context owned by this function.
    let context = unsafe { LAContext::new() };
    let policy = LAPolicy::DeviceOwnerAuthentication;
    if let Err(err) = unsafe { context.canEvaluatePolicy_error(policy) } {
        return Outcome::Unavailable(err.localizedDescription().to_string());
    }

    let (tx, rx) = mpsc::channel::<Result<(), (isize, String)>>();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let result = if ok.as_bool() {
            Ok(())
        } else {
            // SAFETY: LocalAuthentication passes either null or a valid NSError.
            match unsafe { error.as_ref() } {
                Some(err) => Err((err.code(), err.localizedDescription().to_string())),
                None => Err((0, "authentication failed".to_string())),
            }
        };
        let _ = tx.send(result);
    });

    let reason = NSString::from_str(reason);
    // SAFETY: the reply block only captures a `Sender`, which is `Send`.
    unsafe { context.evaluatePolicy_localizedReason_reply(policy, &reason, &reply) };

    match rx.recv_timeout(timeout) {
        Ok(Ok(())) => Outcome::Approved,
        Ok(Err((code, message))) if code == LA_ERROR_NOT_INTERACTIVE || code == LA_ERROR_PASSCODE_NOT_SET => {
            Outcome::Unavailable(message)
        }
        Ok(Err((_, message))) => Outcome::Denied(message),
        Err(_) => {
            // SAFETY: dismisses the pending prompt.
            unsafe { context.invalidate() };
            Outcome::Denied("timed out waiting for authentication".to_string())
        }
    }
}
