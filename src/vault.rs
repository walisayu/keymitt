//! Secret storage: the OS keychain (macOS Keychain, Windows Credential
//! Manager, Linux Secret Service), plus an in-memory store for tests.

use anyhow::{Result, anyhow};
use zeroize::Zeroizing;

pub type SecretValue = Zeroizing<String>;

const SERVICE: &str = "keymitt";

pub trait Vault: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<SecretValue>>;
    fn set(&self, name: &str, value: &str) -> Result<()>;
    /// Returns whether a value existed.
    fn delete(&self, name: &str) -> Result<bool>;
    fn backend(&self) -> &'static str;
}

/// Opens the vault for this platform.
pub fn open() -> Result<Box<dyn Vault>> {
    #[cfg(feature = "testing")]
    if let Some(vault) = testing::from_env()? {
        return Ok(Box::new(vault));
    }
    if let Err(e) = keyring::Entry::store_status() {
        return Err(anyhow!("the OS keychain is not available: {e}"));
    }
    Ok(Box::new(KeyringVault))
}

pub struct KeyringVault;

impl KeyringVault {
    fn entry(name: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, name).map_err(|e| anyhow!("keychain: {e}"))
    }
}

impl Vault for KeyringVault {
    fn get(&self, name: &str) -> Result<Option<SecretValue>> {
        match Self::entry(name)?.get_password() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("keychain: reading {name:?}: {e}")),
        }
    }

    fn set(&self, name: &str, value: &str) -> Result<()> {
        Self::entry(name)?.set_password(value).map_err(|e| match e {
            keyring::Error::TooLong(..) => anyhow!(
                "keychain: {name:?} is too long for this platform's credential store \
                 (Windows Credential Manager holds at most 2560 bytes)"
            ),
            e => anyhow!("keychain: storing {name:?}: {e}"),
        })
    }

    fn delete(&self, name: &str) -> Result<bool> {
        match Self::entry(name)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(anyhow!("keychain: deleting {name:?}: {e}")),
        }
    }

    fn backend(&self) -> &'static str {
        if cfg!(target_os = "macos") {
            "macOS Keychain"
        } else if cfg!(windows) {
            "Windows Credential Manager"
        } else {
            "Secret Service (D-Bus)"
        }
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// In-memory vault. Only compiled into test builds.
    #[derive(Default)]
    pub struct MemoryVault(Mutex<HashMap<String, String>>);

    impl MemoryVault {
        #[cfg(test)]
        pub fn with(values: &[(&str, &str)]) -> Self {
            Self(Mutex::new(values.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()))
        }
    }

    /// `KEYMITT_TEST_VAULT` holds a JSON object of name → value.
    #[cfg(feature = "testing")]
    pub fn from_env() -> Result<Option<MemoryVault>> {
        let Ok(json) = std::env::var("KEYMITT_TEST_VAULT") else {
            return Ok(None);
        };
        let map: HashMap<String, String> = serde_json::from_str(&json)?;
        Ok(Some(MemoryVault(Mutex::new(map))))
    }

    impl Vault for MemoryVault {
        fn get(&self, name: &str) -> Result<Option<SecretValue>> {
            Ok(self.0.lock().unwrap().get(name).cloned().map(Zeroizing::new))
        }
        fn set(&self, name: &str, value: &str) -> Result<()> {
            self.0.lock().unwrap().insert(name.to_string(), value.to_string());
            Ok(())
        }
        fn delete(&self, name: &str) -> Result<bool> {
            Ok(self.0.lock().unwrap().remove(name).is_some())
        }
        fn backend(&self) -> &'static str {
            "in-memory (testing)"
        }
    }
}
