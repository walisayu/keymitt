//! Encrypted, portable backups of the policy and all secret values.
//!
//! Format: an ASCII-armored age file (scrypt passphrase recipient) wrapping a
//! JSON bundle. It can be restored on any platform keymitt supports.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::policy::Policy;
use crate::vault::Vault;

const FORMAT: &str = "keymitt-backup";

#[derive(Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub version: u32,
    pub created: DateTime<Utc>,
    pub policy: Policy,
    pub secrets: BTreeMap<String, Zeroizing<String>>,
}

pub struct Summary {
    pub included: Vec<String>,
    /// In the policy but without a value in the vault.
    pub missing: Vec<String>,
}

/// Collects the policy and every secret value into a bundle.
pub fn collect(policy: &Policy, vault: &dyn Vault) -> Result<(Bundle, Summary)> {
    let mut secrets = BTreeMap::new();
    let mut summary = Summary { included: Vec::new(), missing: Vec::new() };
    for name in policy.secrets.keys() {
        match vault.get(name)? {
            Some(value) => {
                secrets.insert(name.clone(), value);
                summary.included.push(name.clone());
            }
            None => summary.missing.push(name.clone()),
        }
    }
    let bundle = Bundle { format: FORMAT.into(), version: 1, created: Utc::now(), policy: policy.clone(), secrets };
    Ok((bundle, summary))
}

/// Encrypts `bundle` to `out` (which must not exist yet).
pub fn write(bundle: &Bundle, passphrase: SecretString, out: &Path) -> Result<()> {
    let plaintext = Zeroizing::new(serde_json::to_vec(bundle)?);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(out).with_context(|| format!("creating {} (it must not already exist)", out.display()))?;

    let armored = ArmoredWriter::wrap_output(file, Format::AsciiArmor)?;
    let mut writer = age::Encryptor::with_user_passphrase(passphrase).wrap_output(armored)?;
    writer.write_all(&plaintext)?;
    writer.finish()?.finish()?.sync_all()?;
    Ok(())
}

pub fn read(path: &Path, passphrase: SecretString) -> Result<Bundle> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let decryptor = age::Decryptor::new_buffered(ArmoredReader::new(std::io::BufReader::new(file)))
        .context("not a keymitt backup (age file expected)")?;
    if !decryptor.is_scrypt() {
        bail!("not a passphrase-encrypted keymitt backup");
    }
    let identity = age::scrypt::Identity::new(passphrase);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("wrong passphrase or corrupted backup")?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plaintext)?;
    let bundle: Bundle = serde_json::from_slice(&plaintext).context("backup contents are not valid")?;
    if bundle.format != FORMAT || bundle.version != 1 {
        bail!("unsupported backup format {} v{}", bundle.format, bundle.version);
    }
    for name in bundle.secrets.keys().chain(bundle.policy.secrets.keys()) {
        crate::policy::validate_name(name)?;
    }
    Ok(bundle)
}

#[derive(Debug, Default)]
pub struct RestoreReport {
    pub written: Vec<String>,
    pub skipped_existing: Vec<String>,
    pub policy_added: Vec<String>,
    pub policy_kept: Vec<String>,
}

/// Restores values into `vault` and merges policy entries into `policy`.
/// Existing values and policy entries are kept unless `overwrite` is set.
pub fn restore(bundle: &Bundle, vault: &dyn Vault, policy: &mut Policy, overwrite: bool) -> Result<RestoreReport> {
    let mut report = RestoreReport::default();
    for (name, value) in &bundle.secrets {
        if !overwrite && vault.get(name)?.is_some() {
            report.skipped_existing.push(name.clone());
            continue;
        }
        vault.set(name, value)?;
        report.written.push(name.clone());
    }
    for (name, entry) in &bundle.policy.secrets {
        if policy.secrets.contains_key(name) && !overwrite {
            report.policy_kept.push(name.clone());
        } else {
            policy.secrets.insert(name.clone(), entry.clone());
            report.policy_added.push(name.clone());
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SecretPolicy;
    use crate::vault::testing::MemoryVault;

    #[test]
    fn round_trip_and_merge() {
        let mut policy = Policy::default();
        policy.secrets.insert("a".into(), SecretPolicy { description: "A".into(), ..Default::default() });
        policy.secrets.insert("gone".into(), SecretPolicy::default());
        let vault = MemoryVault::with(&[("a", "value-a")]);

        let (bundle, summary) = collect(&policy, &vault).unwrap();
        assert_eq!(summary.included, ["a"]);
        assert_eq!(summary.missing, ["gone"]);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.age");
        write(&bundle, SecretString::from("correct horse battery".to_string()), &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        assert!(!text.contains("value-a"));
        assert!(write(&bundle, SecretString::from("x".to_string()), &path).is_err(), "never overwrites");

        assert!(read(&path, SecretString::from("wrong".to_string())).is_err());
        let restored = read(&path, SecretString::from("correct horse battery".to_string())).unwrap();
        assert_eq!(restored.secrets["a"].as_str(), "value-a");

        let target = MemoryVault::with(&[("a", "newer")]);
        let mut target_policy = Policy::default();
        let report = restore(&restored, &target, &mut target_policy, false).unwrap();
        assert_eq!(report.skipped_existing, ["a"]);
        assert_eq!(target.get("a").unwrap().unwrap().as_str(), "newer");
        assert_eq!(report.policy_added.len(), 2);

        let report = restore(&restored, &target, &mut target_policy, true).unwrap();
        assert_eq!(report.written, ["a"]);
        assert_eq!(target.get("a").unwrap().unwrap().as_str(), "value-a");
    }
}
