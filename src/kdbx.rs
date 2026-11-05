//! Secret values that live in a KeePass database (.kdbx) instead of the OS keychain.
//!
//! Only entries a person has mapped to a secret (`[secrets.NAME.source]`) can be read, and only
//! by keymitt itself: the master password comes from the keychain, the database is opened for
//! one request and dropped afterwards, and nothing is cached. The file is parsed in-process, so
//! KeePass placeholders such as `{REF:P@T:...}` are never expanded.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use keepass::db::fields;
use keepass::{Database, DatabaseKey};
use regex::Regex;
use zeroize::Zeroizing;

use crate::policy::{Policy, SecretSource};
use crate::vault::{SecretValue, Vault};

/// Why a value could not be read. No variant ever carries a secret value.
#[derive(Debug)]
pub enum KdbxError {
    DatabaseMissing(PathBuf),
    Unreadable(PathBuf, String),
    /// The file's size or modification time changed while it was being read.
    Changing(PathBuf),
    /// Truncated, damaged, or not a KeePass 2 database.
    Corrupt(PathBuf, String),
    WrongMaster(PathBuf),
    MasterMissing(String),
    NotConfigured(String),
    EntryMissing(String),
    EntryAmbiguous(String),
    AttachmentMissing(String, String),
    Empty(String),
    NotText(String),
    Placeholder(String),
}

impl fmt::Display for KdbxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseMissing(p) => write!(f, "the KeePass database {} does not exist", p.display()),
            Self::Unreadable(p, e) => write!(f, "cannot read the KeePass database {}: {e}", p.display()),
            Self::Changing(p) => write!(
                f,
                "the KeePass database {} changed while it was being read (saving or syncing?); try again in a moment",
                p.display()
            ),
            Self::Corrupt(p, why) => write!(
                f,
                "the KeePass database {} is damaged or incomplete ({why}); it may be mid-save or mid-sync, \
                 so try again, and restore it from a backup if it persists",
                p.display()
            ),
            Self::WrongMaster(p) => {
                write!(f, "the master password for {} is wrong or the key has changed", p.display())
            }
            Self::MasterMissing(name) => {
                write!(
                    f,
                    "the master password secret {name:?} has no value; ask the user to run `keymitt update {name}`"
                )
            }
            Self::NotConfigured(alias) => write!(f, "no KeePass database named {alias:?} in the policy"),
            Self::EntryMissing(e) => write!(f, "the KeePass entry {e:?} does not exist"),
            Self::EntryAmbiguous(e) => write!(f, "more than one KeePass entry is called {e:?}; rename the duplicates"),
            Self::AttachmentMissing(e, a) => write!(f, "the KeePass entry {e:?} has no attachment {a:?}"),
            Self::Empty(what) => write!(f, "{what} is empty"),
            Self::NotText(what) => write!(f, "{what} is not valid UTF-8 text"),
            Self::Placeholder(e) => write!(
                f,
                "the password of the KeePass entry {e:?} contains a KeePass placeholder such as {{REF:...}}; \
                 keymitt does not expand placeholders, so replace it with the real value"
            ),
        }
    }
}

impl std::error::Error for KdbxError {}

/// KeePass placeholders keepassxc-cli would expand (and so could read another entry with).
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\{(REF:[^}]*|S:[^}]*|T-CONV:[^}]*|T-REPLACE-RX:[^}]*|C:[^}]*|CMD:[^}]*|NEWPASSWORD[^}]*|",
        r"PASSWORD|PASSWORD_ENC|USERNAME|TITLE|URL|URL:[A-Z]+|NOTES|GROUP|GROUP_PATH|GROUP_NOTES|",
        r"DB_PATH|DB_DIR|DB_NAME|DB_BASENAME|DB_EXT|APPDIR|HMACOTP|TIMEOTP|DT_[A-Z]+|ENV_[A-Z_0-9]+)\}",
    ))
    .expect("valid regex")
});

/// Opens the database for one request.
pub fn open(path: &Path, master: &str) -> Result<Database, KdbxError> {
    let stamp = |p: &Path| -> Result<(u64, Option<std::time::SystemTime>), KdbxError> {
        let m = std::fs::metadata(p).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => KdbxError::DatabaseMissing(p.to_path_buf()),
            _ => KdbxError::Unreadable(p.to_path_buf(), e.to_string()),
        })?;
        Ok((m.len(), m.modified().ok()))
    };
    let before = stamp(path)?;
    let bytes = std::fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => KdbxError::DatabaseMissing(path.to_path_buf()),
        _ => KdbxError::Unreadable(path.to_path_buf(), e.to_string()),
    })?;
    let after = stamp(path)?;
    if before != after || bytes.len() as u64 != after.0 {
        return Err(KdbxError::Changing(path.to_path_buf()));
    }
    Database::parse(&bytes, DatabaseKey::new().with_password(master)).map_err(|e| classify(path, &e))
}

fn classify(path: &Path, e: &keepass::db::DatabaseOpenError) -> KdbxError {
    use keepass::db::DatabaseOpenError as E;
    match e {
        E::Key(keepass::error::DatabaseKeyError::IncorrectKey) => KdbxError::WrongMaster(path.to_path_buf()),
        other => KdbxError::Corrupt(path.to_path_buf(), other.to_string()),
    }
}

/// Reads one mapped entry (or attachment) from an open database.
pub fn lookup(db: &Database, source: &SecretSource) -> Result<SecretValue, KdbxError> {
    let parts: Vec<&str> = source.entry.split('/').collect();
    let (title, groups) = parts.split_last().ok_or_else(|| KdbxError::EntryMissing(source.entry.clone()))?;
    let mut group = db.root();
    for name in groups {
        let ids: Vec<_> = group.groups().filter(|g| g.name == *name).map(|g| g.id()).collect();
        let [id] = ids.as_slice() else {
            return Err(if ids.is_empty() {
                KdbxError::EntryMissing(source.entry.clone())
            } else {
                KdbxError::EntryAmbiguous(source.entry.clone())
            });
        };
        group = db.group(*id).ok_or_else(|| KdbxError::EntryMissing(source.entry.clone()))?;
    }
    let mut matches = group.entries().filter(|e| e.get(fields::TITLE) == Some(*title));
    let entry = matches.next().ok_or_else(|| KdbxError::EntryMissing(source.entry.clone()))?;
    if matches.next().is_some() {
        return Err(KdbxError::EntryAmbiguous(source.entry.clone()));
    }

    match &source.attachment {
        Some(name) => {
            let attachment = entry
                .attachment_by_name(name)
                .ok_or_else(|| KdbxError::AttachmentMissing(source.entry.clone(), name.clone()))?;
            let bytes = Zeroizing::new(attachment.data.get().clone());
            if bytes.is_empty() {
                return Err(KdbxError::Empty(format!("the attachment {name:?} of {:?}", source.entry)));
            }
            let text = String::from_utf8(bytes.to_vec())
                .map_err(|_| KdbxError::NotText(format!("the attachment {name:?} of {:?}", source.entry)))?;
            Ok(Zeroizing::new(text))
        }
        None => {
            let password = entry.get(fields::PASSWORD).unwrap_or_default();
            if password.is_empty() {
                return Err(KdbxError::Empty(format!("the password of {:?}", source.entry)));
            }
            if PLACEHOLDER.is_match(password) {
                return Err(KdbxError::Placeholder(source.entry.clone()));
            }
            Ok(Zeroizing::new(password.to_string()))
        }
    }
}

/// The values of every policy secret, read for one request.
#[derive(Default)]
pub struct Snapshot {
    /// Secrets whose value could be read.
    pub values: HashMap<String, SecretValue>,
    /// Secrets taken from a database whose value could not be read, and why.
    pub failures: HashMap<String, KdbxError>,
}

/// Reads the keychain secrets and, opening each database once, every mapped entry. Mapped entries
/// that are not in use are read too so their values can be redacted; a failure for one of them
/// only matters if the request uses it (see [`Snapshot::failures`]).
pub fn snapshot(policy: &Policy, vault: &dyn Vault) -> anyhow::Result<Snapshot> {
    let mut out = Snapshot::default();
    let mut by_db: HashMap<&str, Vec<(&str, &SecretSource)>> = HashMap::new();
    for (name, secret) in &policy.secrets {
        match &secret.source {
            None => {
                if let Some(v) = vault.get(name)? {
                    out.values.insert(name.clone(), v);
                }
            }
            Some(source) => by_db.entry(source.kdbx.as_str()).or_default().push((name, source)),
        }
    }
    for (alias, wanted) in by_db {
        let fail_all = |out: &mut Snapshot, make: &dyn Fn() -> KdbxError| {
            for (name, _) in &wanted {
                out.failures.insert((*name).to_string(), make());
            }
        };
        let Some(db) = policy.kdbx.get(alias) else {
            fail_all(&mut out, &|| KdbxError::NotConfigured(alias.to_string()));
            continue;
        };
        let Some(master) = vault.get(&db.master)? else {
            fail_all(&mut out, &|| KdbxError::MasterMissing(db.master.clone()));
            continue;
        };
        match open(&db.path, &master) {
            Err(KdbxError::DatabaseMissing(p)) => fail_all(&mut out, &|| KdbxError::DatabaseMissing(p.clone())),
            Err(KdbxError::Changing(p)) => fail_all(&mut out, &|| KdbxError::Changing(p.clone())),
            Err(KdbxError::WrongMaster(p)) => fail_all(&mut out, &|| KdbxError::WrongMaster(p.clone())),
            Err(KdbxError::Unreadable(p, e)) => fail_all(&mut out, &|| KdbxError::Unreadable(p.clone(), e.clone())),
            Err(KdbxError::Corrupt(p, e)) => fail_all(&mut out, &|| KdbxError::Corrupt(p.clone(), e.clone())),
            Err(other) => return Err(other.into()),
            Ok(database) => {
                for (name, source) in wanted {
                    match lookup(&database, source) {
                        Ok(v) => {
                            out.values.insert(name.to_string(), v);
                        }
                        Err(e) => {
                            out.failures.insert(name.to_string(), e);
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use keepass::config::{DatabaseConfig, KdfConfig};

    /// Fast key derivation for tests.
    pub fn config() -> DatabaseConfig {
        let mut config = DatabaseConfig::default();
        config.kdf_config =
            KdfConfig::Argon2 { iterations: 1, memory: 8 * 1024, parallelism: 1, version: argon2::Version::Version13 };
        config
    }

    /// An entry to put in a test database.
    pub struct Item<'a> {
        pub group: &'a [&'a str],
        pub title: &'a str,
        pub password: &'a str,
        pub attachment: Option<(&'a str, &'a [u8])>,
    }

    /// Writes a database with fake entries to `path`.
    pub fn write(path: &Path, master: &str, items: &[Item]) {
        let mut db = Database::with_config(config());
        for item in items {
            let mut gid = db.root().id();
            for name in item.group {
                let existing = db.group(gid).unwrap().groups().find(|g| g.name == *name).map(|g| g.id());
                gid = match existing {
                    Some(id) => id,
                    None => {
                        let mut parent = db.group_mut(gid).unwrap();
                        let mut g = parent.add_group();
                        g.name = (*name).to_string();
                        g.id()
                    }
                };
            }
            let mut parent = db.group_mut(gid).unwrap();
            let mut entry = parent.add_entry();
            entry.set_unprotected(fields::TITLE, item.title);
            entry.set_protected(fields::PASSWORD, item.password);
            if let Some((name, data)) = item.attachment {
                entry.add_attachment(name, keepass::db::Value::protected(data.to_vec()));
            }
        }
        let mut file = std::fs::File::create(path).unwrap();
        db.save(&mut file, DatabaseKey::new().with_password(master)).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Item, write};
    use super::*;

    const MASTER: &str = "fake-master-pass-0001";

    fn src(entry: &str) -> SecretSource {
        SecretSource { kdbx: "main".into(), entry: entry.into(), attachment: None }
    }

    fn fixture(dir: &Path) -> PathBuf {
        let path = dir.join("fake.kdbx");
        write(
            &path,
            MASTER,
            &[
                Item { group: &["Servers", "Test"], title: "pg", password: "fake-pg-pass-7731", attachment: None },
                Item {
                    group: &["Keys"],
                    title: "deploy",
                    password: "",
                    attachment: Some((
                        "private_key.pem",
                        b"-----BEGIN FAKE KEY-----\nabc123fake\n-----END FAKE KEY-----\n",
                    )),
                },
                Item { group: &[], title: "evil", password: "{REF:P@T:pg}", attachment: None },
                Item { group: &[], title: "blank", password: "", attachment: None },
                Item { group: &[], title: "dup", password: "fake-dup-1", attachment: None },
                Item { group: &[], title: "dup", password: "fake-dup-2", attachment: None },
            ],
        );
        path
    }

    #[test]
    fn reads_password_and_attachment() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(&fixture(dir.path()), MASTER).unwrap();
        assert_eq!(lookup(&db, &src("Servers/Test/pg")).unwrap().as_str(), "fake-pg-pass-7731");
        let mut key = src("Keys/deploy");
        key.attachment = Some("private_key.pem".into());
        assert!(lookup(&db, &key).unwrap().contains("abc123fake"));
    }

    #[test]
    fn error_cases_never_carry_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path());
        let db = open(&path, MASTER).unwrap();
        assert!(matches!(lookup(&db, &src("Servers/Test/nope")), Err(KdbxError::EntryMissing(_))));
        assert!(matches!(lookup(&db, &src("Nowhere/pg")), Err(KdbxError::EntryMissing(_))));
        assert!(matches!(lookup(&db, &src("blank")), Err(KdbxError::Empty(_))));
        assert!(matches!(lookup(&db, &src("dup")), Err(KdbxError::EntryAmbiguous(_))));
        let mut missing = src("Keys/deploy");
        missing.attachment = Some("other.pem".into());
        assert!(matches!(lookup(&db, &missing), Err(KdbxError::AttachmentMissing(..))));
        let e = lookup(&db, &src("evil")).unwrap_err();
        assert!(matches!(e, KdbxError::Placeholder(_)));
        let text = e.to_string();
        assert!(text.contains("evil") && !text.contains("P@T"), "{text}");
    }

    #[test]
    fn wrong_master_and_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path());
        assert!(matches!(open(&path, "fake-wrong-master"), Err(KdbxError::WrongMaster(_))), "wrong master");
        assert!(matches!(open(&dir.path().join("none.kdbx"), MASTER), Err(KdbxError::DatabaseMissing(_))));
    }

    #[test]
    fn damaged_or_half_written_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path());
        let bytes = std::fs::read(&path).unwrap();
        for cut in [10, bytes.len() / 2, bytes.len() - 5] {
            std::fs::write(&path, &bytes[..cut]).unwrap();
            assert!(matches!(open(&path, MASTER), Err(KdbxError::Corrupt(..))), "cut at {cut}");
        }
        let mut flipped = bytes.clone();
        let at = bytes.len() - 40;
        flipped[at] ^= 0xff;
        std::fs::write(&path, &flipped).unwrap();
        assert!(open(&path, MASTER).is_err(), "bit flip");
        std::fs::write(&path, b"not a database at all").unwrap();
        assert!(matches!(open(&path, MASTER), Err(KdbxError::Corrupt(..))));
    }

    #[test]
    fn a_changed_file_gives_the_new_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path());
        let first = lookup(&open(&path, MASTER).unwrap(), &src("Servers/Test/pg")).unwrap();
        assert_eq!(first.as_str(), "fake-pg-pass-7731");
        write(
            &path,
            MASTER,
            &[Item { group: &["Servers", "Test"], title: "pg", password: "fake-pg-pass-new2", attachment: None }],
        );
        let second = lookup(&open(&path, MASTER).unwrap(), &src("Servers/Test/pg")).unwrap();
        assert_eq!(second.as_str(), "fake-pg-pass-new2");
    }

    #[test]
    fn placeholder_pattern() {
        for bad in ["{REF:P@T:abc}", "x{PASSWORD}y", "{s:Custom}", "{TITLE}", "{url:host}", "{DT_SIMPLE}"] {
            assert!(PLACEHOLDER.is_match(bad), "{bad}");
        }
        for ok in ["pa{ss}word", "{abc}", "a}{b", "{{secret:x}}", "pw-with-{braces-1}"] {
            assert!(!PLACEHOLDER.is_match(ok), "{ok}");
        }
    }
}
