//! Reading files with credentials masked, for config files an agent needs to inspect.
//!
//! Masking is a convenience, not a confidentiality boundary, so reads are also
//! confined: only below the allowed roots, and never well-known credential stores.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::redact::{Redactor, redact_patterns};

pub const DEFAULT_MAX_BYTES: usize = 256 * 1024;

/// Paths (relative to the home directory) that hold credentials. Refused even inside a root.
const HOME_DENYLIST: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".config/gh",
    ".config/keymitt",
    ".config/op",
    ".cloudflared",
    ".wrangler",
    "Library/Preferences/.wrangler",
    "Library/Keychains",
    ".password-store",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".my.cnf",
    ".vault-token",
    ".terraform.d",
    ".gem/credentials",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".claude",
    "AppData/Roaming/keymitt",
    "AppData/Roaming/Microsoft/Credentials",
    "AppData/Local/Microsoft/Credentials",
];

/// File names that are credentials wherever they are.
const NAME_DENYLIST: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ecdsa_sk",
    "id_ed25519_sk",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".pgpass",
    "credentials.json",
];

/// File extensions of key material.
const EXT_DENYLIST: &[&str] = &["pem", "key", "p12", "pfx", "jks", "keystore", "ppk", "kdbx", "age"];

/// Where `read_file_redacted` may read.
#[derive(Debug, Clone)]
pub struct FileAccess {
    roots: Vec<PathBuf>,
    home: Option<PathBuf>,
}

impl FileAccess {
    /// `workspace` is the MCP server's working directory. It is ignored when it is
    /// the home directory or a filesystem root, which would expose too much.
    pub fn new(workspace: Option<&Path>, extra_roots: &[String]) -> Self {
        let home = dirs::home_dir().and_then(|h| h.canonicalize().ok());
        let mut roots = Vec::new();
        if let Some(ws) = workspace.and_then(|w| w.canonicalize().ok()) {
            let too_broad = ws.parent().is_none() || home.as_deref() == Some(ws.as_path());
            if !too_broad {
                roots.push(ws);
            }
        }
        for root in extra_roots {
            let expanded = match (root.strip_prefix("~/"), &home) {
                (Some(rest), Some(h)) => h.join(rest),
                _ => PathBuf::from(root),
            };
            if let Ok(canonical) = expanded.canonicalize() {
                roots.push(canonical);
            }
        }
        Self { roots, home }
    }

    #[cfg(test)]
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Resolves `path` (symlinks included) and checks it may be read.
    pub fn check(&self, path: &Path) -> Result<PathBuf> {
        let resolved = path.canonicalize().with_context(|| format!("cannot open {}", path.display()))?;
        if !self.roots.iter().any(|root| resolved.starts_with(root)) {
            bail!(
                "{} is outside the directories keymitt may read ({}). The user can add a directory under \
                 [files] read_roots in the policy",
                resolved.display(),
                if self.roots.is_empty() {
                    "none: the server was started in the home directory or a filesystem root".to_string()
                } else {
                    self.roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>().join(", ")
                }
            );
        }
        if let Some(home) = &self.home {
            for denied in HOME_DENYLIST {
                if resolved.starts_with(home.join(denied)) {
                    bail!("{} is a credential location; keymitt never reads it", resolved.display());
                }
            }
        }
        let name = resolved.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_ascii_lowercase();
        let ext = resolved.extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
        if NAME_DENYLIST.contains(&name.as_str()) || EXT_DENYLIST.contains(&ext.as_str()) {
            bail!("{} looks like key or credential material; keymitt never reads it", resolved.display());
        }
        Ok(resolved)
    }
}

#[derive(Debug, Serialize)]
pub struct FileOutput {
    pub path: String,
    pub content: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// Known secret values that were masked.
    pub known_secrets_masked: usize,
    /// Credential-looking values that were masked.
    pub patterns_masked: usize,
}

fn open_regular(path: &Path) -> Result<std::fs::File> {
    // Check the type before opening: opening a FIFO would block forever.
    if !std::fs::metadata(path)?.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let file = options.open(path).with_context(|| format!("opening {}", path.display()))?;
    // The path could have been swapped between the check and the open.
    if !file.metadata()?.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok(file)
}

pub fn read_redacted(path: &Path, max_bytes: usize, redactor: &Redactor, access: &FileAccess) -> Result<FileOutput> {
    let resolved = access.check(path)?;
    let file = open_regular(&resolved)?;
    let limit = max_bytes + redactor.max_len();
    let mut raw = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut raw)?;
    let over = raw.len() > limit;
    raw.truncate(limit);
    if raw.iter().take(8192).any(|&b| b == 0) {
        bail!("{} looks like a binary file", resolved.display());
    }

    let (text, truncated, known) = redactor.redact_capped(&raw, over, max_bytes);
    let (content, patterns) = redact_patterns(&text);
    Ok(FileOutput {
        path: resolved.display().to_string(),
        content,
        truncated,
        known_secrets_masked: known,
        patterns_masked: patterns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access_for(dir: &Path) -> FileAccess {
        FileAccess::new(Some(dir), &[])
    }

    #[test]
    fn masks_known_and_pattern_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.ini");
        std::fs::write(&path, "HOST = db\nPASSWD = hunter2hunter2\nNOTE = uses tok-1234567890\n").unwrap();
        let r = Redactor::new([("tok", "tok-1234567890")]);
        let out = read_redacted(&path, DEFAULT_MAX_BYTES, &r, &access_for(dir.path())).unwrap();
        assert!(out.content.contains("HOST = db"));
        assert!(!out.content.contains("hunter2"));
        assert!(out.content.contains("[REDACTED:tok]"));
        assert_eq!((out.known_secrets_masked, out.patterns_masked), (1, 1));
    }

    #[test]
    fn refuses_binary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin");
        std::fs::write(&path, [0u8, 1, 2, 3]).unwrap();
        let r = Redactor::new(std::iter::empty::<(&str, &str)>());
        assert!(read_redacted(&path, 100, &r, &access_for(dir.path())).is_err());
    }

    #[test]
    fn confined_to_roots() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let inside = root.path().join("ok.txt");
        let secret = outside.path().join("secret.txt");
        std::fs::write(&inside, "fine").unwrap();
        std::fs::write(&secret, "token").unwrap();
        let access = access_for(root.path());
        let r = Redactor::new(std::iter::empty::<(&str, &str)>());
        assert!(read_redacted(&inside, 100, &r, &access).is_ok());
        assert!(read_redacted(&secret, 100, &r, &access).unwrap_err().to_string().contains("outside"));
        // A symlink inside the root that points outside is refused as well.
        #[cfg(unix)]
        {
            let link = root.path().join("link.txt");
            std::os::unix::fs::symlink(&secret, &link).unwrap();
            assert!(read_redacted(&link, 100, &r, &access).unwrap_err().to_string().contains("outside"));
        }
    }

    #[test]
    fn refuses_key_material_and_broad_roots() {
        let root = tempfile::tempdir().unwrap();
        for name in ["id_ed25519", "server.pem", "cert.KEY", ".netrc"] {
            let p = root.path().join(name);
            std::fs::write(&p, "x").unwrap();
            let r = Redactor::new(std::iter::empty::<(&str, &str)>());
            assert!(read_redacted(&p, 100, &r, &access_for(root.path())).is_err(), "{name}");
        }
        if let Some(home) = dirs::home_dir() {
            assert!(FileAccess::new(Some(&home), &[]).roots().is_empty(), "home is too broad to be a root");
        }
        assert!(FileAccess::new(Some(Path::new("/")), &[]).roots().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_does_not_hang() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: mkfifo with a valid, NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let r = Redactor::new(std::iter::empty::<(&str, &str)>());
        let err = read_redacted(&fifo, 100, &r, &access_for(root.path())).unwrap_err();
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn partial_secret_at_max_bytes_never_leaks() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "SECRET-0123456789-abcdefghijklmnopqrstuvwxyz";
        let r = Redactor::new([("s", secret)]);
        let mut content = String::new();
        for _ in 0..4 {
            content.push_str(secret);
            content.push('\n');
        }
        content.push_str(&".".repeat(200));
        content.push_str(secret);
        let path = dir.path().join("big.txt");
        std::fs::write(&path, &content).unwrap();
        // Try every cut position around the trailing secret.
        for max in 150..=400 {
            let out = read_redacted(&path, max, &r, &access_for(dir.path())).unwrap();
            assert!(!out.content.contains(&secret[..8]), "leak at max_bytes={max}: {}", out.content);
        }
    }
}
