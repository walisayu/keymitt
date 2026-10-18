//! Where keymitt keeps its (non-secret) files.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

/// Locations of keymitt's files. None of these files contain secret values.
#[derive(Debug, Clone)]
pub struct Paths {
    home: PathBuf,
}

impl Paths {
    /// Resolves the keymitt home directory.
    ///
    /// Order: `$KEYMITT_HOME`, then `%APPDATA%\keymitt` on Windows, or
    /// `$XDG_CONFIG_HOME/keymitt` (falling back to `~/.config/keymitt`) elsewhere.
    pub fn resolve() -> Result<Self> {
        if let Some(home) = std::env::var_os("KEYMITT_HOME").filter(|v| !v.is_empty()) {
            return Ok(Self::at(PathBuf::from(home)));
        }
        let base = if cfg!(windows) {
            dirs::config_dir().ok_or_else(|| anyhow!("cannot locate %APPDATA%"))?
        } else {
            match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
                Some(xdg) => PathBuf::from(xdg),
                None => dirs::home_dir().ok_or_else(|| anyhow!("cannot locate the home directory"))?.join(".config"),
            }
        };
        Ok(Self::at(base.join("keymitt")))
    }

    pub fn at(home: PathBuf) -> Self {
        Self { home }
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn policy_file(&self) -> PathBuf {
        self.home.join("policy.toml")
    }

    pub fn audit_file(&self) -> PathBuf {
        self.home.join("audit.jsonl")
    }

    pub fn pending_dir(&self) -> PathBuf {
        self.home.join("pending")
    }

    /// Creates the home directory (owner-only on Unix).
    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.home).with_context(|| format!("creating {}", self.home.display()))?;
        restrict_dir(&self.home)?;
        Ok(())
    }
}

/// Makes a directory accessible to the current user only (no-op on Windows,
/// where per-user profile directories are already private).
pub fn restrict_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Makes a file readable and writable by the current user only (no-op on Windows).
pub fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
