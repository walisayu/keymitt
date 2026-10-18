//! The policy file: which secrets exist, and how agents may use them.
//!
//! The policy never contains secret values; those live in the OS keychain.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub approval: ApprovalSettings,
    #[serde(default)]
    pub files: FileSettings,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretPolicy>,
}

fn default_version() -> u32 {
    1
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: default_version(),
            approval: ApprovalSettings::default(),
            files: FileSettings::default(),
            secrets: BTreeMap::new(),
        }
    }
}

/// What `read_file_redacted` may read.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSettings {
    /// Extra directories (absolute, or starting with `~/`) besides the MCP
    /// server's working directory. Well-known credential locations stay refused.
    #[serde(default)]
    pub read_roots: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMethod {
    /// Strongest method available on this platform, falling back to weak
    /// methods only when `allow_weak` is true.
    #[default]
    Auto,
    /// Only the platform's authenticating method (Touch ID / password,
    /// Windows Hello, polkit).
    Native,
    /// Approve from another terminal with `keymitt approve <id>`.
    Cli,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSettings {
    #[serde(default)]
    pub method: ApprovalMethod,
    /// Seconds an approval is remembered for an *identical* request.
    /// 0 asks every time.
    #[serde(default)]
    pub ttl_secs: u64,
    /// Seconds to wait for the human before denying.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Allow non-authenticating confirmations (a plain dialog or the CLI)
    /// when no authenticating method is available.
    #[serde(default = "default_true")]
    pub allow_weak: bool,
}

fn default_timeout() -> u64 {
    120
}

fn default_true() -> bool {
    true
}

impl Default for ApprovalSettings {
    fn default() -> Self {
        Self { method: ApprovalMethod::Auto, ttl_secs: 0, timeout_secs: default_timeout(), allow_weak: true }
    }
}

/// How a secret may be handed to a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// Written to the program's standard input.
    Stdin,
    /// Set as an environment variable of the program.
    Env,
    /// Written to an owner-only temporary file that is deleted afterwards.
    File,
    /// Sent by keymitt itself in an HTTP request to an allowed host.
    Http,
}

impl Channel {
    #[cfg(test)]
    pub const ALL: [Channel; 4] = [Channel::Stdin, Channel::Env, Channel::File, Channel::Http];
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Channel::Stdin => "stdin",
            Channel::Env => "env",
            Channel::File => "file",
            Channel::Http => "http",
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPolicy {
    #[serde(default)]
    pub description: String,
    /// Channels this secret may travel through.
    #[serde(default)]
    pub channels: Vec<Channel>,
    /// Programs that may receive this secret: a bare name (`curl`), an
    /// absolute path (`/usr/bin/curl`) or `*` for any program.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Hosts `http_request` may send this secret to: `api.example.com`,
    /// `*.example.com`, an exact origin such as `http://127.0.0.1:8080`,
    /// or `*` for any HTTPS host.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Environment variable names this secret may be put in (channel `env`).
    /// Empty means any name keymitt does not consider dangerous.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
}

impl SecretPolicy {
    /// Whether the secret may be put in the environment variable `name`.
    pub fn allows_env_name(&self, name: &str) -> bool {
        self.env.is_empty() || self.env.iter().any(|n| n == name)
    }

    /// Bare program names in `commands` (matched by file name on PATH rather than by path).
    pub fn bare_commands(&self) -> impl Iterator<Item = &String> {
        self.commands.iter().filter(|c| c.as_str() != "*" && !Path::new(c.as_str()).is_absolute())
    }

    pub fn allows_channel(&self, channel: Channel) -> bool {
        self.channels.contains(&channel)
    }

    /// Whether `program` (an absolute, resolved path) may receive this secret.
    pub fn allows_command(&self, program: &Path) -> bool {
        self.commands.iter().any(|entry| command_matches(entry, program))
    }

    /// Whether this secret may be sent to `url`.
    pub fn allows_url(&self, url: &url::Url) -> bool {
        self.hosts.iter().any(|entry| host_matches(entry, url))
    }

    pub fn is_usable(&self) -> bool {
        !self.channels.is_empty() && (!self.commands.is_empty() || !self.hosts.is_empty())
    }
}

fn command_matches(entry: &str, program: &Path) -> bool {
    let entry = entry.trim();
    if entry == "*" {
        return true;
    }
    let entry_path = Path::new(entry);
    if entry_path.is_absolute() {
        return match (entry_path.canonicalize(), program.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
    }
    if entry.contains(['/', '\\']) {
        // Relative paths are ambiguous; only bare names and absolute paths count.
        return false;
    }
    if cfg!(windows) {
        let stem = program.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        let name = program.file_name().and_then(|s| s.to_str()).unwrap_or_default();
        stem.eq_ignore_ascii_case(entry) || name.eq_ignore_ascii_case(entry)
    } else {
        program.file_name().and_then(|s| s.to_str()) == Some(entry)
    }
}

fn host_matches(entry: &str, url: &url::Url) -> bool {
    let entry = entry.trim().to_ascii_lowercase();
    let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    if entry.contains("://") {
        // Exact origin: scheme, host and port must all match.
        let Ok(allowed) = url::Url::parse(&entry) else {
            return false;
        };
        return allowed.scheme() == url.scheme()
            && allowed.host_str().map(str::to_ascii_lowercase).as_deref() == Some(host.as_str())
            && allowed.port_or_known_default() == url.port_or_known_default();
    }
    // Bare host patterns only ever allow HTTPS on the default port.
    if url.scheme() != "https" || url.port_or_known_default() != Some(443) {
        return false;
    }
    if entry == "*" {
        return true;
    }
    if let Some(suffix) = entry.strip_prefix("*.") {
        return host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}"));
    }
    host == entry
}

/// Secret names are used as keychain account names and in placeholders.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok {
        bail!(
            "invalid secret name {name:?}: use 1-64 characters from A-Z a-z 0-9 . _ -, starting with a letter or digit"
        );
    }
    Ok(())
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        let policy: Policy = toml::from_str(text)?;
        if policy.version != 1 {
            bail!("unsupported policy version {}", policy.version);
        }
        for name in policy.secrets.keys() {
            validate_name(name)?;
        }
        Ok(policy)
    }

    /// Writes the policy atomically with owner-only permissions.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut text = String::from(
            "# keymitt policy — describes how AI agents may use your secrets.\n\
             # This file never contains secret values. See `keymitt help` and the README.\n\n",
        );
        text.push_str(&toml::to_string_pretty(self)?);
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
        std::io::Write::write_all(&mut tmp, text.as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        config::restrict_file(path)?;
        Ok(())
    }

    pub fn secret(&self, name: &str) -> Option<&SecretPolicy> {
        self.secrets.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn host_patterns() {
        let p = SecretPolicy {
            hosts: vec!["api.example.com".into(), "*.corp.test".into(), "http://127.0.0.1:8080".into()],
            ..Default::default()
        };
        assert!(p.allows_url(&url("https://api.example.com/v1")));
        assert!(p.allows_url(&url("https://API.Example.com/v1")));
        assert!(!p.allows_url(&url("http://api.example.com/v1")), "bare hosts are https-only");
        assert!(!p.allows_url(&url("https://api.example.com:8443/")), "bare hosts use port 443 only");
        assert!(!p.allows_url(&url("https://evil.com/?api.example.com")));
        assert!(!p.allows_url(&url("https://api.example.com.evil.com/")));
        assert!(p.allows_url(&url("https://a.corp.test/")));
        assert!(!p.allows_url(&url("https://corp.test/")), "wildcards match subdomains only");
        assert!(!p.allows_url(&url("https://xcorp.test/")));
        assert!(p.allows_url(&url("http://127.0.0.1:8080/x")));
        assert!(!p.allows_url(&url("http://127.0.0.1:8081/x")));
    }

    #[test]
    fn command_patterns() {
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_str().unwrap().to_string();
        let p = SecretPolicy { commands: vec![name], ..Default::default() };
        assert!(p.allows_command(&exe));
        let p = SecretPolicy { commands: vec![exe.display().to_string()], ..Default::default() };
        assert!(p.allows_command(&exe));
        let p = SecretPolicy { commands: vec!["definitely-not-this".into()], ..Default::default() };
        assert!(!p.allows_command(&exe));
        let p = SecretPolicy { commands: vec!["./relative".into()], ..Default::default() };
        assert!(!p.allows_command(Path::new("./relative")));
    }

    #[test]
    fn names() {
        assert!(validate_name("cloudflare-zt").is_ok());
        assert!(validate_name("db.prod_1").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("-x").is_err());
        assert!(validate_name("a b").is_err());
        assert!(validate_name("a}}").is_err());
    }

    #[test]
    fn parse_round_trip() {
        let text = r#"
            [approval]
            ttl_secs = 30

            [secrets.demo]
            description = "Demo token"
            channels = ["stdin", "http"]
            commands = ["curl"]
            hosts = ["api.example.com"]
        "#;
        let p = Policy::parse(text).unwrap();
        assert_eq!(p.approval.ttl_secs, 30);
        assert_eq!(p.approval.timeout_secs, 120);
        let s = p.secret("demo").unwrap();
        assert!(s.allows_channel(Channel::Stdin) && !s.allows_channel(Channel::Env));
        let again = Policy::parse(&toml::to_string_pretty(&p).unwrap()).unwrap();
        assert_eq!(again.secrets.len(), 1);
        assert!(Policy::parse("[secrets.demo]\nbogus = 1\n").is_err(), "typos are rejected");
    }

    #[test]
    fn default_policy_saves_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        assert!(Policy::load(&path).unwrap().secrets.is_empty(), "a missing file is an empty policy");
        let mut p = Policy::default();
        p.secrets.insert("x".into(), SecretPolicy::default());
        p.save(&path).unwrap();
        let loaded = Policy::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert!(loaded.secrets.contains_key("x"));
    }
}
