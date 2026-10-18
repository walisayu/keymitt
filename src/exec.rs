//! Running a program with secrets injected through stdin, environment
//! variables or temporary files — never through command-line arguments.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::policy::{Channel, Policy};
use crate::redact::Redactor;
use crate::template;

/// Captured output kept per stream (before redaction slack).
pub const OUTPUT_CAP: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct RunSpec {
    pub command: Vec<String>,
    pub stdin: Option<String>,
    pub env: BTreeMap<String, String>,
    pub files: Vec<FileSpec>,
    pub cwd: Option<PathBuf>,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct FileSpec {
    pub id: String,
    pub content: String,
}

/// A validated run: the resolved program and the secrets it will receive.
#[derive(Debug)]
pub struct Plan {
    pub program: PathBuf,
    pub secrets: BTreeSet<String>,
    pub summary: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct RunOutput {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stdout_truncated: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stderr_truncated: bool,
    pub redactions: usize,
}

/// Environment variables an agent may not set: they can make an allowed
/// program load other code, read other config, or send traffic elsewhere.
const ENV_DENYLIST: &[&str] = &[
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_DIRS",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SHELL",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "INPUTRC",
    "PROMPT_COMMAND",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "CDPATH",
    "SSH_ASKPASS",
    "SSH_AUTH_SOCK",
    "SSLKEYLOGFILE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "FTP_PROXY",
    "REQUESTS_CA_BUNDLE",
    "PAGER",
    "MANPAGER",
    "EDITOR",
    "VISUAL",
    "BROWSER",
    "TERMINFO",
    "KUBECONFIG",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "MAVEN_OPTS",
    "GRADLE_OPTS",
    "COMPOSER_HOME",
];

/// Prefixes of variable families that load code, configuration or certificates.
const ENV_DENIED_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "BASH_FUNC_",
    "GIT_",
    "NODE_",
    "NPM_CONFIG_",
    "YARN_",
    "PYTHON",
    "PIP_",
    "PERL",
    "RUBY",
    "GEM_",
    "BUNDLE_",
    "JAVA_",
    "_JAVA_",
    "JDK_",
    "CARGO_",
    "RUSTC",
    "RUSTDOC",
    "RUSTFLAGS",
    "RUSTUP_",
    "GOFLAGS",
    "GOPROXY",
    "GOENV",
    "GOTOOLCHAIN",
    "GOROOT",
    "GOPATH",
    "GOPRIVATE",
    "GONOSUMDB",
    "GOINSECURE",
    "DOTNET_",
    "COMPLUS_",
    "CORECLR_",
    "LESS",
    "GPG",
    "GNUPG",
    "SSL_",
    "OPENSSL_",
    "CURL_",
    "WGET",
];

/// Registry tokens that live inside a denied family but are exactly what keymitt is for.
fn is_token_exception(upper: &str) -> bool {
    upper == "NODE_AUTH_TOKEN"
        || upper == "CARGO_REGISTRY_TOKEN"
        || (upper.starts_with("CARGO_REGISTRIES_") && upper.ends_with("_TOKEN"))
}

/// Any one input (stdin, a file, the arguments together) may be at most this big.
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_FILES: usize = 16;

fn check_env(name: &str, value: &str) -> Result<String> {
    if name.is_empty() || name.len() > 128 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("invalid environment variable name {name:?}");
    }
    let upper = name.to_ascii_uppercase();
    let denied = ENV_DENYLIST.contains(&upper.as_str()) || ENV_DENIED_PREFIXES.iter().any(|p| upper.starts_with(p));
    if denied && !is_token_exception(&upper) {
        bail!("environment variable {name} cannot be set through keymitt (it can redirect or hijack the program)");
    }
    let refs = template::references(value);
    let only = match refs.secrets.iter().next() {
        Some(secret)
            if refs.secrets.len() == 1
                && refs.files.is_empty()
                && value.trim() == format!("{{{{secret:{secret}}}}}") =>
        {
            secret.clone()
        }
        _ => bail!("the value of {name} must be exactly one {{{{secret:NAME}}}} placeholder and nothing else"),
    };
    Ok(only)
}

fn valid_file_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// Finds `name` on keymitt's PATH, ignoring relative and empty entries (which would be
/// resolved against a working directory the agent may control).
pub fn find_on_path(name: &str) -> Result<PathBuf> {
    find_in(std::env::var_os("PATH").unwrap_or_default(), name)
}

fn find_in(path_var: std::ffi::OsString, name: &str) -> Result<PathBuf> {
    let dirs: Vec<PathBuf> = std::env::split_paths(&path_var).filter(|p| p.is_absolute()).collect();
    let joined = std::env::join_paths(dirs)?;
    let found = which::which_in_global(name, Some(joined))
        .ok()
        .and_then(|mut found| found.next())
        .with_context(|| format!("program {name:?} not found on PATH"))?;
    found.canonicalize().with_context(|| format!("resolving {}", found.display()))
}

/// Resolves a program the way keymitt will run it: a bare name via [`find_on_path`],
/// or an existing absolute path. Relative paths are refused.
pub fn resolve_program(name: &str) -> Result<PathBuf> {
    if name.is_empty() {
        bail!("empty program name");
    }
    let path = Path::new(name);
    if path.components().count() > 1 || name.contains(['/', '\\']) {
        if !path.is_absolute() {
            bail!("program {name:?} must be a bare name found on PATH or an absolute path");
        }
        return path.canonicalize().with_context(|| format!("program {name:?} not found"));
    }
    find_on_path(name)
}

pub fn display_command(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,{}".contains(c)) {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Validates a request against the policy without touching any secret.
pub fn plan(spec: &RunSpec, policy: &Policy) -> Result<Plan> {
    let Some(program_name) = spec.command.first() else {
        bail!("command is empty");
    };

    let mut uses: BTreeMap<String, BTreeSet<Channel>> = BTreeMap::new();
    let mut file_refs = BTreeSet::new();

    let argv_bytes: usize = spec.command.iter().map(String::len).sum();
    let too_big = argv_bytes > MAX_INPUT_BYTES
        || spec.stdin.as_ref().is_some_and(|s| s.len() > MAX_INPUT_BYTES)
        || spec.files.iter().any(|f| f.content.len() > MAX_INPUT_BYTES);
    if too_big {
        bail!("arguments, stdin and each file are limited to {MAX_INPUT_BYTES} bytes");
    }
    if spec.files.len() > MAX_FILES {
        bail!("at most {MAX_FILES} temporary files per request");
    }

    for arg in &spec.command {
        let refs = template::references(arg);
        if !refs.secrets.is_empty() {
            bail!(
                "secrets may not appear in command-line arguments (other processes can read them). \
                 Pass them through stdin, env or files instead"
            );
        }
        file_refs.extend(refs.files);
    }

    let mut declared = BTreeSet::new();
    for file in &spec.files {
        if !valid_file_id(&file.id) {
            bail!("invalid file id {:?}: use 1-32 characters from A-Z a-z 0-9 - _", file.id);
        }
        if !declared.insert(file.id.clone()) {
            bail!("file id {:?} is declared twice", file.id);
        }
        let refs = template::references(&file.content);
        if !refs.files.is_empty() {
            bail!("file contents may not reference other files");
        }
        for s in refs.secrets {
            uses.entry(s).or_default().insert(Channel::File);
        }
    }

    if let Some(stdin) = &spec.stdin {
        let refs = template::references(stdin);
        for s in refs.secrets {
            uses.entry(s).or_default().insert(Channel::Stdin);
        }
        file_refs.extend(refs.files);
    }

    let mut env_names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in &spec.env {
        let secret = check_env(name, value)?;
        uses.entry(secret.clone()).or_default().insert(Channel::Env);
        env_names.entry(secret).or_default().push(name.clone());
    }

    if let Some(missing) = file_refs.iter().find(|id| !declared.contains(*id)) {
        bail!("{{{{file:{missing}}}}} is used but not declared in `files`");
    }
    if uses.is_empty() {
        bail!("this request uses no secrets; run it with your normal shell tool instead");
    }

    let program = resolve_program(program_name)?;
    for (name, channels) in &uses {
        let Some(secret) = policy.secret(name) else {
            bail!("unknown secret {name:?}. Ask the user to add it with `keymitt add {name}`");
        };
        for channel in channels {
            if !secret.allows_channel(*channel) {
                bail!("policy does not allow secret {name:?} to be passed via {channel}");
            }
        }
        for var in env_names.get(name).into_iter().flatten() {
            if !secret.allows_env_name(var) {
                bail!("policy does not allow secret {name:?} in environment variable {var}");
            }
        }
        if !secret.allows_command(&program) {
            bail!(
                "policy does not allow secret {name:?} to be given to {}. The user can allow it with \
                 `keymitt allow {name} --command <program>`",
                program.display()
            );
        }
    }

    if let Some(cwd) = &spec.cwd {
        if !cwd.is_dir() {
            bail!("working directory {} does not exist", cwd.display());
        }
    }

    // What the human approves. Everything that decides where a secret goes is shown,
    // most important first: the secrets and the program, then what the program is told.
    let secrets: BTreeSet<String> = uses.keys().cloned().collect();
    let mut summary = format!("use {} → {}", secrets.iter().cloned().collect::<Vec<_>>().join(", "), program.display());
    // On Unix the program also sees the name it was called by (see `run`); say so when the
    // file behind a symlink has another name, as with Debian's psql → pg_wrapper.
    if cfg!(unix) && Path::new(program_name).file_name() != program.file_name() {
        summary.push_str(&format!(" (as {})", display_command(std::slice::from_ref(program_name))));
    }
    let mut parts = Vec::new();
    if spec.command.len() > 1 {
        parts.push(format!("args: {}", display_command(&spec.command[1..])));
    }
    if let Some(stdin) = &spec.stdin {
        parts.push(format!("stdin: {stdin}"));
    }
    if !spec.env.is_empty() {
        let vars: Vec<String> = spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        parts.push(format!("env: {}", vars.join(" ")));
    }
    for file in &spec.files {
        parts.push(format!("file {}: {}", file.id, file.content));
    }
    let cwd =
        spec.cwd.clone().or_else(|| std::env::current_dir().ok()).map(|p| p.display().to_string()).unwrap_or_default();
    parts.push(format!("dir: {cwd}"));
    let detail = parts.join(" | ");
    Ok(Plan { program, secrets, summary, detail })
}

/// Reads at most `cap` bytes, draining the rest so the child never blocks.
pub(crate) async fn read_capped<R: AsyncRead + Unpin>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..n.min(room)]);
                truncated |= n > room;
            }
        }
    }
    (buf, truncated)
}

/// Redacts a captured stream; see [`Redactor::redact_capped`].
pub(crate) fn finish_output(raw: &[u8], over_cap: bool, redactor: &Redactor) -> (String, bool, usize) {
    redactor.redact_capped(raw, over_cap, OUTPUT_CAP)
}

fn write_private_file(path: &Path, content: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).with_context(|| format!("creating {}", path.display()))?;
    std::io::Write::write_all(&mut file, content)?;
    Ok(())
}

/// Overwrites then deletes temp files (best effort).
fn shred(paths: &[PathBuf]) {
    for path in paths {
        if let Ok(meta) = std::fs::metadata(path) {
            let _ = std::fs::write(path, vec![0u8; meta.len() as usize]);
        }
        let _ = std::fs::remove_file(path);
    }
}

pub async fn execute(
    spec: &RunSpec,
    plan: &Plan,
    values: &HashMap<String, Zeroizing<String>>,
    redactor: &Redactor,
) -> Result<RunOutput> {
    let dir = tempfile::Builder::new().prefix("keymitt-").tempdir()?;
    crate::config::restrict_dir(dir.path())?;

    let mut file_paths = HashMap::new();
    let mut written = Vec::new();
    for file in &spec.files {
        let path = dir.path().join(&file.id);
        let content = template::render(&file.content, values, &HashMap::new())?;
        write_private_file(&path, content.as_bytes())?;
        written.push(path.clone());
        file_paths.insert(file.id.clone(), path.display().to_string());
    }

    let no_secrets = HashMap::new();
    let mut args = Vec::new();
    for arg in &spec.command[1..] {
        args.push(template::render(arg, &no_secrets, &file_paths)?);
    }
    let mut env = Vec::new();
    for (name, value) in &spec.env {
        env.push((name.clone(), template::render(value, values, &file_paths)?));
    }
    let stdin = match &spec.stdin {
        Some(text) => Some(template::render(text, values, &file_paths)?),
        None => None,
    };

    let mut cmd = tokio::process::Command::new(&plan.program);
    cmd.args(args.iter().map(|a| a.as_str()))
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }
    // Own process group, so that descendants holding the secret can be stopped too.
    #[cfg(unix)]
    cmd.process_group(0);
    // The verified file runs, but under the name it was called by: multi-call programs
    // (Debian's psql, which is pg_wrapper; busybox; clang++) choose what to do from argv[0].
    #[cfg(unix)]
    if let Some(name) = spec.command.first() {
        cmd.arg0(name);
    }
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().with_context(|| format!("starting {}", plan.program.display()))?;
    let group = child.id();
    drop(args);
    drop(env);

    if let (Some(mut pipe), Some(text)) = (child.stdin.take(), stdin) {
        tokio::spawn(async move {
            let _ = pipe.write_all(text.as_bytes()).await;
            let _ = pipe.shutdown().await;
        });
    }

    let limit = OUTPUT_CAP + redactor.max_len();
    let stdout = tokio::spawn(read_capped(child.stdout.take().expect("piped"), limit));
    let stderr = tokio::spawn(read_capped(child.stderr.take().expect("piped"), limit));

    let (exit_code, timed_out) = match tokio::time::timeout(spec.timeout, child.wait()).await {
        Ok(status) => (status?.code(), false),
        Err(_) => {
            let _ = child.kill().await;
            (None, true)
        }
    };
    // Stop anything the program left running with the secret in its environment.
    #[cfg(unix)]
    if let Some(pgid) = group.and_then(|id| i32::try_from(id).ok()) {
        // SAFETY: plain kill(2) on the process group we created.
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    let _ = group;

    // Grandchildren may hold the pipes open; don't wait on them forever.
    let grace = Duration::from_secs(2);
    let (out, out_over) = tokio::time::timeout(grace, stdout).await.ok().and_then(Result::ok).unwrap_or_default();
    let (err, err_over) = tokio::time::timeout(grace, stderr).await.ok().and_then(Result::ok).unwrap_or_default();

    shred(&written);
    drop(dir);

    let (stdout, stdout_truncated, n1) = finish_output(&out, out_over, redactor);
    let (stderr, stderr_truncated, n2) = finish_output(&err, err_over, redactor);
    Ok(RunOutput { exit_code, timed_out, stdout, stderr, stdout_truncated, stderr_truncated, redactions: n1 + n2 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SecretPolicy;

    fn policy_for(program: &Path, channels: Vec<Channel>) -> Policy {
        let mut p = Policy::default();
        p.secrets.insert(
            "tok".into(),
            SecretPolicy { channels, commands: vec![program.display().to_string()], ..Default::default() },
        );
        p
    }

    fn spec(command: &[&str]) -> RunSpec {
        RunSpec {
            command: command.iter().map(|s| s.to_string()).collect(),
            stdin: None,
            env: BTreeMap::new(),
            files: vec![],
            cwd: None,
            timeout: Duration::from_secs(5),
        }
    }

    fn exe() -> PathBuf {
        std::env::current_exe().unwrap()
    }

    #[test]
    fn rejects_secret_in_argv() {
        let p = policy_for(&exe(), Channel::ALL.to_vec());
        let s = spec(&[exe().to_str().unwrap(), "--token={{secret:tok}}"]);
        assert!(plan(&s, &p).unwrap_err().to_string().contains("command-line arguments"));
    }

    #[test]
    fn requires_a_secret() {
        let p = policy_for(&exe(), Channel::ALL.to_vec());
        let s = spec(&[exe().to_str().unwrap()]);
        assert!(plan(&s, &p).unwrap_err().to_string().contains("uses no secrets"));
    }

    #[test]
    fn enforces_channels_and_commands() {
        let mut s = spec(&[exe().to_str().unwrap()]);
        s.stdin = Some("{{secret:tok}}".into());
        assert!(plan(&s, &policy_for(&exe(), vec![Channel::Stdin])).is_ok());
        assert!(plan(&s, &policy_for(&exe(), vec![Channel::Env])).unwrap_err().to_string().contains("via stdin"));
        let other = policy_for(Path::new("/definitely/not/here"), vec![Channel::Stdin]);
        assert!(plan(&s, &other).unwrap_err().to_string().contains("does not allow"));
        let mut unknown = s.clone();
        unknown.stdin = Some("{{secret:nope}}".into());
        assert!(
            plan(&unknown, &policy_for(&exe(), vec![Channel::Stdin]))
                .unwrap_err()
                .to_string()
                .contains("unknown secret")
        );
    }

    #[test]
    fn env_rules() {
        let p = policy_for(&exe(), Channel::ALL.to_vec());
        let mut s = spec(&[exe().to_str().unwrap()]);
        s.env.insert("API_TOKEN".into(), "{{secret:tok}}".into());
        assert!(plan(&s, &p).is_ok());
        for ok in ["GOOGLE_API_KEY", "NODE_AUTH_TOKEN", "CARGO_REGISTRY_TOKEN", "AWS_SECRET_ACCESS_KEY"] {
            let mut t = spec(&[exe().to_str().unwrap()]);
            t.env.insert(ok.into(), "{{secret:tok}}".into());
            assert!(plan(&t, &p).is_ok(), "{ok} should be allowed");
        }
        for value in ["value", "x{{secret:tok}}", "{{secret:tok}} --evil", "{{secret:tok}}{{secret:tok}}"] {
            s.env.insert("API_TOKEN".into(), value.into());
            assert!(plan(&s, &p).unwrap_err().to_string().contains("exactly one"), "{value}");
        }
        let mut s = spec(&[exe().to_str().unwrap()]);
        for bad in [
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "https_proxy",
            "NODE_OPTIONS",
            "SSLKEYLOGFILE",
            "BASH_FUNC_x%%",
            "GIT_SSH_COMMAND",
            "GIT_PAGER",
            "PYTHONWARNINGS",
            "RUSTC_WRAPPER",
            "CORECLR_PROFILER",
            "LESSOPEN",
            "PAGER",
        ] {
            s.env.clear();
            s.env.insert(bad.into(), "{{secret:tok}}".into());
            assert!(plan(&s, &p).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn env_names_can_be_restricted() {
        let mut p = policy_for(&exe(), Channel::ALL.to_vec());
        p.secrets.get_mut("tok").unwrap().env = vec!["GITHUB_TOKEN".into()];
        let mut s = spec(&[exe().to_str().unwrap()]);
        s.env.insert("GITHUB_TOKEN".into(), "{{secret:tok}}".into());
        assert!(plan(&s, &p).is_ok());
        s.env.clear();
        s.env.insert("OTHER".into(), "{{secret:tok}}".into());
        assert!(plan(&s, &p).unwrap_err().to_string().contains("environment variable OTHER"));
    }

    #[test]
    fn prompt_shows_where_the_secret_goes() {
        let p = policy_for(&exe(), Channel::ALL.to_vec());
        let mut s = spec(&[exe().to_str().unwrap(), "--config", "-"]);
        s.stdin = Some("url = \"https://evil.example\"\nheader = \"X: {{secret:tok}}\"".into());
        let plan = plan(&s, &p).unwrap();
        assert!(plan.summary.starts_with("use tok → "));
        assert!(plan.detail.contains("https://evil.example"), "stdin must be shown: {}", plan.detail);
    }

    #[test]
    fn oversized_inputs_are_refused() {
        let p = policy_for(&exe(), Channel::ALL.to_vec());
        let mut s = spec(&[exe().to_str().unwrap()]);
        s.stdin = Some(format!("{{{{secret:tok}}}}{}", "x".repeat(MAX_INPUT_BYTES)));
        assert!(plan(&s, &p).unwrap_err().to_string().contains("limited"));
    }

    #[test]
    fn relative_path_entries_are_ignored() {
        // The directory lives below the current directory, so it can be named both
        // absolutely and relatively (a temp dir may be on another drive on Windows).
        let cwd = std::env::current_dir().unwrap();
        let dir = tempfile::Builder::new().prefix(".keymitt-test-").tempdir_in(&cwd).unwrap();
        let name = if cfg!(windows) { "planted.exe" } else { "planted" };
        let fake = dir.path().join(name);
        std::fs::write(&fake, "x").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let stem = "planted";
        // Found through an absolute entry...
        assert!(find_in(dir.path().as_os_str().to_owned(), stem).is_ok());
        // ...but never through a relative one, even when it points at the same place.
        let relative = dir.path().strip_prefix(&cwd).unwrap().to_path_buf();
        assert!(relative.is_relative());
        assert!(find_in(relative.into_os_string(), stem).is_err());
        let dotted = Path::new(".").join(dir.path().file_name().unwrap());
        assert!(find_in(dotted.into_os_string(), stem).is_err());
        assert!(find_in(std::ffi::OsString::from(""), stem).is_err());
    }

    #[test]
    fn files_must_be_declared() {
        let p = policy_for(&exe(), Channel::ALL.to_vec());
        let mut s = spec(&[exe().to_str().unwrap(), "--config", "{{file:cfg}}"]);
        s.stdin = Some("{{secret:tok}}".into());
        assert!(plan(&s, &p).unwrap_err().to_string().contains("not declared"));
        s.files.push(FileSpec { id: "cfg".into(), content: "token={{secret:tok}}".into() });
        assert!(plan(&s, &p).is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_programs_keep_the_name_they_were_called_by() {
        // A shell behind a symlink with another name: like busybox, it sees that name as argv[0].
        let shell = Path::new("/bin/sh").canonicalize().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().canonicalize().unwrap().join("renamed-sh");
        std::os::unix::fs::symlink(&shell, &link).unwrap();

        let p = policy_for(&shell, Channel::ALL.to_vec());
        let mut s = spec(&[link.to_str().unwrap(), "-c", "cat >/dev/null; echo \"$0\""]);
        s.stdin = Some("{{secret:tok}}".into());
        let plan = plan(&s, &p).unwrap();
        assert!(plan.summary.ends_with(&format!("(as {})", link.display())), "{}", plan.summary);

        let values = HashMap::from([("tok".to_string(), Zeroizing::new("value-1234".to_string()))]);
        let out = execute(&s, &plan, &values, &Redactor::new([("tok", "value-1234")])).await.unwrap();
        assert_eq!(out.stdout.trim(), link.display().to_string());
    }

    #[test]
    fn relative_program_paths_rejected() {
        assert!(resolve_program("./tool").is_err());
        assert!(resolve_program("bin/tool").is_err());
    }

    #[test]
    fn truncation_happens_after_redaction() {
        let secret = "ABCDEFGHIJKLMNOP";
        let r = Redactor::new([("s", secret)]);
        let mut raw = vec![b'x'; OUTPUT_CAP - 4];
        raw.extend_from_slice(secret.as_bytes());
        let (text, truncated, n) = finish_output(&raw, false, &r);
        assert!(truncated && n == 1);
        assert!(!text.contains("ABCD"), "a secret prefix leaked at the cut");
    }
}
