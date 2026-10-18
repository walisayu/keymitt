//! The command-line interface used by humans.

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use crate::approval::{self, Approver, Request};
use crate::audit::{self, Event};
use crate::backup;
use crate::config::Paths;
use crate::policy::{Channel, Policy, SecretPolicy, validate_name};
use crate::vault;

#[derive(Parser)]
#[command(
    name = "keymitt",
    version,
    about = "Let AI agents use your secrets without ever seeing them.",
    long_about = "keymitt stores secrets in your OS keychain and lets AI agents use them through an MCP server. \
Agents refer to secrets as {{secret:NAME}}; keymitt injects the value, asks you to approve each use on your \
device, and redacts the value from everything the agent sees.\n\n\
Files live in $KEYMITT_HOME (default: ~/.config/keymitt, or %APPDATA%\\keymitt on Windows)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Store a new secret (the value is read without echo).
    Add {
        name: String,
        #[command(flatten)]
        rules: Rules,
        #[arg(long, short)]
        description: Option<String>,
        #[command(flatten)]
        source: ValueSource,
    },
    /// Replace the value of an existing secret.
    Update {
        name: String,
        #[command(flatten)]
        source: ValueSource,
    },
    /// Delete a secret and its policy entry.
    Rm {
        name: String,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// List secrets and how they may be used.
    List,
    /// Allow more uses of a secret.
    Allow {
        name: String,
        #[command(flatten)]
        rules: Rules,
    },
    /// Remove allowed uses of a secret.
    Disallow {
        name: String,
        #[command(flatten)]
        rules: Rules,
    },
    /// Run the MCP server on stdio (configure this in your AI client).
    Mcp,
    /// Show the most recent audit log entries.
    Audit {
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
    },
    /// List requests waiting for `keymitt approve`.
    Pending,
    /// Approve a pending request (CLI approval method).
    Approve { id: String },
    /// Deny a pending request (CLI approval method).
    Deny { id: String },
    /// Write an encrypted backup of the policy and all secret values.
    Backup {
        /// Output file (must not exist), e.g. keymitt-backup.age
        file: PathBuf,
    },
    /// Restore secrets and policy entries from a backup.
    Restore {
        file: PathBuf,
        /// Replace existing values and policy entries with the backup's.
        #[arg(long)]
        overwrite: bool,
    },
    /// Check the installation: paths, policy, keychain, approval methods.
    Doctor {
        /// Also trigger a test approval prompt.
        #[arg(long)]
        approval: bool,
    },
    /// Print setup instructions for an integration.
    Setup {
        #[arg(value_enum)]
        target: SetupTarget,
    },
    /// Show where keymitt keeps its files.
    Paths,
    #[cfg(feature = "testing")]
    #[command(hide = true, name = "__echo")]
    Echo { args: Vec<String> },
}

/// Where a secret value comes from. Without a flag, keymitt prompts without echo.
#[derive(Args, Default, Clone, Copy)]
struct ValueSource {
    /// Read the value from standard input instead of prompting.
    #[arg(long, conflicts_with = "from_clipboard")]
    from_stdin: bool,
    /// Read the value from the system clipboard (surrounding whitespace is removed).
    /// The clipboard is cleared afterwards if it still holds the value.
    #[arg(long)]
    from_clipboard: bool,
    /// With --from-clipboard: leave the clipboard as it is.
    #[arg(long, requires = "from_clipboard")]
    keep_clipboard: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum SetupTarget {
    /// Register keymitt with Claude Code.
    Claude,
    /// Install the polkit action used for approval on Linux.
    Polkit,
}

#[derive(Args, Default)]
struct Rules {
    /// Channel the secret may use: stdin, env, file, http (repeatable).
    #[arg(long = "channel", value_parser = parse_channel)]
    channels: Vec<Channel>,
    /// Program that may receive the secret (repeatable). A bare name such as `curl` is
    /// resolved now and stored as its full path; `*` allows any program.
    #[arg(long = "command")]
    commands: Vec<String>,
    /// Environment variable name the secret may be put in, e.g. GITHUB_TOKEN (repeatable).
    /// Without any, every name keymitt considers safe is allowed.
    #[arg(long = "env")]
    env: Vec<String>,
    /// Host http_request may send the secret to, e.g. api.github.com, *.example.com,
    /// http://127.0.0.1:8080 (repeatable).
    #[arg(long = "host")]
    hosts: Vec<String>,
}

fn parse_channel(s: &str) -> Result<Channel, String> {
    match s.to_ascii_lowercase().as_str() {
        "stdin" => Ok(Channel::Stdin),
        "env" => Ok(Channel::Env),
        "file" => Ok(Channel::File),
        "http" => Ok(Channel::Http),
        _ => Err(format!("unknown channel {s:?} (expected stdin, env, file or http)")),
    }
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("keymitt: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let paths = Paths::resolve()?;
    match cli.command {
        Command::Add { name, rules, description, source } => add(&paths, &name, rules, description, source)?,
        Command::Update { name, source } => update(&paths, &name, source)?,
        Command::Rm { name, yes } => remove(&paths, &name, yes)?,
        Command::List => list(&paths)?,
        Command::Allow { name, rules } => edit_rules(&paths, &name, rules, true)?,
        Command::Disallow { name, rules } => edit_rules(&paths, &name, rules, false)?,
        Command::Mcp => mcp(paths)?,
        Command::Audit { lines } => {
            for line in audit::tail(&paths, lines)? {
                println!("{line}");
            }
        }
        Command::Pending => pending(&paths)?,
        Command::Approve { id } => decide(&paths, &id, true)?,
        Command::Deny { id } => decide(&paths, &id, false)?,
        Command::Backup { file } => backup_cmd(&paths, &file)?,
        Command::Restore { file, overwrite } => restore_cmd(&paths, &file, overwrite)?,
        Command::Doctor { approval } => return doctor(&paths, approval),
        Command::Setup { target } => setup(target)?,
        Command::Paths => {
            println!("home:   {}", paths.home().display());
            println!("policy: {}", paths.policy_file().display());
            println!("audit:  {}", paths.audit_file().display());
        }
        #[cfg(feature = "testing")]
        Command::Echo { args } => echo(&args)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn mcp(paths: Paths) -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("KEYMITT_LOG").unwrap_or_else(|_| "warn".into()))
        .init();
    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(crate::server::serve(paths))
}

/// Reads the clipboard's text, without surrounding whitespace.
fn read_clipboard() -> Result<Zeroizing<String>> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| anyhow::anyhow!("cannot open the clipboard: {e}"))?;
    let text = Zeroizing::new(clipboard.get_text().map_err(|e| anyhow::anyhow!("the clipboard holds no text ({e})"))?);
    let value = Zeroizing::new(text.trim().to_string());
    if value.is_empty() {
        bail!("the clipboard is empty; copy the secret first");
    }
    Ok(value)
}

/// Clears the clipboard if it still holds `value` (best effort: clipboard
/// managers may already have kept a copy).
fn clear_clipboard_if(value: &str) {
    let Ok(mut clipboard) = arboard::Clipboard::new() else { return };
    let still_there = clipboard.get_text().map(|t| Zeroizing::new(t).trim() == value).unwrap_or(false);
    if still_there && clipboard.clear().is_ok() {
        println!("Cleared the clipboard.");
    }
}

fn read_value(prompt: &str, source: ValueSource) -> Result<Zeroizing<String>> {
    let value = if source.from_clipboard {
        let value = read_clipboard()?;
        println!("Read {} characters from the clipboard.", value.chars().count());
        value
    } else if source.from_stdin {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut buf)?;
        let trimmed = buf.trim_end_matches(['\r', '\n']);
        Zeroizing::new(trimmed.to_string())
    } else {
        if !std::io::stdin().is_terminal() {
            bail!(
                "standard input is not a terminal; pass --from-stdin to read the value from a pipe, \
                 or --from-clipboard to read it from the clipboard"
            );
        }
        let first = Zeroizing::new(rpassword::prompt_password(prompt)?);
        let second = Zeroizing::new(rpassword::prompt_password("Repeat the value: ")?);
        if *first != *second {
            bail!("the values did not match");
        }
        first
    };
    if value.is_empty() {
        bail!("empty value");
    }
    if value.len() < 8 {
        eprintln!("warning: short values (< 8 characters) can cause unrelated output to be redacted");
    }
    Ok(value)
}

fn load_policy(paths: &Paths) -> Result<Policy> {
    Policy::load(&paths.policy_file())
}

fn save_policy(paths: &Paths, policy: &Policy) -> Result<()> {
    paths.ensure()?;
    policy.save(&paths.policy_file())
}

/// Bare program names are resolved to full paths now, while a person is at the keyboard,
/// so the policy names exactly one program instead of whatever shares its name on PATH.
fn resolve_commands(commands: Vec<String>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for command in commands {
        if command == "*" {
            eprintln!("warning: `*` lets the secret go to any program; prefer specific programs");
            out.push(command);
            continue;
        }
        let resolved = crate::exec::resolve_program(&command)
            .with_context(|| format!("cannot find {command:?}; give its full path"))?;
        let resolved = resolved.display().to_string();
        if resolved != command {
            println!("  {command} → {resolved}");
        }
        out.push(resolved);
    }
    Ok(out)
}

fn add(paths: &Paths, name: &str, rules: Rules, description: Option<String>, source: ValueSource) -> Result<()> {
    validate_name(name)?;
    let mut policy = load_policy(paths)?;
    if policy.secrets.contains_key(name) {
        bail!("secret {name:?} already exists; use `keymitt update {name}` to change its value");
    }
    let commands = resolve_commands(rules.commands)?;
    let vault = vault::open()?;
    let value = read_value(&format!("Value for {name}: "), source)?;
    vault.set(name, &value)?;

    let mut channels = rules.channels;
    if channels.is_empty() {
        // Sensible defaults: whatever the given rules can actually use.
        if !commands.is_empty() {
            channels.extend([Channel::Stdin, Channel::Env, Channel::File]);
        }
        if !rules.hosts.is_empty() {
            channels.push(Channel::Http);
        }
    }
    let entry = SecretPolicy {
        description: description.unwrap_or_default(),
        channels,
        commands,
        hosts: rules.hosts,
        env: rules.env,
    };
    let usable = entry.is_usable();
    policy.secrets.insert(name.to_string(), entry);
    save_policy(paths, &policy)?;

    let mut event = Event::new("add");
    event.secrets = vec![name.to_string()];
    audit::record(paths, &event);
    println!("Stored {name} in the {}.", vault.backend());
    if source.from_clipboard && !source.keep_clipboard {
        clear_clipboard_if(&value);
    }
    if !usable {
        println!(
            "Note: agents can't use it yet. Allow a program or host, e.g.\n  keymitt allow {name} --command curl\n  keymitt allow {name} --host api.example.com"
        );
    }
    println!("Restart your AI client's keymitt server to pick up policy changes.");
    Ok(())
}

fn update(paths: &Paths, name: &str, source: ValueSource) -> Result<()> {
    let policy = load_policy(paths)?;
    if !policy.secrets.contains_key(name) {
        bail!("no secret named {name:?}; use `keymitt add {name}`");
    }
    let vault = vault::open()?;
    let value = read_value(&format!("New value for {name}: "), source)?;
    vault.set(name, &value)?;
    let mut event = Event::new("update");
    event.secrets = vec![name.to_string()];
    audit::record(paths, &event);
    println!("Updated {name}.");
    if source.from_clipboard && !source.keep_clipboard {
        clear_clipboard_if(&value);
    }
    Ok(())
}

fn remove(paths: &Paths, name: &str, yes: bool) -> Result<()> {
    let mut policy = load_policy(paths)?;
    let vault = vault::open()?;
    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!("refusing to delete without confirmation; pass --yes");
        }
        print!("Delete secret {name} from the keychain and the policy? Type its name to confirm: ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim() != name {
            bail!("not confirmed");
        }
    }
    let had_value = vault.delete(name)?;
    let had_entry = policy.secrets.remove(name).is_some();
    if !had_value && !had_entry {
        bail!("no secret named {name:?}");
    }
    save_policy(paths, &policy)?;
    let mut event = Event::new("remove");
    event.secrets = vec![name.to_string()];
    audit::record(paths, &event);
    println!("Deleted {name}.");
    Ok(())
}

fn list(paths: &Paths) -> Result<()> {
    let policy = load_policy(paths)?;
    if policy.secrets.is_empty() {
        println!("No secrets yet. Add one with `keymitt add <name> --command <program>`.");
        return Ok(());
    }
    let vault = vault::open()?;
    for (name, s) in &policy.secrets {
        let stored = match vault.get(name) {
            Ok(Some(_)) => "stored",
            Ok(None) => "MISSING VALUE",
            Err(_) => "keychain error",
        };
        println!(
            "{name}  [{stored}]{}",
            if s.description.is_empty() { String::new() } else { format!("  {}", s.description) }
        );
        let channels: Vec<String> = s.channels.iter().map(ToString::to_string).collect();
        println!("    channels: {}", if channels.is_empty() { "-".into() } else { channels.join(", ") });
        println!("    commands: {}", if s.commands.is_empty() { "-".into() } else { s.commands.join(", ") });
        println!("    hosts:    {}", if s.hosts.is_empty() { "-".into() } else { s.hosts.join(", ") });
        if !s.env.is_empty() {
            println!("    env:      {}", s.env.join(", "));
        }
    }
    Ok(())
}

fn edit_rules(paths: &Paths, name: &str, rules: Rules, allow: bool) -> Result<()> {
    let mut policy = load_policy(paths)?;
    let Some(entry) = policy.secrets.get_mut(name) else {
        bail!("no secret named {name:?}");
    };
    if rules.channels.is_empty() && rules.commands.is_empty() && rules.hosts.is_empty() && rules.env.is_empty() {
        bail!("nothing to change: pass --channel, --command, --host or --env");
    }
    // Compare commands by their resolved form too, so `disallow --command curl` removes /usr/bin/curl.
    let resolved: Vec<String> = rules
        .commands
        .iter()
        .map(|c| crate::exec::resolve_program(c).map(|p| p.display().to_string()).unwrap_or_else(|_| c.clone()))
        .collect();
    if allow {
        let commands = resolve_commands(rules.commands.clone())?;
        for c in rules.channels {
            if !entry.channels.contains(&c) {
                entry.channels.push(c);
            }
        }
        for c in commands {
            if !entry.commands.contains(&c) {
                entry.commands.push(c);
            }
        }
        for e in rules.env {
            if !entry.env.contains(&e) {
                entry.env.push(e);
            }
        }
        for h in rules.hosts {
            if !entry.hosts.contains(&h) {
                entry.hosts.push(h);
            }
        }
        // A newly allowed host is useless without the http channel, and vice versa.
        if !entry.hosts.is_empty() && !entry.channels.contains(&Channel::Http) {
            entry.channels.push(Channel::Http);
        }
    } else {
        entry.channels.retain(|c| !rules.channels.contains(c));
        entry.commands.retain(|c| !rules.commands.contains(c) && !resolved.contains(c));
        entry.env.retain(|e| !rules.env.contains(e));
        entry.hosts.retain(|h| !rules.hosts.contains(h));
    }
    entry.channels.sort();
    save_policy(paths, &policy)?;
    println!("Updated the policy for {name}. Restart your AI client's keymitt server to apply it.");
    Ok(())
}

fn pending(paths: &Paths) -> Result<()> {
    let list = approval::cli::list(paths)?;
    if list.is_empty() {
        println!("No pending requests.");
    }
    for p in list {
        println!(
            "{}  {}\n    {}\n    expires {}",
            approval::printable(&p.request.id),
            approval::printable(&p.request.summary),
            approval::printable(&p.request.detail),
            p.expires.to_rfc3339()
        );
    }
    Ok(())
}

fn require_terminal() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("this command must be run by a person in an interactive terminal");
    }
    Ok(())
}

fn decide(paths: &Paths, id: &str, approve: bool) -> Result<()> {
    require_terminal()?;
    let pending = approval::cli::load(paths, id)?;
    println!(
        "Request {id}: {}\n  {}",
        approval::printable(&pending.request.summary),
        approval::printable(&pending.request.detail)
    );
    if approve {
        print!("Type 'yes' to approve: ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim() != "yes" {
            bail!("not approved");
        }
    }
    approval::cli::decide(paths, id, approve)?;
    println!("{}.", if approve { "Approved" } else { "Denied" });
    Ok(())
}

fn read_passphrase(confirm: bool) -> Result<SecretString> {
    let first = Zeroizing::new(rpassword::prompt_password("Backup passphrase: ")?);
    if confirm {
        if first.chars().count() < 12 {
            bail!("use a passphrase of at least 12 characters");
        }
        let second = Zeroizing::new(rpassword::prompt_password("Repeat the passphrase: ")?);
        if *first != *second {
            bail!("the passphrases did not match");
        }
    }
    Ok(SecretString::from(first.to_string()))
}

fn backup_cmd(paths: &Paths, file: &std::path::Path) -> Result<()> {
    require_terminal()?;
    let policy = load_policy(paths)?;
    if policy.secrets.is_empty() {
        bail!("there are no secrets to back up");
    }
    if file.exists() {
        bail!("{} already exists", file.display());
    }
    let approver = Approver::new(policy.approval.clone(), paths.clone());
    let request = Request::new(
        policy.secrets.keys().cloned().collect(),
        format!("export ALL {} keymitt secrets to an encrypted backup", policy.secrets.len()),
        format!("file: {}", file.display()),
    );
    // Exporting everything is the most sensitive operation: weak approval is never enough.
    let decision = approver.request(&request, true);
    let mut event = Event::new("backup");
    event.action = Some(file.display().to_string());
    event.approval = Some(decision.clone());
    if !decision.approved {
        event.outcome = Some("denied".into());
        audit::record(paths, &event);
        bail!(
            "backup not approved ({}{})",
            decision.method,
            decision.note.map(|n| format!(": {n}")).unwrap_or_default()
        );
    }
    let passphrase = read_passphrase(true)?;
    let vault = vault::open()?;
    let (bundle, summary) = backup::collect(&policy, vault.as_ref())?;
    backup::write(&bundle, passphrase, file)?;
    event.secrets = summary.included.clone();
    event.outcome = Some("written".into());
    audit::record(paths, &event);
    println!("Wrote {} ({} secrets).", file.display(), summary.included.len());
    if !summary.missing.is_empty() {
        println!("Not included (no value in the keychain): {}", summary.missing.join(", "));
    }
    println!("Keep the passphrase somewhere safe: without it the backup cannot be restored.");
    Ok(())
}

fn restore_cmd(paths: &Paths, file: &std::path::Path, overwrite: bool) -> Result<()> {
    require_terminal()?;
    let passphrase = read_passphrase(false)?;
    let bundle = backup::read(file, passphrase)?;
    println!(
        "Backup from {} with {} secrets: {}",
        bundle.created.to_rfc3339(),
        bundle.secrets.len(),
        bundle.secrets.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    let mut policy = load_policy(paths)?;
    let approver = Approver::new(policy.approval.clone(), paths.clone());
    let request = Request::new(
        bundle.secrets.keys().cloned().collect(),
        format!(
            "restore {} secrets from a backup{}",
            bundle.secrets.len(),
            if overwrite { " (overwriting)" } else { "" }
        ),
        format!("file: {}", file.display()),
    );
    // A backup can add policy entries (such as `commands = ["*"]`), so restoring needs strong approval.
    let decision = approver.request(&request, true);
    let mut event = Event::new("restore");
    event.action = Some(file.display().to_string());
    event.approval = Some(decision.clone());
    if !decision.approved {
        event.outcome = Some("denied".into());
        audit::record(paths, &event);
        bail!("restore not approved");
    }
    let vault = vault::open()?;
    let report = backup::restore(&bundle, vault.as_ref(), &mut policy, overwrite)?;
    save_policy(paths, &policy)?;
    event.secrets = report.written.clone();
    event.outcome = Some("restored".into());
    audit::record(paths, &event);
    println!("Restored values: {}", if report.written.is_empty() { "-".into() } else { report.written.join(", ") });
    if !report.skipped_existing.is_empty() {
        println!("Kept existing values (use --overwrite to replace): {}", report.skipped_existing.join(", "));
    }
    if !report.policy_kept.is_empty() {
        println!("Kept existing policy entries: {}", report.policy_kept.join(", "));
    }
    Ok(())
}

fn doctor(paths: &Paths, test_approval: bool) -> Result<ExitCode> {
    let mut ok = true;
    let mut check = |good: bool, label: &str, detail: String| {
        println!("[{}] {label}: {detail}", if good { " ok " } else { "FAIL" });
        ok &= good;
    };

    check(true, "home", paths.home().display().to_string());
    let policy = match load_policy(paths) {
        Ok(p) => {
            check(true, "policy", format!("{} secrets", p.secrets.len()));
            p
        }
        Err(e) => {
            check(false, "policy", format!("{e:#}"));
            Policy::default()
        }
    };
    for (name, s) in &policy.secrets {
        if !s.is_usable() {
            println!("       note: {name} has no allowed program or host, so agents can't use it");
        }
        for bare in s.bare_commands() {
            println!(
                "       note: {name} allows the bare name {bare:?}, which matches any program with that name on PATH; \
                 prefer `keymitt allow {name} --command {bare}` (stores the full path)"
            );
        }
    }

    match vault::open() {
        Ok(vault) => {
            let probe = "keymitt-doctor-probe";
            let result = vault.set(probe, "probe-value").and_then(|_| vault.get(probe)).and_then(|v| {
                vault.delete(probe)?;
                Ok(v)
            });
            match result {
                Ok(Some(v)) if v.as_str() == "probe-value" => check(true, "keychain", vault.backend().to_string()),
                Ok(_) => check(false, "keychain", "value did not round-trip".into()),
                Err(e) => check(false, "keychain", format!("{e:#}")),
            }
            for name in policy.secrets.keys() {
                if !matches!(vault.get(name), Ok(Some(_))) {
                    check(false, "secret", format!("{name} has no value (run `keymitt update {name}`)"));
                }
            }
        }
        Err(e) => check(false, "keychain", format!("{e:#}")),
    }

    let approver = Approver::new(policy.approval.clone(), paths.clone());
    check(true, "approval", approver.describe());
    #[cfg(target_os = "linux")]
    if !std::path::Path::new(approval::linux::POLICY_PATH).exists() {
        println!("       note: strong approval needs the polkit action; see `keymitt setup polkit`");
    }
    check(
        crate::exec::find_on_path("curl").is_ok(),
        "curl",
        crate::exec::find_on_path("curl")
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "not found (http_request needs it)".into()),
    );

    if test_approval {
        let request = Request::new(vec![], "test keymitt approval".into(), "nothing will be used".into());
        let d = approver.request(&request, false);
        check(
            d.approved,
            "approval test",
            format!(
                "{} via {}{}",
                if d.approved { "approved" } else { "denied" },
                d.method,
                d.note.map(|n| format!(" ({n})")).unwrap_or_default()
            ),
        );
    }
    Ok(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn setup(target: SetupTarget) -> Result<()> {
    match target {
        SetupTarget::Claude => {
            let exe = std::env::current_exe().context("locating the keymitt executable")?;
            println!("Register keymitt as an MCP server for Claude Code (all projects):\n");
            println!("  claude mcp add --scope user keymitt -- \"{}\" mcp\n", exe.display());
            println!("Then restart Claude Code. Agents will see the tools list_secrets, run_with_secrets,");
            println!("http_request, read_file_redacted and request_secret.\n");
            println!("Recommended: deny direct reads of credential files so agents use read_file_redacted.");
            println!("See the README section \"Hardening your AI client\".");
        }
        SetupTarget::Polkit => {
            #[cfg(target_os = "linux")]
            {
                println!("Save the following as dev.keymitt.approve.policy and install it with:\n");
                println!("  sudo install -m 644 dev.keymitt.approve.policy {}\n", approval::linux::POLICY_PATH);
                println!("{}", approval::linux::POLICY_XML);
            }
            #[cfg(not(target_os = "linux"))]
            println!("polkit is only used on Linux.");
        }
    }
    Ok(())
}

/// Test helper: prints stdin, `env:NAME` values and `file:PATH` contents.
#[cfg(feature = "testing")]
fn echo(args: &[String]) -> Result<()> {
    let mut stdin = String::new();
    if !std::io::stdin().is_terminal() {
        std::io::stdin().read_to_string(&mut stdin)?;
    }
    println!("stdin={stdin}");
    println!("stdin_len={}", stdin.len());
    for arg in args {
        if let Some(name) = arg.strip_prefix("env:") {
            println!("env {name}={}", std::env::var(name).unwrap_or_default());
        } else if let Some(path) = arg.strip_prefix("file:") {
            println!("file={}", std::fs::read_to_string(path)?);
        } else {
            println!("arg={arg}");
        }
    }
    Ok(())
}
