//! Built-in argument rules, so people don't have to write them by hand.
//!
//! `keepassxc`: the master password of one KeePassXC database. Agents may list and read
//! the non-secret fields, add and edit entries (with generated passwords or a password
//! from another keymitt secret), create groups and move entries — never reveal a password.
//!
//! `keepassxc-entry`: a password that agents may store into that database with
//! `add -p` / `edit -p`, as the second line of stdin after the master password.
//!
//! Checked against keepassxc-cli 2.8.0. Notable findings that shaped the rules:
//! * `show -a Password` prints the password without `-s`; `--all` and `-t` reveal more.
//! * `show` expands placeholders, so notes set to `{PASSWORD}` or `{REF:P@T:Other}` print
//!   passwords: no value an agent supplies may contain `{` or `}`.
//! * `search 'p:abc*'` matches on the password, so passwords can be guessed: no `search`.
//! * `analyze -H` checks passwords against any hash file, `--okon` runs a program: no `analyze`.
//! * `open` reads further commands from stdin: no `open`, and stdin must match exactly.
//! * `add -g` / `edit -g` do not print the generated password.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::argv::{ArgvRules, SubcommandRule};

pub const KEEPASSXC: &str = "keepassxc";
pub const KEEPASSXC_ENTRY: &str = "keepassxc-entry";

/// The keepassxc-cli versions the presets were checked against (prefix of `--version`).
pub const KEEPASSXC_TESTED: &str = "2.8.";

/// Subcommands `--with` may add to the `keepassxc` preset.
const OPTIONAL: &[&str] = &["rm", "rmdir"];

/// Subcommands the presets never offer, and why.
const REFUSED: &[(&str, &str)] = &[
    ("search", "its field prefixes (`p:abc*`) match on passwords, so a password can be guessed"),
    ("analyze", "`-H` tests passwords against any hash file and `--okon` runs a program"),
    ("export", "it prints every password"),
    ("clip", "it puts a password on the clipboard, where other programs can read it"),
    ("open", "it reads further commands from stdin"),
    ("attachment-export", "it writes attachments where the agent can read them"),
    ("attachment-import", "it copies arbitrary files into the database"),
    ("db-edit", "it can change the master password"),
    ("db-create", "it creates databases protected by this password"),
    ("merge", "it copies entries into or from another database"),
    ("import", "it creates databases from files"),
];

const QUIET: &str = "-q/--quiet";

/// Options of `add` (and `edit`) that set non-secret fields or generate a password.
const ENTRY_OPTIONS: &[&str] = &[
    "-u/--username=",
    "--url=",
    "--notes=",
    "-p/--password-prompt",
    "-g/--generate",
    "-L/--length=",
    "-l/--lower",
    "-U/--upper",
    "-n/--numeric",
    "-s/--special",
    "-e/--extended",
    "-x/--exclude=",
    "--exclude-similar",
    "--every-group",
    "-c/--custom=",
];

fn rule(options: &[&str], positionals: &[&str], stdin: &[&String]) -> SubcommandRule {
    SubcommandRule {
        options: options.iter().map(|s| s.to_string()).collect(),
        positionals: positionals.iter().map(|s| s.to_string()).collect(),
        stdin: stdin.iter().map(|s| s.to_string()).collect(),
    }
}

fn base(preset: &str, database: &Path) -> Result<ArgvRules> {
    if !database.is_absolute() {
        bail!("the database path must be absolute");
    }
    Ok(ArgvRules {
        preset: Some(preset.to_string()),
        // KeePassXC placeholders ({PASSWORD}, {REF:...}, {T-CONV:...}) would make `show` print passwords.
        forbid: vec!["{".into(), "}".into()],
        paths: [("database".to_string(), database.display().to_string())].into(),
        subcommands: Default::default(),
    })
}

fn add_and_edit(rules: &mut ArgvRules, stdin: &[&String]) {
    let mut add = vec![QUIET];
    add.extend_from_slice(ENTRY_OPTIONS);
    let mut edit = add.clone();
    edit.push("-t/--title=");
    rules.subcommands.insert("add".into(), rule(&add, &["@database", "text"], stdin));
    rules.subcommands.insert("edit".into(), rule(&edit, &["@database", "text"], stdin));
}

/// Rules for the master password `secret` of `database` (an absolute, resolved path).
pub fn keepassxc(secret: &str, database: &Path, with: &[String]) -> Result<ArgvRules> {
    let mut rules = base(KEEPASSXC, database)?;
    let one = format!("{{{{secret:{secret}}}}}\n");
    let two = format!("{{{{secret:{secret}}}}}\n{{{{secret:*}}}}\n");
    let db = "@database";
    let s = &mut rules.subcommands;
    s.insert("ls".into(), rule(&[QUIET, "-R/--recursive", "-f/--flatten"], &[db, "text?"], &[&one]));
    s.insert("db-info".into(), rule(&[QUIET], &[db], &[&one]));
    s.insert("show".into(), rule(&[QUIET], &[db, "text"], &[&one]));
    s.insert("mkdir".into(), rule(&[QUIET], &[db, "text"], &[&one]));
    s.insert("mv".into(), rule(&[QUIET], &[db, "text", "text"], &[&one]));
    add_and_edit(&mut rules, &[&one, &two]);
    for extra in with {
        if let Some((_, why)) = REFUSED.iter().find(|(name, _)| name == extra) {
            bail!("the keepassxc preset never allows `{extra}`: {why}");
        }
        if !OPTIONAL.contains(&extra.as_str()) {
            bail!("unknown subcommand {extra:?} for --with (available: {})", OPTIONAL.join(", "));
        }
        rules.subcommands.insert(extra.clone(), rule(&[QUIET], &[db, "text"], &[&one]));
    }
    rules.validate()?;
    Ok(rules)
}

/// Rules for `secret`, a password to store into `database` with `add -p` / `edit -p`.
pub fn keepassxc_entry(secret: &str, database: &Path) -> Result<ArgvRules> {
    let mut rules = base(KEEPASSXC_ENTRY, database)?;
    let stdin = format!("{{{{secret:*}}}}\n{{{{secret:{secret}}}}}\n");
    add_and_edit(&mut rules, &[&stdin]);
    rules.validate()?;
    Ok(rules)
}

/// Finds keepassxc-cli: on PATH, or where the KeePassXC installers put it.
pub fn find_keepassxc() -> Result<PathBuf> {
    if let Ok(path) = crate::exec::find_on_path("keepassxc-cli") {
        return Ok(path);
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if cfg!(target_os = "macos") {
        candidates.push("/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli".into());
        if let Some(home) = dirs::home_dir() {
            candidates.push(home.join("Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli"));
        }
    } else if cfg!(windows) {
        candidates.push(r"C:\Program Files\KeePassXC\keepassxc-cli.exe".into());
    }
    for candidate in candidates {
        if candidate.is_file() {
            return candidate.canonicalize().with_context(|| format!("resolving {}", candidate.display()));
        }
    }
    bail!("keepassxc-cli was not found on PATH or in the usual install location; pass --program with its full path")
}

/// The version keepassxc-cli reports, e.g. `2.8.0`.
pub fn keepassxc_version(program: &Path) -> Result<String> {
    let out = std::process::Command::new(program)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("running {} --version", program.display()))?;
    Ok(version_number(&String::from_utf8_lossy(&out.stdout)))
}

/// `KeePassXC 2.8.0` (macOS) or `2.8.0` → `2.8.0`.
fn version_number(text: &str) -> String {
    let text = text.trim();
    text.split_whitespace().find(|t| t.starts_with(|c: char| c.is_ascii_digit())).unwrap_or(text).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(version_number("KeePassXC 2.8.0\n"), "2.8.0");
        assert_eq!(version_number("2.7.9"), "2.7.9");
        assert_eq!(version_number("unknown"), "unknown");
    }

    fn db() -> PathBuf {
        if cfg!(windows) { r"C:\vault\main.kdbx".into() } else { "/vault/main.kdbx".into() }
    }

    #[test]
    fn keepassxc_preset() {
        let rules = keepassxc("kdbx", &db(), &[]).unwrap();
        let subs: Vec<&str> = rules.subcommands.keys().map(String::as_str).collect();
        assert_eq!(subs, ["add", "db-info", "edit", "ls", "mkdir", "mv", "show"]);
        assert_eq!(rules.subcommands["show"].options, ["-q/--quiet"]);
        assert_eq!(rules.subcommands["ls"].stdin, ["{{secret:kdbx}}\n"]);
        assert_eq!(rules.subcommands["add"].stdin, ["{{secret:kdbx}}\n", "{{secret:kdbx}}\n{{secret:*}}\n"]);
        assert!(rules.subcommands["edit"].options.contains(&"-t/--title=".to_string()));
        assert!(!rules.subcommands["add"].options.contains(&"-t/--title=".to_string()));
        assert_eq!(rules.forbid, ["{", "}"]);

        let more = keepassxc("kdbx", &db(), &["rm".into(), "rmdir".into()]).unwrap();
        assert!(more.subcommands.contains_key("rm") && more.subcommands.contains_key("rmdir"));
        for refused in ["search", "analyze", "export", "clip", "open", "db-edit", "merge"] {
            let e = keepassxc("kdbx", &db(), &[refused.into()]).unwrap_err().to_string();
            assert!(e.contains("never allows"), "{refused}: {e}");
        }
        assert!(keepassxc("kdbx", &db(), &["bogus".into()]).is_err());
        assert!(keepassxc("kdbx", Path::new("relative.kdbx"), &[]).is_err());
    }

    #[test]
    fn entry_preset() {
        let rules = keepassxc_entry("new-entry", &db()).unwrap();
        let subs: Vec<&str> = rules.subcommands.keys().map(String::as_str).collect();
        assert_eq!(subs, ["add", "edit"]);
        assert_eq!(rules.subcommands["add"].stdin, ["{{secret:*}}\n{{secret:new-entry}}\n"]);
    }
}
