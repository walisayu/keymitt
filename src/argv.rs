//! Argument rules: the subcommands, options, positional arguments and exact stdin a
//! secret's program may be run with.
//!
//! keymitt never hands the agent's own argument list to a program bound by these rules.
//! It parses the request (accepting the usual spellings: `--opt=value`, `--opt value`,
//! `-xVALUE`, bundled short flags such as `-qR`, options after positional arguments, `--`),
//! checks every piece against the rules, and runs a canonical form instead:
//!
//! ```text
//! SUBCOMMAND --long=value --flag -s -- POSITIONAL...
//! ```
//!
//! with pinned paths replaced by their resolved absolute path. What runs is exactly what the
//! approval prompt shows, so a difference between keymitt's parser and the program's cannot
//! smuggle in an option, and nothing the agent writes reaches the program as a bare `-word`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Rules for one secret. The secret may then be used only with its single program, only
/// with the subcommands listed here, and only through stdin texts that match exactly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgvRules {
    /// The built-in preset these rules came from, if any (`keymitt doctor` checks the
    /// program's version against it). Informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Substrings no option value or free positional argument may contain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbid: Vec<String>,
    /// Named absolute paths. A positional argument written `@NAME` must resolve to this file.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub paths: BTreeMap<String, String>,
    /// The allowed subcommands (the program's first argument) and what each accepts.
    #[serde(default)]
    pub subcommands: BTreeMap<String, SubcommandRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubcommandRule {
    /// Allowed options: `-q/--quiet` is a flag, `-u/--username=` and `--url=` take a value.
    /// Options that take a value need a long name: keymitt passes them as `--name=value`.
    #[serde(default)]
    pub options: Vec<String>,
    /// Positional arguments in order: `@NAME` (a path from `paths`) or `text`.
    /// A trailing `?` makes one optional; optional ones come last.
    #[serde(default)]
    pub positionals: Vec<String>,
    /// Exact stdin texts this subcommand may receive. `{{secret:NAME}}` must be that secret,
    /// `{{secret:*}}` may be any secret (whose own policy is still checked).
    #[serde(default)]
    pub stdin: Vec<String>,
}

/// A request that passed the rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub subcommand: String,
    /// The canonical arguments to run (everything after the program).
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OptSpec {
    short: Option<char>,
    long: Option<String>,
    takes_value: bool,
}

impl OptSpec {
    fn parse(spec: &str) -> Result<Self> {
        let (names, takes_value) = match spec.strip_suffix('=') {
            Some(names) => (names, true),
            None => (spec, false),
        };
        let mut short = None;
        let mut long = None;
        for part in names.split('/') {
            if let Some(name) = part.strip_prefix("--") {
                let valid = name.len() >= 2
                    && name.starts_with(|c: char| c.is_ascii_alphanumeric())
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
                if !valid || long.is_some() {
                    bail!("invalid option {spec:?}: expected a form like `-q/--quiet` or `--url=`");
                }
                long = Some(name.to_string());
            } else if let Some(name) = part.strip_prefix('-') {
                let mut chars = name.chars();
                match (chars.next(), chars.next()) {
                    (Some(c), None) if c.is_ascii_alphanumeric() && short.is_none() => short = Some(c),
                    _ => bail!("invalid option {spec:?}: expected a form like `-q/--quiet` or `--url=`"),
                }
            } else {
                bail!("invalid option {spec:?}: expected a form like `-q/--quiet` or `--url=`");
            }
        }
        if takes_value && long.is_none() {
            bail!("option {spec:?} takes a value, so it needs a long name (keymitt passes values as --name=value)");
        }
        Ok(Self { short, long, takes_value })
    }

    /// How the option is passed to the program.
    fn emit(&self, value: Option<&str>) -> String {
        match (&self.long, value) {
            (Some(long), Some(value)) => format!("--{long}={value}"),
            (Some(long), None) => format!("--{long}"),
            (None, _) => format!("-{}", self.short.expect("a spec has a name")),
        }
    }

    fn display(&self) -> String {
        let mut names = Vec::new();
        if let Some(c) = self.short {
            names.push(format!("-{c}"));
        }
        if let Some(l) = &self.long {
            names.push(format!("--{l}"));
        }
        let mut s = names.join("/");
        if self.takes_value {
            s.push_str(" <value>");
        }
        s
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PosKind {
    Path(String),
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PosSpec {
    kind: PosKind,
    optional: bool,
}

impl PosSpec {
    fn parse(spec: &str, paths: &BTreeMap<String, String>) -> Result<Self> {
        let (body, optional) = match spec.strip_suffix('?') {
            Some(body) => (body, true),
            None => (spec, false),
        };
        let kind = if body == "text" {
            PosKind::Text
        } else if let Some(name) = body.strip_prefix('@') {
            if !paths.contains_key(name) {
                bail!("positional {spec:?} refers to a path that is not defined in `paths`");
            }
            PosKind::Path(name.to_string())
        } else {
            bail!("invalid positional {spec:?}: expected `text` or `@NAME`, optionally followed by `?`");
        };
        Ok(Self { kind, optional })
    }

    fn display(&self) -> String {
        let s = match &self.kind {
            PosKind::Path(name) => format!("@{name}"),
            PosKind::Text => "text".to_string(),
        };
        if self.optional { format!("[{s}]") } else { s }
    }
}

/// A piece of stdin: literal text, or a placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Text(String),
    /// `None` is the wildcard `{{secret:*}}` (only valid in rules).
    Secret(Option<String>),
    File(String),
}

/// The same placeholder syntax as [`crate::template`], plus the wildcard `*`.
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{\s*(?P<kind>secret|file)\s*:\s*(?P<name>[A-Za-z0-9._-]+|\*)\s*\}\}").expect("valid regex")
});

fn segments(text: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut last = 0;
    for c in PLACEHOLDER.captures_iter(text) {
        let m = c.get(0).expect("whole match");
        if m.start() > last {
            out.push(Segment::Text(text[last..m.start()].to_string()));
        }
        let name = &c["name"];
        out.push(match &c["kind"] {
            "secret" if name == "*" => Segment::Secret(None),
            "secret" => Segment::Secret(Some(name.to_string())),
            _ => Segment::File(name.to_string()),
        });
        last = m.end();
    }
    if last < text.len() {
        out.push(Segment::Text(text[last..].to_string()));
    }
    out
}

fn template_matches(template: &[Segment], request: &[Segment]) -> bool {
    template.len() == request.len()
        && template.iter().zip(request).all(|(t, r)| match (t, r) {
            (Segment::Text(a), Segment::Text(b)) => a == b,
            (Segment::Secret(None), Segment::Secret(Some(_))) => true,
            (Segment::Secret(Some(a)), Segment::Secret(Some(b))) => a == b,
            _ => false,
        })
}

fn validate_template(template: &str) -> Result<()> {
    for segment in segments(template) {
        match segment {
            Segment::File(_) => bail!("stdin rule {template:?} may not contain {{{{file:...}}}}"),
            Segment::Secret(Some(name)) => crate::policy::validate_name(&name)?,
            _ => {}
        }
    }
    Ok(())
}

/// Characters an agent-supplied value may never contain: control characters other than
/// newline and tab (escape sequences, carriage returns, NUL).
fn has_bad_control(value: &str) -> bool {
    value.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}

/// The path to hand to the program: on Windows without the `\\?\` prefix that
/// `canonicalize` adds to drive paths, which many programs do not understand.
pub(crate) fn exec_path(path: &Path) -> String {
    let s = path.display().to_string();
    if cfg!(windows)
        && let Some(rest) = s.strip_prefix(r"\\?\")
    {
        let bytes = rest.as_bytes();
        if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
            return rest.to_string();
        }
    }
    s
}

struct Compiled {
    options: Vec<OptSpec>,
    positionals: Vec<PosSpec>,
    stdin: Vec<Vec<Segment>>,
}

impl ArgvRules {
    /// Checks that every rule is well formed. Called when the policy is loaded.
    pub fn validate(&self) -> Result<()> {
        if self.subcommands.is_empty() {
            bail!("argument rules must allow at least one subcommand");
        }
        for (name, path) in &self.paths {
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                bail!("invalid path name {name:?}");
            }
            if !Path::new(path).is_absolute() {
                bail!("path {name} = {path:?} must be absolute");
            }
        }
        if self.forbid.iter().any(String::is_empty) {
            bail!("`forbid` may not contain an empty string");
        }
        for (name, rule) in &self.subcommands {
            if name.is_empty() || name.starts_with('-') || has_bad_control(name) || name.contains(char::is_whitespace) {
                bail!("invalid subcommand name {name:?}");
            }
            self.compile(rule).with_context(|| format!("subcommand {name}"))?;
        }
        Ok(())
    }

    fn compile(&self, rule: &SubcommandRule) -> Result<Compiled> {
        let options = rule.options.iter().map(|s| OptSpec::parse(s)).collect::<Result<Vec<_>>>()?;
        let mut shorts = BTreeSet::new();
        let mut longs = BTreeSet::new();
        for o in &options {
            if o.short.is_some_and(|c| !shorts.insert(c)) || o.long.as_ref().is_some_and(|l| !longs.insert(l.clone())) {
                bail!("option {} is listed twice", o.display());
            }
        }
        let positionals =
            rule.positionals.iter().map(|s| PosSpec::parse(s, &self.paths)).collect::<Result<Vec<_>>>()?;
        if positionals.windows(2).any(|w| w[0].optional && !w[1].optional) {
            bail!("optional positional arguments must come last");
        }
        let mut stdin = Vec::new();
        for template in &rule.stdin {
            validate_template(template)?;
            stdin.push(segments(template));
        }
        Ok(Compiled { options, positionals, stdin })
    }

    fn check_value(&self, what: &str, value: &str) -> Result<()> {
        if has_bad_control(value) {
            bail!("{what} contains a control character");
        }
        if let Some(bad) = self.forbid.iter().find(|f| value.contains(f.as_str())) {
            bail!("{what} may not contain {bad:?}");
        }
        Ok(())
    }

    /// Checks a request (the arguments after the program, its stdin and working directory)
    /// and returns the canonical arguments to run instead.
    pub fn check(&self, args: &[String], stdin: Option<&str>, cwd: &Path) -> Result<Invocation> {
        let allowed = || self.subcommands.keys().cloned().collect::<Vec<_>>().join(", ");
        let Some(subcommand) = args.first() else {
            bail!("a subcommand is required; allowed: {}", allowed());
        };
        let Some(rule) = self.subcommands.get(subcommand) else {
            bail!("subcommand {subcommand:?} is not allowed; allowed: {}", allowed());
        };
        let compiled = self.compile(rule)?;
        let usage = || {
            let opts: Vec<String> = compiled.options.iter().map(OptSpec::display).collect();
            let pos: Vec<String> = compiled.positionals.iter().map(PosSpec::display).collect();
            format!("{subcommand} [{}] {}", opts.join(", "), pos.join(" "))
        };

        let mut options: Vec<(&OptSpec, Option<String>)> = Vec::new();
        let mut positionals: Vec<&String> = Vec::new();
        let mut rest = args[1..].iter();
        let mut only_positionals = false;
        while let Some(token) = rest.next() {
            if only_positionals || token == "-" || !token.starts_with('-') {
                positionals.push(token);
                continue;
            }
            if token == "--" {
                only_positionals = true;
                continue;
            }
            if let Some(body) = token.strip_prefix("--") {
                let (name, inline) = match body.split_once('=') {
                    Some((name, value)) => (name, Some(value.to_string())),
                    None => (body, None),
                };
                let Some(spec) = compiled.options.iter().find(|o| o.long.as_deref() == Some(name)) else {
                    bail!("option --{name} is not allowed; usage: {}", usage());
                };
                if spec.takes_value {
                    let value = match inline {
                        Some(v) => v,
                        None => rest.next().with_context(|| format!("option --{name} needs a value"))?.clone(),
                    };
                    options.push((spec, Some(value)));
                } else if inline.is_some() {
                    bail!("option --{name} does not take a value");
                } else {
                    options.push((spec, None));
                }
                continue;
            }
            // One or more bundled short options: `-q`, `-qR`, `-L20`, `-qL 20`.
            let chars: Vec<char> = token[1..].chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let c = chars[i];
                i += 1;
                let Some(spec) = compiled.options.iter().find(|o| o.short == Some(c)) else {
                    bail!("option -{c} is not allowed; usage: {}", usage());
                };
                if spec.takes_value {
                    let attached: String = chars[i..].iter().collect();
                    let value = if attached.is_empty() {
                        rest.next().with_context(|| format!("option -{c} needs a value"))?.clone()
                    } else {
                        attached
                    };
                    options.push((spec, Some(value)));
                    break;
                }
                options.push((spec, None));
            }
        }

        let required = compiled.positionals.iter().filter(|p| !p.optional).count();
        if positionals.len() < required || positionals.len() > compiled.positionals.len() {
            bail!(
                "expected {} positional argument(s), got {}; usage: {}",
                if required == compiled.positionals.len() {
                    required.to_string()
                } else {
                    format!("{required} to {}", compiled.positionals.len())
                },
                positionals.len(),
                usage()
            );
        }

        let mut out = vec![subcommand.clone()];
        for (spec, value) in &options {
            if let Some(value) = value {
                self.check_value(&format!("the value of {}", spec.display()), value)?;
            }
            out.push(spec.emit(value.as_deref()));
        }
        if !positionals.is_empty() {
            out.push("--".into());
        }
        for (n, (value, spec)) in positionals.iter().zip(&compiled.positionals).enumerate() {
            let what = format!("positional argument {}", n + 1);
            if value.starts_with('-') {
                bail!("{what} may not start with '-'");
            }
            match &spec.kind {
                PosKind::Text => {
                    self.check_value(&what, value)?;
                    out.push((*value).clone());
                }
                PosKind::Path(name) => {
                    let pinned = PathBuf::from(&self.paths[name]);
                    let pinned = pinned
                        .canonicalize()
                        .with_context(|| format!("the allowed {name} path {} does not exist", pinned.display()))?;
                    let given = Path::new(value.as_str());
                    let given = if given.is_absolute() { given.to_path_buf() } else { cwd.join(given) };
                    if given.canonicalize().ok().as_deref() != Some(pinned.as_path()) {
                        bail!("{what} must be the {name} file {}", exec_path(&pinned));
                    }
                    out.push(exec_path(&pinned));
                }
            }
        }

        let request = segments(stdin.unwrap_or_default());
        if request.iter().any(|s| matches!(s, Segment::File(_) | Segment::Secret(None))) {
            bail!("stdin may only contain {{{{secret:NAME}}}} placeholders here");
        }
        if stdin.is_none() || !compiled.stdin.iter().any(|t| template_matches(t, &request)) {
            let forms: Vec<String> = rule.stdin.iter().map(|t| crate::approval::printable(t)).collect();
            if forms.is_empty() {
                bail!("subcommand {subcommand} cannot receive this secret");
            }
            bail!("stdin must be exactly one of: {}", forms.join("  or  "));
        }

        Ok(Invocation { subcommand: subcommand.clone(), args: out })
    }

    /// One line per subcommand, for `keymitt list`.
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for (name, path) in &self.paths {
            lines.push(format!("@{name} = {path}"));
        }
        if !self.forbid.is_empty() {
            lines.push(format!("values may not contain: {}", self.forbid.join(" ")));
        }
        for (name, rule) in &self.subcommands {
            let pos = rule.positionals.join(" ");
            lines.push(format!("{name} [{}] {pos}", rule.options.join(" ")).trim_end().to_string());
            let stdin: Vec<String> = rule.stdin.iter().map(|t| crate::approval::printable(t)).collect();
            lines.push(format!("    stdin: {}", if stdin.is_empty() { "-".into() } else { stdin.join("  |  ") }));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        db: PathBuf,
        rules: ArgvRules,
    }

    /// Rules shaped like the keepassxc preset, for a database in a temp dir.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let db = root.join("main.kdbx");
        std::fs::write(&db, "x").unwrap();
        std::fs::write(root.join("other.kdbx"), "x").unwrap();
        let rules = crate::presets::keepassxc("kdbx", &db, &[]).unwrap();
        Fixture { _dir: dir, root, db, rules }
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    impl Fixture {
        fn check(&self, list: &[&str], stdin: &str) -> Result<Invocation> {
            self.rules.check(&args(list), Some(stdin), &self.root)
        }
        fn ok(&self, list: &[&str]) -> Vec<String> {
            self.check(list, "{{secret:kdbx}}\n").unwrap_or_else(|e| panic!("{list:?} should pass: {e:#}")).args
        }
        fn err(&self, list: &[&str]) -> String {
            match self.check(list, "{{secret:kdbx}}\n") {
                Ok(inv) => panic!("{list:?} should be refused, got {:?}", inv.args),
                Err(e) => format!("{e:#}"),
            }
        }
        fn db(&self) -> String {
            exec_path(&self.db)
        }
    }

    #[test]
    fn option_specs() {
        assert_eq!(
            OptSpec::parse("-u/--username=").unwrap(),
            OptSpec { short: Some('u'), long: Some("username".into()), takes_value: true }
        );
        assert_eq!(OptSpec::parse("--url=").unwrap().emit(Some("x")), "--url=x");
        assert_eq!(OptSpec::parse("-q").unwrap().emit(None), "-q");
        for bad in ["q", "-qq", "--x", "---x", "-q/-r", "-u=", "--a b", "-/--x", ""] {
            assert!(OptSpec::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn canonical_forms() {
        let f = fixture();
        let db = f.db();
        assert_eq!(f.ok(&["ls", &db]), ["ls", "--", &db]);
        assert_eq!(
            f.ok(&["ls", "-qRf", &db, "/Group"]),
            ["ls", "--quiet", "--recursive", "--flatten", "--", &db, "/Group"]
        );
        // Every spelling of a value ends up as --name=value.
        let want = ["edit", "--length=20", "--", db.as_str(), "E"];
        for spelling in [
            &["edit", "-L20", &db, "E"][..],
            &["edit", "-L", "20", &db, "E"],
            &["edit", "--length=20", &db, "E"],
            &["edit", "--length", "20", &db, "E"],
            &["edit", &db, "E", "-L20"],
            &["edit", &db, "-L", "20", "E"],
        ] {
            assert_eq!(f.ok(spelling), want, "{spelling:?}");
        }
        assert_eq!(f.ok(&["ls", "--", &db]), ["ls", "--", &db]);
        assert_eq!(
            f.ok(&["edit", "-qgL20", &db, "E"]),
            ["edit", "--quiet", "--generate", "--length=20", "--", &db, "E"]
        );
        // A value-taking option swallows the next token whatever it is, as the program would.
        assert_eq!(f.ok(&["edit", "--notes", "--quiet", &db, "E"]), ["edit", "--notes=--quiet", "--", &db, "E"]);
        assert_eq!(f.ok(&["add", "--url=https://x", &db, "/G/E"]), ["add", "--url=https://x", "--", &db, "/G/E"]);
    }

    #[test]
    fn password_revealing_requests_are_refused() {
        let f = fixture();
        let db = f.db();
        for (list, why) in [
            (&["show", "-a", "Password", &db, "E"][..], "-a"),
            (&["show", "--attributes=Password", &db, "E"], "--attributes"),
            (&["show", "--attributes", "Password", &db, "E"], "--attributes"),
            (&["show", "-s", &db, "E"], "-s"),
            (&["show", "--show-protected", &db, "E"], "--show-protected"),
            (&["show", "-qs", &db, "E"], "-s"),
            (&["show", &db, "E", "-s"], "-s"),
            (&["show", &db, "E", "-qa", "Password"], "-a"),
            (&["show", "--all", &db, "E"], "--all"),
            (&["show", "-t", &db, "E"], "-t"),
            (&["show", "--show-attachments", &db, "E"], "--show-attachments"),
            (&["show", "-k", "/tmp/key", &db, "E"], "-k"),
            (&["show", "--no-password", &db, "E"], "--no-password"),
            (&["ls", "--quiet=x", &db], "does not take a value"),
            (&["show", "--show-prot", &db, "E"], "--show-prot"),
        ] {
            let e = f.err(list);
            assert!(e.contains(why), "{list:?}: {e}");
        }
        for sub in ["export", "clip", "open", "search", "analyze", "attachment-export", "db-edit", "merge", "import"] {
            assert!(f.err(&[sub, &db]).contains("not allowed"), "{sub}");
        }
        assert!(f.err(&[]).contains("subcommand is required"));
        assert!(f.err(&["--debug-info", "ls", &db]).contains("not allowed"));
    }

    #[test]
    fn placeholders_cannot_be_planted() {
        let f = fixture();
        let db = f.db();
        for list in [
            &["edit", "--notes", "{PASSWORD}", &db, "E"][..],
            &["edit", "--notes={REF:P@T:Other}", &db, "E"],
            &["add", "-u", "{REF:P@I:0123}", &db, "E"],
            &["edit", "-t", "x{S:attr}", &db, "E"],
            &["add", &db, "/G/{PASSWORD}"],
            &["mkdir", &db, "/{T-CONV:/{PASSWORD}/base64/}"],
        ] {
            assert!(f.err(list).contains("may not contain"), "{list:?}");
        }
        assert!(f.err(&["edit", "--notes", "a\u{1b}[2Jb", &db, "E"]).contains("control character"));
        assert_eq!(f.ok(&["edit", "--notes", "two\nlines", &db, "E"])[1], "--notes=two\nlines");
    }

    #[test]
    fn positionals_are_checked() {
        let f = fixture();
        let db = f.db();
        assert!(f.err(&["show", &db]).contains("expected 2"));
        assert!(f.err(&["show", &db, "E", "extra"]).contains("expected 2"));
        assert!(f.err(&["ls", &db, "/a", "/b"]).contains("1 to 2"));
        assert!(f.err(&["show", &db, "-"]).contains("may not start with '-'"));
        assert!(f.err(&["show", &db, "--", "-s"]).contains("may not start with '-'"));
        assert!(f.err(&["show", "--", &db, "-s"]).contains("may not start with '-'"));
    }

    #[test]
    fn the_database_is_pinned() {
        let f = fixture();
        let other = f.root.join("other.kdbx").display().to_string();
        assert!(f.err(&["ls", &other]).contains("must be the database file"));
        assert!(f.err(&["ls", "/definitely/not/here.kdbx"]).contains("must be the database file"));
        // Relative to the request's working directory, and through symlinks: allowed,
        // and always run with the resolved path.
        assert_eq!(f.ok(&["ls", "main.kdbx"]), ["ls", "--", &f.db()]);
        std::fs::create_dir(f.root.join("sub")).unwrap();
        assert_eq!(f.ok(&["ls", "./sub/../main.kdbx"]), ["ls", "--", &f.db()]);
        #[cfg(unix)]
        {
            let link = f.root.join("link.kdbx");
            std::os::unix::fs::symlink(&f.db, &link).unwrap();
            assert_eq!(f.ok(&["ls", link.to_str().unwrap()]), ["ls", "--", &f.db()]);
            let evil = f.root.join("evil.kdbx");
            std::os::unix::fs::symlink(f.root.join("other.kdbx"), &evil).unwrap();
            assert!(f.err(&["ls", evil.to_str().unwrap()]).contains("must be the database file"));
        }
    }

    #[test]
    fn stdin_must_match_exactly() {
        let f = fixture();
        let db = f.db();
        let ls = &["ls", db.as_str()][..];
        assert!(f.check(ls, "{{secret:kdbx}}\n").is_ok());
        assert!(f.check(ls, "{{ secret : kdbx }}\n").is_ok(), "the template syntax allows spaces");
        for bad in [
            "{{secret:kdbx}}",
            "{{secret:kdbx}}\n\n",
            "{{secret:kdbx}}\nshow -s main.kdbx E\n",
            "{{secret:kdbx}}\n{{secret:other}}\n",
            "{{secret:other}}\n",
            "{{secret:*}}\n",
            "{{secret:kdbx}}\n{{file:x}}",
            "",
        ] {
            let e = format!("{:#}", f.check(ls, bad).unwrap_err());
            assert!(e.contains("stdin"), "{bad:?}: {e}");
        }
        assert!(f.rules.check(&args(ls), None, &f.root).is_err(), "stdin is required");
        // add/edit -p may receive one more secret, the new entry's password.
        let add = &["add", "-p", db.as_str(), "E"][..];
        assert!(f.check(add, "{{secret:kdbx}}\n{{secret:new-entry}}\n").is_ok());
        assert!(f.check(add, "{{secret:kdbx}}\n{{secret:new-entry}}\nmore\n").is_err());
        assert!(f.check(ls, "{{secret:kdbx}}\n{{secret:new-entry}}\n").is_err(), "only for add/edit");
    }

    #[test]
    fn validation() {
        let f = fixture();
        assert!(f.rules.validate().is_ok());
        let mut bad = f.rules.clone();
        bad.subcommands.get_mut("ls").unwrap().positionals = vec!["@nope".into()];
        assert!(bad.validate().is_err());
        let mut bad = f.rules.clone();
        bad.subcommands.get_mut("ls").unwrap().positionals = vec!["text?".into(), "text".into()];
        assert!(bad.validate().is_err());
        let mut bad = f.rules.clone();
        bad.subcommands.get_mut("ls").unwrap().options.push("-q/--quiet".into());
        assert!(format!("{:#}", bad.validate().unwrap_err()).contains("twice"));
        let mut bad = f.rules.clone();
        bad.subcommands.get_mut("ls").unwrap().stdin = vec!["{{file:x}}".into()];
        assert!(bad.validate().is_err());
        let mut bad = f.rules.clone();
        bad.paths.insert("rel".into(), "relative/path".into());
        assert!(bad.validate().is_err());
        assert!(ArgvRules::default().validate().is_err(), "no subcommands");
    }
}
