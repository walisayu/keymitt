//! End-to-end tests: start `keymitt mcp`, speak MCP over stdio, and check
//! that what the agent receives never contains a secret value.
//!
//! Run with `cargo test --features testing`.
#![cfg(feature = "testing")]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

const SECRET: &str = "kmt-Sup3r-S3cret-Value-0042";
const OTHER: &str = "other-Secret-Value-77777";

struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    home: tempfile::TempDir,
}

impl Server {
    fn start(policy: &str, approver: &str) -> Self {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("policy.toml"), policy).unwrap();
        Self::start_in(home, approver, json!({ "demo": SECRET, "other": OTHER }))
    }

    /// Starts the server on an existing keymitt home with the given vault contents.
    fn start_in(home: tempfile::TempDir, approver: &str, vault: Value) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_keymitt"))
            .arg("mcp")
            .current_dir(home.path())
            .env("KEYMITT_HOME", home.path())
            .env("KEYMITT_TEST_VAULT", vault.to_string())
            .env("KEYMITT_TEST_APPROVER", approver)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut server = Self { child, stdin, stdout, next_id: 1, home };
        let init = server.request(
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "keymitt-test", "version": "0" }
            }),
        );
        assert_eq!(init["result"]["serverInfo"]["name"], "keymitt", "{init}");
        server.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        server
    }

    fn send(&mut self, message: Value) {
        writeln!(self.stdin, "{message}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let mut line = String::new();
            assert!(self.stdout.read_line(&mut line).unwrap() > 0, "server closed stdout");
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    /// Calls a tool; returns (is_error, text) and asserts no secret leaked.
    fn tool(&mut self, name: &str, arguments: Value) -> (bool, String) {
        let response = self.request("tools/call", json!({ "name": name, "arguments": arguments }));
        let raw = response.to_string();
        assert!(!raw.contains(SECRET) && !raw.contains(OTHER), "secret leaked to the agent: {raw}");
        let result = &response["result"];
        let text = result["content"][0]["text"].as_str().unwrap_or_default().to_string();
        (result["isError"].as_bool().unwrap_or(false), text)
    }

    fn audit_log(&self) -> String {
        std::fs::read_to_string(self.home.path().join("audit.jsonl")).unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn exe() -> String {
    env!("CARGO_BIN_EXE_keymitt").to_string()
}

fn policy() -> String {
    format!(
        r#"
[approval]
timeout_secs = 5

[secrets.demo]
description = "Demo token"
channels = ["stdin", "env", "file"]
commands = ['{exe}']

[secrets.other]
description = "Never used directly"
channels = ["stdin"]
commands = ["definitely-not-a-real-program"]
"#,
        exe = exe()
    )
}

#[test]
fn lists_tools_and_secrets_without_values() {
    let mut s = Server::start(&policy(), "approve");
    let tools = s.request("tools/list", json!({}));
    let names: Vec<&str> =
        tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in ["list_secrets", "run_with_secrets", "http_request", "read_file_redacted", "request_secret"] {
        assert!(names.contains(&expected), "missing tool {expected}: {names:?}");
    }
    let (is_error, text) = s.tool("list_secrets", json!({}));
    assert!(!is_error);
    assert!(text.contains("\"demo\"") && text.contains("Demo token"), "{text}");
}

#[test]
fn injects_through_every_channel_and_redacts() {
    let mut s = Server::start(&policy(), "approve");
    let stdin = format!("stdin has {{{{secret:demo}}}} and a literal {OTHER}");
    let (is_error, text) = s.tool(
        "run_with_secrets",
        json!({
            "command": [exe(), "__echo", "env:TOKEN", "file:{{file:cfg}}"],
            "stdin": stdin,
            "env": { "TOKEN": "{{secret:demo}}" },
            "files": [{ "id": "cfg", "content": "cfg={{secret:demo}}" }]
        }),
    );
    assert!(!is_error, "{text}");
    assert!(text.contains("stdin has [REDACTED:demo] and a literal [REDACTED:other]"), "{text}");
    assert!(text.contains("env TOKEN=[REDACTED:demo]"), "{text}");
    assert!(text.contains("file=cfg=[REDACTED:demo]"), "{text}");
    // The program received the real value: its stdin length proves the substitution.
    let expected_len = format!("stdin has {SECRET} and a literal {OTHER}").len();
    assert!(text.contains(&format!("stdin_len={expected_len}")), "{text}");

    let log = s.audit_log();
    assert!(log.contains("\"event\":\"run\"") && log.contains("\"approved\":true"), "{log}");
    assert!(!log.contains(SECRET), "audit log must not contain values");
}

#[test]
fn denied_requests_do_not_run() {
    let mut s = Server::start(&policy(), "deny");
    let (is_error, text) =
        s.tool("run_with_secrets", json!({ "command": [exe(), "__echo"], "stdin": "{{secret:demo}}" }));
    assert!(is_error && text.contains("did not approve"), "{text}");
    assert!(s.audit_log().contains("\"outcome\":\"denied\""));
}

#[test]
fn policy_violations_are_rejected_before_approval() {
    let mut s = Server::start(&policy(), "approve");
    let (is_error, text) = s.tool("run_with_secrets", json!({ "command": [exe(), "--token={{secret:demo}}"] }));
    assert!(is_error && text.contains("command-line arguments"), "{text}");

    let (is_error, text) =
        s.tool("run_with_secrets", json!({ "command": [exe(), "__echo"], "stdin": "{{secret:other}}" }));
    assert!(is_error && text.contains("does not allow"), "{text}");

    let (is_error, text) =
        s.tool("run_with_secrets", json!({ "command": [exe(), "__echo"], "stdin": "{{secret:nope}}" }));
    assert!(is_error && text.contains("unknown secret"), "{text}");

    let (is_error, text) =
        s.tool("run_with_secrets", json!({ "command": [exe(), "__echo"], "env": { "LD_PRELOAD": "{{secret:demo}}" } }));
    assert!(is_error && text.contains("cannot be set"), "{text}");

    let (is_error, text) = s.tool(
        "http_request",
        json!({ "url": "https://example.com/", "headers": { "Authorization": "Bearer {{secret:demo}}" } }),
    );
    assert!(is_error, "{text}");
}

#[test]
fn reads_files_with_credentials_masked() {
    let mut s = Server::start(&policy(), "approve");
    let path = s.home.path().join("app.ini");
    std::fs::write(&path, format!("HOST = db\nPASSWD = hunter2-hunter2\nNOTE = token is {SECRET}\n")).unwrap();
    let (is_error, text) = s.tool("read_file_redacted", json!({ "path": path }));
    assert!(!is_error, "{text}");
    assert!(text.contains("HOST = db") && text.contains("[REDACTED:demo]"), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
}

#[test]
fn reads_are_confined_to_the_workspace() {
    let mut s = Server::start(&policy(), "approve");
    let outside = tempfile::tempdir().unwrap();
    let path = outside.path().join("other.txt");
    std::fs::write(&path, "nothing to see").unwrap();
    let (is_error, text) = s.tool("read_file_redacted", json!({ "path": path }));
    assert!(is_error && text.contains("outside"), "{text}");
    let key = s.home.path().join("id_ed25519");
    std::fs::write(&key, "-----BEGIN OPENSSH PRIVATE KEY-----").unwrap();
    let (is_error, text) = s.tool("read_file_redacted", json!({ "path": key }));
    assert!(is_error && text.contains("key or credential"), "{text}");
}

#[test]
fn over_long_requests_are_refused_before_approval() {
    let mut s = Server::start(&policy(), "approve");
    let padding = "a".repeat(800);
    let (is_error, text) =
        s.tool("run_with_secrets", json!({ "command": [exe(), "__echo", padding], "stdin": "{{secret:demo}}" }));
    assert!(is_error && text.contains("too long"), "{text}");
    assert!(!s.audit_log().contains("\"approved\":true"));
}

#[test]
fn request_secret_returns_instructions() {
    let mut s = Server::start(&policy(), "approve");
    let (is_error, text) =
        s.tool("request_secret", json!({ "name": "github-token", "description": "GitHub PAT $(touch /tmp/x)" }));
    assert!(!is_error && text.contains("keymitt add github-token"), "{text}");
    assert!(text.contains("--description 'GitHub PAT $(touch /tmp/x)'"), "description must be single-quoted: {text}");
    let (is_error, _) = s.tool("request_secret", json!({ "name": "demo" }));
    assert!(is_error, "existing names are reported");
}

/// A policy whose secret `demo` may run `keymitt __echo` only as its argument rules allow.
fn bound_policy(db: &std::path::Path) -> String {
    format!(
        r#"
[approval]
timeout_secs = 5

[secrets.demo]
channels = ["stdin"]
commands = ['{exe}']
redact_patterns = true

[secrets.demo.argv]
forbid = ["{{", "}}"]
paths = {{ database = '{db}' }}

[secrets.demo.argv.subcommands.__echo]
options = ["-q/--quiet", "-n/--name="]
positionals = ["@database", "text?"]
stdin = ["{{{{secret:demo}}}}\n"]
"#,
        exe = exe(),
        db = db.display()
    )
}

#[test]
fn argument_rules_decide_what_runs() {
    let home = tempfile::tempdir().unwrap();
    let db = home.path().canonicalize().unwrap().join("main.kdbx");
    std::fs::write(&db, "x").unwrap();
    std::fs::write(home.path().join("other.kdbx"), "x").unwrap();
    std::fs::write(home.path().join("policy.toml"), bound_policy(&db)).unwrap();
    let mut s = Server::start_in(home, "approve", json!({ "demo": SECRET, "other": OTHER }));

    let (is_error, text) = s.tool("list_secrets", json!({}));
    assert!(!is_error && text.contains("\"argv\"") && text.contains("__echo"), "{text}");

    // The program receives the canonical form: long options, the resolved database path.
    let (is_error, text) = s.tool(
        "run_with_secrets",
        json!({
            "command": [exe(), "__echo", "main.kdbx", "-qn", "x password=hunter2-hunter2", "Entry"],
            "stdin": "{{secret:demo}}\n"
        }),
    );
    assert!(!is_error, "{text}");
    for want in ["arg=--quiet", "arg=--name=x password=[REDACTED]", &format!("arg={}", plain(&db)), "arg=Entry"] {
        assert!(text.contains(want), "missing {want:?}: {text}");
    }
    assert!(text.contains("stdin=[REDACTED:demo]") && !text.contains("hunter2"), "{text}");
    assert!(s.audit_log().contains("__echo --quiet"), "the audit log records what ran");

    for (request, why) in [
        (json!({ "command": [exe(), "__echo", "main.kdbx", "-s"], "stdin": "{{secret:demo}}\n" }), "not allowed"),
        (
            json!({ "command": [exe(), "__echo", "main.kdbx", "--name={PASSWORD}"], "stdin": "{{secret:demo}}\n" }),
            "may not contain",
        ),
        (
            json!({ "command": [exe(), "__echo", "other.kdbx"], "stdin": "{{secret:demo}}\n" }),
            "must be the database file",
        ),
        (json!({ "command": [exe(), "__echo", "main.kdbx"], "stdin": "{{secret:demo}}\nmore\n" }), "stdin must be"),
        (
            json!({ "command": [exe(), "__echo", "main.kdbx"], "stdin": "{{secret:demo}}\n", "env": { "X_TOKEN": "{{secret:demo}}" } }),
            "via env",
        ),
        (json!({ "command": [exe(), "other-subcommand", "main.kdbx"], "stdin": "{{secret:demo}}\n" }), "not allowed"),
    ] {
        let (is_error, text) = s.tool("run_with_secrets", request.clone());
        assert!(is_error && text.contains(why), "{request}: {text}");
    }
}

const MASTER: &str = "kmt-Master-Pass-0042";
const STORED: &str = "kmt-Stored-Entry-0042";
const NEW_PASSWORD: &str = "kmt-New-Entry-Pass-0042";

fn keepassxc_cli() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("KEYMITT_TEST_KEEPASSXC") {
        return Some(path.into());
    }
    let name = if cfg!(windows) { "keepassxc-cli.exe" } else { "keepassxc-cli" };
    let on_path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join(name))
        .find(|p| p.is_file());
    on_path.or_else(|| {
        let mac = std::path::PathBuf::from("/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli");
        mac.is_file().then_some(mac)
    })
}

/// Runs keepassxc-cli directly (outside keymitt) and returns its standard output.
fn keepassxc(cli: &std::path::Path, args: &[&str], stdin: &str) -> String {
    let mut child = Command::new(cli)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "keepassxc-cli {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The `keepassxc` presets against the real keepassxc-cli. Skipped when it is not installed.
#[test]
fn keepassxc_presets_against_the_real_program() {
    let Some(cli) = keepassxc_cli() else {
        eprintln!("skipped: keepassxc-cli not found (set KEYMITT_TEST_KEEPASSXC to its path)");
        return;
    };
    let cli = cli.canonicalize().unwrap();
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().canonicalize().unwrap();
    let db = dir.join("main.kdbx").display().to_string();
    let other = dir.join("other.kdbx").display().to_string();
    for path in [&db, &other] {
        keepassxc(&cli, &["db-create", "-q", "-t", "100", "-p", path], &format!("{MASTER}\n{MASTER}\n"));
    }
    keepassxc(&cli, &["add", "-q", "-p", "-u", "bob", &db, "Gitea"], &format!("{MASTER}\n{STORED}\n"));

    // Set the policy up the way a person would.
    std::fs::write(dir.join("policy.toml"), "[approval]\ntimeout_secs = 5\n\n[secrets.kdbx]\n\n[secrets.newpw]\n")
        .unwrap();
    for (name, preset) in [("kdbx", "keepassxc"), ("newpw", "keepassxc-entry")] {
        let out = Command::new(exe())
            .args(["allow", name, "--preset", preset, "--database", &db, "--program"])
            .arg(&cli)
            .env("KEYMITT_HOME", &dir)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let mut s = Server::start_in(home, "approve", json!({ "kdbx": MASTER, "newpw": NEW_PASSWORD }));
    let mut call = |args: &[&str], stdin: &str| -> (bool, String) {
        let mut command = vec![cli.display().to_string()];
        command.extend(args.iter().map(|a| a.to_string()));
        let (is_error, text) = s.tool("run_with_secrets", json!({ "command": command, "stdin": stdin }));
        for value in [MASTER, STORED, NEW_PASSWORD] {
            assert!(!text.contains(value), "a password reached the agent: {text}");
        }
        (is_error, text)
    };
    let master = "{{secret:kdbx}}\n";

    let (is_error, text) = call(&["ls", "-q", &db], master);
    assert!(!is_error && text.contains("Gitea"), "{text}");
    let (is_error, text) = call(&["show", "-q", &db, "Gitea"], master);
    assert!(!is_error && text.contains("bob"), "{text}");

    let refused: [&[&str]; 12] = [
        &["show", "-a", "Password", &db, "Gitea"],
        &["show", "--attributes=Password", &db, "Gitea"],
        &["show", "-qs", &db, "Gitea"],
        &["show", "--show-protected", &db, "Gitea"],
        &["show", &db, "Gitea", "-a", "Password"],
        &["search", &db, "p:kmt*"],
        &["export", "-f", "csv", &db],
        &["clip", &db, "Gitea"],
        &["analyze", "-H", "/dev/null", &db],
        &["edit", "--notes", "{PASSWORD}", &db, "Gitea"],
        &["add", "--url", "{REF:P@T:Gitea}", &db, "Probe"],
        &["ls", &other],
    ];
    for args in refused {
        let (is_error, text) = call(args, master);
        assert!(is_error, "{args:?} ran: {text}");
    }
    let (is_error, _) = call(&["open", &db], &format!("{master}show -s {db} Gitea\n"));
    assert!(is_error);
    let (is_error, text) = call(&["ls", &db], &format!("{master}show -s {db} Gitea\n"));
    assert!(is_error && text.contains("stdin must be"), "{text}");
    let (is_error, _) = call(&["ls", &db], "{{secret:newpw}}\n");
    assert!(is_error, "the entry password cannot open the database");

    // Writes: an entry whose password comes from another secret, and a generated password.
    let (is_error, text) = call(&["add", "-qp", "-u", "alice", &db, "New"], "{{secret:kdbx}}\n{{secret:newpw}}\n");
    assert!(!is_error, "{text}");
    let (is_error, text) = call(&["edit", "-g", "-L", "24", &db, "Gitea"], master);
    assert!(!is_error, "{text}");

    // keepassxc-cli really received the values: check directly, outside keymitt.
    let unlock = format!("{MASTER}\n");
    assert_eq!(keepassxc(&cli, &["show", "-q", "-a", "Password", &db, "New"], &unlock).trim(), NEW_PASSWORD);
    let generated = keepassxc(&cli, &["show", "-q", "-a", "Password", &db, "Gitea"], &unlock);
    assert!(generated.trim().len() == 24 && generated.trim() != STORED, "{generated}");
}

/// A resolved path as keymitt hands it to programs: on Windows without the `\\?\` prefix.
fn plain(path: &std::path::Path) -> String {
    let s = path.display().to_string();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if cfg!(windows) => rest.to_string(),
        _ => s,
    }
}
