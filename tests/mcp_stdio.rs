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
        let mut child = Command::new(env!("CARGO_BIN_EXE_keymitt"))
            .arg("mcp")
            .current_dir(home.path())
            .env("KEYMITT_HOME", home.path())
            .env("KEYMITT_TEST_VAULT", json!({ "demo": SECRET, "other": OTHER }).to_string())
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
