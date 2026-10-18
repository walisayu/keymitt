//! The MCP server agents talk to (stdio).

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::approval::{Approver, Decision, Request};
use crate::audit::{self, Event};
use crate::config::Paths;
use crate::exec::{self, FileSpec, RunSpec};
use crate::files;
use crate::http::{self, HttpSpec};
use crate::policy::{Policy, validate_name};
use crate::redact::Redactor;
use crate::vault::{self, Vault};

const INSTRUCTIONS: &str = "\
keymitt lets you use the user's secrets (API tokens, passwords, keys) without ever seeing them.

Rules:
- Never ask the user to paste a secret into the chat. If a secret you need is missing, call request_secret.
- Call list_secrets to see which secrets exist and how each may be used.
- Refer to a secret with the placeholder {{secret:NAME}}. keymitt substitutes the value at the last moment.
- For HTTP APIs prefer http_request. For programs use run_with_secrets and pass secrets through stdin, \
env values or temporary files — never as command-line arguments.
- Every use asks the user to approve on their own device (Touch ID, Windows Hello, polkit...). \
If a request is denied, do not retry it unchanged; ask the user what they want instead.
- All output is redacted: secret values (and encodings of them) appear as [REDACTED:NAME].
- To inspect config files that may contain credentials (.env, app.ini, settings files), \
use read_file_redacted instead of cat or a file reader.";

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunParams {
    /// Program and arguments, e.g. ["curl", "-sS", "--config", "-"]. Not run through a shell.
    /// The program must be a bare name found on PATH or an absolute path.
    /// Arguments may contain {{file:ID}} but never {{secret:NAME}}.
    pub command: Vec<String>,
    /// Text written to the program's standard input. May contain {{secret:NAME}} and {{file:ID}}.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Environment variables to set for the program. Every value must contain a {{secret:NAME}}
    /// placeholder, e.g. {"GITHUB_TOKEN": "{{secret:github}}"}.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Temporary owner-only files, deleted after the run. Their content may contain {{secret:NAME}};
    /// refer to their path as {{file:ID}} in command, stdin or env.
    #[serde(default)]
    pub files: Vec<FileParam>,
    /// Working directory (absolute path). Defaults to the server's working directory.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Seconds before the program is killed. Default 60, maximum 600.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FileParam {
    /// Identifier used in {{file:ID}} (letters, digits, - and _).
    pub id: String,
    /// File content; may contain {{secret:NAME}}.
    pub content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HttpParams {
    /// HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS). Default GET.
    #[serde(default)]
    pub method: Option<String>,
    /// Full URL. Must not contain placeholders. The host must be allowed for every secret used.
    pub url: String,
    /// Request headers; values may contain {{secret:NAME}}, e.g. {"Authorization": "Bearer {{secret:github}}"}.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Request body; may contain {{secret:NAME}}.
    #[serde(default)]
    pub body: Option<String>,
    /// Seconds before giving up. Default 30, maximum 300.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadFileParams {
    /// Path of the file to read (absolute, or relative to the server's working directory).
    pub path: String,
    /// Maximum bytes to return. Default 262144.
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RequestSecretParams {
    /// Suggested name for the secret (letters, digits, . _ -), e.g. "github-token".
    pub name: String,
    /// What the secret is, e.g. "GitHub fine-grained token with repo read access".
    #[serde(default)]
    pub description: Option<String>,
    /// How you intend to use it: program names and/or API hosts.
    #[serde(default)]
    pub intended_use: Option<String>,
}

#[derive(Serialize)]
struct SecretInfo<'a> {
    name: &'a str,
    description: &'a str,
    channels: Vec<String>,
    commands: &'a [String],
    hosts: &'a [String],
    usable: bool,
}

struct Inner {
    paths: Paths,
    policy: Policy,
    files: files::FileAccess,
    vault: Box<dyn Vault>,
    approver: Approver,
    approvals: Mutex<HashMap<String, Instant>>,
}

#[derive(Clone)]
pub struct KeymittServer {
    inner: Arc<Inner>,
    #[allow(dead_code, reason = "read by the tool_handler macro")]
    tool_router: ToolRouter<Self>,
}

fn text_result(value: &impl Serialize) -> CallToolResult {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
    CallToolResult::success(vec![ContentBlock::text(text)])
}

fn error_result(message: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.to_string())])
}

fn denied_result(decision: &Decision) -> CallToolResult {
    error_result(format!(
        "The user did not approve this request ({}{}). Do not retry it unchanged; ask the user how to proceed.",
        decision.method,
        decision.note.as_deref().map(|n| format!(": {n}")).unwrap_or_default()
    ))
}

impl KeymittServer {
    pub fn new(paths: Paths, policy: Policy, vault: Box<dyn Vault>) -> Self {
        let approver = Approver::new(policy.approval.clone(), paths.clone());
        let workspace = std::env::current_dir().ok();
        let files = files::FileAccess::new(workspace.as_deref(), &policy.files.read_roots);
        Self {
            inner: Arc::new(Inner { paths, policy, files, vault, approver, approvals: Mutex::new(HashMap::new()) }),
            tool_router: Self::tool_router(),
        }
    }

    /// Loads the values of `names` from the vault (on a blocking thread).
    async fn load(&self, names: Vec<String>) -> Result<HashMap<String, Zeroizing<String>>> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut values = HashMap::new();
            for name in names {
                match inner.vault.get(&name)? {
                    Some(v) => {
                        values.insert(name, v);
                    }
                    None => anyhow::bail!(
                        "secret {name:?} is in the policy but has no value; ask the user to run `keymitt update {name}`"
                    ),
                }
            }
            Ok(values)
        })
        .await?
    }

    /// A redactor for every registered secret, not just the ones in use.
    async fn redactor(&self) -> Result<Redactor> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut pairs = Vec::new();
            for name in inner.policy.secrets.keys() {
                if let Some(v) = inner.vault.get(name)? {
                    pairs.push((name.clone(), v));
                }
            }
            Ok(Redactor::new(pairs.iter().map(|(n, v)| (n.as_str(), v.as_str()))))
        })
        .await?
    }

    async fn approve(&self, request: Request, fingerprint: String) -> Decision {
        let ttl = Duration::from_secs(self.inner.policy.approval.ttl_secs);
        if !ttl.is_zero() {
            let cache = self.inner.approvals.lock().unwrap();
            if cache.get(&fingerprint).is_some_and(|t| t.elapsed() < ttl) {
                return Decision::approved("remembered", false);
            }
        }
        let inner = self.inner.clone();
        let decision = tokio::task::spawn_blocking(move || inner.approver.request(&request, false))
            .await
            .unwrap_or_else(|e| Decision::denied("error", false, e.to_string()));
        if decision.approved && !ttl.is_zero() {
            self.inner.approvals.lock().unwrap().insert(fingerprint, Instant::now());
        }
        decision
    }

    fn record(&self, event: Event) {
        audit::record(&self.inner.paths, &event);
    }

    /// Error text for the agent, with every registered secret value removed.
    async fn redacted_error(&self, e: &anyhow::Error) -> CallToolResult {
        let message = format!("{e:#}");
        match self.redactor().await {
            Ok(r) => error_result(r.redact_to_string(message.as_bytes()).0),
            Err(_) => error_result("the request failed (details withheld because they could not be redacted)"),
        }
    }
}

#[tool_router]
impl KeymittServer {
    #[tool(description = "List the secrets you may use (names, descriptions and allowed uses — never values).")]
    async fn list_secrets(&self) -> CallToolResult {
        let secrets: Vec<SecretInfo> = self
            .inner
            .policy
            .secrets
            .iter()
            .map(|(name, s)| SecretInfo {
                name,
                description: &s.description,
                channels: s.channels.iter().map(ToString::to_string).collect(),
                commands: &s.commands,
                hosts: &s.hosts,
                usable: s.is_usable(),
            })
            .collect();
        text_result(&serde_json::json!({
            "secrets": secrets,
            "placeholder": "{{secret:NAME}}",
            "approval": "each use is approved by the user on their device",
        }))
    }

    #[tool(description = "Run a program with secrets injected via stdin, environment variables or temporary files. \
The user approves each run on their device. Output is returned with all secret values redacted. \
Example: {\"command\": [\"curl\", \"-sS\", \"--config\", \"-\"], \"stdin\": \"url = \\\"https://api.example.com/me\\\"\\nheader = \\\"Authorization: Bearer {{secret:api}}\\\"\"}")]
    async fn run_with_secrets(&self, Parameters(p): Parameters<RunParams>) -> CallToolResult {
        let spec = RunSpec {
            command: p.command,
            stdin: p.stdin,
            env: p.env,
            files: p.files.into_iter().map(|f| FileSpec { id: f.id, content: f.content }).collect(),
            cwd: p.cwd.map(PathBuf::from),
            timeout: Duration::from_secs(p.timeout_secs.unwrap_or(60).clamp(1, 600)),
        };
        let action = exec::display_command(&spec.command);
        let mut event = Event::new("run");
        event.action = Some(action);

        let plan = match exec::plan(&spec, &self.inner.policy) {
            Ok(plan) => plan,
            Err(e) => {
                event.outcome = Some(format!("rejected: {e}"));
                self.record(event);
                return error_result(e);
            }
        };
        event.secrets = plan.secrets.iter().cloned().collect();

        let request = Request::new(event.secrets.clone(), plan.summary.clone(), plan.detail.clone());
        if let Err(e) = request.check_length() {
            event.outcome = Some(format!("rejected: {e}"));
            self.record(event);
            return error_result(e);
        }
        let fingerprint = format!(
            "run\0{}\0{:?}\0{:?}\0{:?}\0{:?}\0{:?}",
            plan.program.display(),
            spec.command,
            spec.stdin,
            spec.env,
            spec.files,
            spec.cwd
        );
        let decision = self.approve(request, fingerprint).await;
        event.approval = Some(decision.clone());
        if !decision.approved {
            event.outcome = Some("denied".into());
            self.record(event);
            return denied_result(&decision);
        }

        let result = async {
            let values = self.load(event.secrets.clone()).await?;
            let redactor = self.redactor().await?;
            exec::execute(&spec, &plan, &values, &redactor).await
        }
        .await;
        match result {
            Ok(output) => {
                event.outcome = Some(match (output.timed_out, output.exit_code) {
                    (true, _) => "timed out".into(),
                    (_, Some(code)) => format!("exit {code}"),
                    (_, None) => "killed by signal".into(),
                });
                event.redactions = Some(output.redactions);
                self.record(event);
                text_result(&output)
            }
            Err(e) => {
                event.outcome = Some("error".into());
                self.record(event);
                self.redacted_error(&e).await
            }
        }
    }

    #[tool(
        description = "Send an HTTP request with secrets in headers or the body. keymitt sends it itself (via curl), \
only to hosts the policy allows for those secrets, without following redirects. The user approves each request. \
Example: {\"url\": \"https://api.github.com/user\", \"headers\": {\"Authorization\": \"Bearer {{secret:github}}\"}}"
    )]
    async fn http_request(&self, Parameters(p): Parameters<HttpParams>) -> CallToolResult {
        let spec = HttpSpec {
            method: p.method.unwrap_or_else(|| "GET".into()),
            url: p.url,
            headers: p.headers,
            body: p.body,
            timeout: Duration::from_secs(p.timeout_secs.unwrap_or(30).clamp(1, 300)),
        };
        let mut event = Event::new("http");
        event.action = Some(format!("{} {}", spec.method.to_ascii_uppercase(), spec.url));

        let plan = match http::plan(&spec, &self.inner.policy) {
            Ok(plan) => plan,
            Err(e) => {
                event.outcome = Some(format!("rejected: {e}"));
                self.record(event);
                return error_result(e);
            }
        };
        event.secrets = plan.secrets.iter().cloned().collect();

        let request = Request::new(event.secrets.clone(), plan.summary.clone(), plan.detail.clone());
        if let Err(e) = request.check_length() {
            event.outcome = Some(format!("rejected: {e}"));
            self.record(event);
            return error_result(e);
        }
        let fingerprint = format!("http\0{}\0{}\0{:?}\0{:?}", spec.method, spec.url, spec.headers, spec.body);
        let decision = self.approve(request, fingerprint).await;
        event.approval = Some(decision.clone());
        if !decision.approved {
            event.outcome = Some("denied".into());
            self.record(event);
            return denied_result(&decision);
        }

        let result = async {
            let values = self.load(event.secrets.clone()).await?;
            let redactor = self.redactor().await?;
            http::execute(&spec, &plan, &values, &redactor).await
        }
        .await;
        match result {
            Ok(output) => {
                event.outcome = Some(match (&output.error, output.status) {
                    (Some(e), _) => e.clone(),
                    (None, Some(status)) => format!("HTTP {status}"),
                    (None, None) => "no response".into(),
                });
                event.redactions = Some(output.redactions);
                self.record(event);
                text_result(&output)
            }
            Err(e) => {
                event.outcome = Some("error".into());
                self.record(event);
                self.redacted_error(&e).await
            }
        }
    }

    #[tool(
        description = "Read a text file with credentials masked: values of all registered secrets plus anything that \
looks like a password, token, private key or connection-string password. Use this instead of cat for config files."
    )]
    async fn read_file_redacted(&self, Parameters(p): Parameters<ReadFileParams>) -> CallToolResult {
        let path = PathBuf::from(&p.path);
        let max = p.max_bytes.unwrap_or(files::DEFAULT_MAX_BYTES).clamp(1, 4 * 1024 * 1024);
        let mut event = Event::new("read_file");
        event.action = Some(path.display().to_string());
        let result = async {
            let redactor = self.redactor().await?;
            let access = self.inner.files.clone();
            tokio::task::spawn_blocking(move || files::read_redacted(&path, max, &redactor, &access)).await?
        }
        .await;
        match result {
            Ok(out) => {
                event.redactions = Some(out.known_secrets_masked + out.patterns_masked);
                self.record(event);
                text_result(&out)
            }
            Err(e) => {
                event.outcome = Some("error".into());
                self.record(event);
                self.redacted_error(&e).await
            }
        }
    }

    #[tool(description = "Ask the user to store a secret you need. Returns the exact command for the user to run in \
their own terminal. Never ask for the value in chat.")]
    async fn request_secret(&self, Parameters(p): Parameters<RequestSecretParams>) -> CallToolResult {
        if let Err(e) = validate_name(&p.name) {
            return error_result(e);
        }
        if self.inner.policy.secrets.contains_key(&p.name) {
            return error_result(format!(
                "secret {:?} already exists. If its value is missing or wrong, ask the user to run `keymitt update {}`.",
                p.name, p.name
            ));
        }
        let mut command = format!("keymitt add {}", p.name);
        if let Some(d) = p.description.as_deref().filter(|d| !d.is_empty()) {
            // Single quotes: nothing inside is expanded when the user pastes the command.
            let d: String = crate::approval::printable(d).chars().take(200).collect();
            command.push_str(&format!(" --description '{}'", d.replace('\'', r"'\''")));
        }
        command.push_str(" --command <program> --host <api-host>");
        text_result(&serde_json::json!({
            "tell_the_user": format!(
                "Please store this secret yourself by running in a terminal:\n  {command}\n\
                 Replace <program>/<api-host> with what it may be used for{}, or drop the flags you don't need. \
                 keymitt will prompt for the value without echoing it; if you have copied the value, add \
                 --from-clipboard to read it from the clipboard instead. Do not paste the value into this chat.\n\
                 Then restart the keymitt MCP server so it picks up the new policy.",
                p.intended_use
                    .map(|u| format!(
                        " (intended use: {})",
                        crate::approval::printable(&u).chars().take(200).collect::<String>()
                    ))
                    .unwrap_or_default()
            ),
        }))
    }
}

#[tool_handler]
impl ServerHandler for KeymittServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("keymitt", env!("CARGO_PKG_VERSION"))
                    .with_title("keymitt — use secrets without seeing them"),
            )
            .with_instructions(INSTRUCTIONS)
    }
}

pub async fn serve(paths: Paths) -> Result<()> {
    let policy = Policy::load(&paths.policy_file())?;
    let vault = vault::open()?;
    tracing::info!(secrets = policy.secrets.len(), backend = vault.backend(), "keymitt MCP server starting");
    let server = KeymittServer::new(paths, policy, vault);
    let running = server.serve(rmcp::transport::stdio()).await?;
    running.waiting().await?;
    Ok(())
}
