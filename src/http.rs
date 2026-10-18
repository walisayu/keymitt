//! HTTP requests sent by keymitt itself (through the system `curl`), so a
//! secret only ever travels to hosts the policy allows.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::exec::{OUTPUT_CAP, finish_output, read_capped};
use crate::policy::{Channel, Policy};
use crate::redact::Redactor;
use crate::template;

const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Headers curl or the transport must control; an agent setting them could reroute the
/// request (`Host` on a shared CDN) or desynchronise it.
const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "proxy-authorization",
    "proxy-connection",
];

const MAX_BODY_BYTES: usize = 1024 * 1024;
const STDERR_CAP: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const BODY_PREVIEW_CHARS: usize = 160;

#[derive(Debug, Clone)]
pub struct HttpSpec {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct Plan {
    pub url: url::Url,
    pub curl: PathBuf,
    pub secrets: BTreeSet<String>,
    pub summary: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct HttpOutput {
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub body_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub redactions: usize,
}

fn is_token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

pub fn plan(spec: &HttpSpec, policy: &Policy) -> Result<Plan> {
    let method = spec.method.to_ascii_uppercase();
    if !METHODS.contains(&method.as_str()) {
        bail!("unsupported method {}", spec.method);
    }
    if template::has_secret(&spec.url) || spec.url.contains("{{") {
        bail!("placeholders are not allowed in the URL; send secrets in a header or the body");
    }
    let url = url::Url::parse(&spec.url).with_context(|| format!("invalid URL {:?}", spec.url))?;
    if !matches!(url.scheme(), "https" | "http") {
        bail!("only http(s) URLs are supported");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("credentials in the URL are not allowed; use a header with a {{{{secret:NAME}}}} placeholder");
    }

    if spec.headers.len() > MAX_HEADERS {
        bail!("at most {MAX_HEADERS} headers");
    }
    if spec.body.as_ref().is_some_and(|b| b.len() > MAX_BODY_BYTES) {
        bail!("the body is limited to {MAX_BODY_BYTES} bytes");
    }
    let mut secrets = BTreeSet::new();
    for (name, value) in &spec.headers {
        if !is_token(name) {
            bail!("invalid header name {name:?}");
        }
        if FORBIDDEN_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            bail!("the {name} header cannot be set through keymitt");
        }
        if value.contains(['\r', '\n', '\0']) {
            bail!("header {name} contains a line break");
        }
        let refs = template::references(value);
        if !refs.files.is_empty() {
            bail!("file placeholders are not supported in http_request");
        }
        secrets.extend(refs.secrets);
    }
    if let Some(body) = &spec.body {
        let refs = template::references(body);
        if !refs.files.is_empty() {
            bail!("file placeholders are not supported in http_request");
        }
        secrets.extend(refs.secrets);
    }
    if secrets.is_empty() {
        bail!("this request uses no secrets; use your normal tools for it");
    }

    for name in &secrets {
        let Some(secret) = policy.secret(name) else {
            bail!("unknown secret {name:?}. Ask the user to add it with `keymitt add {name}`");
        };
        if !secret.allows_channel(Channel::Http) {
            bail!("policy does not allow secret {name:?} to be used with http_request");
        }
        if !secret.allows_url(&url) {
            bail!(
                "policy does not allow secret {name:?} to be sent to {}. The user can allow it with \
                 `keymitt allow {name} --host <host>`",
                url.origin().ascii_serialization()
            );
        }
    }

    let curl = crate::exec::find_on_path("curl").context("http_request needs `curl` on PATH")?;
    let names: Vec<_> = secrets.iter().cloned().collect();
    // What the human approves: where the secrets go first, then everything sent.
    let summary = format!("send {} → {}", names.join(", "), url.origin().ascii_serialization());
    let mut parts = vec![format!("{method} {url}")];
    for (name, value) in &spec.headers {
        parts.push(format!("{name}: {value}"));
    }
    if let Some(body) = &spec.body {
        let preview: String = body.chars().take(BODY_PREVIEW_CHARS).collect();
        let more = if body.chars().count() > BODY_PREVIEW_CHARS {
            format!("… ({} bytes)", body.len())
        } else {
            String::new()
        };
        parts.push(format!("body: {preview}{more}"));
    }
    let detail = parts.join(" | ");
    Ok(Plan { url, curl, secrets, summary, detail })
}

/// Quotes a value for a curl config file.
fn quote(value: &str) -> Result<String> {
    if value.contains(['\r', '\n', '\0']) {
        bail!("value contains a line break");
    }
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
}

fn parse_headers(dump: &str) -> (Option<u16>, Vec<(String, String)>) {
    // With interim responses (100 Continue) there are several blocks; keep the last.
    let block = dump
        .split("\r\n\r\n")
        .flat_map(|b| b.split("\n\n"))
        .filter(|b| b.trim_start().starts_with("HTTP/"))
        .last()
        .unwrap_or_default();
    let mut lines = block.lines();
    let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok());
    let headers =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    (status, headers)
}

pub async fn execute(
    spec: &HttpSpec,
    plan: &Plan,
    values: &HashMap<String, Zeroizing<String>>,
    redactor: &Redactor,
) -> Result<HttpOutput> {
    let dir = tempfile::Builder::new().prefix("keymitt-http-").tempdir()?;
    crate::config::restrict_dir(dir.path())?;
    let header_dump = dir.path().join("headers");

    let no_files = HashMap::new();
    let mut config = Zeroizing::new(String::new());
    let method = spec.method.to_ascii_uppercase();
    config.push_str(&format!("url = {}\n", quote(plan.url.as_str())?));
    if method == "HEAD" {
        config.push_str("head\n");
    } else {
        config.push_str(&format!("request = {}\n", quote(&method)?));
    }
    for (name, value) in &spec.headers {
        let value = template::render(value, values, &no_files)?;
        config.push_str(&format!("header = {}\n", quote(&format!("{name}: {}", value.as_str()))?));
    }
    let mut body_file = None;
    if let Some(body) = &spec.body {
        let path = dir.path().join("body");
        let rendered = template::render(body, values, &no_files)?;
        std::fs::write(&path, rendered.as_bytes())?;
        crate::config::restrict_file(&path)?;
        config.push_str(&format!("data-binary = {}\n", quote(&format!("@{}", path.display()))?));
        body_file = Some(path);
    }
    let proto = if plan.url.scheme() == "http" { "=http" } else { "=https" };
    config.push_str(&format!("proto = \"{proto}\"\nmax-redirs = 0\nsilent\nshow-error\n"));
    config.push_str(&format!("max-time = {}\n", spec.timeout.as_secs().max(1)));
    config.push_str(&format!("dump-header = {}\n", quote(&header_dump.display().to_string())?));

    let mut cmd = tokio::process::Command::new(&plan.curl);
    // --disable must come first: it stops curl from reading ~/.curlrc.
    cmd.args(["--disable", "--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().context("starting curl")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(config.as_bytes()).await?;
        stdin.shutdown().await?;
    }
    drop(config);

    let limit = OUTPUT_CAP + redactor.max_len();
    let stdout = tokio::spawn(read_capped(child.stdout.take().expect("piped"), limit));
    let stderr = tokio::spawn(read_capped(child.stderr.take().expect("piped"), STDERR_CAP + redactor.max_len()));
    let exit = match tokio::time::timeout(spec.timeout + Duration::from_secs(5), child.wait()).await {
        Ok(status) => status?.code(),
        Err(_) => {
            let _ = child.kill().await;
            None
        }
    };
    let (body, over) = stdout.await.unwrap_or_default();
    let (err, err_over) = stderr.await.unwrap_or_default();

    let dump = std::fs::read_to_string(&header_dump).unwrap_or_default();
    if let Some(path) = body_file {
        let _ = std::fs::remove_file(path);
    }
    drop(dir);

    let (status, raw_headers) = parse_headers(&dump);
    let mut redactions = 0;
    let headers = raw_headers
        .into_iter()
        .map(|(k, v)| {
            let (v, n) = redactor.redact_to_string(v.as_bytes());
            redactions += n;
            (k, v)
        })
        .collect();
    let (body, body_truncated, n) = finish_output(&body, over, redactor);
    redactions += n;
    let error = match exit {
        Some(0) => None,
        Some(code) => {
            let (text, _, n) = redactor.redact_capped(&err, err_over, STDERR_CAP);
            redactions += n;
            Some(format!("curl exited with {code}: {}", text.trim()))
        }
        None => Some("request timed out".into()),
    };
    Ok(HttpOutput { status, headers, body, body_truncated, error, redactions })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SecretPolicy;

    fn policy() -> Policy {
        let mut p = Policy::default();
        p.secrets.insert(
            "api".into(),
            SecretPolicy { channels: vec![Channel::Http], hosts: vec!["api.example.com".into()], ..Default::default() },
        );
        p
    }

    fn spec(url: &str, header: &str) -> HttpSpec {
        HttpSpec {
            method: "GET".into(),
            url: url.into(),
            headers: BTreeMap::from([("Authorization".into(), header.into())]),
            body: None,
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn host_allowlist() {
        if crate::exec::find_on_path("curl").is_err() {
            return;
        }
        assert!(plan(&spec("https://api.example.com/v1", "Bearer {{secret:api}}"), &policy()).is_ok());
        let err = plan(&spec("https://evil.example.net/", "Bearer {{secret:api}}"), &policy()).unwrap_err();
        assert!(err.to_string().contains("does not allow"));
    }

    #[test]
    fn rejects_injection() {
        assert!(plan(&spec("https://api.example.com/?k={{secret:api}}", "x"), &policy()).is_err());
        assert!(plan(&spec("https://u:p@api.example.com/", "Bearer {{secret:api}}"), &policy()).is_err());
        assert!(plan(&spec("https://api.example.com/", "x\r\nHost: evil {{secret:api}}"), &policy()).is_err());
        assert!(plan(&spec("ftp://api.example.com/", "Bearer {{secret:api}}"), &policy()).is_err());
    }

    #[test]
    fn forbidden_headers_and_prompt() {
        if crate::exec::find_on_path("curl").is_err() {
            return;
        }
        let mut s = spec("https://api.example.com/v1", "Bearer {{secret:api}}");
        s.headers.insert("Host".into(), "other-tenant.example.net".into());
        assert!(plan(&s, &policy()).unwrap_err().to_string().contains("Host header"));
        let s = spec("https://api.example.com/v1", "Bearer {{secret:api}}");
        let plan = plan(&s, &policy()).unwrap();
        assert_eq!(plan.summary, "send api → https://api.example.com");
        assert!(plan.detail.contains("Authorization: Bearer {{secret:api}}"));
    }

    #[test]
    fn config_quoting() {
        assert_eq!(quote(r#"a"b\c"#).unwrap(), r#""a\"b\\c""#);
        assert!(quote("a\nb").is_err());
    }

    #[test]
    fn header_dump_parsing() {
        let dump = "HTTP/1.1 100 Continue\r\n\r\nHTTP/2 201 \r\ncontent-type: application/json\r\nx-id: 7\r\n\r\n";
        let (status, headers) = parse_headers(dump);
        assert_eq!(status, Some(201));
        assert_eq!(headers[0], ("content-type".to_string(), "application/json".to_string()));
    }
}
