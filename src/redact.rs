//! Output redaction.
//!
//! Two layers:
//! * [`Redactor`] replaces every known secret value — including common
//!   encodings of it (base64, URL-encoding, hex, JSON escaping) — with
//!   `[REDACTED:<name>]`.
//! * [`redact_patterns`] masks things that merely *look* like credentials
//!   (password fields, private keys, well-known token formats). It is used
//!   for files, where unknown secrets are likely.

use std::borrow::Cow;
use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use regex::{Captures, Regex};

/// Encoded variants are only generated for secrets at least this long;
/// shorter fragments would cause false positives.
const MIN_VARIANT_LEN: usize = 8;

pub struct Redactor {
    matcher: Option<AhoCorasick>,
    replacements: Vec<String>,
    max_len: usize,
}

impl Redactor {
    /// Builds a redactor for `(name, value)` pairs.
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut replacements = Vec::new();
        for (name, value) in secrets {
            if value.is_empty() {
                continue;
            }
            for variant in variants(value) {
                if !patterns.contains(&variant) {
                    patterns.push(variant);
                    replacements.push(format!("[REDACTED:{name}]"));
                }
            }
        }
        let max_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let matcher = (!patterns.is_empty()).then(|| {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)
                .expect("literal patterns always build")
        });
        Self { matcher, replacements, max_len }
    }

    /// Length of the longest pattern.
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// Redacts output that was read up to a limit, then keeps at most `cap` bytes.
    ///
    /// When `input_truncated` is set, the stream went on past `raw`, so a secret may
    /// start in the last `max_len - 1` bytes and end beyond them. Such a fragment can
    /// never match, and earlier (shorter) replacement markers would pull it into the
    /// returned text — so everything from that point on is dropped. A secret that was
    /// read completely and straddles that point is kept whole, so it is still redacted.
    /// Returns the text, whether anything was cut, and the number of redactions.
    pub fn redact_capped(&self, raw: &[u8], input_truncated: bool, cap: usize) -> (String, bool, usize) {
        let mut end = raw.len();
        if input_truncated {
            end = raw.len().saturating_sub(self.max_len.saturating_sub(1));
            if let Some(matcher) = &self.matcher {
                for m in matcher.find_iter(raw) {
                    if m.start() >= end {
                        break;
                    }
                    if m.end() > end {
                        end = m.end();
                        break;
                    }
                }
            }
        }
        let (text, count) = self.redact_to_string(&raw[..end]);
        if text.len() <= cap {
            return (text, input_truncated, count);
        }
        let mut cut = cap;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        (text[..cut].to_string(), true, count)
    }

    /// Returns the redacted bytes and how many replacements were made.
    pub fn redact_bytes(&self, input: &[u8]) -> (Vec<u8>, usize) {
        let Some(matcher) = &self.matcher else {
            return (input.to_vec(), 0);
        };
        let mut out = Vec::with_capacity(input.len());
        let mut count = 0;
        matcher.replace_all_with_bytes(input, &mut out, |m, _, dst| {
            count += 1;
            dst.extend_from_slice(self.replacements[m.pattern().as_usize()].as_bytes());
            true
        });
        (out, count)
    }

    /// Redacts and converts to text (invalid UTF-8 is replaced).
    pub fn redact_to_string(&self, input: &[u8]) -> (String, usize) {
        let (bytes, count) = self.redact_bytes(input);
        (String::from_utf8_lossy(&bytes).into_owned(), count)
    }
}

/// The forms in which a secret might show up in output.
fn variants(value: &str) -> Vec<Vec<u8>> {
    let raw = value.as_bytes();
    let mut out = vec![raw.to_vec()];
    let mut push = |v: Vec<u8>| {
        if !v.is_empty() && !out.contains(&v) {
            out.push(v);
        }
    };

    let json = serde_json::to_string(value).expect("strings serialize");
    push(json.as_bytes()[1..json.len() - 1].to_vec());

    if raw.len() >= MIN_VARIANT_LEN {
        // URL encodings: everything-but-alphanumerics, encodeURIComponent, and form
        // encoding ('+' for space), each also with lowercase hex digits.
        const URI_COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
            .remove(b'-')
            .remove(b'_')
            .remove(b'.')
            .remove(b'!')
            .remove(b'~')
            .remove(b'*')
            .remove(b'\'')
            .remove(b'(')
            .remove(b')');
        for encoded in [
            percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string(),
            percent_encoding::utf8_percent_encode(value, URI_COMPONENT).to_string(),
            url::form_urlencoded::byte_serialize(raw).collect::<String>(),
        ] {
            push(lowercase_percent_escapes(&encoded).into_bytes());
            push(encoded.into_bytes());
        }
        push(hex::encode(raw).into_bytes());
        push(hex::encode_upper(raw).into_bytes());
        // A secret embedded in a larger base64 blob encodes differently
        // depending on its offset modulo 3. Keep only the characters that
        // are fully determined by the secret's own bits.
        for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
            for offset in 0..3usize {
                let mut buf = vec![0u8; offset];
                buf.extend_from_slice(raw);
                let encoded = engine.encode(&buf);
                let start = (offset * 8).div_ceil(6);
                let end = ((offset + raw.len()) * 8) / 6;
                if end > start && end - start >= MIN_VARIANT_LEN {
                    push(encoded.as_bytes()[start..end].to_vec());
                }
            }
        }
    }
    out
}

/// `%2F` → `%2f`, leaving everything else alone.
fn lowercase_percent_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut hex_left = 0;
    for c in s.chars() {
        if hex_left > 0 {
            out.push(c.to_ascii_lowercase());
            hex_left -= 1;
        } else {
            if c == '%' {
                hex_left = 2;
            }
            out.push(c);
        }
    }
    out
}

const MASK: &str = "[REDACTED]";

static KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    // key = value / key: value / "key": "value", where the key name looks sensitive.
    Regex::new(
        r#"(?im)(?P<prefix>(?:^|[\s{,;(])[ \t]*(?:export[ \t]+)?["']?[A-Za-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth|jwt|signing[_-]?key|session[_-]?key|dsn|connection[_-]?string|conn[_-]?str)[A-Za-z0-9_.\-]*["']?[ \t]*[=:][ \t]*)(?P<value>"[^"\n]*"|'[^'\n]*'|(?:(?:bearer|basic|token)[ \t]+)?[^\s#;,]+)"#,
    )
    .expect("valid regex")
});

static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
        .expect("valid regex")
});

static TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(?:",
        r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", // JWT
        r"|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}",      // GitHub
        r"|glpat-[A-Za-z0-9_-]{20,}",                                     // GitLab
        r"|sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}",    // Anthropic / OpenAI
        r"|xox[abprs]-[A-Za-z0-9-]{10,}",                                 // Slack
        r"|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}",                            // AWS access key ids
        r"|AIza[0-9A-Za-z_-]{35}",                                        // Google API keys
        r"|npm_[A-Za-z0-9]{36}",                                          // npm
        r")"
    ))
    .expect("valid regex")
});

static URL_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<head>\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:)(?P<pass>[^\s@/]+)(?P<tail>@)").expect("valid regex")
});

/// Masks values that look like credentials. Returns the text and the number of masks applied.
pub fn redact_patterns(text: &str) -> (String, usize) {
    let mut count = 0;
    let text = PRIVATE_KEY.replace_all(text, |_: &Captures| {
        count += 1;
        "[REDACTED PRIVATE KEY]"
    });
    let text = URL_PASSWORD.replace_all(&text, |c: &Captures| {
        count += 1;
        format!("{}{MASK}{}", &c["head"], &c["tail"])
    });
    let text = KEY_VALUE.replace_all(&text, |c: &Captures| {
        let value = &c["value"];
        if value.starts_with("[REDACTED") || value.is_empty() {
            return c[0].to_string();
        }
        count += 1;
        let quote = match value.chars().next() {
            Some(q @ ('"' | '\'')) => Cow::Owned(q.to_string()),
            _ => Cow::Borrowed(""),
        };
        format!("{}{quote}{MASK}{quote}", &c["prefix"])
    });
    let text = TOKENS.replace_all(&text, |_: &Captures| {
        count += 1;
        MASK
    });
    (text.into_owned(), count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-Value_42!xyz";

    fn redact(input: &str) -> (String, usize) {
        Redactor::new([("demo", SECRET)]).redact_to_string(input.as_bytes())
    }

    #[test]
    fn raw_and_repeated() {
        let (out, n) = redact(&format!("a {SECRET} b {SECRET}"));
        assert_eq!(out, "a [REDACTED:demo] b [REDACTED:demo]");
        assert_eq!(n, 2);
    }

    #[test]
    fn encodings() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(SECRET);
        let url = percent_encoding::utf8_percent_encode(SECRET, percent_encoding::NON_ALPHANUMERIC).to_string();
        for encoded in [b64, url, hex::encode(SECRET), hex::encode_upper(SECRET)] {
            let (out, n) = redact(&format!("x={encoded};"));
            assert!(n >= 1, "{encoded} not redacted: {out}");
            assert!(!out.contains(&encoded));
        }
    }

    #[test]
    fn base64_at_any_offset() {
        for prefix in ["", "a", "ab", "abc", "user:"] {
            let blob = base64::engine::general_purpose::STANDARD.encode(format!("{prefix}{SECRET}"));
            let (out, n) = redact(&blob);
            assert!(n >= 1, "offset {} not caught: {blob} -> {out}", prefix.len());
        }
    }

    #[test]
    fn more_url_encodings() {
        let secret = "p@ss w/rd*(x)'!~";
        let r = Redactor::new([("s", secret)]);
        let form = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect::<String>();
        let lower = percent_encoding::utf8_percent_encode(secret, percent_encoding::NON_ALPHANUMERIC)
            .to_string()
            .to_lowercase();
        for encoded in [form, lower] {
            let (out, n) = r.redact_to_string(format!("q={encoded}&x=1").as_bytes());
            assert!(n >= 1, "{encoded} not redacted: {out}");
        }
    }

    #[test]
    fn partial_secret_at_read_limit_never_leaks() {
        // Several full occurrences shrink the text (marker shorter than the secret);
        // a secret cut by the read limit must not slide into the returned window.
        let secret = "SECRET-0123456789-abcdefghijklmnopqrstuvwxyz";
        let r = Redactor::new([("s", secret)]);
        let cap = 300;
        let limit = cap + r.max_len();
        let mut raw = Vec::new();
        for _ in 0..4 {
            raw.extend_from_slice(secret.as_bytes());
            raw.push(b' ');
        }
        let start = limit - 20; // 20 bytes of the secret fit, the rest was never read
        raw.resize(start, b'.');
        raw.extend_from_slice(&secret.as_bytes()[..20]);
        assert_eq!(raw.len(), limit);
        let (text, truncated, _) = r.redact_capped(&raw, true, cap);
        assert!(truncated);
        assert!(!text.contains(&secret[..8]), "a secret prefix leaked: {text}");
    }

    #[test]
    fn json_escaped() {
        let tricky = "pa\"ss\\word\n12";
        let r = Redactor::new([("t", tricky)]);
        let json = serde_json::to_string(&serde_json::json!({ "p": tricky })).unwrap();
        let (out, n) = r.redact_to_string(json.as_bytes());
        assert_eq!(n, 1, "{out}");
    }

    #[test]
    fn longest_match_and_multiple_secrets() {
        let r = Redactor::new([("short", "abcdefgh"), ("long", "abcdefgh-ijkl")]);
        let (out, _) = r.redact_to_string(b"abcdefgh-ijkl abcdefgh");
        assert_eq!(out, "[REDACTED:long] [REDACTED:short]");
    }

    #[test]
    fn no_secrets_is_identity() {
        let r = Redactor::new(std::iter::empty::<(&str, &str)>());
        assert_eq!(r.redact_to_string(b"hello").0, "hello");
    }

    #[test]
    fn patterns_in_config_files() {
        let ini = "[database]\nUSER = gitea\nPASSWD = hunter2-example\nSECRET_KEY = abcdef\nLFS_JWT_SECRET = xyz123\nDOMAIN = example.com\n";
        let (out, n) = redact_patterns(ini);
        assert_eq!(n, 3, "{out}");
        assert!(out.contains("USER = gitea") && out.contains("DOMAIN = example.com"));
        assert!(!out.contains("hunter2-example") && !out.contains("abcdef") && !out.contains("xyz123"));

        let env = "export API_TOKEN=\"tok\"\nDATABASE_URL=postgres://app:hunter2@db:5432/x\n";
        let (out, _) = redact_patterns(env);
        assert!(!out.contains("tok\"") && !out.contains("hunter2"), "{out}");
        assert!(out.contains("postgres://app:[REDACTED]@db"));

        let json = r#"{"client_secret": "abc", "name": "x"}"#;
        let (out, _) = redact_patterns(json);
        assert!(!out.contains("abc") && out.contains(r#""name": "x""#), "{out}");

        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(redact_patterns(pem).0, "[REDACTED PRIVATE KEY]");

        let tok = "token ghp_0123456789abcdefghijABCDEFGHIJ0123 here";
        assert!(!redact_patterns(tok).0.contains("ghp_"));
    }
}
