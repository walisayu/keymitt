//! Placeholders that agents use to refer to secrets and temp files.
//!
//! * `{{secret:NAME}}` — replaced by the secret's value.
//! * `{{file:ID}}` — replaced by the path of a temporary file the agent
//!   declared in the same request.

use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use anyhow::{Result, bail};
use regex::{Captures, Regex};
use zeroize::Zeroizing;

static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{\s*(?P<kind>secret|file)\s*:\s*(?P<name>[A-Za-z0-9._-]+)\s*\}\}").expect("valid regex")
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct References {
    pub secrets: BTreeSet<String>,
    pub files: BTreeSet<String>,
}

pub fn references(text: &str) -> References {
    let mut refs = References::default();
    for c in PLACEHOLDER.captures_iter(text) {
        let name = c["name"].to_string();
        match &c["kind"] {
            "secret" => refs.secrets.insert(name),
            _ => refs.files.insert(name),
        };
    }
    refs
}

pub fn has_secret(text: &str) -> bool {
    !references(text).secrets.is_empty()
}

/// Substitutes placeholders. Every referenced name must be present.
pub fn render(
    text: &str,
    secrets: &HashMap<String, Zeroizing<String>>,
    files: &HashMap<String, String>,
) -> Result<Zeroizing<String>> {
    let mut missing = None;
    let rendered = PLACEHOLDER.replace_all(text, |c: &Captures| {
        let name = &c["name"];
        let value = match &c["kind"] {
            "secret" => secrets.get(name).map(|v| v.as_str()),
            _ => files.get(name).map(String::as_str),
        };
        match value {
            Some(v) => v.to_string(),
            None => {
                missing.get_or_insert_with(|| format!("{}:{name}", &c["kind"]));
                String::new()
            }
        }
    });
    let rendered = Zeroizing::new(rendered.into_owned());
    if let Some(what) = missing {
        bail!("unknown placeholder {{{{{what}}}}}");
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_and_renders() {
        let text = "Authorization: Bearer {{secret:api}} --config {{ file : cfg }} {{secret:api}}";
        let refs = references(text);
        assert_eq!(refs.secrets.iter().collect::<Vec<_>>(), ["api"]);
        assert_eq!(refs.files.iter().collect::<Vec<_>>(), ["cfg"]);

        let secrets = HashMap::from([("api".to_string(), Zeroizing::new("T0K".to_string()))]);
        let files = HashMap::from([("cfg".to_string(), "/tmp/x".to_string())]);
        let out = render(text, &secrets, &files).unwrap();
        assert_eq!(out.as_str(), "Authorization: Bearer T0K --config /tmp/x T0K");
    }

    #[test]
    fn missing_is_an_error() {
        let err = render("{{secret:nope}}", &HashMap::new(), &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("secret:nope"));
    }

    #[test]
    fn ordinary_braces_untouched() {
        assert!(references("{{ .Values.x }} {{secret}} {secret:x}").secrets.is_empty());
    }
}
