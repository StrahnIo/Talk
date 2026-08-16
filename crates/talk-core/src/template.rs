//! Message templating: the swappable `TemplateEngine` and the built-in Tera
//! implementation.
//!
//! A [`TemplateSpec`] is a pair of Tera template strings — `subject` and `body`
//! — rendered from a shared context. Specs load from a `template.toml` file or
//! fall back to a built-in default, so delivery content is operator-tunable
//! without a code change.

use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("template parse/render error: {0}")]
    Render(String),
}

/// A subject + body template pair (Tera syntax), rendered from one context.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSpec {
    /// Tera template for the message subject.
    pub subject: String,
    /// Tera template for the message body.
    pub body: String,
}

impl TemplateSpec {
    /// The built-in invoice template, used when no `template.toml` override is
    /// configured. Context: `sender_name`, `sender_address`, `amount`,
    /// `invoice`, `received_at`.
    pub fn default_invoice() -> Self {
        Self {
            subject: "Invoice from {{ sender_name }}".to_string(),
            body: [
                "From:     {{ sender_name }}",
                "Address:  {{ sender_address }}",
                "Amount:   {{ amount }} ZEC",
                "Received: {{ received_at }}",
                "",
                "{{ invoice }}",
            ]
            .join("\n"),
        }
    }

    /// Load a spec from a `template.toml` file (keyed by template name).
    ///
    /// `None` when the file does not exist; any other IO or parse error is
    /// surfaced so a misconfigured override fails loudly rather than silently
    /// falling back.
    pub fn load(path: &Path, name: &str) -> Result<Option<TemplateSpec>, TemplateError> {
        match std::fs::read_to_string(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(raw) => {
                let map: std::collections::HashMap<String, TemplateSpec> =
                    toml::from_str(&raw).map_err(|e| TemplateError::Render(e.to_string()))?;
                map.get(name)
                    .cloned()
                    .ok_or_else(|| {
                        TemplateError::Render(format!(
                            "template.toml {} has no [{}] section",
                            path.display(),
                            name
                        ))
                    })
                    .map(Some)
            }
        }
    }
}

/// A message templating engine.
pub trait TemplateEngine: Send + Sync {
    /// Render a single template string against a JSON context.
    fn render(&self, template: &str, data: &serde_json::Value) -> Result<String, TemplateError>;
}

/// The Tera-based template engine.
#[derive(Debug, Default)]
pub struct TeraEngine;

impl TemplateEngine for TeraEngine {
    fn render(&self, template: &str, data: &serde_json::Value) -> Result<String, TemplateError> {
        let mut ctx = tera::Context::new();
        if let Some(obj) = data.as_object() {
            for (k, v) in obj {
                ctx.insert(k, v);
            }
        }
        tera::Tera::one_off(template, &ctx, false).map_err(|e| TemplateError::Render(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn render(t: &TemplateSpec, data: &serde_json::Value) -> (String, String) {
        let engine = TeraEngine;
        (
            engine.render(&t.subject, data).expect("subject"),
            engine.render(&t.body, data).expect("body"),
        )
    }

    #[test]
    fn default_invoice_renders_fields() {
        let spec = TemplateSpec::default_invoice();
        let data = json!({
            "sender_name": "Alice Smith",
            "sender_address": "t1abc",
            "amount": "1.5",
            "invoice": "line one\nline two",
            "received_at": "2026-08-16"
        });
        let (subject, body) = render(&spec, &data);
        assert_eq!(subject, "Invoice from Alice Smith");
        assert!(body.contains("From:     Alice Smith"));
        assert!(body.contains("Address:  t1abc"));
        assert!(body.contains("Amount:   1.5 ZEC"));
        assert!(body.contains("Received: 2026-08-16"));
        assert!(body.contains("line one\nline two"));
    }

    #[test]
    fn bad_template_fails() {
        let engine = TeraEngine;
        let err = engine
            .render("{{ sender_name", &serde_json::Value::Null)
            .expect_err("unclosed tag");
        assert!(matches!(err, TemplateError::Render(_)));
    }

    #[test]
    fn template_spec_roundtrips_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("template.toml");
        std::fs::write(
            &path,
            "[invoice]\nsubject = \"Hi {{ sender_name }}\"\nbody = \"Amt {{ amount }}\"\n",
        )
        .unwrap();
        let spec = TemplateSpec::load(&path, "invoice")
            .expect("load")
            .expect("some");
        assert_eq!(spec.subject, "Hi {{ sender_name }}");
        assert_eq!(spec.body, "Amt {{ amount }}");
    }

    #[test]
    fn missing_template_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let spec = TemplateSpec::load(&dir.path().join("nope.toml"), "invoice").expect("load");
        assert!(spec.is_none());
    }

    #[test]
    fn template_toml_missing_key_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("template.toml");
        std::fs::write(&path, "[other]\nsubject = \"x\"\nbody = \"y\"\n").unwrap();
        assert!(TemplateSpec::load(&path, "invoice").is_err());
    }
}
