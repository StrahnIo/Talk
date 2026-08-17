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
    /// `invoice`, `received_at`. Renders a minimal HTML form (the amount row
    /// is omitted when `amount` is empty).
    pub fn default_invoice() -> Self {
        Self {
            subject: "Invoice from {{ sender_name }}".to_string(),
            body: [
                "<!DOCTYPE html>",
                "<html><head><meta charset=\"utf-8\"><title>Invoice</title></head>",
                "<body style=\"margin:0;padding:0;background:#f4f6f8;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;color:#1a2027;\">",
                "  <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"padding:32px 0;\"><tr><td align=\"center\">",
                "    <table role=\"presentation\" width=\"520\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#ffffff;border-radius:10px;box-shadow:0 2px 8px rgba(26,32,39,0.08);\">",
                "      <tr><td style=\"background:#111827;padding:18px 26px;\"><span style=\"color:#fff;font-weight:700;\">Invoice</span></td></tr>",
                "      <tr><td style=\"padding:26px 30px;\">",
                "        <div style=\"font-size:12px;color:#6b7280;text-transform:uppercase;\">From</div>",
                "        <div style=\"font-size:18px;font-weight:700;\">{{ sender_name | escape }}</div>",
                "        <div style=\"font-size:13px;color:#6b7280;\">{{ sender_address | escape }}</div>",
                "        {% if amount %}",
                "        <div style=\"margin-top:20px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:14px 18px;\">",
                "          <span style=\"color:#6b7280;\">Amount due:</span>",
                "          <span style=\"font-size:22px;font-weight:800;float:right;\">{{ amount | escape }} ZEC</span>",
                "        </div>",
                "        {% endif %}",
                "        <div style=\"margin-top:18px;font-size:12px;color:#6b7280;text-transform:uppercase;\">Invoice</div>",
                "        <pre style=\"margin:6px 0 0;padding:12px 14px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;font-size:13px;white-space:pre-wrap;\">{{ invoice | escape }}</pre>",
                "        <div style=\"margin-top:18px;font-size:12px;color:#9ca3af;\">Received {{ received_at }}</div>",
                "      </td></tr>",
                "    </table>",
                "  </td></tr></table>",
                "</body></html>",
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

/// Render both templates of a spec against the invoice context.
///
/// Context: `sender_name`, `sender_address`, `amount`, `invoice`,
/// `received_at`. Returns `(subject, body)`.
pub fn render_invoice(
    spec: &TemplateSpec,
    sender_name: &str,
    sender_address: &str,
    amount: &str,
    invoice: &str,
    received_at: &str,
) -> Result<(String, String), TemplateError> {
    let data = serde_json::json!({
        "sender_name": sender_name,
        "sender_address": sender_address,
        "amount": amount,
        "invoice": invoice,
        "received_at": received_at,
    });
    let engine = TeraEngine;
    let subject = engine.render(&spec.subject, &data)?;
    let body = engine.render(&spec.body, &data)?;
    Ok((subject, body))
}

/// A human-readable UTC timestamp for the template context.
pub fn received_at() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Resolve the template spec: explicit `template_path` if set (must exist),
/// else `<data_dir>/template.toml` if present, else the built-in default.
pub fn resolve_template(
    template_path: Option<&Path>,
    data_dir: &Path,
) -> Result<TemplateSpec, TemplateError> {
    if let Some(path) = template_path {
        return TemplateSpec::load(path, "invoice")?.ok_or_else(|| {
            TemplateError::Render(format!("configured template file {} not found", path.display()))
        });
    }
    match TemplateSpec::load(&data_dir.join("template.toml"), "invoice")? {
        Some(spec) => Ok(spec),
        None => Ok(TemplateSpec::default_invoice()),
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
        assert!(body.contains("<!DOCTYPE html>"), "{body}");
        assert!(body.contains("Alice Smith"), "{body}");
        assert!(body.contains("t1abc"), "{body}");
        assert!(body.contains("1.5 ZEC"), "{body}");
        assert!(body.contains("line one\nline two"), "{body}");
        assert!(body.contains("Received 2026-08-16"), "{body}");
    }

    #[test]
    fn default_invoice_omits_empty_amount() {
        let spec = TemplateSpec::default_invoice();
        let data = json!({
            "sender_name": "bob@example.org",
            "sender_address": "bob@example.org",
            "amount": "",
            "invoice": "invoice text",
            "received_at": "2026-08-16"
        });
        let (_, body) = render(&spec, &data);
        assert!(body.contains("invoice text"), "{body}");
        assert!(!body.contains("Amount due"), "no amount row: {body}");
        assert!(!body.contains("ZEC"), "no empty amount: {body}");
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
