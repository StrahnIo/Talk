//! Shared template resolution and context helpers for the daemon.

use std::path::Path;
use talk_core::template::{TemplateError, TemplateSpec};

/// Resolve the template spec: explicit `template_path` if set (must exist),
/// else `<data_dir>/template.toml` if present, else the built-in default.
pub fn resolve_template(
    template_path: Option<&Path>,
    data_dir: &Path,
) -> Result<TemplateSpec, TemplateError> {
    if let Some(path) = template_path {
        return TemplateSpec::load(path, "invoice")?.ok_or_else(|| {
            TemplateError::Render(format!(
                "configured template file {} not found",
                path.display()
            ))
        });
    }
    match TemplateSpec::load(&data_dir.join("template.toml"), "invoice")? {
        Some(spec) => Ok(spec),
        None => Ok(TemplateSpec::default_invoice()),
    }
}

/// A human-readable UTC timestamp for the template context.
pub fn received_at() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

/// `n` random bytes as hex (message ids etc.).
pub fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
