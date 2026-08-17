//! Shared template resolution and context helpers for the daemon.

use std::path::Path;
use talk_core::template::{TemplateError, TemplateSpec};

/// Resolve the template spec: explicit `template_path` if set (must exist),
/// else `<data_dir>/template.toml` if present, else the built-in default.
pub fn resolve_template(
    template_path: Option<&Path>,
    data_dir: &Path,
) -> Result<TemplateSpec, TemplateError> {
    talk_core::resolve_template(template_path, data_dir)
}

/// A human-readable UTC timestamp for the template context.
pub fn received_at() -> String {
    talk_core::received_at()
}

/// `n` random bytes as hex (message ids etc.).
pub fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
