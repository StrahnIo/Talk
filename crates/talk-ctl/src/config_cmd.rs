//! `talkctl config` — inspect and edit the daemon TOML config file.

use crate::CtlError;
use clap::Subcommand;
use std::path::{Path, PathBuf};

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the effective config file (secrets redacted).
    Show,
    /// Read one dotted key, e.g. `general.domain`.
    Get { key: String },
    /// Set one dotted key and re-validate, e.g. `sockets.imap_listen 127.0.0.1:1144`.
    Set { key: String, value: String },
    /// Parse and validate the config file.
    Validate,
}

pub fn run(config_path: Option<&Path>, action: ConfigAction) -> Result<(), CtlError> {
    let path = resolve_path(config_path)?;
    match action {
        ConfigAction::Show => {
            let mut value = read_toml(&path)?;
            redact(&mut value, "mailbox.passphrase");
            println!(
                "{}",
                toml::to_string_pretty(&value).map_err(|e| CtlError::msg(e.to_string()))?
            );
        }
        ConfigAction::Get { key } => {
            let value = read_toml(&path)?;
            match get_path(&value, &key) {
                Ok(v) => println!("{v}"),
                Err(e) => return Err(CtlError::msg(e)),
            }
        }
        ConfigAction::Set { key, value } => {
            let mut root = read_toml(&path)?;
            let new_value = parse_value(&value);
            set_path(&mut root, &key, new_value)?;
            let out = toml::to_string_pretty(&root).map_err(|e| CtlError::msg(e.to_string()))?;
            // Validate before writing: unknown keys / bad types / invalid
            // domains must reject the whole change.
            talk_core::config::Config::parse(&out)
                .map_err(|e| CtlError::msg(format!("refusing to write invalid config: {e}")))?;
            std::fs::write(&path, out).map_err(CtlError::from)?;
            println!("ok: {key} = {value} ({})", path.display());
        }
        ConfigAction::Validate => {
            talk_core::config::Config::load(&path)?;
            println!("ok: {} is valid", path.display());
        }
    }
    Ok(())
}

fn resolve_path(config_path: Option<&Path>) -> Result<PathBuf, CtlError> {
    Ok(config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("config.toml")))
}

fn read_toml(path: &Path) -> Result<toml::Value, CtlError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CtlError::msg(format!("cannot read config {}: {e}", path.display())))?;
    toml::from_str(&raw).map_err(|e| CtlError::msg(format!("malformed config: {e}")))
}

fn redact(value: &mut toml::Value, dotted: &str) {
    if let Ok(v) = get_path_mut(value, dotted) {
        *v = toml::Value::String("***".to_string());
    }
}

fn get_path<'a>(root: &'a toml::Value, path: &str) -> Result<&'a toml::Value, String> {
    let mut cur = root;
    for part in path.split('.') {
        let table = cur
            .as_table()
            .ok_or_else(|| format!("{path}: '{part}' is not a table"))?;
        cur = table
            .get(part)
            .ok_or_else(|| format!("no such key: {path}"))?;
    }
    Ok(cur)
}

fn get_path_mut<'a>(root: &'a mut toml::Value, path: &str) -> Result<&'a mut toml::Value, String> {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.is_empty() {
        return Err("empty path".into());
    }
    let mut cur = root;
    for (i, part) in parts.iter().enumerate() {
        let is_leaf = i == parts.len() - 1;
        let table = cur
            .as_table_mut()
            .ok_or_else(|| format!("{path}: '{part}' is not a table"))?;
        if is_leaf {
            return table
                .get_mut(*part)
                .ok_or_else(|| format!("no such key: {path}"));
        }
        cur = table
            .get_mut(*part)
            .ok_or_else(|| format!("no such key: {path}"))?;
    }
    unreachable!("loop returns at the leaf")
}

fn set_path(root: &mut toml::Value, path: &str, value: toml::Value) -> Result<(), CtlError> {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.is_empty() {
        return Err(CtlError::msg("empty key"));
    }
    let mut cur = root;
    for (i, part) in parts.iter().enumerate() {
        let is_leaf = i == parts.len() - 1;
        let table = cur
            .as_table_mut()
            .ok_or_else(|| CtlError::msg(format!("{path}: '{part}' is not a table")))?;
        if is_leaf {
            if !table.contains_key(*part) {
                return Err(CtlError::msg(format!("unknown key: {path}")));
            }
            table.insert(part.to_string(), value);
            return Ok(());
        }
        if !table.contains_key(*part) {
            return Err(CtlError::msg(format!("unknown key: {path}")));
        }
        cur = table.get_mut(*part).expect("checked contains_key");
    }
    Err(CtlError::msg("invalid path"))
}

/// Parse a CLI value into a TOML value: typed when it parses as TOML, else a
/// bare string. Empty string stays an empty string.
fn parse_value(s: &str) -> toml::Value {
    if s.trim().is_empty() {
        return toml::Value::String(String::new());
    }
    toml::from_str::<toml::Value>(s).unwrap_or_else(|_| toml::Value::String(s.to_string()))
}
