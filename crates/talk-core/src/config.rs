use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;

/// Daemon configuration, loaded from a TOML file.
///
/// See `config.example.toml` in the repository root for the shape.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub network: Network,
    pub sockets: Sockets,
    pub tls: Tls,
    pub mailbox: Mailbox,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct General {
    pub data_dir: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub indexer_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sockets {
    pub secure_mailbox: PathBuf,
    pub zsmtp: PathBuf,
    pub imap_listen: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mailbox {
    #[serde(default = "default_true")]
    pub encrypt_db: bool,
    #[serde(default)]
    pub passphrase: String,
    pub wallet_dir: PathBuf,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

impl Config {
    /// Load configuration from a TOML file at `path`.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        let raw = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        toml::from_str(&raw).map_err(|source| ConfigError::Parse { path, source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_example_config() {
        let example = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
        let cfg = Config::load(&example).expect("example config must parse");
        assert_eq!(cfg.general.log_level, "info");
        assert!(cfg.mailbox.encrypt_db);
        assert_eq!(
            cfg.mailbox.wallet_dir,
            PathBuf::from("/var/lib/talk/wallets")
        );
    }

    #[test]
    fn defaults_log_level_and_encrypt() {
        let raw = r#"
            [general]
            data_dir = "/tmp/talk"

            [network]
            indexer_url = "lwd.example.com:9067"

            [sockets]
            secure_mailbox = "/tmp/secure.sock"
            zsmtp = "/tmp/zsmtp.sock"
            imap_listen = "127.0.0.1:993"

            [tls]
            cert = "/tmp/cert.pem"
            key = "/tmp/key.pem"

            [mailbox]
            wallet_dir = "/tmp/wallets"
        "#;
        let cfg: Config = toml::from_str(raw).expect("minimal config must parse");
        assert_eq!(cfg.general.log_level, "info");
        assert!(cfg.mailbox.encrypt_db);
    }
}
