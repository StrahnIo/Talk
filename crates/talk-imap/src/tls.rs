//! Optional IMAPS (TLS) support for the IMAP server.

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("io reading {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("no certificates found in {0}")]
    NoCertificates(String),
    #[error("no private key found in {0}")]
    NoPrivateKey(String),
    #[error("invalid private key in {0}")]
    InvalidPrivateKey(String),
    #[error("tls config: {0}")]
    Config(#[from] rustls::Error),
}

/// Build a `rustls::ServerConfig` from PEM certificate + private key files.
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ServerConfig>, TlsError> {
    // Load certificates.
    let cert_file = fs::File::open(cert_path).map_err(|source| TlsError::Io {
        path: cert_path.to_path_buf(),
        source,
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Io {
            path: cert_path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(cert_path.display().to_string()));
    }

    // Load the private key.
    let key_file = fs::File::open(key_path).map_err(|source| TlsError::Io {
        path: key_path.to_path_buf(),
        source,
    })?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| TlsError::Io {
            path: key_path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?
        .ok_or_else(|| TlsError::NoPrivateKey(key_path.display().to_string()))?;
    let key: PrivateKeyDer<'static> = key;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| TlsError::InvalidPrivateKey(key_path.display().to_string()))?;

    Ok(Arc::new(config))
}
