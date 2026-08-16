//! Domain key resolution: how a client finds a server's public domain key.
//!
//! The sender verifies the receiver's identity against the receiver's public
//! domain key, published in DNS as a `_zsmtp._tcp.<domain>` TXT record (the
//! DKIM analog). v1 resolves via Cloudflare DNS-over-HTTPS (one JSON request)
//! or via a static in-memory map (tests / config bootstrap).

use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("no domain key found for {0}")]
    NotFound(String),
    #[error("malformed TXT record: {0}")]
    Malformed(String),
    #[error("invalid domain key: {0}")]
    InvalidKey(String),
    #[error("http: {0}")]
    Http(String),
}

/// Resolves a domain to its public verification key.
pub trait DomainKeyResolver: Send + Sync {
    fn resolving_key(&self, domain: &str) -> Result<VerifyingKey, ResolverError>;
}

/// A static in-memory resolver: `domain -> verifying key`. Used by tests and
/// config-file bootstrapping.
#[derive(Default)]
pub struct StaticDomainKeyResolver {
    keys: HashMap<String, VerifyingKey>,
}

impl StaticDomainKeyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, domain: &str, key: VerifyingKey) {
        self.keys.insert(domain.to_string(), key);
    }
}

impl DomainKeyResolver for StaticDomainKeyResolver {
    fn resolving_key(&self, domain: &str) -> Result<VerifyingKey, ResolverError> {
        self.keys
            .get(domain)
            .copied()
            .ok_or_else(|| ResolverError::NotFound(domain.to_string()))
    }
}

/// Cloudflare DNS-over-HTTPS resolver.
///
/// Queries `https://cloudflare-dns.com/dns-query?name=_zsmtp._tcp.<domain>&type=TXT`
/// with `Accept: application/dns-json`. The first TXT record is the base64
/// encoded 32-byte ed25519 verification key.
pub struct DohDomainKeyResolver {
    /// The DoH endpoint, e.g. `https://cloudflare-dns.com/dns-query`.
    endpoint: String,
    client: ureq::Agent,
}

impl Default for DohDomainKeyResolver {
    fn default() -> Self {
        Self::new("https://cloudflare-dns.com/dns-query")
    }
}

impl DohDomainKeyResolver {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: ureq::Agent::new_with_defaults(),
        }
    }
}

#[derive(serde::Deserialize)]
struct DnsResponse {
    #[serde(default)]
    status: i32,
    #[serde(default)]
    answer: Vec<DnsAnswer>,
}

#[derive(serde::Deserialize)]
struct DnsAnswer {
    #[serde(rename = "type")]
    r#type: i32,
    #[serde(default)]
    data: String,
}

impl DomainKeyResolver for DohDomainKeyResolver {
    fn resolving_key(&self, domain: &str) -> Result<VerifyingKey, ResolverError> {
        // Build the DoH URL.
        let name = format!("_zsmtp._tcp.{domain}");
        let url = format!("{}?name={}&type=TXT", self.endpoint, name);

        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/dns-json")
            .call()
            .map_err(|e| ResolverError::Http(e.to_string()))?;

        // Read and parse the JSON.
        let body = resp
            .into_body()
            .read_to_string()
            .map_err(|e| ResolverError::Http(e.to_string()))?;
        let parsed: DnsResponse =
            serde_json::from_str(&body).map_err(|e| ResolverError::Malformed(e.to_string()))?;

        if parsed.status != 0 {
            return Err(ResolverError::NotFound(domain.to_string()));
        }
        let record = parsed
            .answer
            .iter()
            .find(|a| a.r#type == 16)
            .ok_or_else(|| ResolverError::NotFound(domain.to_string()))?;

        // TXT data is a quoted string in JSON, e.g. `"<base64>"`.
        let data = record.data.trim_matches('"').trim_matches('\'').to_string();
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data)
            .map_err(|e| ResolverError::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ResolverError::InvalidKey("expected 32 bytes".into()))?;
        VerifyingKey::from_bytes(&key).map_err(|e| ResolverError::InvalidKey(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn static_resolver_returns_inserted_key() {
        let mut r = StaticDomainKeyResolver::new();
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = key.verifying_key();
        r.insert("example.org", vk);
        assert_eq!(r.resolving_key("example.org").unwrap(), vk);
    }

    #[test]
    fn static_resolver_missing_domain() {
        let r = StaticDomainKeyResolver::new();
        assert!(matches!(
            r.resolving_key("nope.org"),
            Err(ResolverError::NotFound(_))
        ));
    }
}
