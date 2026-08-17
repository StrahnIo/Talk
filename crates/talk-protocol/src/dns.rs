//! Domain key and endpoint resolution: how a client finds a server's public
//! domain key and its ZSMTP TCP endpoint.
//!
//! Both live under a unified DNS service name, `_zpayments._tcp.<domain>`:
//! - a **TXT** record carrying the base64 32-byte ed25519 verification key, and
//! - an **SRV** record carrying `priority weight port target` for the daemon's
//!   ZSMTP TCP endpoint (implicit TLS).
//!
//! v1 resolves via Cloudflare DNS-over-HTTPS (one JSON request per query) or
//! via a static in-memory map (tests / config bootstrap).

use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use thiserror::Error;

/// The unified DNS service name for ZSMTP discovery.
pub const SRV_SERVICE: &str = "_zpayments._tcp";

/// The designated local-counterparty domain: resolution for it skips DNS and
/// resolves straight to a localhost port (see `COUNTERPARTY_PORT_SMTP`).
pub const COUNTERPARTY_DOMAIN: &str = "example.com";

/// Env var: the counterparty's ZSMTP TCP port on localhost (`_zpayments._tcp`
/// SRV analog). Pattern: `COUNTERPARTY_PORT_<SERVICE>`.
pub const COUNTERPARTY_PORT_SMTP: &str = "COUNTERPARTY_PORT_SMTP";

/// Env var: the counterparty's public domain key, hex (32 bytes), so the
/// AUTH/ADDR handshake verifies without DNS.
pub const COUNTERPARTY_DOMAINKEY_HEX: &str = "COUNTERPARTY_DOMAINKEY_HEX";

/// Whether `domain` is the designated local counterparty.
pub fn is_counterparty(domain: &str) -> bool {
    domain.eq_ignore_ascii_case(COUNTERPARTY_DOMAIN)
}

/// The counterparty's local endpoint from `COUNTERPARTY_PORT_SMTP`.
/// `None` when unset (the caller falls back to `send_endpoint`, else errors).
fn counterparty_endpoint() -> Option<String> {
    std::env::var(COUNTERPARTY_PORT_SMTP)
        .ok()
        .and_then(|p| p.trim().parse::<u16>().ok())
        .map(|port| format!("127.0.0.1:{port}"))
}

/// The counterparty's public domain key from `COUNTERPARTY_DOMAINKEY_HEX`.
fn counterparty_key() -> Result<VerifyingKey, ResolverError> {
    let raw = std::env::var(COUNTERPARTY_DOMAINKEY_HEX)
        .map_err(|_| ResolverError::NotFound(COUNTERPARTY_DOMAIN.to_string()))?;
    let bytes = hex::decode(raw.trim()).map_err(|e| ResolverError::InvalidKey(e.to_string()))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ResolverError::InvalidKey("expected 32 bytes".into()))?;
    VerifyingKey::from_bytes(&key).map_err(|e| ResolverError::InvalidKey(e.to_string()))
}

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("no domain key found for {0}")]
    NotFound(String),
    #[error("malformed TXT record: {0}")]
    Malformed(String),
    #[error("invalid domain key: {0}")]
    InvalidKey(String),
    #[error("no SRV record found for {0}")]
    NoSrv(String),
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

/// Resolves a domain to its ZSMTP TCP endpoint (`host:port`).
pub trait EndpointResolver: Send + Sync {
    fn resolve_endpoint(&self, domain: &str) -> Result<String, ResolverError>;
}

/// Static endpoint map: `domain -> host:port`. Used by tests and local dev.
#[derive(Default)]
pub struct StaticEndpointResolver {
    endpoints: HashMap<String, String>,
}

impl StaticEndpointResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, domain: &str, endpoint: impl Into<String>) {
        self.endpoints.insert(domain.to_string(), endpoint.into());
    }
}

impl EndpointResolver for StaticEndpointResolver {
    fn resolve_endpoint(&self, domain: &str) -> Result<String, ResolverError> {
        self.endpoints
            .get(domain)
            .cloned()
            .ok_or_else(|| ResolverError::NoSrv(domain.to_string()))
    }
}

/// Shared DNS-over-HTTPS query client.
struct DohClient {
    endpoint: String,
    agent: ureq::Agent,
}

impl DohClient {
    fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            agent: ureq::Agent::new_with_defaults(),
        }
    }

    /// Query DoH for answers of a given DNS type under a name.
    fn query(&self, name: &str, r#type: &str) -> Result<Vec<String>, ResolverError> {
        let url = format!("{}?name={name}&type={type}", self.endpoint);
        let resp = self
            .agent
            .get(&url)
            .header("Accept", "application/dns-json")
            .call()
            .map_err(|e| ResolverError::Http(e.to_string()))?;
        let body = resp
            .into_body()
            .read_to_string()
            .map_err(|e| ResolverError::Http(e.to_string()))?;
        let parsed: DnsResponse =
            serde_json::from_str(&body).map_err(|e| ResolverError::Malformed(e.to_string()))?;
        if parsed.status != 0 {
            return Err(ResolverError::NotFound(name.to_string()));
        }
        Ok(parsed
            .answer
            .iter()
            .filter(|a| a.r#type == 16 || a.r#type == 33)
            .map(|a| a.data.trim_matches('"').trim_matches('\'').to_string())
            .collect())
    }
}

/// Cloudflare DNS-over-HTTPS resolver for the domain key.
///
/// Queries `https://cloudflare-dns.com/dns-query?name=_zpayments._tcp.<domain>&type=TXT`
/// with `Accept: application/dns-json`. The first TXT record is the base64
/// encoded 32-byte ed25519 verification key.
pub struct DohDomainKeyResolver {
    client: DohClient,
}

impl Default for DohDomainKeyResolver {
    fn default() -> Self {
        Self::new("https://cloudflare-dns.com/dns-query")
    }
}

impl DohDomainKeyResolver {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            client: DohClient::new(endpoint),
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
        if is_counterparty(domain) {
            // The designated counterparty has no DNS; use COUNTERPARTY_DOMAINKEY_HEX.
            return counterparty_key();
        }
        let name = format!("{SRV_SERVICE}.{domain}");
        let records = self.client.query(&name, "TXT")?;
        let record = records
            .first()
            .ok_or_else(|| ResolverError::NotFound(domain.to_string()))?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, record)
            .map_err(|e| ResolverError::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ResolverError::InvalidKey("expected 32 bytes".into()))?;
        VerifyingKey::from_bytes(&key).map_err(|e| ResolverError::InvalidKey(e.to_string()))
    }
}

/// Cloudflare DNS-over-HTTPS resolver for the ZSMTP endpoint.
///
/// Queries `_zpayments._tcp.<domain>` for an SRV record, parses
/// `priority weight port target`, picks the lowest priority, and returns
/// `target:port`.
pub struct DohEndpointResolver {
    client: DohClient,
}

impl Default for DohEndpointResolver {
    fn default() -> Self {
        Self::new("https://cloudflare-dns.com/dns-query")
    }
}

impl DohEndpointResolver {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            client: DohClient::new(endpoint),
        }
    }
}

/// Parse an SRV data string `"priority weight port target"`.
pub fn parse_srv(data: &str) -> Option<(u16, u16, u16, String)> {
    let mut parts = data.split_whitespace();
    let priority: u16 = parts.next()?.parse().ok()?;
    let weight: u16 = parts.next()?.parse().ok()?;
    let port: u16 = parts.next()?.parse().ok()?;
    let target = parts.next()?.to_string();
    if target.is_empty() {
        return None;
    }
    Some((priority, weight, port, target))
}

impl EndpointResolver for DohEndpointResolver {
    fn resolve_endpoint(&self, domain: &str) -> Result<String, ResolverError> {
        if is_counterparty(domain) {
            // The designated counterparty skips SRV: resolve to a localhost
            // port from COUNTERPARTY_PORT_SMTP. Unset → NoSrv so callers fall
            // back to the send_endpoint override, else a clear error.
            return counterparty_endpoint().ok_or_else(|| ResolverError::NoSrv(domain.to_string()));
        }
        let name = format!("{SRV_SERVICE}.{domain}");
        let records = self.client.query(&name, "SRV")?;
        let mut best: Option<(u16, u16, u16, String)> = None;
        for data in &records {
            if let Some(parsed) = parse_srv(data) {
                let better = match &best {
                    None => true,
                    Some((bp, _, _, _)) => parsed.0 < *bp,
                };
                if better {
                    best = Some(parsed);
                }
            }
        }
        let (_, _, port, target) = best.ok_or_else(|| ResolverError::NoSrv(domain.to_string()))?;
        Ok(format!("{target}:{port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Env is process-global; serialize all env-mutating tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    #[test]
    fn parse_srv_standard() {
        assert_eq!(
            parse_srv("10 0 8888 payments.stygian.io"),
            Some((10, 0, 8888, "payments.stygian.io".to_string()))
        );
    }

    #[test]
    fn parse_srv_picks_lowest_priority() {
        let a = parse_srv("20 0 8888 a.example.org").unwrap();
        let b = parse_srv("10 0 9999 b.example.org").unwrap();
        assert!(b.0 < a.0);
    }

    #[test]
    fn parse_srv_rejects_malformed() {
        assert!(parse_srv("10 0 8888").is_none());
        assert!(parse_srv("not numbers").is_none());
        assert!(parse_srv("10 0 8888 ").is_none());
    }

    #[test]
    fn static_endpoint_resolver() {
        let mut r = StaticEndpointResolver::new();
        r.insert("example.org", "payments.example.org:8888");
        assert_eq!(
            r.resolve_endpoint("example.org").unwrap(),
            "payments.example.org:8888"
        );
        assert!(matches!(
            r.resolve_endpoint("nope.org"),
            Err(ResolverError::NoSrv(_))
        ));
    }

    #[test]
    fn counterparty_endpoint_from_env() {
        let _g = ENV_LOCK.lock().unwrap();
        // SAFETY: guarded by the mutex; edition-2024 requires unsafe set_var.
        unsafe { std::env::set_var(COUNTERPARTY_PORT_SMTP, "1465") };
        let r = DohEndpointResolver::default();
        assert_eq!(
            r.resolve_endpoint(COUNTERPARTY_DOMAIN).unwrap(),
            "127.0.0.1:1465"
        );
        // Case-insensitive.
        assert_eq!(r.resolve_endpoint("EXAMPLE.COM").unwrap(), "127.0.0.1:1465");
        unsafe { std::env::remove_var(COUNTERPARTY_PORT_SMTP) };
    }

    #[test]
    fn counterparty_endpoint_unset_is_nosrv() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(COUNTERPARTY_PORT_SMTP) };
        let r = DohEndpointResolver::default();
        assert!(matches!(
            r.resolve_endpoint(COUNTERPARTY_DOMAIN),
            Err(ResolverError::NoSrv(_))
        ));
    }

    #[test]
    fn counterparty_key_from_env() {
        let _g = ENV_LOCK.lock().unwrap();
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = key.verifying_key();
        unsafe { std::env::set_var(COUNTERPARTY_DOMAINKEY_HEX, hex::encode(vk.to_bytes())) };
        let r = DohDomainKeyResolver::default();
        assert_eq!(r.resolving_key(COUNTERPARTY_DOMAIN).unwrap(), vk);
        unsafe { std::env::remove_var(COUNTERPARTY_DOMAINKEY_HEX) };
    }

    #[test]
    fn counterparty_key_missing_errors() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(COUNTERPARTY_DOMAINKEY_HEX) };
        let r = DohDomainKeyResolver::default();
        assert!(r.resolving_key(COUNTERPARTY_DOMAIN).is_err());
    }
}
