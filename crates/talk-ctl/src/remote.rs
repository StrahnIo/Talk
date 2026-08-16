//! `attest` / `send` — prefer the running daemon's `secure_mailbox.sock`,
//! falling back to direct domain-key signing / an outbound ZSMTP client when
//! the daemon is down.

use crate::store::Ctx;
use crate::CtlError;
use std::path::Path;
use talk_protocol::attestation::{Attestation, AttestationMode, mint_pair};
use talk_protocol::envelope::Payload;
use talk_protocol::mailbox::SecureMailboxClient;
use talk_protocol::{
    DohDomainKeyResolver, DohEndpointResolver, DomainKeyResolver, EndpointResolver, SendInvoice,
};
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// attest
// ---------------------------------------------------------------------------

pub fn attest(config_path: Option<&Path>, user: &str, mode: &str) -> Result<(), CtlError> {
    let mode = parse_mode(mode)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(attest_async(config_path, user, mode))
}

async fn attest_async(
    config_path: Option<&Path>,
    user: &str,
    mode: AttestationMode,
) -> Result<(), CtlError> {
    let ctx = Ctx::load(config_path)?;
    match socket_connect(&ctx).await {
        Ok(stream) => {
            let mut client = SecureMailboxClient::new(stream);
            let blob = client.attest(user, mode).await.map_err(|e| {
                CtlError::msg(format!("daemon: {e}"))
            })?;
            print_attestation(&blob)
        }
        Err(_) => {
            // Daemon is down: sign directly with the persisted domain key.
            let domain_key = ctx.domain_key()?;
            let (address, pubkey) = mint_pair(mode);
            let att = Attestation::sign(
                &ctx.cfg.general.domain,
                user,
                mode,
                address,
                pubkey,
                &domain_key,
            );
            print_attestation(&att.to_json().into_bytes())
        }
    }
}

fn print_attestation(blob: &[u8]) -> Result<(), CtlError> {
    let s = String::from_utf8_lossy(blob);
    let att = Attestation::from_json(&s)
        .map_err(|e| CtlError::msg(format!("daemon returned invalid attestation: {e}")))?;
    println!("domain      {}", att.domain);
    println!("user        {}", att.user);
    println!("mode        {}", match att.mode {
        AttestationMode::Ephemeral => "ephemeral",
        AttestationMode::Attested => "attested",
    });
    println!("address     {}", att.address);
    println!("pubkey      {}", att.pubkey);
    println!("signature   {}", hex::encode(&att.signature));
    Ok(())
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------

pub fn send(
    config_path: Option<&Path>,
    sender: &str,
    recipient: &str,
    file: &Path,
    plaintext: bool,
    message_id: Option<&str>,
) -> Result<(), CtlError> {
    let body = std::fs::read(file)
        .map_err(|e| CtlError::msg(format!("cannot read {}: {e}", file.display())))?;
    let payload = if plaintext { Payload::Plaintext } else { Payload::Sealed };
    let message_id = message_id.map(str::to_string).unwrap_or_else(gen_message_id);
    if sender.is_empty() {
        return Err(CtlError::msg("sender username is required"));
    }
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(send_async(config_path, sender, recipient, message_id, payload, body))
}

async fn send_async(
    config_path: Option<&Path>,
    sender: &str,
    recipient: &str,
    message_id: String,
    payload: Payload,
    body: Vec<u8>,
) -> Result<(), CtlError> {
    let ctx = Ctx::load(config_path)?;
    match socket_connect(&ctx).await {
        Ok(stream) => {
            let mut client = SecureMailboxClient::new(stream);
            let resp = client.send(sender, recipient, &message_id, payload, &body).await?;
            if resp.starts_with("OK ") {
                println!("{resp}");
                Ok(())
            } else {
                Err(CtlError::msg(format!("daemon: {resp}")))
            }
        }
        Err(_) => {
            // Daemon is down: deliver directly via an outbound ZSMTP client.
            direct_send(&ctx, sender, recipient, message_id, payload, body).await
        }
    }
}

async fn direct_send(
    ctx: &Ctx,
    sender: &str,
    recipient: &str,
    message_id: String,
    payload: Payload,
    body: Vec<u8>,
) -> Result<(), CtlError> {
    let receiver_domain = recipient
        .split('@')
        .nth(1)
        .ok_or_else(|| CtlError::msg("malformed recipient mailbox"))?
        .to_string();
    let receiver_pub = DohDomainKeyResolver::default()
        .resolving_key(&receiver_domain)
        .map_err(|e| CtlError::msg(format!("cannot resolve domain key: {e}")))?;
    let endpoint = match DohEndpointResolver::default()
        .resolve_endpoint(&receiver_domain)
    {
        Ok(ep) => ep,
        Err(_) => {
            if !ctx.cfg.network.send_endpoint.is_empty() {
                ctx.cfg.network.send_endpoint.clone()
            } else {
                return Err(CtlError::msg("cannot resolve endpoint (no SRV, no send_endpoint override)"));
            }
        }
    };
    let recipient_user = recipient.split('@').next().unwrap_or("").to_string();
    let invoice = SendInvoice {
        endpoint,
        receiver_domain,
        sender_domain: ctx.cfg.general.domain.clone(),
        sender_username: sender.to_string(),
        recipient_user,
        receiver_pub,
        message_id,
        payload,
        body,
    };
    invoice.deliver().await.map_err(|e| CtlError::msg(format!("deliver: {e}")))?;
    println!("delivered to {recipient}");
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn socket_connect(ctx: &Ctx) -> Result<UnixStream, std::io::Error> {
    UnixStream::connect(ctx.socket_path()).await
}

fn parse_mode(s: &str) -> Result<AttestationMode, CtlError> {
    match s {
        "ephemeral" => Ok(AttestationMode::Ephemeral),
        "attested" => Ok(AttestationMode::Attested),
        other => Err(CtlError::msg(format!("invalid attestation mode: {other}"))),
    }
}

fn gen_message_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("talkctl-{}", hex::encode(bytes))
}
