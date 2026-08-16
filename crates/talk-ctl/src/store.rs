//! Direct-access account, share, keyring, and settings management.

use crate::{CtlError, KeyringAction, SettingsAction, ShareAction, UserAction};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use talk_core::config::Config;
use talk_keys::{DataKey, PerShareWrapper, Share, ShareScheme};
use talk_mailstore::SqliteMailStore;
use talk_protocol::attestation::RegistrationAttestation;

/// A resolved daemon context: the effective config and its mailbox store.
pub struct Ctx {
    pub cfg: Config,
    pub store: SqliteMailStore,
}

impl Ctx {
    /// Resolve the config (explicit path, else `config.toml` in the cwd) and
    /// open the mailbox store it points at.
    pub fn load(config_path: Option<&Path>) -> Result<Self, CtlError> {
        let cfg = match config_path {
            Some(p) => Config::load(p)?,
            None => Config::load(Path::new("config.toml"))?,
        };
        let db_path = cfg.general.data_dir.join("mailbox.db");
        let store = SqliteMailStore::open(&db_path)?;
        Ok(Self { cfg, store })
    }

    pub fn socket_path(&self) -> PathBuf {
        self.cfg.sockets.secure_mailbox.clone()
    }

    /// The persisted domain signing key (`data_dir/domainkey`), load-only.
    ///
    /// The daemon creates it on first boot; the CLI never generates it.
    pub fn domain_key(&self) -> Result<SigningKey, CtlError> {
        let path = self.cfg.general.data_dir.join("domainkey");
        let raw = std::fs::read(&path).map_err(|e| {
            CtlError::msg(format!(
                "cannot read domain key {}: {e} (run talkd once to create it)",
                path.display()
            ))
        })?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| CtlError::msg("domain key must be 32 bytes"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }
}

/// Summary line: daemon identity + store shape.
pub fn status(config_path: Option<&Path>) -> Result<(), CtlError> {
    let ctx = Ctx::load(config_path)?;
    let users = ctx.store.list_users()?;
    let settings = ctx.store.list_settings()?;
    let domain_key = ctx.domain_key().ok();
    println!("version        talkd {}", env!("CARGO_PKG_VERSION"));
    println!("domain         {}", ctx.cfg.general.domain);
    println!("data_dir       {}", ctx.cfg.general.data_dir.display());
    println!(
        "mailbox_db     {}",
        ctx.cfg.general.data_dir.join("mailbox.db").display()
    );
    println!("secure_mailbox {}", ctx.socket_path().display());
    println!("indexer        {}", ctx.cfg.network.indexer_url);
    println!(
        "send_endpoint  {}",
        if ctx.cfg.network.send_endpoint.is_empty() {
            "srv"
        } else {
            &ctx.cfg.network.send_endpoint
        }
    );
    println!("users          {}", users.len());
    println!("settings       {}", settings.len());
    match domain_key {
        Some(_) => println!("domain_key     present"),
        None => println!("domain_key     missing (run talkd once)"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

pub fn settings_run(config_path: Option<&Path>, action: SettingsAction) -> Result<(), CtlError> {
    let ctx = Ctx::load(config_path)?;
    match action {
        SettingsAction::List => {
            for (k, v) in ctx.store.list_settings()? {
                println!("{k} = {v}");
            }
        }
        SettingsAction::Get { key } => match ctx.store.get_setting(&key)? {
            Some(v) => println!("{v}"),
            None => return Err(CtlError::msg(format!("no such setting: {key}"))),
        },
        SettingsAction::Set { key, value } => {
            ctx.store.set_setting(&key, &value)?;
            println!("ok: {key} = {value}");
        }
        SettingsAction::Delete { key } => {
            ctx.store.delete_setting(&key)?;
            println!("ok: deleted {key}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

pub fn user_run(config_path: Option<&Path>, action: UserAction) -> Result<(), CtlError> {
    let ctx = Ctx::load(config_path)?;
    match action {
        UserAction::List => {
            for u in ctx.store.list_users()? {
                println!(
                    "{:<20} id={} ivk={} attested={}",
                    u.username,
                    u.id,
                    yes_no(u.has_ivk),
                    yes_no(u.has_attestation),
                );
            }
        }
        UserAction::Show { username } => {
            let user = require_user(&ctx, &username)?;
            println!("username      {}", user.username);
            println!("id            {}", user.id);
            println!("master_pubkey {}", hex::encode(&user.master_pubkey));
            match &user.ivk_commitment {
                Some(ivk) => println!("ivk_commitment {}", ivk),
                None => println!("ivk_commitment (none)"),
            }
            match &user.registration_attestation {
                Some(r) => {
                    println!("attestation   present");
                    match RegistrationAttestation::from_json(r) {
                        Ok(parsed) => println!(
                            "  R: domain={} registered_at={} sig={}",
                            parsed.domain,
                            parsed.registered_at,
                            hex::encode(&parsed.signature)
                        ),
                        Err(_) => println!("  R: unparseable"),
                    }
                }
                None => println!("attestation   (none)"),
            }
            let shares = ctx.store.list_shares(user.id)?;
            println!(
                "shares        {} ({})",
                shares.len(),
                shares.iter().filter(|s| !s.revoked).count()
            );
            let keyring = ctx.store.list_keyring(user.id)?;
            println!("keyring       {} pinned", keyring.len());
        }
        UserAction::Create {
            username,
            password,
            pubkey,
            ivk,
            shares,
        } => {
            let password = password.unwrap_or_else(|| prompt_password("Password: "));
            let pubkey_bytes = decode_hex_32(&pubkey)
                .ok_or_else(|| CtlError::msg("--pubkey must be 32 bytes of hex"))?;
            let ivk = match &ivk {
                Some(h) => {
                    decode_hex_32(h)
                        .ok_or_else(|| CtlError::msg("--ivk must be 32 bytes of hex"))?;
                    Some(h.clone())
                }
                None => None,
            };
            if username.is_empty() || password.is_empty() {
                return Err(CtlError::msg("username and password are required"));
            }
            let hash = talk_mailstore::hash_password(&password)
                .map_err(|e| CtlError::msg(format!("password hash failed: {e}")))?;
            let domain_key = ctx.domain_key()?;
            let r = RegistrationAttestation::sign(
                &ctx.cfg.general.domain,
                &username,
                &pubkey_bytes,
                ivk.as_deref(),
                unix_now(),
                &domain_key,
            )
            .to_json();
            let user = ctx
                .store
                .create_user_full(&username, &hash, &pubkey_bytes, ivk, Some(r))?;
            println!("ok: registered {}", user.username);

            if shares > 0 {
                init_shares(&ctx, user.id, shares)?;
            }
        }
        UserAction::Delete { username } => {
            ctx.store.delete_user(&username)?;
            println!("ok: deleted {username}");
        }
        UserAction::Passwd { username, password } => {
            require_user(&ctx, &username)?;
            let password = password.unwrap_or_else(|| prompt_password("New password: "));
            let hash = talk_mailstore::hash_password(&password)
                .map_err(|e| CtlError::msg(format!("password hash failed: {e}")))?;
            ctx.store.set_password(&username, &hash)?;
            println!("ok: password changed for {username}");
        }
        UserAction::SetIvk { username, ivk } => {
            require_user(&ctx, &username)?;
            decode_hex_32(&ivk).ok_or_else(|| CtlError::msg("ivk must be 32 bytes of hex"))?;
            ctx.store.set_ivk(&username, Some(&ivk))?;
            println!("ok: ivk set for {username}");
        }
        UserAction::UnsetIvk { username } => {
            require_user(&ctx, &username)?;
            ctx.store.set_ivk(&username, None)?;
            println!("ok: ivk cleared for {username}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// shares
// ---------------------------------------------------------------------------

pub fn share_run(config_path: Option<&Path>, action: ShareAction) -> Result<(), CtlError> {
    let ctx = Ctx::load(config_path)?;
    match action {
        ShareAction::List { username } => {
            let user = require_user(&ctx, &username)?;
            for s in ctx.store.list_shares(user.id)? {
                println!(
                    "{:<16} {} wrapped={}",
                    s.share_id,
                    if s.revoked { "revoked" } else { "active " },
                    hex::encode(&s.wrapped_dk)
                );
            }
        }
        ShareAction::Init { username, shares } => {
            let user = require_user(&ctx, &username)?;
            if shares == 0 {
                return Err(CtlError::msg("--shares must be >= 1"));
            }
            init_shares(&ctx, user.id, shares)?;
        }
        ShareAction::Revoke { username, share_id } => {
            let user = require_user(&ctx, &username)?;
            ctx.store.revoke_share(user.id, &share_id)?;
            println!("ok: share {share_id} revoked for {username}");
        }
    }
    Ok(())
}

/// Generate a fresh DK, wrap it under `n` shares, persist the wrappers, and
/// print each share's secret (the app password) exactly once.
fn init_shares(ctx: &Ctx, user_id: i64, n: u32) -> Result<(), CtlError> {
    let dk = DataKey::generate(&mut OsRng);
    let shares: Vec<Share> = (0..n).map(|_| Share::generate(&mut OsRng)).collect();
    let set = PerShareWrapper.wrap(&dk, &shares);

    for (share, wrapper) in shares.iter().zip(set.wrappers.iter()) {
        let id = hex::encode(wrapper.share_id);
        ctx.store.add_share(user_id, &id, &wrapper.wrapped)?;
        println!("share id={id} secret={}", hex::encode(share.as_bytes()));
    }
    eprintln!(
        "note: share secrets above are app passwords; store them safely. The DK is not stored by the server."
    );
    println!("ok: registered {} shares", n);
    Ok(())
}

// ---------------------------------------------------------------------------
// keyring
// ---------------------------------------------------------------------------

pub fn keyring_run(config_path: Option<&Path>, action: KeyringAction) -> Result<(), CtlError> {
    let ctx = Ctx::load(config_path)?;
    match action {
        KeyringAction::Pin {
            username,
            sender,
            pubkey,
        } => {
            let user = require_user(&ctx, &username)?;
            let key = pubkey.unwrap_or_default();
            ctx.store.keyring_set_trusted(user.id, &sender, &key, &[])?;
            println!("ok: pinned {sender} for {username}");
        }
        KeyringAction::List { username } => {
            let user = require_user(&ctx, &username)?;
            for e in ctx.store.list_keyring(user.id)? {
                println!(
                    "{:<28} {} pubkey={}",
                    e.sender_mailbox,
                    e.state,
                    if e.sender_pubkey.is_empty() {
                        "(none)"
                    } else {
                        &e.sender_pubkey
                    }
                );
            }
        }
        KeyringAction::Unpin { username, sender } => {
            let user = require_user(&ctx, &username)?;
            ctx.store.unpin_keyring(user.id, &sender)?;
            println!("ok: unpinned {sender} for {username}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn require_user(ctx: &Ctx, username: &str) -> Result<talk_mailstore::User, CtlError> {
    ctx.store
        .get_user(username)?
        .ok_or_else(|| CtlError::msg(format!("no such user: {username}")))
}

fn prompt_password(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_default()
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Some(out)
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64
}
