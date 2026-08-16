//! `talkctl key` — X25519 master keypair and ECIES seal/unseal.

use crate::CtlError;
use clap::Subcommand;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use talk_keys::{
    DataKey, generate_master_pair, master_pubkey, master_public_from_bytes, open_envelope,
    seal_envelope,
};

#[derive(Debug, Subcommand)]
pub enum KeyAction {
    /// Generate an X25519 master keypair. Prints the public key; the private
    /// key goes to a file (`--out`) or is printed once.
    Generate {
        /// Write the private key (raw 32 bytes, mode 0600) to this file.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Write the public key (raw 32 bytes) to this file.
        #[arg(long)]
        pub_out: Option<PathBuf>,
        /// Overwrite `--out`/`--pub-out` if they exist.
        #[arg(long)]
        force: bool,
    },
    /// Derive and print the public key from a private key file or hex.
    Pubkey {
        /// Private key file (raw 32 bytes).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Private key as 64 hex chars.
        #[arg(long)]
        hex: Option<String>,
    },
    /// Encrypt data to a public key (ECIES). Defaults to the `--key`'s own
    /// public key unless `--to` is given.
    Seal {
        /// Private key file (raw 32 bytes).
        #[arg(long)]
        key: PathBuf,
        /// Recipient public key (64 hex chars); defaults to the key's own.
        #[arg(long)]
        to: Option<String>,
        /// Input file (default: stdin).
        #[arg(long)]
        input: Option<PathBuf>,
        /// Output file (default: stdout).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Decrypt a sealed envelope with the private key.
    Unseal {
        /// Private key file (raw 32 bytes).
        #[arg(long)]
        key: PathBuf,
        /// Input file (default: stdin).
        #[arg(long)]
        input: Option<PathBuf>,
        /// Output file (default: stdout).
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

pub fn run(action: KeyAction) -> Result<(), CtlError> {
    match action {
        KeyAction::Generate {
            out,
            pub_out,
            force,
        } => generate(out.as_deref(), pub_out.as_deref(), force),
        KeyAction::Pubkey { key, hex } => pubkey(key.as_deref(), hex.as_deref()),
        KeyAction::Seal {
            key,
            to,
            input,
            output,
        } => seal(&key, to.as_deref(), input.as_deref(), output.as_deref()),
        KeyAction::Unseal { key, input, output } => {
            unseal(&key, input.as_deref(), output.as_deref())
        }
    }
}

fn generate(out: Option<&Path>, pub_out: Option<&Path>, force: bool) -> Result<(), CtlError> {
    let pair = generate_master_pair();

    if let Some(path) = out {
        write_new(path, pair.private.as_bytes(), 0o600, force)?;
    }
    if let Some(path) = pub_out {
        write_new(path, pair.public.as_bytes(), 0o644, force)?;
    }

    println!("public: {}", hex::encode(pair.public.as_bytes()));
    if let Some(path) = out {
        eprintln!(
            "note: private key written to {} (mode 0600)",
            path.display()
        );
    } else {
        eprintln!("note: private key printed once below; store it safely.");
        println!("private: {}", hex::encode(pair.private.as_bytes()));
    }
    Ok(())
}

fn pubkey(key: Option<&Path>, hex: Option<&str>) -> Result<(), CtlError> {
    let private = match (key, hex) {
        (Some(path), _) => load_private_key(path)?,
        (None, Some(h)) => {
            let bytes = decode_hex_32(h)
                .ok_or_else(|| CtlError::msg("private key must be 32 bytes of hex"))?;
            DataKey::from_bytes(bytes)
        }
        (None, None) => {
            return Err(CtlError::msg("provide --key <file> or --hex <private-key>"));
        }
    };
    let public = master_pubkey(&private);
    println!("{}", hex::encode(public.as_bytes()));
    Ok(())
}

fn seal(
    key_file: &Path,
    to: Option<&str>,
    input: Option<&Path>,
    output: Option<&Path>,
) -> Result<(), CtlError> {
    let private = load_private_key(key_file)?;
    let recipient = match to {
        Some(h) => {
            let bytes =
                decode_hex_32(h).ok_or_else(|| CtlError::msg("--to must be 32 bytes of hex"))?;
            master_public_from_bytes(bytes)
        }
        None => master_pubkey(&private),
    };
    let data = read_input(input)?;
    let envelope = seal_envelope(&recipient, &data, &mut rand::rngs::OsRng);
    write_output(output, &envelope)
}

fn unseal(key_file: &Path, input: Option<&Path>, output: Option<&Path>) -> Result<(), CtlError> {
    let private = load_private_key(key_file)?;
    let envelope = read_input(input)?;
    let plaintext = open_envelope(&private, &envelope)
        .map_err(|e| CtlError::msg(format!("unseal failed: {e}")))?;
    write_output(output, &plaintext)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Load a private key from a raw 32-byte file.
fn load_private_key(path: &Path) -> Result<DataKey, CtlError> {
    let raw = std::fs::read(path)
        .map_err(|e| CtlError::msg(format!("cannot read key {}: {e}", path.display())))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| CtlError::msg(format!("key file {} must be 32 bytes", path.display())))?;
    Ok(DataKey::from_bytes(bytes))
}

/// Write a file, refusing to overwrite unless `force` is set.
fn write_new(path: &Path, bytes: &[u8], mode: u32, force: bool) -> Result<(), CtlError> {
    if path.exists() && !force {
        return Err(CtlError::msg(format!(
            "{} already exists (use --force to overwrite)",
            path.display()
        )));
    }
    std::fs::write(path, bytes).map_err(CtlError::from)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(CtlError::from)?;
    Ok(())
}

fn read_input(input: Option<&Path>) -> Result<Vec<u8>, CtlError> {
    match input {
        Some(p) => {
            std::fs::read(p).map_err(|e| CtlError::msg(format!("cannot read {}: {e}", p.display())))
        }
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(CtlError::from)?;
            Ok(buf)
        }
    }
}

fn write_output(output: Option<&Path>, bytes: &[u8]) -> Result<(), CtlError> {
    match output {
        Some(p) => std::fs::write(p, bytes).map_err(CtlError::from),
        None => {
            std::io::stdout().write_all(bytes).map_err(CtlError::from)?;
            Ok(())
        }
    }
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
