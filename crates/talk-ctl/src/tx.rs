//! `talkctl tx` — the transaction ledger.

use crate::store::Ctx;
use crate::CtlError;
use clap::Subcommand;
use talk_mailstore::{Transaction, TxDirection, TxState};

#[derive(Debug, Subcommand)]
pub enum TxAction {
    /// List ledger transactions (optionally filtered).
    List {
        #[arg(long)]
        dir: Option<String>,
        #[arg(long)]
        state: Option<String>,
    },
    /// Show one transaction in detail.
    Show { id: i64 },
    /// Transition an inbound transaction opaque -> resolved (simulated
    /// on-chain binding match).
    Resolve {
        id: i64,
        /// Optional on-chain binding (hex) to record.
        #[arg(long)]
        binding: Option<String>,
    },
    /// Transition a resolved inbound transaction to spent.
    MarkSpent { id: i64 },
    /// Re-send an outbound transaction from its persisted body and
    /// re-classify (sent / failed / retrying).
    Retry { id: i64 },
    /// Mark an outbound transaction failed.
    Fail { id: i64 },
}

pub fn run(config_path: Option<&std::path::Path>, action: TxAction) -> Result<(), CtlError> {
    let ctx = Ctx::load(config_path)?;
    match action {
        TxAction::List { dir, state } => list(&ctx, dir.as_deref(), state.as_deref()),
        TxAction::Show { id } => show(&ctx, id),
        TxAction::Resolve { id, binding } => resolve(&ctx, id, binding.as_deref()),
        TxAction::MarkSpent { id } => {
            let tx = require_tx(&ctx, id)?;
            if tx.direction != TxDirection::In {
                return Err(CtlError::msg("only inbound transactions can be spent"));
            }
            ctx.store.tx_transition(id, TxState::Spent)?;
            println!("ok: tx {id} -> spent");
            Ok(())
        }
        TxAction::Fail { id } => {
            require_tx(&ctx, id)?;
            ctx.store.tx_transition(id, TxState::Failed)?;
            println!("ok: tx {id} -> failed");
            Ok(())
        }
        TxAction::Retry { id } => retry(&ctx, id),
    }
}

fn list(ctx: &Ctx, dir: Option<&str>, state: Option<&str>) -> Result<(), CtlError> {
    let direction = match dir {
        Some(d) => Some(TxDirection::parse(d).ok_or_else(|| {
            CtlError::msg(format!("invalid direction: {d} (use in|out)"))
        })?),
        None => None,
    };
    let state = match state {
        Some(s) => Some(TxState::parse(s).ok_or_else(|| {
            CtlError::msg(format!(
                "invalid state: {s} (use opaque|resolved|spent|sent|failed|retrying)"
            ))
        })?),
        None => None,
    };
    for t in ctx.store.tx_list(direction, state)? {
        println!(
            "{:>4} {:<4} {:<8} {:<30} -> {:<30} amount={:<8} mid={}",
            t.id,
            t.direction.as_str(),
            t.state.as_str(),
            t.sender_mailbox,
            t.recipient_mailbox,
            t.amount,
            t.message_id,
        );
    }
    Ok(())
}

fn show(ctx: &Ctx, id: i64) -> Result<(), CtlError> {
    let t = require_tx(ctx, id)?;
    println!("id              {}", t.id);
    println!("direction       {}", t.direction.as_str());
    println!("state           {}", t.state.as_str());
    println!("sender          {}", t.sender_mailbox);
    println!("recipient       {}", t.recipient_mailbox);
    println!("amount          {}", t.amount);
    println!("binding         {}", t.binding.as_deref().unwrap_or("(none)"));
    println!("message_id      {}", t.message_id);
    println!(
        "message_row     {}",
        t.message_row_id.map(|r| r.to_string()).unwrap_or_else(|| "(none)".into())
    );
    println!(
        "outbound_body   {}",
        t.outbound_body.as_ref().map(|b| format!("{} bytes", b.len())).unwrap_or_else(|| "(none)".into())
    );
    println!("payload         {}", t.payload);
    println!("created_at      {}", t.created_at);
    println!("updated_at      {}", t.updated_at);
    Ok(())
}

fn resolve(ctx: &Ctx, id: i64, binding: Option<&str>) -> Result<(), CtlError> {
    let tx = require_tx(ctx, id)?;
    if tx.direction != TxDirection::In {
        return Err(CtlError::msg("only inbound transactions can be resolved"));
    }
    if let Some(b) = binding {
        ctx.store.tx_set_binding(id, Some(b))?;
    }
    ctx.store.tx_transition(id, TxState::Resolved)?;
    println!("ok: tx {id} -> resolved");
    Ok(())
}

fn retry(ctx: &Ctx, id: i64) -> Result<(), CtlError> {
    let tx = require_tx(ctx, id)?;
    if tx.direction != TxDirection::Out {
        return Err(CtlError::msg("only outbound transactions can be retried"));
    }
    let body = tx
        .outbound_body
        .clone()
        .ok_or_else(|| CtlError::msg("no outbound body persisted for this transaction"))?;
    let sender = tx.sender_mailbox.split('@').next().unwrap_or("").to_string();
    let payload = match tx.payload.as_str() {
        "plaintext" => talk_protocol::envelope::Payload::Plaintext,
        _ => talk_protocol::envelope::Payload::Sealed,
    };
    let rt = tokio::runtime::Runtime::new()?;
    let recipient = tx.recipient_mailbox.clone();
    let message_id = tx.message_id.clone();
    let state = rt.block_on(async move {
        crate::remote::deliver_invoice(ctx, &sender, &recipient, &message_id, payload, body).await
    })?;
    println!("ok: tx {id} re-sent -> {}", state.as_str());
    Ok(())
}

fn require_tx(ctx: &Ctx, id: i64) -> Result<Transaction, CtlError> {
    ctx.store
        .tx_get(id)?
        .ok_or_else(|| CtlError::msg(format!("no such transaction: {id}")))
}
