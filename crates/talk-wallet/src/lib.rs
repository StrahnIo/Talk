//! Lightwalletd client, per-user scanning, and send path.
//!
//! Generates tonic gRPC stubs from the vendored lightwalletd protos
//! (`proto/service.proto`, `proto/compact_formats.proto`).

pub mod client;
pub mod wallet;

// Generated gRPC stubs.
pub mod rpc {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

pub use client::{LightwalletdClient, WalletError};
pub use wallet::UserWallet;
