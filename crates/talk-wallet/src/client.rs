//! Minimal lightwalletd gRPC client.
//!
//! Connects to a lightwalletd endpoint and exposes the core RPCs needed by the
//! daemon: latest block height, block ranges (compact blocks), and transaction
//! broadcasting.

use crate::rpc::{
    BlockId, BlockRange, ChainSpec, RawTransaction,
    compact_tx_streamer_client::CompactTxStreamerClient,
};
use thiserror::Error;
use tonic::Status;
use tonic::transport::Channel;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("gRPC transport: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("gRPC: {0}")]
    Rpc(#[from] Status),
    #[error("lightwalletd rejected broadcast: {0}")]
    BroadcastRejected(String),
}

/// A connection to a lightwalletd server.
pub struct LightwalletdClient {
    streamer: CompactTxStreamerClient<Channel>,
}

impl LightwalletdClient {
    /// Connect to a lightwalletd endpoint (e.g. `"lwd.example.com:9067"`).
    pub async fn connect(endpoint: &str) -> Result<Self, WalletError> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| WalletError::InvalidEndpoint(e.to_string()))?
            .connect()
            .await?;
        Ok(Self {
            streamer: CompactTxStreamerClient::new(channel),
        })
    }

    /// Fetch the latest confirmed block height.
    pub async fn latest_height(&mut self) -> Result<u64, WalletError> {
        let resp = self.streamer.get_latest_block(ChainSpec {}).await?;
        Ok(resp.into_inner().height)
    }

    /// Fetch a range of compact blocks `[start, end]` (inclusive) as a stream.
    pub async fn block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Vec<crate::rpc::CompactBlock>, WalletError> {
        let req = BlockRange {
            start: Some(BlockId {
                height: start,
                hash: Vec::new(),
            }),
            end: Some(BlockId {
                height: end,
                hash: Vec::new(),
            }),
            pool_types: Vec::new(),
        };
        let mut stream = self.streamer.get_block_range(req).await?.into_inner();
        let mut blocks = Vec::new();
        while let Some(block) = stream.message().await? {
            blocks.push(block);
        }
        Ok(blocks)
    }

    /// Broadcast a raw transaction to the network.
    pub async fn send_transaction(&mut self, data: Vec<u8>) -> Result<(), WalletError> {
        let req = RawTransaction { data, height: 0 };
        let resp = self.streamer.send_transaction(req).await?.into_inner();
        if resp.error_code != 0 {
            return Err(WalletError::BroadcastRejected(resp.error_message));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_fails_cleanly() {
        let err = LightwalletdClient::connect("http://127.0.0.1:1").await;
        assert!(err.is_err(), "no lightwalletd should listen on port 1");
    }
}
