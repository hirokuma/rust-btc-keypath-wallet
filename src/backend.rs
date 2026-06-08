use bdk_electrum::electrum_client;
use std::{result::Result, sync::Arc};
use thiserror::Error;

use bdk_wallet::{
    KeychainKind,
    bitcoin::{Transaction, Txid},
    chain::{
        local_chain::CannotConnectError,
        spk_client::{FullScanRequestBuilder, FullScanResponse, SyncRequestBuilder, SyncResponse},
    },
};

use crate::config;

#[derive(Error, Debug)]
pub enum BackendError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),

    #[error(transparent)]
    Electrum(#[from] electrum_client::Error),

    #[error(transparent)]
    CannotConnect(#[from] CannotConnectError),
}

pub trait BackendRpc: Send + Sync {
    /// Full scan for startup
    fn initial_scan(
        &self,
        req: FullScanRequestBuilder<KeychainKind>,
    ) -> Result<FullScanResponse<KeychainKind>, BackendError>;

    /// Sync known scriptPubKeys
    fn sync(
        &self,
        req: SyncRequestBuilder<(KeychainKind, u32)>,
    ) -> Result<SyncResponse, BackendError>;

    /// Get the transaction
    fn get_tx(&self, txid: Txid) -> Result<Arc<Transaction>, BackendError>;

    /// Send the transaction
    fn send_tx(&self, tx: &Transaction) -> Result<Txid, BackendError>;
}
