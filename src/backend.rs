use bdk_electrum::electrum_client;
use std::{result::Result, sync::Arc};
use thiserror::Error;

use bdk_wallet::{
    KeychainKind,
    bitcoin::{Transaction, Txid},
    chain::spk_client::{
        FullScanRequestBuilder, FullScanResponse, SyncRequestBuilder, SyncResponse,
    },
};

#[derive(Error, Debug)]
pub enum BackendError {
    #[error("Electrum client error occurred: reason={reason}, source={source}")]
    Electrum {
        reason: String,
        #[source]
        source: electrum_client::Error,
    },
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
