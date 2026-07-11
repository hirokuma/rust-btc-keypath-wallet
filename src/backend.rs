use bdk_electrum::electrum_client;
use std::{result::Result, sync::Arc};

use bdk_wallet::{
    KeychainKind,
    bitcoin::{Transaction, Txid},
    chain::spk_client::{
        FullScanRequestBuilder, FullScanResponse, SyncRequestBuilder, SyncResponse,
    },
};

#[derive(thiserror::Error, Debug)]
pub enum BackendSourceError {
    #[error("Electrum: {0}")]
    Electrum(#[from] electrum_client::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("new instance")]
    New {
        #[source]
        source: BackendSourceError,
    },

    #[error("full scan error")]
    FullScan {
        #[source]
        source: BackendSourceError,
    },

    #[error("sync error")]
    Sync {
        #[source]
        source: BackendSourceError,
    },

    #[error("get transaction error")]
    GetTx {
        txid: Txid,
        #[source]
        source: BackendSourceError,
    },

    #[error("send transaction error")]
    SendTx {
        inputs: usize,
        outputs: usize,
        #[source]
        source: BackendSourceError,
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
