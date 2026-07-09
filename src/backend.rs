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
pub enum BackendSourceError {
    #[error("Electrum: {0}")]
    Electrum(#[from] electrum_client::Error),
}

#[derive(Error, Debug)]
pub enum BackendError {
    #[error("new instance({source}): {err_info}")]
    New {
        err_info: String,
        #[source]
        source: BackendSourceError,
    },

    #[error("full scan error({source}): {err_info}")]
    FullScan {
        err_info: String,
        #[source]
        source: BackendSourceError,
    },

    #[error("sync error({source}): {err_info}")]
    Sync {
        err_info: String,
        #[source]
        source: BackendSourceError,
    },

    #[error("get transaction error({source}): txid={txid}")]
    GetTx {
        txid: Txid,
        #[source]
        source: BackendSourceError,
    },

    #[error("send transaction error({source}): inputs={inputs}, outputs={outputs}")]
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
