use std::{result::Result, sync::Arc};

use bdk_electrum::electrum_client::Error as ElectrumError;
use bdk_wallet::{
    KeychainKind,
    bitcoin::{Address, Transaction, Txid},
    chain::spk_client::{
        FullScanRequestBuilder, FullScanResponse, SyncRequestBuilder, SyncResponse,
    },
};

#[derive(thiserror::Error, Debug)]
pub enum BackendSourceError {
    #[error("Electrum: {0}")]
    Electrum(#[from] Box<ElectrumError>),
}

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("new client error: server={server}")]
    NewClient {
        server: String,
        #[source]
        source: BackendSourceError,
    },

    #[error("{0}")]
    FullScan(#[source] BackendSourceError),

    #[error("sync error")]
    Sync(#[source] BackendSourceError),

    #[error("get transaction error: {source}")]
    GetTx {
        txid: Txid,
        #[source]
        source: BackendSourceError,
    },

    #[error("find txs: {source}")]
    FindTxs {
        addr: Address,
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

#[derive(Debug, Clone)]
pub struct ScriptHistory {
    /// Confirmation height of the transaction. 0 if unconfirmed, -1 if unconfirmed while some of
    /// its inputs are unconfirmed too.
    pub height: u32,
    /// Txid of the transaction.
    pub txid: Txid,
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

    fn find_txs(
        &self,
        addr: &Address,
        last_height: u32,
        only_confirmed: bool,
    ) -> Result<Vec<ScriptHistory>, BackendError>;

    /// Send the transaction
    fn send_tx(&self, tx: &Transaction) -> Result<Txid, BackendError>;
}
