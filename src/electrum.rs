use std::{result::Result, sync::Arc};

use bdk_electrum::{BdkElectrumClient, electrum_client};
use bdk_wallet::{
    KeychainKind,
    bitcoin::{Transaction, Txid},
    chain::spk_client::{
        FullScanRequestBuilder, FullScanResponse, SyncRequestBuilder, SyncResponse,
    },
};
use tracing::*;

use crate::{
    backend::{BackendError, BackendRpc, BackendSourceError},
    config::ElectrumConfig,
    log_err,
};

pub struct ElectrumRpc {
    client: BdkElectrumClient<electrum_client::Client>,
    batch_size: usize,
    gap_limit: usize,
}

impl ElectrumRpc {
    pub fn new(config: &ElectrumConfig) -> Result<ElectrumRpc, BackendError> {
        let client = electrum_client::Client::new(&config.server).map_err(|e| {
            log_err!(
                BackendError::NewClient {
                    server: config.server.clone(),
                    source: BackendSourceError::Electrum(e),
                },
                "new: server={}",
                config.server
            )
        })?;
        let client = BdkElectrumClient::new(client);
        Ok(ElectrumRpc {
            client,
            batch_size: config.batch_size,
            gap_limit: config.gap_limit,
        })
    }
}

impl BackendRpc for ElectrumRpc {
    fn initial_scan(
        &self,
        req: FullScanRequestBuilder<KeychainKind>,
    ) -> Result<FullScanResponse<KeychainKind>, BackendError> {
        let update = self
            .client
            .full_scan(req, self.gap_limit, self.batch_size, false)
            .map_err(|e| {
                log_err!(
                    BackendError::FullScan {
                        source: BackendSourceError::Electrum(e),
                    },
                    "initial_scan: gap_limit = {}, batch_size = {}",
                    self.gap_limit,
                    self.batch_size
                )
            })?;
        trace!("full_scan done");
        Ok(update)
    }

    fn sync(
        &self,
        req: SyncRequestBuilder<(KeychainKind, u32)>,
    ) -> Result<SyncResponse, BackendError> {
        let update = self.client.sync(req, self.batch_size, false).map_err(|e| {
            log_err!(
                BackendError::Sync {
                    source: BackendSourceError::Electrum(e),
                },
                "sync: batch_size={}",
                self.batch_size
            )
        })?;
        trace!("sync done");
        Ok(update)
    }

    fn get_tx(&self, txid: Txid) -> Result<Arc<Transaction>, BackendError> {
        self.client.fetch_tx(txid).map_err(|e| {
            log_err!(
                BackendError::GetTx {
                    txid,
                    source: BackendSourceError::Electrum(e),
                },
                "fetch_tx"
            )
        })
    }

    fn send_tx(&self, tx: &Transaction) -> Result<Txid, BackendError> {
        self.client.transaction_broadcast(tx).map_err(|e| {
            log_err!(
                BackendError::SendTx {
                    inputs: tx.input.len(),
                    outputs: tx.output.len(),
                    source: BackendSourceError::Electrum(e),
                },
                "send_tx"
            )
        })
    }
}
