use std::{result::Result, sync::Arc};

use bdk_electrum::{
    BdkElectrumClient,
    electrum_client::{self, ElectrumApi},
};
use bdk_wallet::{
    KeychainKind,
    bitcoin::{Address, Transaction, Txid},
    chain::spk_client::{
        FullScanRequestBuilder, FullScanResponse, SyncRequestBuilder, SyncResponse,
    },
};
use tracing::*;

use crate::{
    backend::{BackendError, BackendRpc, BackendSourceError, ScriptHistory},
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
                    source: BackendSourceError::Electrum(Box::new(e)),
                },
                "new",
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
                    BackendError::FullScan(BackendSourceError::Electrum(Box::new(e))),
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
                BackendError::Sync(BackendSourceError::Electrum(Box::new(e))),
                "sync: batch_size={}",
                self.batch_size
            )
        })?;
        trace!("sync done");
        Ok(update)
    }

    fn get_current_height(&self) -> Result<u32, BackendError> {
        Ok(self
            .client
            .inner
            .block_headers_subscribe()
            .map_err(|e| {
                log_err!(
                    BackendError::FullScan(BackendSourceError::Electrum(Box::new(e))),
                    "get_current_height"
                )
            })?
            .height as u32)
    }

    fn get_tx(&self, txid: Txid) -> Result<Arc<Transaction>, BackendError> {
        self.client.fetch_tx(txid).map_err(|e| {
            log_err!(
                BackendError::GetTx {
                    txid,
                    source: BackendSourceError::Electrum(Box::new(e)),
                },
                "fetch_tx"
            )
        })
    }

    fn fetch_script_history(
        &self,
        addr: &Address,
        last_height: u32,
        only_confirmed: bool,
    ) -> Result<Vec<ScriptHistory>, BackendError> {
        let script = addr.script_pubkey();
        let history = self.client.inner.script_get_history(&script).map_err(|e| {
            log_err!(
                BackendError::FindTxs {
                    addr: addr.clone(),
                    source: BackendSourceError::Electrum(Box::new(e)),
                },
                "script_get_history"
            )
        })?;
        let history: Vec<ScriptHistory> = history
            .into_iter()
            .filter(|h| {
                if only_confirmed {
                    h.height > 0 && h.height as u32 > last_height
                } else {
                    h.height <= 0 || h.height as u32 > last_height
                }
            })
            .map(|h| {
                let height = if h.height > 0 { h.height as u32 } else { 0 };
                ScriptHistory {
                    txid: h.tx_hash,
                    height,
                }
            })
            .collect();
        Ok(history)
    }

    fn send_tx(&self, tx: &Transaction) -> Result<Txid, BackendError> {
        self.client.transaction_broadcast(tx).map_err(|e| {
            log_err!(
                BackendError::SendTx {
                    inputs: tx.input.len(),
                    outputs: tx.output.len(),
                    source: BackendSourceError::Electrum(Box::new(e)),
                },
                "send_tx"
            )
        })
    }
}
