use std::{result::Result, sync::Arc};

use bdk_electrum::{BdkElectrumClient, electrum_client};
use bdk_wallet::bitcoin::{Transaction, Txid};

use crate::{
    backend::{BackendError, BackendRpc},
    config::ElectrumConfig,
    logger::*,
    wallet::Wallet,
};

pub struct ElectrumRpc {
    client: BdkElectrumClient<electrum_client::Client>,
}

impl ElectrumRpc {
    const BATCH_SIZE: usize = 5;
    const GAP_LIMIT: usize = 20;

    pub fn new(config: &ElectrumConfig) -> Result<ElectrumRpc, BackendError> {
        let client = electrum_client::Client::new(&config.server)?;
        let client = BdkElectrumClient::new(client);
        Ok(ElectrumRpc { client })
    }
}

impl BackendRpc for ElectrumRpc {
    fn full_scan(&self, wallet: &mut Wallet) -> Result<(), BackendError> {
        let req = wallet.start_full_scan();
        let update =
            self.client
                .full_scan(req, ElectrumRpc::GAP_LIMIT, ElectrumRpc::BATCH_SIZE, false)?;
        wallet.apply_update(update)?;

        debug!("full_scan done");
        Ok(())
    }

    fn sync(&self, wallet: &mut Wallet) -> Result<(), BackendError> {
        let req = wallet.start_sync_with_revealed_spks();
        let update = self.client.sync(req, ElectrumRpc::BATCH_SIZE, false)?;
        wallet.apply_update(update)?;

        Ok(())
    }

    fn get_tx(&self, txid: Txid) -> Result<Arc<Transaction>, BackendError> {
        Ok(self.client.fetch_tx(txid)?)
    }

    fn send_tx(&self, tx: &Transaction) -> Result<Txid, BackendError> {
        Ok(self.client.transaction_broadcast(tx)?)
    }
}
