use bdk_electrum::electrum_client;
use std::{result::Result, sync::Arc};
use thiserror::Error;

use bdk_wallet::{
    bitcoin::{Transaction, Txid},
    chain::local_chain::CannotConnectError,
};

use crate::{Wallet, config};

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
    fn full_scan(&self, wallet: &mut Wallet) -> Result<(), BackendError>;
    fn sync(&self, wallet: &mut Wallet) -> Result<(), BackendError>;
    fn get_tx(&self, txid: Txid) -> Result<Arc<Transaction>, BackendError>;
    fn send_tx(&self, tx: &Transaction) -> Result<Txid, BackendError>;
}
