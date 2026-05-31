mod backend;
mod config;
mod electrum;
mod logger;
mod wallet;

use bdk_wallet::bitcoin::{
    FeeRate, address::{NetworkUnchecked, ParseError}, consensus::encode::{FromHexError, deserialize_hex, serialize_hex}, key::rand::{self, RngCore}
};
pub use bdk_wallet::{
    Balance,
    bitcoin::{Address, Amount, Transaction, Txid},
};
use std::{result::Result, sync::Arc};
use thiserror::Error;

use crate::{
    backend::{BackendError, BackendRpc},
    config::{Config, ConfigError},
    logger::*,
    wallet::{Wallet, WalletError},
};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ConfigError(#[from] ConfigError),

    #[error(transparent)]
    BackendError(#[from] BackendError),

    #[error(transparent)]
    WalletError(#[from] WalletError),

    #[error(transparent)]
    ConvError(#[from] FromHexError),

    #[error(transparent)]
    ParseError(#[from] ParseError),

    #[error("File error: {0}")]
    FileError(&'static str),

    #[error("Invalid parameters error: {0}")]
    InvalidParams(&'static str),
}

// trait _BtcWalletT {
//     fn initial_sync(&mut self) -> Result<(), Error>;
//     fn sync(&mut self) -> Result<(), Error>;
//     fn balance(&self) -> u64;
//     fn new_address(&mut self) -> String;
//     fn get_address(&self, index: u32) -> String;
//     fn get_rawtx_hex(&self) -> String;
//     fn print_rawtx_hex(&self, tx_hex: &str);
//     fn spend(&self, out_addr: &str, amount: u64, fee_rate: f64) -> Result<String, Error>;
//     fn send_rawtx_hex(&self, tx_hex: &str) -> Result<(), Error>;
// }

pub fn load_config(config_fname: &str) -> Result<Config, Error> {
    Ok(Config::new(config_fname)?)
}

pub struct BtcWallet {
    pub config: Config,
    pub rpc: Box<dyn BackendRpc>,
    pub wallet: Wallet,
}

impl BtcWallet {
    pub fn create_or_load(config: Config) -> Result<Self, Error> {
        let is_create = if config.privkey_fname.exists() && config.wallet_fname.exists() {
            false
        } else if !config.privkey_fname.exists() && !config.wallet_fname.exists() {
            true
        } else {
            return Err(Error::InvalidParams(""));
        };
        let (rpc, wallet) = Self::init(&config, is_create)?;
        debug!("create_or_load done");
        Ok(Self {
            config,
            rpc,
            wallet,
        })
    }

    pub fn create(config: Config) -> Result<Self, Error> {
        let (rpc, wallet) = Self::init(&config, true)?;
        debug!("create done");
        Ok(Self {
            config,
            rpc,
            wallet,
        })
    }

    pub fn load(config: Config) -> Result<Self, Error> {
        let (rpc, wallet) = Self::init(&config, false)?;
        debug!("load done");
        Ok(Self {
            config,
            rpc,
            wallet,
        })
    }

    fn init(config: &Config, is_create: bool) -> Result<(Box<dyn BackendRpc>, Wallet), Error> {
        let mut wallet = if is_create {
            let mut seed: [u8; 32] = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            Wallet::create(&config, &seed)?
        } else {
            Wallet::load(&config)?
        };
        let rpc = match config.backend {
            config::Backend::Electrum => electrum::ElectrumRpc::new(&config.electrum)?,
        };
        rpc.full_scan(&mut wallet)?;
        Ok((Box::new(rpc), wallet))
    }
}

impl BtcWallet {
    // pub fn initial_sync(&mut self) -> Result<(), Error> {
    //     Ok(self.rpc.full_scan(&mut self.wallet)?)
    // }

    pub fn sync(&mut self) -> Result<(), Error> {
        Ok(self.rpc.sync(&mut self.wallet)?)
    }

    pub fn balance(&self) -> Balance {
        self.wallet.balance()
    }

    pub fn new_address(&mut self) -> Address {
        self.wallet.new_address()
    }

    pub fn get_address(&self, index: u32) -> Address {
        self.wallet.get_address(index)
    }

    pub fn get_tx(&self, txid: Txid) -> Result<Arc<Transaction>, Error> {
        Ok(self.rpc.get_tx(txid)?)
    }

    pub fn to_tx(&self, tx_hex: &str) -> Result<Transaction, Error> {
        Ok(deserialize_hex(tx_hex)?)
    }

    pub fn tx_to_string(&self, tx: &Transaction) -> String {
        serialize_hex(tx)
    }

    pub fn create_tx(&mut self, out_addr: &str, amount: u64, fee_rate: f64) -> Result<Transaction, Error> {
        let out_addr: Address<NetworkUnchecked> = out_addr.parse()?;
        let out_addr: Address = out_addr.require_network(self.config.network)?;
        let amount = Amount::from_sat(amount);
        let fee_rate = FeeRate::from_sat_per_kwu((fee_rate * 1000.0 / 4.0) as u64);
        Ok(self.wallet.create_tx(&out_addr, amount, fee_rate, false)?)
    }

    pub fn send_tx(&self, tx: &Transaction) -> Result<Txid, Error> {
        Ok(self.rpc.send_tx(tx)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet;
    use tempfile::tempdir;

    #[test]
    fn test_create_load() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create(config.clone()).unwrap();
        }
        {
            let _ = BtcWallet::load(config.clone()).unwrap();
        }
        {
            let result = BtcWallet::create(config.clone());
            assert_eq!(result.is_ok(), false);
        }
    }

    #[test]
    fn test_create_or_load() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create_or_load(config.clone()).unwrap();
        }
        {
            let _ = BtcWallet::load(config.clone()).unwrap();
        }
        {
            let result = BtcWallet::create(config.clone());
            assert_eq!(result.is_ok(), false);
        }
    }

    #[test]
    fn test_fail_load_not_created() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let result = BtcWallet::load(config.clone());
            assert_eq!(result.is_ok(), false);
        }
    }

    #[test]
    fn test_fail_load_no_privkey_file() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create(config.clone()).unwrap();
        }
        {
            std::fs::remove_file(&config.privkey_fname).unwrap();
            let result = BtcWallet::load(config.clone());
            assert_eq!(result.is_ok(), false);
        }
    }

    #[test]
    fn test_fail_load_no_wallet_file() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create(config.clone()).unwrap();
        }
        {
            std::fs::remove_file(&config.wallet_fname).unwrap();
            let result = BtcWallet::load(config.clone());
            assert_eq!(result.is_ok(), false);
        }
    }

    fn make_config(dir: &tempfile::TempDir) -> Config {
        let bdk_path = dir.path().join("wallet.bdk");
        let xpriv_path = dir.path().join("xpriv.txt");
        Config {
            wallet_fname: bdk_path,
            privkey_fname: xpriv_path,
            network: bdk_wallet::bitcoin::Network::Regtest,
            backend: config::Backend::Electrum,
            electrum: config::ElectrumConfig {
                enabled: true,
                server: "tcp://127.0.0.1:50001".to_string(),
            },
        }
    }
}
