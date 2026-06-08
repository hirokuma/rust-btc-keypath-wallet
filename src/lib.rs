mod backend;
mod config;
mod electrum;
mod logger;
mod wallet;

use bdk_wallet::{bitcoin::{
    self, FeeRate,
    address::{NetworkUnchecked, ParseError},
    consensus::encode::{FromHexError, deserialize_hex, serialize_hex},
    key::rand::{self, RngCore},
}, chain::local_chain::CannotConnectError};
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
    Config(#[from] ConfigError),

    #[error(transparent)]
    Backend(#[from] BackendError),

    #[error(transparent)]
    CannotConnect(#[from] CannotConnectError),

    #[error(transparent)]
    Wallet(#[from] WalletError),

    #[error(transparent)]
    Convert(#[from] FromHexError),

    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error("file existance error: {0}")]
    FileExistance(&'static str),
}

pub fn load_config(config_fname: &str) -> Result<Config, Error> {
    Ok(Config::new(config_fname)
        .inspect_err(|e| trace!("fail load_config({}): {}", config_fname, e))?)
}

pub struct BtcWallet {
    pub config: Config,
    pub rpc: Box<dyn BackendRpc>,
    pub wallet: Wallet,
}

impl BtcWallet {
    /// BtcWalletのウォレットファイルと秘密鍵ファイルがあるならload、両方ともなければ生成する
    pub fn create_or_load(config: Config) -> Result<Self, Error> {
        let is_create = if config.privkey_fname.exists() && config.wallet_fname.exists() {
            false
        } else if !config.privkey_fname.exists() && !config.wallet_fname.exists() {
            true
        } else {
            trace!("invalid wallet files");
            return Err(Error::FileExistance("invalid wallet files"));
        };
        let (rpc, wallet) = Self::init(&config, is_create)?;
        debug!("create_or_load done");
        Ok(Self {
            config,
            rpc,
            wallet,
        })
    }

    /// BtcWalletを生成する。ウォレットファイルか秘密鍵ファイルがある場合は失敗する。
    pub fn create(config: Config) -> Result<Self, Error> {
        let (rpc, wallet) = Self::init(&config, true)?;
        debug!("create done");
        Ok(Self {
            config,
            rpc,
            wallet,
        })
    }

    /// BtcWalletをloadする。ウォレットファイルか秘密鍵ファイルがない場合は失敗する。
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
            Wallet::create(config, &seed)?
        } else {
            Wallet::load(config)?
        };
        let rpc = match config.backend {
            config::Backend::Electrum => electrum::ElectrumRpc::new(&config.electrum)?,
        };
        let req = wallet.start_full_scan();
        let update = rpc.initial_scan(req)?;
        wallet.apply_update(update)?;
        Ok((Box::new(rpc), wallet))
    }
}

impl BtcWallet {
    pub fn sync(&mut self) -> Result<(), Error> {
        let req = self.wallet.start_sync_with_revealed_spks();
        let update = self.rpc.sync(req)?;
        Ok(self.wallet.apply_update(update)?)
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

    pub fn create_tx(
        &mut self,
        out_addr: &str,
        amount: u64,
        fee_rate: f64,
    ) -> Result<Transaction, Error> {
        self.create_tx_sighash_type(out_addr, amount, fee_rate, None)
    }

    /// SINGLE+ANYONE_CAN_PAY sighashタイプを使用してトランザクションを作成する
    ///
    /// この署名タイプは、特定の入力のみを署名し、他の入力の変更を許可します
    pub fn create_tx_single_anypay(
        &mut self,
        out_addr: &str,
        amount: u64,
        fee_rate: f64,
    ) -> Result<Transaction, Error> {
        self.create_tx_sighash_type(
            out_addr,
            amount,
            fee_rate,
            Some(bitcoin::TapSighashType::SinglePlusAnyoneCanPay),
        )
    }

    fn create_tx_sighash_type(
        &mut self,
        out_addr: &str,
        amount: u64,
        fee_rate: f64,
        sighash_type: Option<bitcoin::TapSighashType>,
    ) -> Result<Transaction, Error> {
        let out_addr: Address<NetworkUnchecked> = out_addr.parse()?;
        let out_addr: Address = out_addr.require_network(self.config.network)?;
        let amount = Amount::from_sat(amount);

        // sat/vB から sat/kwu に変換 (1 sat/vB = 250 sat/kwu)
        // https://deepwiki.com/search/fee-ratesatsvbytefeerate_1892991e-17d5-4d2e-bd27-97078e3a1930?mode=fast
        let fee_rate = FeeRate::from_sat_per_kwu((fee_rate * 1000.0 / 4.0) as u64);

        Ok(self
            .wallet
            .create_tx(&out_addr, amount, fee_rate, sighash_type)?)
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
                batch_size: Some(10),
                gap_limit: Some(20),
            },
        }
    }
}
