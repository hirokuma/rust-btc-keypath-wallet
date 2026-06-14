mod backend;
mod config;
mod electrum;
mod logger;
mod wallet;

pub use bdk_wallet::{
    self, Balance,
    bitcoin::{self, Address, Amount, Transaction, Txid, bip32::Xpriv},
    miniscript,
};
use bdk_wallet::{
    bitcoin::{
        FeeRate, address::{NetworkUnchecked, ParseError}, consensus::encode::{FromHexError, deserialize_hex, serialize_hex}, hex::HexToArrayError, key::rand::{self, RngCore}
    },
    chain::local_chain::CannotConnectError,
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
    TxConvert(#[from] FromHexError),

    #[error(transparent)]
    TxidConvert(#[from] HexToArrayError),

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
    // fn save_callback(privkey: &Xpriv, _config: &Config) {
    //     *saved_privkey.borrow_mut() = Some(privkey.clone());
    // }


    /// BtcWalletのウォレットファイルと秘密鍵ファイルがあるならload、両方ともなければ生成する
    pub fn create_or_load(
        config: Config,
        privkey_save_callback: Option<&dyn Fn(&Xpriv, &Config)>,
        privkey_load_callback: Option<&dyn Fn(&Config) -> Xpriv>,
    ) -> Result<Self, Error> {
        let is_create = match (&config.privkey_fname, config.wallet_fname.exists()) {
            (Some(fname), true) if fname.exists() => false,
            (None, true) => false,
            (Some(fname), false) if !fname.exists() => true,
            (None, false) => true,
            _ => {
                trace!("invalid wallet files");
                return Err(Error::FileExistance("invalid wallet files"));
            }
        };
        let (rpc, wallet) = Self::init(
            &config,
            is_create,
            privkey_save_callback,
            privkey_load_callback,
        )?;
        debug!("create_or_load done");
        Ok(Self {
            config,
            rpc,
            wallet,
        })
    }

    /// BtcWalletを生成する。ウォレットファイルか秘密鍵ファイルがある場合は失敗する。
    pub fn create(
        config: Config,
        privkey_save_callback: Option<&dyn Fn(&Xpriv, &Config)>,
    ) -> Result<Self, Error> {
        let (rpc, wallet) = Self::init(&config, true, privkey_save_callback, None)?;
        debug!("create done");
        Ok(Self {
            config,
            rpc,
            wallet,
        })
    }

    /// BtcWalletをloadする。ウォレットファイルか秘密鍵ファイルがない場合は失敗する。
    pub fn load(
        config: Config,
        privkey_load_callback: Option<&dyn Fn(&Config) -> Xpriv>,
    ) -> Result<Self, Error> {
        let (rpc, wallet) = Self::init(&config, false, None, privkey_load_callback)?;
        debug!("load done");
        Ok(Self {
            config,
            rpc,
            wallet,
        })
    }

    fn init(
        config: &Config,
        is_create: bool,
        privkey_save_callback: Option<impl Fn(&Xpriv, &Config)>,
        privkey_load_callback: Option<&dyn Fn(&Config) -> Xpriv>,
    ) -> Result<(Box<dyn BackendRpc>, Wallet), Error> {
        let mut wallet = if is_create {
            let mut seed: [u8; 32] = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            Wallet::create(config, &seed, privkey_save_callback)?
        } else {
            Wallet::load(config, privkey_load_callback)?
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
    /// ウォレット同期
    pub fn sync(&mut self) -> Result<(), Error> {
        let req = self.wallet.start_sync_with_revealed_spks();
        let update = self.rpc.sync(req)?;
        Ok(self.wallet.apply_update(update)?)
    }

    /// 残高取得
    pub fn balance(&self) -> Balance {
        self.wallet.balance()
    }

    /// 新規アドレスを返す。HDウォレットのインデックスを更新する。
    pub fn new_address(&mut self) -> Address {
        self.wallet.new_address()
    }

    /// インデックスに該当するアドレスを返す。
    pub fn get_address(&self, index: u32) -> Address {
        self.wallet.get_address(index)
    }

    /// アドレス文字列をAddress型に変換する。
    pub fn parse_address(&self, addr_str: &str) -> Result<Address, Error> {
        let addr: Address<NetworkUnchecked> = addr_str.parse()?;
        Ok(addr.require_network(self.config.network)?)
    }

    /// TXIDに該当するトランザクションを取得する。
    pub fn get_tx(&self, txid: Txid) -> Result<Arc<Transaction>, Error> {
        Ok(self.rpc.get_tx(txid)?)
    }

    pub fn parse_txid_hex(&self, txid_hex: &str) -> Result<Txid, Error> {
        Ok(txid_hex.parse()?)
    }

    pub fn parse_tx_hex(&self, tx_hex: &str) -> Result<Transaction, Error> {
        Ok(deserialize_hex(tx_hex)?)
    }

    pub fn to_tx_hex(&self, tx: &Transaction) -> String {
        serialize_hex(tx)
    }

    pub fn create_tx(
        &mut self,
        addr: &Address,
        amount: u64,
        fee_rate: f64,
    ) -> Result<Transaction, Error> {
        self.create_tx_sighash_type(addr, amount, fee_rate, None)
    }

    /// SINGLE+ANYONE_CAN_PAY sighashタイプを使用してトランザクションを作成する
    ///
    /// この署名タイプは、特定の入力のみを署名し、他の入力の変更を許可します
    pub fn create_tx_single_anypay(
        &mut self,
        addr: &Address,
        amount: u64,
        fee_rate: f64,
    ) -> Result<Transaction, Error> {
        self.create_tx_sighash_type(
            addr,
            amount,
            fee_rate,
            Some(bitcoin::TapSighashType::SinglePlusAnyoneCanPay),
        )
    }

    fn create_tx_sighash_type(
        &mut self,
        addr: &Address,
        amount: u64,
        fee_rate: f64,
        sighash_type: Option<bitcoin::TapSighashType>,
    ) -> Result<Transaction, Error> {
        let amount = Amount::from_sat(amount);

        // sat/vB から sat/kwu に変換 (1 sat/vB = 250 sat/kwu)
        // https://deepwiki.com/search/fee-ratesatsvbytefeerate_1892991e-17d5-4d2e-bd27-97078e3a1930?mode=fast
        let fee_rate = FeeRate::from_sat_per_kwu((fee_rate * 1000.0 / 4.0) as u64);

        Ok(self
            .wallet
            .create_tx(addr, amount, fee_rate, sighash_type)?)
    }

    pub fn send_tx(&self, tx: &Transaction) -> Result<Txid, Error> {
        Ok(self.rpc.send_tx(tx)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_load() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create(config.clone(), None).unwrap();
        }
        {
            let _ = BtcWallet::load(config.clone(), None).unwrap();
        }
        {
            let result = BtcWallet::create(config.clone(), None);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_create_or_load() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create_or_load(config.clone(), None, None).unwrap();
        }
        {
            let _ = BtcWallet::load(config.clone(), None).unwrap();
        }
        {
            let result = BtcWallet::create(config.clone(), None);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fail_load_not_created() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let result = BtcWallet::load(config.clone(), None);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fail_load_no_privkey_file() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create(config.clone(), None).unwrap();
        }
        {
            std::fs::remove_file(config.privkey_fname.as_ref().unwrap()).unwrap();
            let result = BtcWallet::load(config.clone(), None);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fail_load_no_wallet_file() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create(config.clone(), None).unwrap();
        }
        {
            std::fs::remove_file(&config.wallet_fname).unwrap();
            let result = BtcWallet::load(config.clone(), None);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_parse_txid_hex() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        let wallet = BtcWallet::create(config.clone(), None).unwrap();

        // empty
        let txid_str = "";
        let txid = wallet.parse_txid_hex(txid_str);
        assert!(txid.is_err());

        // valid txid (32 bytes = 64 hex chars)
        let txid_str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let txid = wallet.parse_txid_hex(txid_str);
        assert!(txid.is_ok());
        let result: Txid = txid_str.parse().unwrap();
        assert_eq!(txid.unwrap(), result);

        // short
        let txid_str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
        let txid = wallet.parse_txid_hex(txid_str);
        assert!(txid.is_err());

        // long
        let txid_str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00";
        let txid = wallet.parse_txid_hex(txid_str);
        assert!(txid.is_err());
    }

    #[test]
    fn test_create_load_with_callback() {
        let dir = tempdir().unwrap();
        let config = make_config_no_privkey(&dir);
        use std::cell::RefCell;
        let saved_privkey: RefCell<Option<Xpriv>> = RefCell::new(None);

        {
            let save_callback = |privkey: &Xpriv, _config: &Config| {
                *saved_privkey.borrow_mut() = Some(privkey.clone());
            };
            let _ = BtcWallet::create(config.clone(), Some(&save_callback)).unwrap();
            assert!(saved_privkey.borrow().is_some());
        }

        {
            let load_callback = |_config: &Config| -> Xpriv { saved_privkey.borrow().as_ref().unwrap().clone() };
            let _ = BtcWallet::load(config.clone(), Some(&load_callback)).unwrap();
        }
    }

    #[test]
    fn test_create_or_load_with_callback() {
        let dir = tempdir().unwrap();
        let config = make_config_no_privkey(&dir);
        use std::cell::RefCell;
        let saved_privkey: RefCell<Option<Xpriv>> = RefCell::new(None);

        {
            let save_callback = |privkey: &Xpriv, _config: &Config| {
                *saved_privkey.borrow_mut() = Some(privkey.clone());
            };
            let _ = BtcWallet::create_or_load(config.clone(), Some(&save_callback), None).unwrap();
            assert!(saved_privkey.borrow().is_some());
        }

        {
            let load_callback = |_config: &Config| -> Xpriv { saved_privkey.borrow().as_ref().unwrap().clone() };
            let _ = BtcWallet::load(config.clone(), Some(&load_callback)).unwrap();
        }
    }

    fn make_config(dir: &tempfile::TempDir) -> Config {
        let bdk_path = dir.path().join("wallet.bdk");
        let xpriv_path = dir.path().join("xpriv.txt");
        Config {
            wallet_fname: bdk_path,
            privkey_fname: Some(xpriv_path),
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

    fn make_config_no_privkey(dir: &tempfile::TempDir) -> Config {
        let bdk_path = dir.path().join("wallet.bdk");
        Config {
            wallet_fname: bdk_path,
            privkey_fname: None,
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
