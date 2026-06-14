mod backend;
pub mod config;
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
        FeeRate,
        address::{NetworkUnchecked, ParseError},
        bip32,
        consensus::encode::{FromHexError, deserialize_hex, serialize_hex},
        hex::HexToArrayError,
        key::rand::{self, RngCore},
    },
    chain::local_chain::CannotConnectError,
};
use std::{fs::File, io::prelude::*, result::Result, str::FromStr, sync::Arc};
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

    #[error(transparent)]
    PrivkeyFile(#[from] std::io::Error),

    #[error(transparent)]
    Bip32(#[from] bip32::Error),

    #[error("Callback function error: {0}")]
    Callback(String),
}

pub fn load_config(config_fname: &str) -> Result<Config, Error> {
    Ok(Config::new(config_fname)
        .inspect_err(|e| trace!("fail load_config({}): {}", config_fname, e))?)
}

pub fn save_private_key(xprv: &Xpriv, config: &Config) -> Result<(), Error> {
    let xprv_str = xprv.to_string();
    let mut f = File::create(&config.privkey_fname)?;
    writeln!(f, "{}", xprv_str)?;
    Ok(())
}

pub fn load_private_key(config: &Config) -> Result<Xpriv, Error> {
    let mut xprv = String::new();
    let mut f = File::open(&config.privkey_fname)?;
    f.read_to_string(&mut xprv)?;
    if let Some(first_line) = xprv.lines().next() {
        let xprv_str = first_line.to_string();
        Ok(Xpriv::from_str(&xprv_str)?)
    } else {
        Err(Error::Callback(format!(
            "fail load privkey text file: {}",
            config.privkey_fname.to_string_lossy()
        )))
    }
}

pub struct BtcWallet {
    pub config: Config,
    pub rpc: Box<dyn BackendRpc>,
    pub wallet: Wallet,
}

impl BtcWallet {
    /// BtcWalletを生成する。ウォレットファイルか秘密鍵ファイルがある場合は失敗する。
    pub fn create(
        config: Config,
        mut privkey_save_callback: impl FnMut(&Xpriv, &Config) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let mut seed: [u8; 32] = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let (mut wallet, xprv) = Wallet::create(&config, &seed)?;
        privkey_save_callback(&xprv, &config)?;

        let rpc = match config.backend {
            config::Backend::Electrum => electrum::ElectrumRpc::new(&config.electrum)?,
        };
        let req = wallet.start_full_scan();
        let update = rpc.initial_scan(req)?;
        wallet.apply_update(update)?;

        debug!("create done");
        Ok(Self {
            config,
            rpc: Box::new(rpc),
            wallet,
        })
    }

    /// BtcWalletをloadする。ウォレットファイルか秘密鍵ファイルがない場合は失敗する。
    pub fn load(
        config: Config,
        mut privkey_load_callback: impl FnMut(&Config) -> Result<Xpriv, Error>,
    ) -> Result<Self, Error> {
        let xprv = privkey_load_callback(&config)?;
        let mut wallet = Wallet::load(&config, xprv)?;
        let rpc = match config.backend {
            config::Backend::Electrum => electrum::ElectrumRpc::new(&config.electrum)?,
        };
        let req = wallet.start_full_scan();
        let update = rpc.initial_scan(req)?;
        wallet.apply_update(update)?;

        debug!("load done");
        Ok(Self {
            config,
            rpc: Box::new(rpc),
            wallet,
        })
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
            let _ = BtcWallet::create(config.clone(), save_private_key).unwrap();
        }
        {
            let _ = BtcWallet::load(config.clone(), load_private_key).unwrap();
        }
        {
            let result = BtcWallet::create(config.clone(), save_private_key);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fail_load_not_created() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let result = BtcWallet::load(config.clone(), load_private_key);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fail_load_no_privkey_file() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create(config.clone(), save_private_key).unwrap();
        }
        {
            std::fs::remove_file(&config.privkey_fname).unwrap();
            let result = BtcWallet::load(config, load_private_key);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fail_load_no_wallet_file() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create(config.clone(), save_private_key).unwrap();
        }
        {
            std::fs::remove_file(&config.wallet_fname).unwrap();
            let result = BtcWallet::load(config.clone(), load_private_key);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_parse_txid_hex() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        let wallet = BtcWallet::create(config.clone(), save_private_key).unwrap();

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
        let config = make_config(&dir);
        let mut saved_privkey: Option<Xpriv> = None;

        {
            let save_callback = |privkey: &Xpriv, _config: &Config| -> Result<(), Error> {
                saved_privkey = Some(*privkey);
                Ok(())
            };
            let _ = BtcWallet::create(config.clone(), save_callback).unwrap();
            assert!(saved_privkey.is_some());
        }

        {
            let load_callback =
                |_config: &Config| -> Result<Xpriv, Error> { Ok(saved_privkey.unwrap()) };
            let _ = BtcWallet::load(config.clone(), load_callback).unwrap();
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
