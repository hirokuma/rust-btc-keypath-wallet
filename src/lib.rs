mod backend;
mod config;
mod electrum;
mod wallet;

pub use bdk_wallet::bitcoin::{Address, Amount, Network, Transaction, Txid, bip32::Xpriv};
pub use bdk_wallet::{self, Balance, miniscript};
use bdk_wallet::{
    bitcoin::{
        self, FeeRate,
        address::{NetworkUnchecked, ParseError},
        bip32,
        consensus::encode::{FromHexError, deserialize_hex, serialize_hex},
        hex::HexToArrayError,
        key::rand::{self, RngCore},
    },
    chain::local_chain::CannotConnectError,
};
use std::str::FromStr;
use std::{
    path::{Path, PathBuf},
    result::Result,
    sync::Arc,
};
use tracing::*;
use wallet_utils::{encdec, log_err};

pub use crate::config::{Backend, Config, ElectrumConfig};
use crate::{
    backend::{BackendError, BackendRpc},
    config::ConfigError,
    wallet::{Wallet, WalletError},
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Config(#[source] ConfigError),

    #[error("{0}")]
    Backend(#[source] BackendError),

    #[error("{0}")]
    CannotConnect(#[source] CannotConnectError),

    #[error("{0}")]
    Wallet(#[source] Box<WalletError>),

    #[error("tx conversion error")]
    TxConvert {
        tx_hex: String,
        #[source]
        source: FromHexError,
    },

    #[error("TXID conversion error")]
    TxidConvert {
        txid_hex: String,
        #[source]
        source: HexToArrayError,
    },

    #[error("parse error")]
    Parse {
        str: String,
        #[source]
        source: ParseError,
    },

    #[error("BIP32 error: {0}")]
    Bip32(#[source] bip32::Error),

    #[error("fail access wallet file: {0}")]
    WalletFile(PathBuf),

    #[error("fail wallet file enc/dec: {0}")]
    WalletEncDec(#[source] encdec::EncDecError),
}

pub fn load_config(config_fname: &Path) -> Result<Config, Error> {
    Config::new(config_fname).map_err(|e| log_err!(Error::Config(e), "load_config"))
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
        mut privkey_save_callback: impl FnMut(&Path, &str) -> Result<(), encdec::EncDecError>,
    ) -> Result<Self, Error> {
        if Path::new(&config.privkey_path).exists() {
            return Err(log_err!(
                Error::WalletFile(config.privkey_path),
                "private key file already exist"
            ));
        }
        if Path::new(&config.wallet_path).exists() {
            return Err(log_err!(
                Error::WalletFile(config.wallet_path),
                "wallet file already exist"
            ));
        }

        let mut seed: [u8; 32] = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let (mut wallet, xprv) = Wallet::create(&config, &seed)
            .map_err(|e| log_err!(Error::Wallet(Box::new(e)), "create wallet"))?;
        privkey_save_callback(&config.privkey_path, &xprv.to_string())
            .map_err(|e| log_err!(Error::WalletEncDec(e), "privkey_save_callback"))?;

        let rpc = match config.backend {
            config::Backend::Electrum => electrum::ElectrumRpc::new(&config.electrum)
                .map_err(|e| log_err!(Error::Backend(e), "create wallet"))?,
        };
        let req = wallet.start_full_scan();
        let update = rpc
            .initial_scan(req)
            .map_err(|e| log_err!(Error::Backend(e), "create wallet"))?;
        wallet
            .apply_update(update)
            .map_err(|e| log_err!(Error::CannotConnect(e), "create wallet"))?;

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
        mut privkey_load_callback: impl FnMut(&Path) -> Result<String, encdec::EncDecError>,
    ) -> Result<Self, Error> {
        if !Path::new(&config.privkey_path).exists() {
            return Err(log_err!(
                Error::WalletFile(config.privkey_path),
                "private key file not exist"
            ));
        }
        if !Path::new(&config.wallet_path).exists() {
            return Err(log_err!(
                Error::WalletFile(config.wallet_path),
                "wallet file not exist"
            ));
        }

        let xprv = privkey_load_callback(&config.privkey_path)
            .map_err(|e| log_err!(Error::WalletEncDec(e), "privkey_load_callback"))?;
        let xprv =
            Xpriv::from_str(&xprv).map_err(|e| log_err!(Error::Bip32(e), "Xpriv::from_str"))?;
        let mut wallet = Wallet::load(&config, xprv)
            .map_err(|e| log_err!(Error::Wallet(Box::new(e)), "load wallet"))?;
        let rpc = match config.backend {
            config::Backend::Electrum => electrum::ElectrumRpc::new(&config.electrum)
                .map_err(|e| log_err!(Error::Backend(e), "load wallet"))?,
        };
        let req = wallet.start_full_scan();
        let update = rpc
            .initial_scan(req)
            .map_err(|e| log_err!(Error::Backend(e), "load wallet"))?;
        wallet
            .apply_update(update)
            .map_err(|e| log_err!(Error::CannotConnect(e), "load wallet"))?;

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
        let update = self
            .rpc
            .sync(req)
            .map_err(|e| log_err!(Error::Backend(e), "sync"))?;
        self.wallet
            .apply_update(update)
            .map_err(|e| log_err!(Error::CannotConnect(e), "sync"))
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
        let addr: Address<NetworkUnchecked> = addr_str.parse().map_err(|e| {
            log_err!(
                Error::Parse {
                    str: addr_str.to_string(),
                    source: e,
                },
                "parse_address"
            )
        })?;
        addr.require_network(self.config.network).map_err(|e| {
            log_err!(
                Error::Parse {
                    str: self.config.network.to_string(),
                    source: e,
                },
                "parse_address"
            )
        })
    }

    /// TXIDに該当するトランザクションを取得する。
    pub fn get_tx(&self, txid: Txid) -> Result<Arc<Transaction>, Error> {
        self.rpc
            .get_tx(txid)
            .map_err(|e| log_err!(Error::Backend(e), "get_tx"))
    }

    pub fn parse_txid_hex(&self, txid_hex: &str) -> Result<Txid, Error> {
        txid_hex.parse().map_err(|e| {
            log_err!(
                Error::TxidConvert {
                    txid_hex: txid_hex.to_string(),
                    source: e,
                },
                "parse_txid"
            )
        })
    }

    pub fn parse_tx_hex(&self, tx_hex: &str) -> Result<Transaction, Error> {
        deserialize_hex(tx_hex).map_err(move |e| {
            log_err!(
                Error::TxConvert {
                    tx_hex: tx_hex.to_string(),
                    source: e,
                },
                "parse_tx_hex"
            )
        })
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

        self.wallet
            .create_tx(addr, amount, fee_rate, sighash_type)
            .map_err(|e| log_err!(Error::Wallet(Box::new(e)), "create_tx_sighash_type"))
    }

    pub fn send_tx(&self, tx: &Transaction) -> Result<Txid, Error> {
        self.rpc
            .send_tx(tx)
            .map_err(|e| log_err!(Error::Backend(e), "send_tx"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::result::Result;
    use tempfile::tempdir;

    fn save_private_key(path: &Path, xprv: &str) -> Result<(), encdec::EncDecError> {
        encdec::save_encoded_private_key(path, xprv, "passphrase")
    }
    fn load_private_key(path: &Path) -> Result<String, encdec::EncDecError> {
        encdec::load_encoded_private_key(path, "passphrase")
    }

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
            std::fs::remove_file(&config.privkey_path).unwrap();
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
            std::fs::remove_file(&config.wallet_path).unwrap();
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
        let mut saved_privkey: Option<String> = None;

        {
            let save_callback = |_path: &Path, privkey: &str| -> Result<(), encdec::EncDecError> {
                saved_privkey = Some(privkey.to_string()); // call check
                Ok(())
            };
            let _ = BtcWallet::create(config.clone(), save_callback).unwrap();
            assert!(saved_privkey.is_some());
        }

        {
            let load_callback =
                |_path: &Path| -> Result<String, encdec::EncDecError> { Ok("".to_string()) };
            let result = BtcWallet::load(config.clone(), load_callback);
            assert!(result.is_err()); // save_callbackでファイル保存していないのでエラーになる
        }
    }

    fn make_config(dir: &tempfile::TempDir) -> Config {
        let bdk_path = dir.path().join("wallet.bdk");
        let xpriv_path = dir.path().join("xpriv.txt");
        Config {
            wallet_path: bdk_path,
            privkey_path: xpriv_path,
            network: bdk_wallet::bitcoin::Network::Regtest,
            backend: config::Backend::Electrum,
            electrum: config::ElectrumConfig {
                enabled: true,
                server: "tcp://127.0.0.1:50001".to_string(),
                batch_size: 10,
                gap_limit: 20,
            },
        }
    }
}
