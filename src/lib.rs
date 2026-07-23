mod backend;
mod config;
mod electrum;
mod htlc;
mod taproot;
mod wallet;

// pub use
pub use crate::{
    config::{Backend, Config, ElectrumConfig},
    htlc::Htlc,
};
pub use bdk_wallet::bitcoin::{
    Address, Amount, Network, OutPoint, Transaction, Txid, XOnlyPublicKey, bip32::Xpriv,
    hashes::Hash, hashes::sha256::Hash as Sha256, key::Keypair,
};
pub use bdk_wallet::{AddressInfo, Balance, miniscript, rusqlite};

// use std
use std::{
    path::{Path, PathBuf},
    result::Result,
    str::FromStr,
    sync::Arc,
};

// use
use bdk_wallet::bitcoin::{
    self, FeeRate,
    address::NetworkUnchecked,
    bip32,
    consensus::encode::{FromHexError, deserialize_hex, serialize_hex},
    hex::HexToArrayError,
    key::rand::{self, RngCore},
    secp256k1,
};
use tracing::*;
use wallet_utils::{encdec, log_err};

// use crate
use crate::{
    backend::{BackendError, BackendRpc, ScriptHistory},
    config::ConfigError,
    htlc::HtlcError,
    taproot::TapError,
    wallet::{Wallet, WalletError},
};

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("ParseError: {0}")]
    AddressParse(#[from] bdk_wallet::bitcoin::address::ParseError),

    #[error("ParseOutPointError: {0}")]
    ParseOutPoint(#[from] bitcoin::blockdata::transaction::ParseOutPointError),

    #[error("HexToArrayError: {0}")]
    HexConvert(#[source] HexToArrayError),

    #[error("tx conversion error")]
    FromHex(#[source] FromHexError),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Config(#[source] ConfigError),

    #[error("{0}")]
    Backend(#[source] BackendError),

    #[error("{0}")]
    Tap(#[from] TapError),

    #[error("{0}")]
    Htlc(#[source] HtlcError),

    #[error("{0}")]
    Wallet(#[source] Box<WalletError>),

    #[error("{0}")]
    Secp(#[source] secp256k1::Error),

    #[error("parse error")]
    Parse(#[source] ParseError),

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
    /// BtcWalletを生成する。ウォレットファイルがある場合は失敗する。
    pub fn create(config: Config) -> Result<(Self, String), Error> {
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
            .map_err(|e| log_err!(Error::Wallet(Box::new(e)), "create wallet"))?;

        debug!("create done");
        Ok((
            Self {
                config,
                rpc: Box::new(rpc),
                wallet,
            },
            xprv.to_string(),
        ))
    }

    /// BtcWalletをloadする。ウォレットファイルがない場合は失敗する。
    pub fn load(config: Config, xprv: &str) -> Result<Self, Error> {
        if !Path::new(&config.wallet_path).exists() {
            return Err(log_err!(
                Error::WalletFile(config.wallet_path),
                "wallet file not exist"
            ));
        }

        let xprv =
            Xpriv::from_str(xprv).map_err(|e| log_err!(Error::Bip32(e), "Xpriv::from_str"))?;
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
            .map_err(|e| log_err!(Error::Wallet(Box::new(e)), "load wallet"))?;

        debug!("load done");
        Ok(Self {
            config,
            rpc: Box::new(rpc),
            wallet,
        })
    }

    pub fn inner_wallet(&self) -> &wallet::InnerWallet {
        &self.wallet.wallet
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
            .map_err(|e| log_err!(Error::Wallet(Box::new(e)), "sync"))
    }

    /// 残高取得
    pub fn balance(&self) -> Balance {
        self.wallet.balance()
    }

    /// 新規アドレスを返す。HDウォレットのインデックスを更新する。
    pub fn new_address(&mut self) -> Result<Address, Error> {
        let ai = self.wallet.new_address_info();
        self.wallet
            .persist()
            .map_err(|e| log_err!(Error::Wallet(Box::new(e)), "new_address"))?;
        debug!("new_address: {}, index={}", ai.address, ai.index);
        Ok(ai.address)
    }

    /// インデックスに該当するAddressInfoを返す
    pub fn get_address_info(&self, index: u32) -> AddressInfo {
        self.wallet.get_address_info(index)
    }

    /// インデックスに該当するアドレスを返す
    pub fn get_address(&self, index: u32) -> Address {
        self.wallet.get_address_info(index).address
    }

    /// 最後に公開されたインデックスを取得する。未使用の場合はNoneを返す。
    /// get_address()を使用する際の参考にするとよい。
    pub fn derived_address_index(&self) -> Option<u32> {
        self.wallet.derived_address_index()
    }

    /// アドレス文字列をAddress型に変換する
    pub fn parse_address(&self, addr_str: &str) -> Result<Address, Error> {
        let addr: Address<NetworkUnchecked> = addr_str.parse().map_err(|e| {
            log_err!(
                Error::Parse(ParseError::AddressParse(e)),
                "parse_address: {}",
                addr_str,
            )
        })?;
        addr.require_network(self.config.network).map_err(|e| {
            log_err!(
                Error::Parse(ParseError::AddressParse(e)),
                "require_network: {}",
                self.config.network,
            )
        })
    }

    /// AddressInfoをXOnlyPublicKeyに変換する
    pub fn conv_xonly_internal_pubkey(
        &self,
        addr_info: &AddressInfo,
    ) -> Result<XOnlyPublicKey, Error> {
        Ok(taproot::conv_xonly_internal_pubkey(
            &self.wallet.wallet,
            addr_info,
        )?)
    }

    pub fn get_current_height(&self) -> Result<u32, Error> {
        self.rpc
            .get_current_height()
            .map_err(|e| log_err!(Error::Backend(e), "get_current_height"))
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
                Error::Parse(ParseError::HexConvert(e)),
                "parse_txid: txid_str={}",
                txid_hex,
            )
        })
    }

    pub fn parse_tx_hex(&self, tx_hex: &str) -> Result<Transaction, Error> {
        deserialize_hex(tx_hex).map_err(move |e| {
            log_err!(
                Error::Parse(ParseError::FromHex(e)),
                "parse_tx_hex: tx_hex={}",
                tx_hex
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
            .map_err(|e| log_err!(Error::Backend(e), "send_tx: {:#?}", tx))
    }

    pub fn fetch_script_history(
        &self,
        addr: &Address,
        last_height: u32,
        only_confirmed: bool,
    ) -> Result<Vec<ScriptHistory>, Error> {
        self.rpc
            .fetch_script_history(addr, last_height, only_confirmed)
            .map_err(|e| log_err!(Error::Backend(e), "find_txs: {}", addr))
    }

    pub fn generate_keypair(&self) -> Keypair {
        let secp = self.wallet.wallet.secp_ctx();
        let (secret_key, _public_key) = secp.generate_keypair(&mut rand::thread_rng());
        Keypair::from_secret_key(secp, &secret_key)
    }

    pub fn keypair_from_slice(&self, key: &[u8; 32]) -> Result<Keypair, Error> {
        Keypair::from_seckey_slice(self.wallet.wallet.secp_ctx(), key)
            .map_err(|e| log_err!(Error::Secp(e), "keypair_from_slice"))
    }
}

pub fn htlc_new(
    preimage_hash: Sha256,
    csv_blocks: u32,
    claim_xonly_pubkey: XOnlyPublicKey,
    refund_xonly_pubkey: XOnlyPublicKey,
) -> Result<htlc::Htlc, Error> {
    htlc::Htlc::new(
        preimage_hash,
        csv_blocks,
        claim_xonly_pubkey,
        refund_xonly_pubkey,
    )
    .map_err(|e| log_err!(Error::Htlc(e), "htlc_new"))
}

pub fn fee_from_rate(fee_rate: f64, vsize: usize) -> Amount {
    let fee = (fee_rate * vsize as f64 + 0.5) as u64;
    debug!("fee_rate = {}", fee_rate);
    debug!("fee = {}", fee);
    Amount::from_sat(fee)
}

pub fn generate_preimage() -> ([u8; 32], Sha256) {
    htlc::generate_preimage()
}

pub fn to_sha256(hash_str: &str) -> Result<Sha256, Error> {
    Sha256::from_str(hash_str).map_err(|e| {
        log_err!(
            Error::Parse(ParseError::HexConvert(e)),
            "to_sha256: hash_str={}",
            hash_str,
        )
    })
}

pub fn to_outpoint(outpoint: &str) -> Result<OutPoint, Error> {
    outpoint.parse().map_err(|e| {
        log_err!(
            Error::Parse(ParseError::ParseOutPoint(e)),
            "to_outpoint: {}",
            outpoint
        )
    })
}

pub fn to_xonly_pubkey(bytes: &[u8; 32]) -> Result<XOnlyPublicKey, TapError> {
    XOnlyPublicKey::from_slice(bytes).map_err(|e| log_err!(TapError::Secp(e), "xonly_pubkey"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_load() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        let (_w, p) = BtcWallet::create(config.clone()).unwrap();
        let _ = BtcWallet::load(config.clone(), &p).unwrap();
        {
            let result = BtcWallet::create(config.clone());
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fail_load_not_created() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let result = BtcWallet::load(config.clone(), "");
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fail_load_no_privkey_file() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        {
            let _ = BtcWallet::create(config.clone()).unwrap();
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
            std::fs::remove_file(&config.wallet_path).unwrap();
            let result = BtcWallet::load(config.clone(), "");
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_parse_txid_hex() {
        let dir = tempdir().unwrap();
        let config = make_config(&dir);
        let (wallet, _xprv) = BtcWallet::create(config.clone()).unwrap();

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

    fn make_config(dir: &tempfile::TempDir) -> Config {
        let bdk_path = dir.path().join("wallet.bdk");
        Config {
            wallet_path: bdk_path,
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
