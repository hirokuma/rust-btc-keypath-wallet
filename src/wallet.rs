use std::{path::PathBuf, result::Result};

use bdk_wallet::{
    Balance, CreateWithPersistError, KeychainKind, LoadWithPersistError, PersistedWallet,
    SignOptions, Update, Wallet as BdkWallet,
    bitcoin::{
        self, Address, Amount, FeeRate, NetworkKind, Transaction,
        bip32::{self, Xpriv},
        psbt::ExtractTxError,
    },
    chain::{
        local_chain::CannotConnectError,
        spk_client::{FullScanRequestBuilder, SyncRequestBuilder},
    },
    descriptor::DescriptorError,
    error::CreateTxError,
    rusqlite::{self, Connection, OpenFlags},
    signer::SignerError,
    template::{Bip86, DescriptorTemplate},
};
use tracing::*;

use crate::{config::Config, log_err};

#[derive(thiserror::Error, Debug)]
pub enum WalletError {
    #[error("create wallet error")]
    CreateWallet {
        path: PathBuf,
        #[source]
        source: CreateWithPersistError<rusqlite::Error>,
    },

    #[error("load wallet error")]
    LoadWallet {
        path: PathBuf,
        #[source]
        source: LoadWithPersistError<rusqlite::Error>,
    },

    #[error("open wallet error")]
    OpenWallet {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error("generate descriptor error")]
    Descriptor(#[source] DescriptorError),

    #[error("BIP32 error")]
    Bip32(#[source] bip32::Error),

    #[error("create transaction error")]
    CreateTx(#[source] CreateTxError),

    #[error("extract transaction error")]
    ExtractTx(#[source] Box<ExtractTxError>),

    #[error("signer error")]
    Signer(#[source] SignerError),

    #[error("transaction is not finalized")]
    TxFinalize,

    #[error("wallet file error")]
    WalletFile,
}

pub struct Wallet {
    wallet: PersistedWallet<Connection>,
    conn: Connection,
}

impl Wallet {
    pub fn start_full_scan(&self) -> FullScanRequestBuilder<KeychainKind> {
        self.wallet.start_full_scan()
    }

    pub fn start_sync_with_revealed_spks(&self) -> SyncRequestBuilder<(KeychainKind, u32)> {
        self.wallet.start_sync_with_revealed_spks()
    }

    pub fn apply_update(&mut self, update: impl Into<Update>) -> Result<(), CannotConnectError> {
        self.wallet.apply_update(update)
    }

    pub fn persist(&mut self) {
        let _ = self.wallet.persist(&mut self.conn);
    }
}

impl Wallet {
    pub fn create(config: &Config, seed: &[u8; 32]) -> Result<(Self, Xpriv), WalletError> {
        let kind = NetworkKind::from(config.network);
        let xprv: Xpriv = Xpriv::new_master(config.network, seed)
            .map_err(|e| log_err!(WalletError::Bip32(e), "create"))?;
        let (descriptor, key_map, _) = Bip86(xprv, KeychainKind::External)
            .build(kind)
            .map_err(|e| log_err!(WalletError::Descriptor(e), "create external key"))?;
        let (change_descriptor, change_key_map, _) = Bip86(xprv, KeychainKind::Internal)
            .build(kind)
            .map_err(|e| log_err!(WalletError::Descriptor(e), "create internal key"))?;
        let mut conn = Connection::open_with_flags(
            &config.wallet_path,
            OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .map_err(|e| {
            log_err!(
                WalletError::OpenWallet {
                    path: config.wallet_path.clone(),
                    source: e,
                },
                "create wallet"
            )
        })?;
        let external_descriptor_priv = descriptor.to_string_with_secret(&key_map);
        let internal_descriptor_priv = change_descriptor.to_string_with_secret(&change_key_map);
        let wallet = BdkWallet::create(external_descriptor_priv, internal_descriptor_priv)
            .network(config.network)
            .create_wallet(&mut conn)
            .map_err(|e| {
                log_err!(
                    WalletError::CreateWallet {
                        path: config.wallet_path.clone(),
                        source: e,
                    },
                    "create wallet"
                )
            })?;

        Ok((Wallet { wallet, conn }, xprv))
    }

    pub fn load(config: &Config, xprv: Xpriv) -> Result<Self, WalletError> {
        if !config.wallet_path.exists() {
            return Err(log_err!(WalletError::WalletFile, "wallet file not exists"));
        }
        let mut conn =
            Connection::open_with_flags(&config.wallet_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(|e| {
                    log_err!(
                        WalletError::OpenWallet {
                            path: config.wallet_path.clone(),
                            source: e,
                        },
                        "load wallet"
                    )
                })?;
        let kind = NetworkKind::from(config.network);
        let (descriptor, key_map, _) = Bip86(xprv, KeychainKind::External)
            .build(kind)
            .map_err(|e| log_err!(WalletError::Descriptor(e), "load external key"))?;
        let (change_descriptor, change_key_map, _) = Bip86(xprv, KeychainKind::Internal)
            .build(kind)
            .map_err(|e| log_err!(WalletError::Descriptor(e), "load internal key"))?;
        let external_descriptor_priv = descriptor.to_string_with_secret(&key_map);
        let internal_descriptor_priv = change_descriptor.to_string_with_secret(&change_key_map);

        let wallet_opt = BdkWallet::load()
            .descriptor(KeychainKind::External, Some(external_descriptor_priv))
            .descriptor(KeychainKind::Internal, Some(internal_descriptor_priv))
            .extract_keys()
            .check_network(config.network)
            .load_wallet(&mut conn)
            .map_err(|e| {
                log_err!(
                    WalletError::LoadWallet {
                        path: config.wallet_path.clone(),
                        source: e,
                    },
                    "load wallet"
                )
            })?;
        let wallet = match wallet_opt {
            Some(wallet) => wallet,
            None => {
                return Err(log_err!(WalletError::WalletFile, "load result is none"));
            }
        };
        Ok(Wallet { wallet, conn })
    }
}

impl Wallet {
    pub fn balance(&self) -> Balance {
        self.wallet.balance()
    }

    pub fn new_address(&mut self) -> Address {
        let addr_info = self.wallet.reveal_next_address(KeychainKind::External);
        debug!(
            "new_address: {}, index={}",
            addr_info.address, addr_info.index
        );
        addr_info.address
    }

    pub fn get_address(&self, index: u32) -> Address {
        let addr_info = self.wallet.peek_address(KeychainKind::External, index);
        debug!(
            "get_address: {}, index={}",
            addr_info.address, addr_info.index
        );
        addr_info.address
    }

    pub fn derived_address_index(&self) -> Option<u32> {
        self.wallet.derivation_index(KeychainKind::External)
    }

    pub fn create_tx(
        &mut self,
        addr: &Address,
        amount: Amount,
        fee_rate: FeeRate,
        sighash_type: Option<bitcoin::TapSighashType>,
    ) -> Result<Transaction, WalletError> {
        let mut builder = self.wallet.build_tx();
        builder.add_recipient(addr.script_pubkey(), amount);
        let mut allow_all_sighashes = false;

        // sighash_typeが指定された場合、すべてのsighashを許可する
        if let Some(sig_hash_type) = sighash_type {
            allow_all_sighashes = true;
            builder.sighash(sig_hash_type.into());
        }
        builder.fee_rate(fee_rate);
        let mut psbt = builder
            .finish()
            .map_err(|e| log_err!(WalletError::CreateTx(e), "create_tx"))?;
        let finalized = self
            .wallet
            .sign(
                &mut psbt,
                SignOptions {
                    trust_witness_utxo: true,
                    allow_all_sighashes,
                    ..Default::default()
                },
            )
            .map_err(|e| log_err!(WalletError::Signer(e), "create_tx"))?;
        if !finalized {
            return Err(WalletError::TxFinalize);
        }
        let tx = psbt
            .extract_tx()
            .map_err(Box::new)
            .map_err(|e| log_err!(WalletError::ExtractTx(e), "create_tx"))?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bdk_wallet::{
        AddressInfo, KeychainKind,
        bitcoin::{
            Address, Network, Script,
            bip32::{DerivationPath, Xpriv},
            key::{TapTweak, XOnlyPublicKey},
            secp256k1::{PublicKey, Secp256k1},
        },
    };

    use super::*;

    #[test]
    // BIP-86 Test Vectors
    // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
    fn test_descriptor() {
        const WALLET_NETWORK: Network = Network::Bitcoin;
        let mut db = Connection::open_in_memory().expect("Can't open database");

        // Account 0, first receiving address = m/86'/0'/0'/0/0
        let xprv1 = "tr(xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu/86'/0'/0'/0/*)";
        // Account 0, first change address = m/86'/0'/0'/1/0
        let xprv2 = "tr(xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu/86'/0'/0'/1/*)";
        let wallet_opt = BdkWallet::load()
            .descriptor(KeychainKind::External, Some(xprv1))
            .descriptor(KeychainKind::Internal, Some(xprv2))
            .extract_keys()
            .check_network(WALLET_NETWORK)
            .load_wallet(&mut db)
            .expect("wallet");
        let wallet = match wallet_opt {
            Some(wallet) => wallet,
            None => BdkWallet::create(xprv1, xprv2)
                .network(WALLET_NETWORK)
                .create_wallet(&mut db)
                .expect("wallet"),
        };

        let address: AddressInfo = wallet.peek_address(KeychainKind::External, 0);
        assert_eq!(
            address.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            "external address"
        );
        println!(
            "Generated external address {} at index {}",
            address.address, address.index
        );
        let address: AddressInfo = wallet.peek_address(KeychainKind::Internal, 0);
        assert_eq!(
            address.to_string(),
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
            "internal address"
        );
        println!(
            "Generated internal address {} at index {}",
            address.address, address.index
        );

        let secp = Secp256k1::new();
        let xprv = Xpriv::from_str("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu").expect("Invalid xprv");
        let derivation_path = DerivationPath::from_str("m/86'/0'/0'/0/0").expect("Invalid path");
        let derived = xprv
            .derive_priv(&secp, &derivation_path)
            .expect("Derivation failed");
        let secret_key = derived.private_key;

        // 1. internal public key (untweaked)
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let xonly_pubkey = XOnlyPublicKey::from(public_key);
        assert_eq!(
            xonly_pubkey.to_string(),
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
            "x-only pubkey"
        );
        println!("Internal x-only pubkey: {}", xonly_pubkey);

        // 2. tweaked pubkey
        let (tweaked_xonly, _parity) = xonly_pubkey.tap_tweak(&secp, None);
        assert_eq!(
            tweaked_xonly.to_string(),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
            "tweaked x-only pubkey"
        );
        println!("Tweaked x-only pubkey: {}", tweaked_xonly);

        // 3. scriptPubKey
        let mut script_bytes = Vec::with_capacity(1 + 32);
        script_bytes.push(0x51); // OP_1
        script_bytes.push(0x20); // length
        script_bytes.extend_from_slice(&tweaked_xonly.serialize());
        let script_pubkey = Script::from_bytes(&script_bytes);
        let script_pubkey_str = hex::encode(script_pubkey.as_bytes());
        assert_eq!(
            script_pubkey_str,
            "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
            "scriptPubKey"
        );
        println!("scriptPubKey (hex): {}", script_pubkey_str);

        // 4. P2TR address
        let address = Address::p2tr_tweaked(tweaked_xonly, WALLET_NETWORK);
        assert_eq!(
            address.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            "external address"
        );
        println!("P2TR address: {}", address);
    }
}
