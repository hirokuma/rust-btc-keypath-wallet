use bdk_wallet::{
    AddressInfo, KeychainKind, Wallet as BdkWallet,
    bitcoin::{
        ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxOut,
        bip32::Error as Bip32Error,
        hashes::Hash,
        key::Keypair,
        secp256k1::{self, Message, XOnlyPublicKey, schnorr::Signature},
        sighash::{Prevouts, SighashCache, TaprootError},
        taproot::{ControlBlock, LeafVersion, Signature as TaprootSig},
    },
    miniscript::{DefiniteDescriptorKey, Descriptor, descriptor::ConversionError},
};
use hex::FromHexError;
use thiserror::Error;
use tracing::*;

use wallet_utils::log_err;

#[derive(Error, Debug)]
pub enum TapError {
    #[error("{0}")]
    FromHex(#[source] FromHexError),

    #[error("{0}")]
    Secp(#[source] secp256k1::Error),

    #[error("{0}")]
    Conversion(#[source] ConversionError),

    #[error("{0}")]
    Bip32(#[source] Bip32Error),

    #[error("{0}")]
    Taproot(#[source] TaprootError),

    #[error("descriptor error: {0}")]
    NoKey(String),

    #[error("witness error: leaf_name={0}")]
    Witness(String),

    #[error("sign error")]
    Sign,

    #[error("{0}")]
    Error(String),
}

// pick as internal key a "Nothing Up My Sleeve" (NUMS) point
// TODO H + rG
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
pub const NUMS_XPUBKEY: &[u8] = &[
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

pub struct TaprootSpendData {
    pub leaf_script: ScriptBuf,
    pub control_block: ControlBlock,
    pub leaf_hash: TapLeafHash,
}

pub fn conv_xonly_internal_pubkey(
    wallet: &BdkWallet,
    addr_info: &AddressInfo,
) -> Result<XOnlyPublicKey, TapError> {
    let xonly: XOnlyPublicKey = {
        let desc = wallet
            .public_descriptor(KeychainKind::External)
            .at_derivation_index(addr_info.index)
            .map_err(|e| log_err!(TapError::Conversion(e), "at_derivation_index"))?
            .derived_descriptor(wallet.secp_ctx())
            .map_err(|e| log_err!(TapError::Conversion(e), "derived_descriptor"))?;
        match desc {
            Descriptor::Tr(tr) => tr.internal_key().inner.x_only_public_key().0,
            _ => Err(TapError::NoKey("Expected Taproot descriptor".into()))?,
        }
    };
    Ok(xonly)
}

pub fn build_taproot_leaf_spend_data(
    htlc_derived: &Descriptor<DefiniteDescriptorKey>,
    xonly: XOnlyPublicKey,
    leaf_name: &str,
) -> Result<TaprootSpendData, TapError> {
    let Descriptor::Tr(tr) = htlc_derived else {
        return Err(log_err!(
            TapError::Witness(leaf_name.to_string()),
            "expected Taproot descriptor"
        ));
    };

    let spend_info = tr.spend_info();
    let xonly_bytes = xonly.serialize();
    let (leaf_script, control_block) = spend_info
        .script_map()
        .keys()
        .find_map(|(script, ver)| {
            if script.as_bytes().windows(32).any(|w| w == xonly_bytes) {
                spend_info
                    .control_block(&(script.clone(), *ver))
                    .map(|cb| (script.clone(), cb))
            } else {
                None
            }
        })
        .ok_or_else(|| log_err!(TapError::Witness(leaf_name.to_string()), "leaf not found"))?;

    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    Ok(TaprootSpendData {
        leaf_script,
        control_block,
        leaf_hash,
    })
}

pub fn sign_taproot_script_spend(
    wallet: &BdkWallet,
    is_dummy: bool,
    keypair: &Keypair,
    spend_tx: &Transaction,
    vin_index: usize,
    prev_txout: &TxOut,
    leaf_hash: TapLeafHash,
) -> Result<TaprootSig, TapError> {
    if is_dummy {
        let dummy = Signature::from_slice(&[0u8; 64]).unwrap();
        return Ok(TaprootSig {
            signature: dummy,
            sighash_type: TapSighashType::Default,
        });
    }
    let prevouts = [prev_txout];
    let mut sighash_cache = SighashCache::new(spend_tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            vin_index,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| log_err!(TapError::Taproot(e), "taproot_script_spend_signature_hash"))?;

    let secp = wallet.secp_ctx();
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, keypair);

    Ok(TaprootSig {
        signature,
        sighash_type: TapSighashType::Default,
    })
}
