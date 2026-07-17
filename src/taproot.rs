use bdk_wallet::{
    AddressInfo, KeychainKind, Wallet,
    bitcoin::{
        Amount, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxOut,
        bip32::{ChildNumber, DerivationPath, Error as Bip32Error},
        hashes::Hash,
        key::Keypair,
        secp256k1::{self, Message, XOnlyPublicKey, schnorr::Signature},
        sighash::{Prevouts, SighashCache, TaprootError},
        taproot::{ControlBlock, LeafVersion, Signature as TaprootSig},
    },
    keys::DescriptorSecretKey,
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

pub fn fee_from_rate(fee_rate: f64, vsize: usize) -> Amount {
    let fee = (fee_rate * vsize as f64 + 0.5) as u64;
    debug!("fee_rate = {}", fee_rate);
    debug!("fee = {}", fee);
    Amount::from_sat(fee)
}

pub fn xonly_pubkey_from_str(hex_str: &str) -> Result<XOnlyPublicKey, TapError> {
    let bytes = hex::decode(hex_str).map_err(|e| log_err!(TapError::FromHex(e), "xonly_pubkey"))?;
    XOnlyPublicKey::from_slice(&bytes).map_err(|e| log_err!(TapError::Secp(e), "xonly_pubkey"))
}

pub fn convert_xonly_pubkey(
    wallet: &Wallet,
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
    wallet: &Wallet,
    is_dummy: bool,
    addr_index: u32,
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

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = sign_schnorr(wallet, addr_index, &msg)?;

    Ok(TaprootSig {
        signature,
        sighash_type: TapSighashType::Default,
    })
}

pub fn sign_schnorr(
    wallet: &Wallet,
    addr_index: u32,
    msg: &Message,
) -> Result<Signature, TapError> {
    let signers = wallet.get_signers(KeychainKind::External);
    let xprv = signers
        .signers()
        .iter()
        .find_map(|&s| match s.descriptor_secret_key() {
            Some(DescriptorSecretKey::XPrv(xprv)) => Some(xprv),
            _ => None,
        })
        .ok_or_else(|| log_err!(TapError::Sign, "no secret key in wallet"))?;

    let child = ChildNumber::from_normal_idx(addr_index)
        .map_err(|e| log_err!(TapError::Bip32(e), "from_normal_idx"))?;
    let mut path_vec: Vec<ChildNumber> = xprv.derivation_path.into_iter().copied().collect();
    path_vec.push(child);
    let full_path = DerivationPath::from(path_vec);

    let secp = wallet.secp_ctx();
    let sec_key = xprv
        .xkey
        .derive_priv(secp, &full_path)
        .map_err(|e| log_err!(TapError::Bip32(e), "derive_priv"))?
        .private_key;

    let keypair = Keypair::from_secret_key(secp, &sec_key);
    Ok(secp.sign_schnorr(msg, &keypair))
}
