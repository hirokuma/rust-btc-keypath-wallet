use std::{collections::BTreeMap, result::Result};

use bdk_wallet::{
    Wallet as BdkWallet,
    bitcoin::{
        Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, TapLeafHash,
        Transaction, TxIn, TxOut, Witness, absolute,
        bip32::Error as Bip32Error,
        hashes::{Hash, sha256},
        key::{
            Keypair,
            rand::{self, RngCore},
        },
        relative::LockTime,
        secp256k1::{self, Parity, XOnlyPublicKey},
        sighash::TaprootError,
        taproot::{ControlBlock, LeafVersion, Signature as TaprootSig},
        transaction,
    },
    descriptor,
    keys::DescriptorPublicKey,
    miniscript::{
        DefiniteDescriptorKey, Descriptor, Error as MiniscriptError, Preimage32, Satisfier,
        descriptor::{ConversionError, DescriptorKeyParseError},
    },
};
use hex::FromHexError;
use thiserror::Error;
use tracing::*;

use wallet_utils::log_err;

use crate::{
    fee_from_rate,
    taproot::{NUMS_XPUBKEY, TapError, build_taproot_leaf_spend_data, sign_taproot_script_spend},
};

#[derive(Error, Debug)]
pub enum HtlcError {
    #[error(transparent)]
    Tap(#[from] TapError),

    #[error("{0}")]
    FromHex(#[source] FromHexError),

    #[error("{0}")]
    Conversion(#[source] ConversionError),

    #[error("{0}")]
    Descriptor(#[source] descriptor::DescriptorError),

    #[error("{0}")]
    DescriptorKeyParse(#[source] DescriptorKeyParseError),

    #[error("{0}")]
    Bip32(#[source] Bip32Error),

    #[error("{0}")]
    Taproot(#[source] TaprootError),

    #[error("{0}")]
    Miniscript(#[source] MiniscriptError),

    #[error("{0}")]
    Secp(#[source] secp256k1::Error),

    #[error("descriptor error: {0}")]
    NoKey(String),

    #[error("witness error: leaf_name={0}")]
    Witness(String),

    #[error("sign error")]
    Sign,
}

struct HtlcSatisfier {
    sigs: BTreeMap<(PublicKey, TapLeafHash), TaprootSig>,
    preimages: BTreeMap<sha256::Hash, Preimage32>,
    control_blocks: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,
    sequence: Option<u32>,
}

impl Satisfier<PublicKey> for HtlcSatisfier {
    fn lookup_tap_leaf_script_sig(&self, pk: &PublicKey, lh: &TapLeafHash) -> Option<TaprootSig> {
        self.sigs.get(&(*pk, *lh)).copied()
    }

    fn lookup_sha256(&self, h: &sha256::Hash) -> Option<Preimage32> {
        self.preimages.get(h).copied()
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>> {
        Some(&self.control_blocks)
    }

    fn check_older(&self, csv: LockTime) -> bool {
        self.sequence
            .is_some_and(|sequence| csv.to_consensus_u32() >= sequence)
    }
}

#[derive(Debug, Clone)]
pub struct Htlc {
    pub preimage_hash: sha256::Hash,
    pub csv_blocks: u32,

    derived: Descriptor<DefiniteDescriptorKey>,
}

impl Htlc {
    pub fn new(
        preimage_hash: sha256::Hash,
        csv_blocks: u32,
        claim_xonly_pubkey: XOnlyPublicKey,
        refund_xonly_pubkey: XOnlyPublicKey,
    ) -> Result<Self, HtlcError> {
        let desc = generate_htlc_descriptor(
            &preimage_hash,
            csv_blocks,
            &claim_xonly_pubkey,
            &refund_xonly_pubkey,
        )?;
        let derived = desc
            .at_derivation_index(0)
            .map_err(|e| log_err!(HtlcError::Conversion(e), "new"))?;
        Ok(Self {
            preimage_hash,
            csv_blocks,
            derived,
        })
    }

    pub fn address(&self, network: Network) -> Result<Address, HtlcError> {
        self.derived
            .address(network)
            .map_err(|e| log_err!(HtlcError::Miniscript(e), "address"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_claim_tx(
        &self,
        wallet: &BdkWallet,
        prev_outpoint: OutPoint,
        prev_txout: &TxOut,
        vin_index: usize,
        preimage: [u8; 32],
        claim_keypair: &Keypair,
        fee_rate: f64,
        script_pubkey: ScriptBuf,
    ) -> Result<Transaction, HtlcError> {
        let mut spend_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![transaction::TxOut {
                value: Amount::ZERO, // fee計算後に設定
                script_pubkey,
            }],
        };

        // dummy witness stack for calculate fee
        let witness = self.htlc_witness_stack(
            wallet,
            true, // dummy
            &spend_tx,
            vin_index,
            prev_txout,
            claim_keypair,
            Some(preimage),
            None,
            "claim",
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        let fee = fee_from_rate(fee_rate, spend_tx.vsize());
        spend_tx.output[0].value = prev_txout.value - fee;

        let witness = self.htlc_witness_stack(
            wallet,
            false,
            &spend_tx,
            vin_index,
            prev_txout,
            claim_keypair,
            Some(preimage),
            None,
            "claim",
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        Ok(spend_tx)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_refund_tx(
        &self,
        wallet: &BdkWallet,
        prev_outpoint: OutPoint,
        prev_txout: &TxOut,
        vin_index: usize,
        refund_keypair: &Keypair,
        fee_rate: f64,
        script_pubkey: ScriptBuf,
    ) -> Result<Transaction, HtlcError> {
        let mut spend_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(self.csv_blocks),
                witness: Witness::default(),
            }],
            output: vec![transaction::TxOut {
                value: Amount::ZERO, // fee計算後に設定
                script_pubkey,
            }],
        };

        let witness = self.htlc_witness_stack(
            wallet,
            true, // dummy
            &spend_tx,
            vin_index,
            prev_txout,
            refund_keypair,
            None,
            Some(spend_tx.input[vin_index].sequence.to_consensus_u32()),
            "refund",
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        let fee = crate::fee_from_rate(fee_rate, spend_tx.vsize());
        spend_tx.output[0].value = prev_txout.value - fee;

        let witness = self.htlc_witness_stack(
            wallet,
            false,
            &spend_tx,
            vin_index,
            prev_txout,
            refund_keypair,
            None,
            Some(spend_tx.input[vin_index].sequence.to_consensus_u32()),
            "refund",
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        Ok(spend_tx)
    }

    #[allow(clippy::too_many_arguments)]
    fn htlc_witness_stack(
        &self,
        wallet: &BdkWallet,
        is_dummy: bool,
        spend_tx: &Transaction,
        vin_index: usize,
        prev_txout: &TxOut,
        keypair: &Keypair,
        preimage: Option<[u8; 32]>,
        sequence: Option<u32>,
        leaf_name: &str,
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let preimages: BTreeMap<sha256::Hash, Preimage32> = if let Some(preimage) = preimage {
            let mut preimages = BTreeMap::new();
            preimages.insert(self.preimage_hash, preimage);
            preimages
        } else {
            BTreeMap::new()
        };

        let spend_data =
            build_taproot_leaf_spend_data(&self.derived, keypair.x_only_public_key().0, leaf_name)?;
        let taproot_sig = sign_taproot_script_spend(
            wallet,
            is_dummy,
            keypair,
            spend_tx,
            vin_index,
            prev_txout,
            spend_data.leaf_hash,
        )?;

        let pk = PublicKey::from(keypair.x_only_public_key().0.public_key(Parity::Even));

        let mut sigs = BTreeMap::new();
        sigs.insert((pk, spend_data.leaf_hash), taproot_sig);

        let mut control_blocks = BTreeMap::new();
        control_blocks.insert(
            spend_data.control_block,
            (spend_data.leaf_script, LeafVersion::TapScript),
        );

        let satisfier = HtlcSatisfier {
            sigs,
            preimages,
            control_blocks,
            sequence,
        };

        let htlc_definite = self
            .derived
            .derived_descriptor(wallet.secp_ctx())
            .map_err(|e| log_err!(HtlcError::Conversion(e), "witness_stack"))?;
        let (witness_stack, _script_sig) = htlc_definite
            .get_satisfaction(satisfier)
            .map_err(|e| log_err!(HtlcError::Miniscript(e), "get_satisfaction"))?;
        Ok(witness_stack)
    }
}

pub fn generate_preimage() -> ([u8; 32], sha256::Hash) {
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let hash: sha256::Hash = sha256::Hash::hash(&preimage);
    (preimage, hash)
}

fn generate_htlc_descriptor(
    preimage_hash: &sha256::Hash,
    csv_blocks: u32,
    claim_xonly_pubkey: &XOnlyPublicKey,
    refund_xonly_pubkey: &XOnlyPublicKey,
) -> Result<Descriptor<DescriptorPublicKey>, HtlcError> {
    let xonly_pk = XOnlyPublicKey::from_slice(NUMS_XPUBKEY)
        .map_err(|e| log_err!(HtlcError::Secp(e), "convert NUMS_XPUBKEY"))?;
    let (htlc_descriptor, _key_map, _networks) = bdk_wallet::descriptor!(
        tr(
            xonly_pk,
            {
                and_v(v:sha256(*preimage_hash), pk(*claim_xonly_pubkey)),
                and_v(v:older(csv_blocks), pk(*refund_xonly_pubkey))
            }
        )
    )
    .map_err(|e| log_err!(HtlcError::Descriptor(e), "desc! macro"))?;
    Ok(htlc_descriptor)
}
