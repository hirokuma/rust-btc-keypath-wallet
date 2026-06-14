use std::{fs::File, io::prelude::*, path::PathBuf};

use bdk_wallet::bitcoin::Network;
use serde::Deserialize;
use thiserror::Error;

use crate::logger::trace;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error(transparent)]
    File(#[from] std::io::Error),

    #[error(transparent)]
    Toml(#[from] toml::de::Error),

    #[error("Invalid parameters: {0}")]
    InvalidParams(&'static str),
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Electrum,
}

/// Wallet config
#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    /// BDK Wallet filename
    pub wallet_fname: PathBuf,
    /// Private key text filename (optional)
    pub privkey_fname: PathBuf,
    /// Network(Bitcoin, Testnet, Testnet4, Signet, Regtest)
    pub network: Network,
    /// Backend type
    pub backend: Backend,
    /// Electrum backend config
    pub electrum: ElectrumConfig,
}

/// Electrum backend config
#[derive(Deserialize, Debug, Clone)]
pub struct ElectrumConfig {
    /// true: enable this backend
    #[serde(default)]
    pub enabled: bool,

    /// Server URL(tcp:// or ssl://)
    #[serde(default)]
    pub server: String,

    /// Batch size
    pub batch_size: Option<usize>,

    /// Gap limit
    pub gap_limit: Option<usize>,
}

impl Config {
    pub fn new(fname: &str) -> Result<Config, ConfigError> {
        let mut settings = String::new();
        let mut f =
            File::open(fname).inspect_err(|e| trace!("fail open file({}): {}", fname, e))?;
        f.read_to_string(&mut settings)
            .inspect_err(|e| trace!("fail read file({}): {}", fname, e))?;
        let data: Config = toml::from_str(&settings)
            .inspect_err(|e| trace!("fail convert config from TOML: {e}"))?;
        if !data.electrum.enabled {
            trace!("no backend enabled");
            return Err(ConfigError::InvalidParams("no backend enabled"));
        }
        Ok(data)
    }
}
