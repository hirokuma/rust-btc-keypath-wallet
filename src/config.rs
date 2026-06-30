use std::{fs::File, io::prelude::*, path::PathBuf};

use bdk_wallet::bitcoin::Network;
use serde::Deserialize;
use thiserror::Error;

use crate::{err_log, logger::*};

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("I/O error({source}): {reason}")]
    File {
        path: PathBuf,
        reason: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("TOML parsing error({source})")]
    Toml {
        #[source]
        source: toml::de::Error,
    },

    #[error("no enabled backend")]
    NoBackend,
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
        let mut f = File::open(fname).map_err(|e| ConfigError::File {
            path: fname.into(),
            reason: "open",
            source: e,
        })?;
        f.read_to_string(&mut settings).map_err(|e| {
            err_log!(ConfigError::File {
                path: fname.into(),
                reason: "read_to_string",
                source: e,
            })
        })?;
        let data: Config =
            toml::from_str(&settings).map_err(|e| err_log!(ConfigError::Toml { source: e }))?;
        if !data.electrum.enabled {
            return Err(ConfigError::NoBackend);
        }
        Ok(data)
    }
}
