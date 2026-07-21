use std::{
    fs::File,
    io::prelude::*,
    path::{Path, PathBuf},
};

use bdk_wallet::bitcoin::Network;
use serde::Deserialize;
use tracing::*;

use crate::log_err;

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("I/O error: {path}")]
    File {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("TOML parsing error")]
    Toml(#[source] toml::de::Error),

    #[error("no enabled backend")]
    NoBackend,

    #[error("invalid parameter")]
    InvalidParam,
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
    pub wallet_path: PathBuf,

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
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Gap limit
    #[serde(default = "default_gap_limit")]
    pub gap_limit: usize,
}

fn default_batch_size() -> usize {
    30
}
fn default_gap_limit() -> usize {
    20
}

impl Config {
    pub fn new(fname: &Path) -> Result<Config, ConfigError> {
        let mut settings = String::new();
        let mut f = File::open(fname).map_err(|e| {
            log_err!(
                ConfigError::File {
                    path: fname.into(),
                    source: e,
                },
                "oepn"
            )
        })?;
        f.read_to_string(&mut settings).map_err(|e| {
            log_err!(
                ConfigError::File {
                    path: fname.into(),
                    source: e,
                },
                "read_to_string"
            )
        })?;
        let data: Config =
            toml::from_str(&settings).map_err(|e| log_err!(ConfigError::Toml(e), "config"))?;
        data.check()?;
        Ok(data)
    }

    pub fn check(&self) -> Result<(), ConfigError> {
        if !self.electrum.enabled {
            return log_err!(Err(ConfigError::NoBackend), "check");
        } else {
            if !check_electrum(&self.electrum) {
                return Err(ConfigError::InvalidParam);
            }
        }
        Ok(())
    }
}

fn check_electrum(electrum: &ElectrumConfig) -> bool {
    if electrum.batch_size == 0 {
        error!("batch_size={}", electrum.batch_size);
        return false;
    }
    if electrum.gap_limit == 0 {
        error!("gap_limit={}", electrum.gap_limit);
        return false;
    }
    true
}
