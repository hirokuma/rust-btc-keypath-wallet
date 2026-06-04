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

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub wallet_fname: PathBuf,
    pub privkey_fname: PathBuf,
    pub network: Network,
    pub backend: Backend,
    pub electrum: ElectrumConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ElectrumConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server: String,
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
