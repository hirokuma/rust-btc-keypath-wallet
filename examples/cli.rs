use std::path::Path;

use anyhow::Result;
use btc_wallet::{self, BtcWallet, config::Config};
use clap::{CommandFactory, Parser, Subcommand};
use tracing::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create wallet
    Create,
    /// Balance
    Balance,
    /// Get addresses.
    Addrs,
    /// Get new address.
    #[command(name = "newaddr")]
    NewAddr,
    /// Decode transaction hex string.
    Tx {
        /// hex string to decode
        tx_hex: String,
    },
    /// Create a spendable transaction.
    Spend {
        /// output address
        out_addr: String,
        /// amount sats
        amount: u64,
        /// feerate
        fee_rate: f64,
    },
    /// Create a spendable transaction signed by SINGLE+ANYONE_CAN_PAY
    #[command(name = "spend-single")]
    SpendSingle {
        /// output address
        out_addr: String,
        /// amount sats
        amount: u64,
        /// feerate
        fee_rate: f64,
    },
    /// Send raw transaction.
    #[command(name = "sendrawtx")]
    SendRawTx { tx_hex: String },
    /// Remove wallet files
    RemoveWalletFiles,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();
    tracing::info!("bdk_wallet example");

    let cli = Cli::parse();

    let config = btc_wallet::load_config(Path::new("./config.toml"))
        .inspect_err(|e| error!("load_config: {e}"))?;
    let passphrase = "SuperSecurePassword123!";
    let save_privkey = |xprv: &btc_wallet::Xpriv, config: &Config| {
        btc_wallet::save_encoded_private_key(xprv, config, passphrase)
    };
    let load_privkey = |config: &Config| btc_wallet::load_encoded_private_key(config, passphrase);

    match cli.command {
        None => {
            // clap will show help if user asks, but when no subcommand provided, print help
            Cli::command().print_help()?;
            println!();
        }
        Some(Commands::Create) => {
            let wallet =
                BtcWallet::create(config, save_privkey).inspect_err(|e| error!("create: {e}"))?;
            println!("wallet created: {}", wallet.config.network);
        }
        Some(Commands::Balance) => {
            let wallet =
                BtcWallet::load(config, load_privkey).inspect_err(|e| error!("load: {e}"))?;
            let balance = wallet.balance();
            println!("balance: {}", balance);
        }
        Some(Commands::Addrs) => {
            todo!();
        }
        Some(Commands::NewAddr) => {
            let mut wallet =
                BtcWallet::load(config, load_privkey).inspect_err(|e| error!("load: {e}"))?;
            let new_addr = wallet.new_address();
            println!("new address: {}", new_addr);
        }
        Some(Commands::Tx { tx_hex }) => {
            let wallet =
                BtcWallet::load(config, load_privkey).inspect_err(|e| error!("load: {e}"))?;
            let tx = wallet
                .parse_tx_hex(&tx_hex)
                .inspect_err(|e| error!("to_hex: {e}"))?;
            println!("{:#?}", tx);
        }
        Some(Commands::Spend {
            out_addr,
            amount,
            fee_rate,
        }) => {
            let mut wallet =
                BtcWallet::load(config, load_privkey).inspect_err(|e| error!("load: {e}"))?;
            let out_addr = wallet.parse_address(&out_addr)?;
            let tx = wallet
                .create_tx(&out_addr, amount, fee_rate)
                .inspect_err(|e| error!("create_tx: {e}"))?;
            println!("tx: {:#?}", tx);
            println!("raw_tx: {}", wallet.to_tx_hex(&tx));
        }
        Some(Commands::SpendSingle {
            out_addr,
            amount,
            fee_rate,
        }) => {
            let mut wallet =
                BtcWallet::load(config, load_privkey).inspect_err(|e| error!("load: {e}"))?;
            let out_addr = wallet.parse_address(&out_addr)?;
            let tx = wallet
                .create_tx_single_anypay(&out_addr, amount, fee_rate)
                .inspect_err(|e| error!("create_tx: {e}"))?;
            println!("tx: {:#?}", tx);
            println!("raw_tx: {}", wallet.to_tx_hex(&tx));
        }
        Some(Commands::SendRawTx { tx_hex }) => {
            let wallet =
                BtcWallet::load(config, load_privkey).inspect_err(|e| error!("load: {e}"))?;
            let tx = wallet
                .parse_tx_hex(&tx_hex)
                .inspect_err(|e| error!("to_hex: {e}"))?;
            let txid = wallet
                .send_tx(&tx)
                .inspect_err(|e| error!("send_tx: {e}"))?;
            println!("txid: {}", txid);
        }
        Some(Commands::RemoveWalletFiles) => {
            std::fs::remove_file(&config.wallet_fname)?;
            println!("remove: {}", config.wallet_fname.to_string_lossy());
            std::fs::remove_file(&config.wallet_fname)?;
        }
    }

    Ok(())
}
