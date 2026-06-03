use anyhow::Result;
use btc_wallet::BtcWallet;
use clap::{CommandFactory, Parser, Subcommand};

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
    /// Send raw transaction.
    #[command(name = "sendrawtx")]
    SendRawTx { tx_hex: String },
    /// Remove wallet files
    RemoveWalletFiles,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    let config = btc_wallet::load_config("./config.toml")?;

    match cli.command {
        None => {
            // clap will show help if user asks, but when no subcommand provided, print help
            Cli::command().print_help()?;
            println!();
        }
        Some(Commands::Create) => {
            let wallet = BtcWallet::create(config)?;
            println!("wallet created: {}", wallet.config.network);
        }
        Some(Commands::Balance) => {
            let wallet = BtcWallet::load(config)?;
            let balance = wallet.balance();
            println!("balance: {}", balance);
        }
        Some(Commands::Addrs) => {
            todo!();
        }
        Some(Commands::NewAddr) => {
            let mut wallet = BtcWallet::load(config)?;
            let new_addr = wallet.new_address();
            println!("new address: {}", new_addr);
        }
        Some(Commands::Tx { tx_hex }) => {
            let wallet = BtcWallet::load(config)?;
            let tx = wallet.to_tx(&tx_hex)?;
            println!("{:#?}", tx);
        }
        Some(Commands::Spend {
            out_addr,
            amount,
            fee_rate,
        }) => {
            let mut wallet = BtcWallet::load(config)?;
            let tx = wallet.create_tx(&out_addr, amount, fee_rate)?;
            println!("tx: {:#?}", tx);
            println!("raw_tx: {}", wallet.tx_to_string(&tx));
        }
        Some(Commands::SendRawTx { tx_hex }) => {
            let wallet = BtcWallet::load(config)?;
            let tx = wallet.to_tx(&tx_hex)?;
            let txid = wallet.send_tx(&tx)?;
            println!("txid: {}", txid);
        }
        Some(Commands::RemoveWalletFiles) => {
            std::fs::remove_file(&config.wallet_fname)?;
            println!("remove: {}", config.wallet_fname.to_string_lossy());
            std::fs::remove_file(&config.privkey_fname)?;
            println!("remove: {}", config.privkey_fname.to_string_lossy());
        }
    }

    Ok(())
}
