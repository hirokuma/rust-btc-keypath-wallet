use anyhow::Result;
use btc_wallet::{self, BtcWallet, Config, Network};
use std::{
    io::{self, Write},
    path::Path,
};
use tracing::*;
use tracing_subscriber::{EnvFilter, prelude::*};
use wallet_utils::encdec;

fn main() -> Result<()> {
    let filter = EnvFilter::builder().parse_lossy("debug,btc_wallet=info");
    tracing_subscriber::Registry::default()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_filter(filter),
        )
        .init();

    let config = Config {
        wallet_path: Path::new("./sample-wallet.bdk").to_path_buf(),
        network: Network::Regtest,
        backend: btc_wallet::Backend::Electrum,
        electrum: btc_wallet::ElectrumConfig {
            enabled: true,
            server: "tcp://127.0.0.1:50001".to_string(),
            batch_size: 10,
            gap_limit: 20,
        },
    };
    config.check()?;

    let xprv_path = Path::new("./sample-priv.txt");
    let passphrase = "SuperSecurePassword123!";
    let save_privkey =
        |path: &Path, xprv: &str| encdec::save_encoded_private_key(path, xprv, passphrase);
    let load_privkey = |path: &Path| encdec::load_encoded_private_key(path, passphrase);

    let mut wallet = match config.wallet_path.exists() {
        true => {
            tracing::info!("load wallet");
            let xprv = load_privkey(Path::new(xprv_path))?;
            BtcWallet::load(config, &xprv)
        }
        false => {
            tracing::info!("create wallet");
            let (w, xprv) = BtcWallet::create(config)?;
            save_privkey(Path::new(xprv_path), &xprv)?;
            Ok(w)
        }
    }
    .inspect_err(|e| error!(Err=?e, "Fail wallet instance creation"))?;
    debug!("wallet created/loaded: {}", wallet.config.network);

    let addr1 = wallet.new_address()?;
    println!("Send 1 BTC to {}", addr1);
    update_balances(&mut wallet);

    let txs = wallet.fetch_script_history(&addr1, 0, false)?;
    println!("txs({}):\n{:?}", addr1, txs);

    let addr2 = wallet.new_address()?;
    let tx_send = wallet.create_tx_single_anypay(&addr2, 100_000_000 - 160, 1.0)?;

    debug!("tx_send: {:#?}", tx_send);

    let txid = wallet.send_tx(&tx_send)?;
    println!("txid={}", txid);
    std::thread::sleep(std::time::Duration::from_secs(2));

    let tx_get = wallet.get_tx(txid)?;
    assert_eq!(tx_send, *tx_get);
    println!("done.");

    Ok(())
}

fn update_balances(wallet1: &mut BtcWallet) {
    let mut balance1 = wallet1.balance();
    println!("before balance1: {}", balance1);

    loop {
        print!(".");
        io::stdout().flush().unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        wallet1.sync().unwrap();
        let new_balance1 = wallet1.balance();
        if new_balance1.confirmed != balance1.confirmed {
            balance1 = new_balance1;
            println!();
            println!("after balance: {}", balance1);
            break;
        }
    }
}
