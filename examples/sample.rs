use anyhow::Result;
use bdk_wallet::bitcoin::Network;
use btc_wallet::{self, BtcWallet, config::Config};
use std::{
    io::{self, Write},
    path::Path,
};
use tracing::*;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let config = Config {
        wallet_fname: Path::new("./sample-wallet.bdk").to_path_buf(),
        privkey_fname: Path::new("./sample-privkey.txt").to_path_buf(),
        network: Network::Regtest,
        backend: btc_wallet::config::Backend::Electrum,
        electrum: btc_wallet::config::ElectrumConfig {
            enabled: true,
            server: "tcp://127.0.0.1:50001".to_string(),
            batch_size: None,
            gap_limit: None,
        },
    };

    let mut wallet = match config.privkey_fname.exists() {
        true => BtcWallet::load(config, btc_wallet::load_private_key),
        false => BtcWallet::create(config, btc_wallet::save_private_key),
    }
    .inspect_err(|e| error!("wallet: {e}"))?;
    debug!("wallet created/loaded: {}", wallet.config.network);

    let addr1 = wallet.new_address();
    println!("Send 1 BTC to {}", addr1);
    update_balances(&mut wallet);

    let addr2 = wallet.new_address();
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
