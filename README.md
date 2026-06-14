# rust-btc-keypath-wallet

[bdk_wallet](https://docs.rs/bdk_wallet/latest/bdk_wallet/)などを使ったテスト用のBitcoinライブラリ。  

```bash
cargo add --git https://github.com/hirokuma/rust-btc-keypath-wallet.git
```

## 注意

秘密鍵をテキストファイルに保存するなど、テスト用にしか作っていない。

## Example

### Sample

```shell
$ cargo run --example sample
Send 1 BTC to bcrt1ptd39q0j4dpje2meexwtw9p72cntfg0g8v52ahm4wkryp7q8wrqeqz4t50v
before balance1: { immature: 0 BTC, trusted_pending: 0 BTC, untrusted_pending: 0.99999840 BTC, confirmed: 0 BTC }
..........
after balance: { immature: 0 BTC, trusted_pending: 0 BTC, untrusted_pending: 0 BTC, confirmed: 1.99999840 BTC }
txid=0fd97171f02aa7ae5b479a25dd84465725cf1df71a5d9e8baeb4c01c516b0c87
done.
```

### CLI

```shell
$ cargo run --example cli -- create
```

```shell
$ cargo run --example clie --features "tracing" -- create
```
