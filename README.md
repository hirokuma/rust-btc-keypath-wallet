# rust-btc-keypath-wallet

[bdk_wallet](https://docs.rs/bdk_wallet/latest/bdk_wallet/)などを使ったテスト用のBitcoinライブラリ。  

```bash
cargo add --git https://github.com/hirokuma/rust-btc-keypath-wallet.git
```

## 注意

秘密鍵をテキストファイルに保存するなど、テスト用にしか作っていない。

## Example

```shell
$ cargo run --example main -- create
```

```shell
$ cargo run --example main --features "tracing" -- create
```
