use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    string::FromUtf8Error,
};

use argon2::{Argon2, password_hash::Salt};
use bdk_wallet::bitcoin::key::rand::{RngCore, rngs::OsRng};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum EncDecError {
    #[error("Create file error: {path}: {source}")]
    CreateFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Open file error: {path}: {source}")]
    OpenFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Write file error: {reason}: {source}")]
    WriteFile {
        reason: &'static str,
        source: std::io::Error,
    },

    #[error("Read file error: {reason}: {source}")]
    ReadFile {
        reason: &'static str,
        source: std::io::Error,
    },

    #[error("Convert UTF8: {reason}: {source}")]
    ConvUtf8 {
        reason: &'static str,
        source: FromUtf8Error,
    },

    #[error("Argon error: {0}")]
    Argon(String),

    #[error("ChaCha error: {0}")]
    ChaCha(String),

    #[error("Hash is None: {0}")]
    HashNone(&'static str),

    #[error("Invalid length: {0}")]
    InvalidLength(&'static str),
}

// 定数の定義
const SALT_LEN: usize = Salt::RECOMMENDED_LENGTH; // Argon2id用のソルト長 (16バイト)
const NONCE_LEN: usize = 12; // ChaCha20Poly1305用のナンス長 (12バイト)
const KEY_LEN: usize = 32; // 派生させる鍵の長さ (256ビット = 32バイト)
const AAD: &[u8] = b"https://github.com/hirokuma/rust-btc-keypath-wallet.git";

/// パスフレーズを用いてデータを暗号化し、ファイルに保存する
///
/// ## 実行フロー
/// 1. ソルトとナンスを生成 (OsRngでセキュアに)
/// 2. Argon2idでパスフレーズから32バイトの暗号鍵を導出
/// 3. ChaCha20Poly1305でデータを暗号化
/// 4. 暗号化結果をファイルに保存 (ソルト→ナンス→暗号文の順)
///
/// ## ファイル形式
/// - Salt : 16 bytes
/// - Nonce : 12 bytes
/// - Message : ...
///
/// ## エラー
/// - `IO`: ファイル操作エラー
/// - `FromUtf8Error`: 文字列変換エラー
/// - `Argon(...)`: Argon2処理エラー
/// - `ChaCha(...)`: ChaCha20Poly1305処理エラー
pub fn encrypt_to_file(path: &Path, data: &str, passphrase: &str) -> Result<(), EncDecError> {
    let mut salt_bytes = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt_bytes);

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );
    let mut derived_key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut derived_key)
        .map_err(|e| EncDecError::Argon(format!("failed to hash password: {e}")))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
        .map_err(|e| EncDecError::ChaCha(format!("new_from_slice: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: data.as_bytes(),
        aad: AAD,
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| EncDecError::ChaCha(format!("encrypt: {e}")))?;
    derived_key.zeroize();

    let mut file = File::create(path).map_err(|e| EncDecError::CreateFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.write_all(&salt_bytes)
        .map_err(|e| EncDecError::WriteFile {
            reason: "salt_bytes",
            source: e,
        })?;
    file.write_all(&nonce_bytes)
        .map_err(|e| EncDecError::WriteFile {
            reason: "nonce_bytes",
            source: e,
        })?;
    file.write_all(&ciphertext)
        .map_err(|e| EncDecError::WriteFile {
            reason: "ciphertext",
            source: e,
        })?;

    Ok(())
}

/// パスフレーズを用いてファイルからデータを復号する
///
/// ## 実行フロー
/// 1. ファイル全体の読み込み
/// 2. ソルト、ナンス、暗号文のパース
/// 3. 同じソルトでパスフレーズから鍵の再導出
/// 4. ChaCha20Poly1305による復号処理
/// 5. 復元されたデータの文字列変換
///
/// ## メモリ安全
/// - 同じソルトとパスフレーズで必ず同じ鍵が生成される
/// - セキュアなメモリ確保 (zeroed buffer)
/// - 復号後はすぐにゼロ埋めされる
pub fn decrypt_from_file(path: &Path, passphrase: &str) -> Result<String, EncDecError> {
    // 1. ファイル全体の読み込み
    let mut file = File::open(path).map_err(|e| EncDecError::OpenFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut file_content = Vec::new();
    file.read_to_end(&mut file_content)
        .map_err(|e| EncDecError::ReadFile {
            reason: "decrypt file",
            source: e,
        })?;

    // データの長さが最低限（ソルト＋ナンス）あるかチェック
    if file_content.len() < (SALT_LEN + NONCE_LEN) {
        return Err(EncDecError::InvalidLength(
            "Invalid file format: file too short",
        ));
    }

    let salt_bytes = &file_content[0..SALT_LEN];
    let nonce_bytes = &file_content[SALT_LEN..(SALT_LEN + NONCE_LEN)];
    let ciphertext = &file_content[(SALT_LEN + NONCE_LEN)..];

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );
    let mut derived_key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt_bytes, &mut derived_key)
        .map_err(|e| EncDecError::Argon(format!("failed to hash password: {e}")))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
        .map_err(|e| EncDecError::ChaCha(format!("new_from_slice: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad: AAD,
    };
    let decrypted_bytes = cipher
        .decrypt(nonce, payload)
        .map_err(|e| EncDecError::ChaCha(format!("decrypt: {e}")))?;
    derived_key.zeroize();

    let decrypted_string =
        String::from_utf8(decrypted_bytes).map_err(|e| EncDecError::ConvUtf8 {
            reason: "decrypted bytes",
            source: e,
        })?;
    Ok(decrypted_string)
}
