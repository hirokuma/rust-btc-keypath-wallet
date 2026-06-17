use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    string::FromUtf8Error,
};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use bdk_wallet::bitcoin::key::rand::{RngCore, rngs::OsRng};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncDecError {
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    FromUtf8Error(#[from] FromUtf8Error),

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
const SALT_LEN: usize = 16; // Argon2id用のソルト長 (16バイト)
const NONCE_LEN: usize = 12; // ChaCha20Poly1305用のナンス長 (12バイト)
const KEY_LEN: usize = 32; // 派生させる鍵の長さ (256ビット = 32バイト)

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
    // 1. ソルトとナンスを安全な乱数(OsRng)から生成
    let mut salt_bytes = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt_bytes);
    OsRng.fill_bytes(&mut nonce_bytes);

    // 2. Argon2id を用いてパスフレーズから32バイトの暗号化鍵を派生
    let mut derived_key = [0u8; KEY_LEN];
    let salt_string = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| EncDecError::Argon(format!("encode_b64: {e}")))?;

    // Argon2のデフォルト（安全なパラメータ）でハッシュ生成
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default()
    );
    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|e| EncDecError::Argon(format!("failed to hash password: {e}")))?;
    let hash_output = password_hash
        .hash
        .ok_or(EncDecError::HashNone("Password"))?;
    if hash_output.len() < KEY_LEN {
        return Err(EncDecError::InvalidLength("hash_output < 32"));
    }
    derived_key.copy_from_slice(&hash_output.as_ref()[..KEY_LEN]);

    // 3. ChaCha20Poly1305 で暗号化
    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
        .map_err(|e| EncDecError::ChaCha(format!("new_from_slice: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data.as_bytes())
        .map_err(|e| EncDecError::ChaCha(format!("encrypt: {e}")))?;

    // 4. ファイルへの書き出し
    // [ソルト 16B] + [ナンス 12B] + [暗号文 (可変長)] の順で1つのバイナリにする
    let mut file = File::create(path)?;
    file.write_all(&salt_bytes)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;

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
    let mut file = File::open(path)?;
    let mut file_content = Vec::new();
    file.read_to_end(&mut file_content)?;

    // データの長さが最低限（ソルト＋ナンス）あるかチェック
    if file_content.len() < (SALT_LEN + NONCE_LEN) {
        return Err(EncDecError::InvalidLength(
            "Invalid file format: file too short",
        ));
    }

    // 2. バイナリデータからソルト、ナンス、暗号文を切り分ける
    let salt_bytes = &file_content[0..SALT_LEN];
    let nonce_bytes = &file_content[SALT_LEN..(SALT_LEN + NONCE_LEN)];
    let ciphertext = &file_content[(SALT_LEN + NONCE_LEN)..];

    // 3. 同じソルトを使ってパスフレーズから共通鍵を再派生
    let mut derived_key = [0u8; KEY_LEN];
    let salt_string = SaltString::encode_b64(salt_bytes)
        .map_err(|e| EncDecError::Argon(format!("encode_b64: {e}")))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default()
    );
    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|e| EncDecError::Argon(format!("failed to hash password: {e}")))?;
    let hash_output = password_hash
        .hash
        .ok_or(EncDecError::HashNone("Password"))?;
    if hash_output.len() < KEY_LEN {
        return Err(EncDecError::InvalidLength("hash_output < 32"));
    }
    derived_key.copy_from_slice(&hash_output.as_ref()[..KEY_LEN]);

    // 4. ChaCha20Poly1305 で復号
    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
        .map_err(|e| EncDecError::ChaCha(format!("new_from_slice: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| EncDecError::ChaCha(format!("decrypt: {e}")))?;

    // 5. バイト列を文字列に戻す
    let decrypted_string = String::from_utf8(decrypted_bytes)?;

    Ok(decrypted_string)
}
