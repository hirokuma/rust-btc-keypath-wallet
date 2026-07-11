use std::{
    convert::TryInto,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    string::FromUtf8Error,
};

use argon2::{Argon2, password_hash::Salt};
use bdk_wallet::bitcoin::key::rand::{RngCore, rngs::OsRng};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload, common::InvalidLength},
};
use serde::Deserialize;
use tempfile::NamedTempFile;
use tracing::*;
use zeroize::Zeroize;

use crate::log_err;

#[derive(thiserror::Error, Debug)]
pub enum EncDecError {
    #[error("I/O error: {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("convert UTF8 error")]
    ConvUtf8(#[source] FromUtf8Error),

    #[error("wincode write error")]
    WinCodeWrite(#[source] wincode::WriteError),

    #[error("wincode read error")]
    WinCodeRead(#[source] wincode::ReadError),

    #[error("argon2 error")]
    Argon2(argon2::Error),

    #[error("crypto invalid length error")]
    CryptoInvalidLen(InvalidLength),

    #[error("nonce convert error")]
    ConvNonce(core::array::TryFromSliceError),

    #[error("ChaCha20Poly1305 error")]
    ChaCha(chacha20poly1305::aead::Error),

    #[error("hash is none")]
    HashNone(&'static str),

    #[error("invalid length")]
    InvalidLength,

    #[error("invalid data")]
    InvalidData,

    #[error("unknown version")]
    UnknownVersion(u32),
}

const VERSION_V1: u32 = 0x0000_0000_0000_0001;
const SALT_LEN_V1: usize = Salt::RECOMMENDED_LENGTH; // Argon2id用のソルト長
const NONCE_LEN_V1: usize = 24; // XChaCha20Poly1305用のナンス長
const KEY_LEN_V1: usize = 32; // 派生させる鍵の長さ
const AAD_V1: &[u8] = b"https://github.com/hirokuma/rust-btc-keypath-wallet.git";

#[derive(wincode::SchemaWrite, wincode::SchemaRead, Deserialize, Debug)]
struct FormatV1<'a> {
    salt_bytes: &'a [u8],
    nonce_bytes: &'a [u8],
    ciphertext: &'a [u8],
}

const VERSION_LATEST: u32 = VERSION_V1;

/// パスフレーズを用いてデータを暗号化し、ファイルに保存する
///
/// ## 実行フロー
/// 1. ソルトとナンスを生成 (OsRngでセキュアに)
/// 2. Argon2idでパスフレーズから32バイトの暗号鍵を導出
/// 3. ChaCha20Poly1305でデータを暗号化
/// 4. 暗号化結果をファイルに保存 (ソルト→ナンス→暗号文の順)
///
/// ## エラー
/// - `IO`: ファイル操作エラー
/// - `FromUtf8Error`: 文字列変換エラー
/// - `Argon(...)`: Argon2処理エラー
/// - `ChaCha(...)`: ChaCha20Poly1305処理エラー
pub fn encrypt_to_file(path: &Path, data: &str, passphrase: &str) -> Result<(), EncDecError> {
    let salt_bytes: [u8; SALT_LEN_V1] = generate_random_bytes();
    let nonce_bytes: [u8; NONCE_LEN_V1] = generate_random_bytes();

    let mut derived_key = derive_key(passphrase.as_bytes(), &salt_bytes)
        .map_err(|e| log_err!(EncDecError::Argon2(e), "failed to hash password on encrypt"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(&derived_key).map_err(|e| {
        log_err!(
            EncDecError::CryptoInvalidLen(e),
            "new_from_slice on encrypt"
        )
    })?;
    let payload = Payload {
        msg: data.as_bytes(),
        aad: AAD_V1,
    };
    let ciphertext = cipher
        .encrypt(<&XNonce>::from(&nonce_bytes), payload)
        .map_err(|e| log_err!(EncDecError::ChaCha(e), "encrypt"))?;
    derived_key.zeroize();

    let enc_data = FormatV1 {
        salt_bytes: &salt_bytes,
        nonce_bytes: &nonce_bytes,
        ciphertext: &ciphertext,
    };
    write_file_v1(path, &enc_data)?;

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
    let mut file = File::open(path).map_err(|e| {
        log_err!(
            EncDecError::Io {
                path: path.to_path_buf(),
                source: e,
            },
            "open decrypt file"
        )
    })?;
    let mut file_content = Vec::new();
    file.read_to_end(&mut file_content).map_err(|e| {
        log_err!(
            EncDecError::Io {
                path: path.to_path_buf(),
                source: e,
            },
            "read decrypt file"
        )
    })?;
    if file_content.len() < 4 {
        return Err(log_err!(
            EncDecError::InvalidLength,
            "less than file version"
        ));
    }
    let version_bytes: [u8; 4] = file_content[0..4]
        .try_into()
        .map_err(|_e| log_err!(EncDecError::InvalidData, "fail convert version"))?;
    let version = u32::from_le_bytes(version_bytes);
    let dec_data = match version {
        VERSION_V1 => read_file_v1(&file_content[4..])?,
        _ => {
            return Err(log_err!(
                EncDecError::UnknownVersion(version),
                "decrypt_from_file"
            ));
        }
    };

    let mut derived_key = derive_key(passphrase.as_bytes(), dec_data.salt_bytes)
        .map_err(|e| log_err!(EncDecError::Argon2(e), "failed to hash password on decrypt"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(&derived_key).map_err(|e| {
        log_err!(
            EncDecError::CryptoInvalidLen(e),
            "new_from_slice on decrypt"
        )
    })?;

    let payload = Payload {
        msg: dec_data.ciphertext,
        aad: AAD_V1,
    };
    let nonce = XNonce::try_from(dec_data.nonce_bytes)
        .map_err(|e| log_err!(EncDecError::ConvNonce(e), "dec_data.nonce_bytes"))?;
    let decrypted_bytes = cipher
        .decrypt(&nonce, payload)
        .map_err(|e| log_err!(EncDecError::ChaCha(e), "decryrpt nonce_bytes"))?;
    derived_key.zeroize();

    let decrypted_string = String::from_utf8(decrypted_bytes)
        .map_err(|e| log_err!(EncDecError::ConvUtf8(e), "decrypted bytes"))?;
    Ok(decrypted_string)
}

fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN_V1], argon2::Error> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );

    let mut key = [0u8; KEY_LEN_V1];
    argon2.hash_password_into(passphrase, salt, &mut key)?;
    Ok(key)
}

// Read private key file version 1
fn write_file_v1(path: &Path, enc_data: &FormatV1) -> Result<(), EncDecError> {
    let target_dir = path.parent().unwrap_or(Path::new("."));
    let mut file = NamedTempFile::new_in(target_dir).map_err(|e| {
        log_err!(
            EncDecError::Io {
                path: target_dir.to_path_buf(),
                source: e,
            },
            "create temporary file"
        )
    })?;
    let enc = wincode::serialize(enc_data)
        .map_err(|e| log_err!(EncDecError::WinCodeWrite(e), "serialize format v1"))?;
    let version_bytes: [u8; 4] = VERSION_LATEST.to_le_bytes();
    file.write_all(&version_bytes).map_err(|e| {
        log_err!(
            EncDecError::Io {
                path: path.to_path_buf(),
                source: e,
            },
            "write version"
        )
    })?;
    file.write_all(&enc).map_err(|e| {
        log_err!(
            EncDecError::Io {
                path: path.to_path_buf(),
                source: e,
            },
            "write format v1"
        )
    })?;
    file.persist(path).map_err(|e| {
        log_err!(
            EncDecError::Io {
                path: path.to_path_buf(),
                source: e.error,
            },
            "temporary file to real"
        )
    })?;
    Ok(())
}

// Read private key file version 1
fn read_file_v1<'a>(file_content: &'a [u8]) -> Result<FormatV1<'a>, EncDecError> {
    let dec: FormatV1 = wincode::deserialize(file_content)
        .map_err(|e| log_err!(EncDecError::WinCodeRead(e), "deserilize format v1"))?;
    Ok(dec)
}
