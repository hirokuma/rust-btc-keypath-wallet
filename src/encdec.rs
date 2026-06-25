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
    aead::{Aead, KeyInit, Payload},
};
use serde::Deserialize;
use tempfile::NamedTempFile;
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

    #[error("WinCode write error: {reason}: {source}")]
    WinCodeWrite {
        reason: &'static str,
        source: wincode::WriteError,
    },

    #[error("WinCode read error: {reason}: {source}")]
    WinCodeRead {
        reason: &'static str,
        source: wincode::ReadError,
    },

    #[error("Argon error: {0}")]
    Argon(String),

    #[error("ChaCha error: {0}")]
    ChaCha(String),

    #[error("Hash is None: {0}")]
    HashNone(&'static str),

    #[error("Invalid length: {0}")]
    InvalidLength(&'static str),

    #[error("Unknown version: {version}")]
    UnknownVersion { version: u32 },
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

    let mut derived_key = derive_key(passphrase.as_bytes(), &salt_bytes)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&derived_key)
        .map_err(|e| EncDecError::ChaCha(format!("new_from_slice: {e}")))?;
    let payload = Payload {
        msg: data.as_bytes(),
        aad: AAD_V1,
    };
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), payload)
        .map_err(|e| EncDecError::ChaCha(format!("encrypt: {e}")))?;
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
    if file_content.len() < 4 {
        return Err(EncDecError::InvalidLength("less than file version"));
    }
    let version_bytes: [u8; 4] = file_content[0..4]
        .try_into()
        .map_err(|_e| EncDecError::InvalidLength("fail convert version"))?;
    let version = u32::from_le_bytes(version_bytes);
    let dec_data = match version {
        VERSION_V1 => read_file_v1(&file_content[4..])?,
        _ => {
            return Err(EncDecError::UnknownVersion { version });
        }
    };

    let mut derived_key = derive_key(passphrase.as_bytes(), dec_data.salt_bytes)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&derived_key)
        .map_err(|e| EncDecError::ChaCha(format!("new_from_slice: {e}")))?;

    let payload = Payload {
        msg: dec_data.ciphertext,
        aad: AAD_V1,
    };
    let decrypted_bytes = cipher
        .decrypt(XNonce::from_slice(dec_data.nonce_bytes), payload)
        .map_err(|e| EncDecError::ChaCha(format!("decrypt: {e}")))?;
    derived_key.zeroize();

    let decrypted_string =
        String::from_utf8(decrypted_bytes).map_err(|e| EncDecError::ConvUtf8 {
            reason: "decrypted bytes",
            source: e,
        })?;
    Ok(decrypted_string)
}

fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN_V1], EncDecError> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );

    let mut key = [0u8; KEY_LEN_V1];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| EncDecError::Argon(format!("failed to hash password: {e}")))?;
    Ok(key)
}

// Read private key file version 1
fn write_file_v1(path: &Path, enc_data: &FormatV1) -> Result<(), EncDecError> {
    let target_dir = path.parent().unwrap_or(Path::new("."));
    let mut file = NamedTempFile::new_in(target_dir).map_err(|e| EncDecError::CreateFile {
        path: target_dir.to_path_buf(),
        source: e,
    })?;
    let enc = wincode::serialize(enc_data).map_err(|e| EncDecError::WinCodeWrite {
        reason: "serialize format v1",
        source: e,
    })?;
    let version_bytes: [u8; 4] = VERSION_LATEST.to_le_bytes();
    file.write_all(&version_bytes)
        .map_err(|e| EncDecError::WriteFile {
            reason: "version",
            source: e,
        })?;
    file.write_all(&enc).map_err(|e| EncDecError::WriteFile {
        reason: "write format v1",
        source: e,
    })?;
    file.persist(path)
        .map_err(|e| e.error)
        .map_err(|e| EncDecError::CreateFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(())
}

// Read private key file version 1
fn read_file_v1<'a>(file_content: &'a [u8]) -> Result<FormatV1<'a>, EncDecError> {
    let dec: FormatV1 =
        wincode::deserialize(file_content).map_err(|e| EncDecError::WinCodeRead {
            reason: "deserilize format v1",
            source: e,
        })?;
    Ok(dec)
}
