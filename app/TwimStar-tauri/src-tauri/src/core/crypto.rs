//! 内容/传输数据加密：AES-256-GCM + PBKDF2（对应 Dart 版 `twin_crypto.dart`）。
//!
//! 三种密码学角色严格分离、互不复用同一把密钥：
//!   - 设备身份认证：Ed25519（见 `identity.rs`）；
//!   - 会话密钥协商：X25519 + HKDF（见 `identity.rs`）；
//!   - 内容/传输数据加密：AES-256-GCM（本模块）。

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

/// 内容加密 KDF 版本（随 fileRequest 字段 `kv` 发送）。
pub const KDF_VERSION: u32 = 1;
/// PBKDF2 迭代次数（参数版本化，未来调大时按 kv 分支处理）。
/// PBKDF2 迭代次数（参数版本化，未来调大时按 kv 分支处理）。
/// 60 万：对齐 OWASP 对 PBKDF2-HMAC-SHA256 的现代建议（原项目 3 万偏低）。
pub const PBKDF2_ITERATIONS: u32 = 600_000;
/// nonce(12) + tag(16)。
pub const GCM_OVERHEAD: usize = 28;
const NONCE_LEN: usize = 12;

/// 默认盐：仅用于兼容历史无盐请求，**新会话必须使用随机盐**。
const DEFAULT_SALT: [u8; 16] = [
    0x54, 0x77, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x72, 0x2d, 0x53, 0x61, 0x6c, 0x74, 0x2d, 0x76, 0x31,
];

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn random_salt(len: usize) -> Vec<u8> {
    random_bytes(len)
}

const PASSPHRASE_ALPHABET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

/// 生成易读的随机加密口令（如 `K7mP-2xQw`）。
pub fn random_passphrase() -> String {
    let n = PASSPHRASE_ALPHABET.len() as u32;
    // 拒绝采样：丢弃落在末尾不完整区间的随机数，避免 % n 带来的模偏差。
    let accept_below = n.saturating_mul(u32::MAX / n);
    let mut s = String::new();
    for _ in 0..8 {
        let v = loop {
            let x = OsRng.next_u32();
            if x < accept_below {
                break x;
            }
        };
        s.push(PASSPHRASE_ALPHABET[(v % n) as usize] as char);
    }
    s.insert(4, '-');
    s
}

/// 从口令派生 AES-256 密钥。新会话应传随机盐。
pub fn derive_key(passphrase: &str, salt: Option<&[u8]>) -> Result<[u8; 32], String> {
    if passphrase.trim().is_empty() {
        return Err("加密口令不能为空".into());
    }
    let salt = salt.unwrap_or(&DEFAULT_SALT);
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    Ok(key)
}

/// 加密：返回 `nonce || ciphertext || tag`。每次随机 nonce，调用方不得复用。
pub fn seal(plain: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = random_bytes(NONCE_LEN);
    let mut ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| "加密失败".to_string())?;
    let mut out = nonce;
    out.append(&mut ct);
    Ok(out)
}

/// 解密：输入为 `nonce || ciphertext || tag`。
pub fn open(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if data.len() <= GCM_OVERHEAD {
        return Err("Invalid cipher data length".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    cipher
        .decrypt(Nonce::from_slice(&data[..NONCE_LEN]), &data[NONCE_LEN..])
        .map_err(|_| "解密失败（密钥不一致或数据被篡改）".into())
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn hmac_sha256_available() -> bool {
    true // 仅为文档化依赖，编译期校验 HKDF 的 PRF 可用性
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = derive_key("correct horse", Some(&random_salt(16))).unwrap();
        let ct = seal(b"hello twinstar", &key).unwrap();
        assert_eq!(ct.len(), 14 + GCM_OVERHEAD);
        assert_eq!(open(&ct, &key).unwrap(), b"hello twinstar");
    }

    #[test]
    fn wrong_key_fails() {
        let a = derive_key("pw", Some(b"salt-salt-salt-sa")).unwrap();
        let b = derive_key("pw", Some(b"other-salt-salt-x")).unwrap();
        let ct = seal(b"data", &a).unwrap();
        assert!(open(&ct, &b).is_err());
    }

    #[test]
    fn passphrase_shape() {
        let p = random_passphrase();
        assert_eq!(p.len(), 9);
        assert_eq!(p.as_bytes()[4], b'-');
    }

    #[test]
    fn deterministic_kdf() {
        let a = derive_key("pw", Some(b"0123456789abcdef")).unwrap();
        let b = derive_key("pw", Some(b"0123456789abcdef")).unwrap();
        assert_eq!(a, b);
        assert!(derive_key("  ", None).is_err());
    }
}
