//! 设备长期身份（对应 Dart 版 `device_identity.dart`）。
//!
//! - `deviceId = hex(SHA-256(Ed25519 公钥))`：公钥决定身份，不使用可随意伪造的随机 UUID；
//! - 私钥只保存在本机应用数据目录，永不出网、永不写日志；
//! - iroh 端点私钥由身份种子域分隔派生，传输层认证即公钥（QUIC/TLS 1.3）。

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// SHA-256 的 hex 编码（deviceId 派生使用）。
fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// 设备长期身份（Ed25519）。
pub struct DeviceIdentity {
    seed: [u8; 32],
    pub public_key: [u8; 32],
    pub device_id: String,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 绝不打印私钥材料。
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl DeviceIdentity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let public_key = signing.verifying_key().to_bytes();
        let device_id = Self::derive_device_id(&public_key);
        Self {
            seed,
            public_key,
            device_id,
        }
    }

    pub fn generate_ephemeral() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// 公钥的 base64 形式（随广播/连接码分发，公开信息）。
    pub fn public_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.public_key)
    }

    /// 由公钥派生 deviceId（唯一权威算法，对端验证时必须复算一致）。
    pub fn derive_device_id(public_key: &[u8]) -> String {
        sha256_hex(public_key)
    }

    /// 派生 iroh 端点私钥种子。
    ///
    /// 不直接用签名种子当端点密钥——同一份密钥材料复用在两个协议上会互相牵连，
    /// 这里用域分隔的 HKDF-SHA256 单独派生，泄露端点密钥也推不出签名私钥。
    /// 效果：同一台设备的"连接码"跨重启保持稳定，不用每次重新复制。
    pub fn derive_endpoint_seed(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"TwinStar/endpoint-salt/v1"), &self.seed);
        let mut out = [0u8; 32];
        // expand 到 32 字节（= 一个 SHA-256 输出块）在 HKDF 定义内必然成功。
        hk.expand(b"TwinStar/iroh-endpoint/v1", &mut out)
            .expect("HKDF 展开 32 字节不会失败");
        out
    }

    // ------------------------------------------------------------ 持久化

    fn file_path() -> Option<PathBuf> {
        // Android 上 dirs 全返 None，退到应用私有 config 目录（与接收目录分离），
        // 保证连接码跨重启稳定。
        Some(
            dirs::data_dir()
                .unwrap_or_else(crate::core::path::android_config_dir)
                .join("device_identity.json"),
        )
    }

    /// 从应用数据目录加载身份；不存在则生成并持久化（损坏则备份重建）。
    pub fn load_or_create() -> Self {
        let Some(path) = Self::file_path() else {
            return Self::generate_ephemeral();
        };
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(identity) = Self::from_json(&raw) {
                return identity;
            }
            let _ = std::fs::rename(
                &path,
                path.with_extension(format!("corrupt-{}", now_millis())),
            );
        }
        let identity = Self::generate_ephemeral();
        let _ = std::fs::create_dir_all(path.parent().unwrap_or(&path));
        let _ = std::fs::write(&path, identity.to_json());
        identity
    }

    fn to_json(&self) -> String {
        use base64::Engine;
        serde_json::json!({
            "alg": "ed25519",
            "pub": self.public_key_base64(),
            "seed": base64::engine::general_purpose::STANDARD.encode(self.seed),
        })
        .to_string()
    }

    fn from_json(raw: &str) -> Result<Self, String> {
        use base64::Engine;
        let v: serde_json::Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        let seed_b64 = v["seed"].as_str().ok_or("缺少 seed")?;
        let seed_bytes = base64::engine::general_purpose::STANDARD
            .decode(seed_b64)
            .map_err(|e| e.to_string())?;
        let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| "seed 必须为 32 字节")?;
        let identity = Self::from_seed(seed);
        // 校验落盘公钥与 seed 派生一致，防止文件被篡改。
        if let Some(pub_b64) = v["pub"].as_str() {
            if pub_b64 != identity.public_key_base64() {
                return Err("设备身份文件公钥不一致".into());
            }
        }
        Ok(identity)
    }
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_sha256_of_pubkey() {
        let id = DeviceIdentity::from_seed([7u8; 32]);
        assert_eq!(id.device_id, sha256_hex(&id.public_key));
        assert_eq!(id.device_id.len(), 64);
        // 确定性：同 seed 同身份
        assert_eq!(DeviceIdentity::from_seed([7u8; 32]).device_id, id.device_id);
    }

    #[test]
    fn persistence_roundtrip() {
        let id = DeviceIdentity::from_seed([9u8; 32]);
        let json = id.to_json();
        let back = DeviceIdentity::from_json(&json).unwrap();
        assert_eq!(back.device_id, id.device_id);
        assert!(DeviceIdentity::from_json("{}").is_err());
    }
}
