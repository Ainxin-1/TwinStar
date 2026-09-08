//! 设备长期身份与会话密钥协商（对应 Dart 版 `device_identity.dart`）。
//!
//! - `deviceId = hex(SHA-256(Ed25519 公钥))`：公钥决定身份，不再使用可随意伪造的随机 UUID；
//! - 认证握手时用私钥对对端随机挑战签名，对端用公钥验证；
//! - 私钥只保存在本机应用数据目录，永不出网、永不写日志。

use std::path::PathBuf;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use super::crypto::{random_bytes, sha256_hex};

/// 握手签名域分隔串。
pub const DEVICE_AUTH_DOMAIN: &[u8] = b"TwinStar/device-auth/v2";
/// 传输密钥派生域分隔串。
pub const TRANSPORT_INFO_DOMAIN: &[u8] = b"TwinStar/transport/v2";

/// 设备长期身份（Ed25519）。
pub struct DeviceIdentity {
    seed: [u8; 32],
    signing: SigningKey,
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
            signing,
            public_key,
            device_id,
        }
    }

    pub fn generate_ephemeral() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// 公钥的 base64 形式（随广播/配对/握手分发，公开信息）。
    pub fn public_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.public_key)
    }

    /// 供 UI 展示的身份指纹（公钥 SHA-256 前 8 位，每 4 位分组）。
    pub fn fingerprint(&self) -> String {
        let h = sha256_hex(&self.public_key);
        let short = h[..8].to_uppercase();
        format!("{} {}", &short[..4], &short[4..])
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

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// 用公钥验证签名；长度不对返回 false 而不抛错。
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // 先按字节长度做强类型转换（try_into 在长度不对时返回 Err 而非 panic），
        // 这样非法输入只返回 false，不会让整条校验链路崩在一个 unwrap 上。
        let Ok(pk): Result<[u8; 32], _> = public_key.try_into() else {
            return false;
        };
        let Ok(sig): Result<[u8; 64], _> = signature.try_into() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
            return false;
        };
        vk.verify(message, &Signature::from_bytes(&sig)).is_ok()
    }

    // ------------------------------------------------------------ 持久化

    fn file_path() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("TwinStar").join("device_identity.json"))
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

/// 一次连接使用的临时 X25519 密钥对（会话结束即丢弃，不持久化）。
pub struct EphemeralX25519 {
    secret: StaticSecret,
    pub public_key: [u8; 32],
}

impl EphemeralX25519 {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self { secret, public_key }
    }

    /// ECDH：与对端临时公钥计算共享密钥（32B）。
    pub fn shared_secret(&self, peer_public: &[u8]) -> Result<[u8; 32], String> {
        if peer_public.len() != 32 {
            return Err("X25519 公钥必须为 32 字节".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(peer_public);
        Ok(self.secret.diffie_hellman(&PublicKey::from(arr)).to_bytes())
    }
}

/// 会话密钥派生：ECDH 共享密钥 → HKDF-SHA256 → AES-256 传输密钥。
pub struct SessionKeys;

impl SessionKeys {
    pub fn derive_transport_key(
        ecdh_secret: &[u8],
        info: &[u8],
        salt: &[u8],
    ) -> Result<[u8; 32], String> {
        let hk = Hkdf::<Sha256>::new(Some(salt), ecdh_secret);
        let mut key = [0u8; 32];
        hk.expand(info, &mut key)
            .map_err(|_| "HKDF 派生失败".to_string())?;
        Ok(key)
    }

    /// 构造确定性、与方向无关的 HKDF info：域分隔 + 字典序较小公钥在前。
    pub fn build_transport_info(static_a: &[u8], static_b: &[u8]) -> Vec<u8> {
        let (first, second) = if compare_bytes(static_a, static_b) <= 0 {
            (static_a, static_b)
        } else {
            (static_b, static_a)
        };
        let mut out = Vec::with_capacity(TRANSPORT_INFO_DOMAIN.len() + 64);
        out.extend_from_slice(TRANSPORT_INFO_DOMAIN);
        out.extend_from_slice(first);
        out.extend_from_slice(second);
        out
    }
}

fn compare_bytes(a: &[u8], b: &[u8]) -> i32 {
    let n = a.len().min(b.len());
    for i in 0..n {
        let d = a[i] as i32 - b[i] as i32;
        if d != 0 {
            return d;
        }
    }
    a.len() as i32 - b.len() as i32
}

/// 生成 n 字节密码学安全随机数（握手 nonce 等）。
pub fn secure_random(n: usize) -> Vec<u8> {
    random_bytes(n)
}

/// 常量时间字节比较。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn device_id_is_sha256_of_pubkey() {
        let id = DeviceIdentity::from_seed([7u8; 32]);
        assert_eq!(id.device_id, sha256_hex(&id.public_key));
        assert_eq!(id.device_id.len(), 64);
        // 确定性：同 seed 同身份
        assert_eq!(DeviceIdentity::from_seed([7u8; 32]).device_id, id.device_id);
    }

    #[test]
    fn sign_and_verify() {
        let id = DeviceIdentity::from_seed([1u8; 32]);
        let sig = id.sign(b"payload");
        assert!(DeviceIdentity::verify(&id.public_key, b"payload", &sig));
        assert!(!DeviceIdentity::verify(&id.public_key, b"other", &sig));
        assert!(!DeviceIdentity::verify(&[0u8; 16], b"payload", &sig));
    }

    #[test]
    fn ecdh_is_symmetric_and_keys_match() {
        let a = EphemeralX25519::generate();
        let b = EphemeralX25519::generate();
        let sa = a.shared_secret(&b.public_key).unwrap();
        let sb = b.shared_secret(&a.public_key).unwrap();
        assert_eq!(sa, sb);

        let pa = [1u8; 32];
        let pb = [2u8; 32];
        let info_ab = SessionKeys::build_transport_info(&pa, &pb);
        let info_ba = SessionKeys::build_transport_info(&pb, &pa);
        assert_eq!(info_ab, info_ba);
        let k1 = SessionKeys::derive_transport_key(&sa, &info_ab, &[]).unwrap();
        let k2 = SessionKeys::derive_transport_key(&sb, &info_ba, &[]).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn persistence_roundtrip() {
        let id = DeviceIdentity::from_seed([9u8; 32]);
        let json = id.to_json();
        let back = DeviceIdentity::from_json(&json).unwrap();
        assert_eq!(back.device_id, id.device_id);
        assert!(DeviceIdentity::from_json("{}").is_err());
    }

    #[test]
    fn fingerprint_format() {
        let id = DeviceIdentity::from_seed([3u8; 32]);
        let fp = id.fingerprint();
        assert_eq!(fp.len(), 9);
        assert_eq!(fp.as_bytes()[4], b' ');
        let _ = base64::engine::general_purpose::STANDARD.encode([0u8; 4]);
    }
}
