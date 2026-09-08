//! 设备信息（PeerInfo）与其编解码（对应 Dart 版 `peer_info.dart` / `peer_info_codec.dart`）。
//!
//! JSON 广播**绝不携带 encryptKey**；配对文本才带内容加密口令。

use serde::{Deserialize, Serialize};

use super::limits::{MAX_PEER_NAME_LENGTH, MAX_PASSPHRASE_LENGTH};

/// 一次设备发现的完整信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
    #[serde(default = "default_device_type")]
    pub device_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// 本机 UDP 端口（发现/打洞/数据共用，默认 45678）。旧设备无此字段时回退默认值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_device_id: Option<String>,
    /// 仅配对码文本会带内容加密口令；JSON 广播不写此字段。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypt_key: Option<String>,
    /// Ed25519 身份公钥（base64），广播键名 `idk`。
    #[serde(default, rename = "idk", skip_serializing_if = "Option::is_none")]
    pub identity_pub_key: Option<String>,
    /// Unix 毫秒时间戳。
    #[serde(default)]
    pub last_seen: i64,
}

fn default_device_type() -> String {
    "unknown".into()
}

impl PeerInfo {
    pub fn new(id: &str, name: &str, ip: &str, port: u16) -> Self {
        Self {
            id: id.into(),
            name: name.chars().take(MAX_PEER_NAME_LENGTH).collect(),
            ip: ip.into(),
            port,
            device_type: default_device_type(),
            public_ip: None,
            public_port: None,
            udp_port: None,
            ipv6: None,
            relay_uri: None,
            relay_device_id: None,
            encrypt_key: None,
            identity_pub_key: None,
            last_seen: now_ms(),
        }
    }

    /// 链式设置 UDP 端口（广播 / 主动打洞目标端口）。
    pub fn with_udp_port(mut self, port: u16) -> Self {
        self.udp_port = Some(port);
        self
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------- 广播 JSON

/// 编码为局域网广播 JSON（**不含** encryptKey）。
pub fn encode_json(peer: &PeerInfo) -> String {
    let mut p = peer.clone();
    p.encrypt_key = None;
    serde_json::to_string(&p).unwrap_or_default()
}

pub fn decode_json(raw: &str) -> Option<PeerInfo> {
    let mut p: PeerInfo = serde_json::from_str(raw).ok()?;
    if p.id.is_empty() || p.name.is_empty() || p.ip.is_empty() {
        return None;
    }
    p.name.truncate(MAX_PEER_NAME_LENGTH);
    if let Some(k) = &p.encrypt_key {
        if k.len() > MAX_PASSPHRASE_LENGTH {
            p.encrypt_key = None;
        }
    }
    Some(p)
}

// ---------------------------------------------------------------- 配对文本

const PAIR_HEADER: &str = "TwinStar-Pair:";

/// 编码为可复制粘贴的配对文本（v2 头部，携带 `idk`）。
pub fn encode_text(peer: &PeerInfo, encrypt_key: Option<&str>) -> String {
    let mut s = String::from("TwinStar-Pair:2\n");
    let mut line = |k: &str, v: String| {
        if !v.is_empty() {
            s.push_str(&format!("{}={}\n", k, v));
        }
    };
    line("id", peer.id.clone());
    line("name", peer.name.clone());
    line("ip", peer.ip.clone());
    line("port", peer.port.to_string());
    line("deviceType", peer.device_type.clone());
    line("idk", peer.identity_pub_key.clone().unwrap_or_default());
    line("publicIp", peer.public_ip.clone().unwrap_or_default());
    line(
        "publicPort",
        peer.public_port.map(|p| p.to_string()).unwrap_or_default(),
    );
    line("udpPort", peer.udp_port.map(|p| p.to_string()).unwrap_or_default());
    line("ipv6", peer.ipv6.clone().unwrap_or_default());
    line("relayUri", peer.relay_uri.clone().unwrap_or_default());
    line(
        "relayDeviceId",
        peer.relay_device_id.clone().unwrap_or_default(),
    );
    if let Some(k) = encrypt_key {
        if !k.is_empty() {
            line("encryptKey", k.to_string());
        }
    }
    s
}

/// 从配对文本解码；兼容 v1/v2 头部（v1 无身份公钥，无法通过 v2 认证）。
pub fn decode_text(raw: &str) -> Option<PeerInfo> {
    let mut lines = raw.lines();
    let first = lines.next()?.trim();
    if !first.starts_with(PAIR_HEADER) {
        return None;
    }
    let mut map = std::collections::HashMap::new();
    for line in lines {
        if let Some(idx) = line.find('=') {
            if idx == 0 {
                continue;
            }
            let k = line[..idx].trim();
            let v = line[idx + 1..].trim();
            if !k.is_empty() && !v.is_empty() {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    let port: u16 = map.get("port")?.parse().ok()?;
    Some(PeerInfo {
        id: map.get("id").cloned().unwrap_or_default(),
        name: map.get("name").cloned().unwrap_or_default(),
        ip: map.get("ip").cloned().unwrap_or_default(),
        port,
        device_type: map
            .get("deviceType")
            .cloned()
            .unwrap_or_else(default_device_type),
        public_ip: map.get("publicIp").cloned(),
        public_port: map.get("publicPort").and_then(|v| v.parse().ok()),
        udp_port: map.get("udpPort").and_then(|v| v.parse().ok()),
        ipv6: map.get("ipv6").cloned(),
        relay_uri: map.get("relayUri").cloned(),
        relay_device_id: map.get("relayDeviceId").cloned(),
        encrypt_key: map.get("encryptKey").cloned(),
        identity_pub_key: map.get("idk").cloned(),
        last_seen: now_ms(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_hides_encrypt_key() {
        let mut p = PeerInfo::new("dev-1", "笔记本", "192.168.1.9", 45679);
        p.encrypt_key = Some("secret".into());
        let json = encode_json(&p);
        assert!(!json.contains("secret"));
        let back = decode_json(&json).unwrap();
        assert_eq!(back.port, 45679);
        assert!(back.encrypt_key.is_none());
    }

    #[test]
    fn pair_text_roundtrip() {
        let mut p = PeerInfo::new("dev-1", "PC", "10.0.0.2", 45679);
        p.identity_pub_key = Some("AAAA".into());
        let text = encode_text(&p, Some("K7mP-2xQw"));
        assert!(text.starts_with("TwinStar-Pair:2"));
        let back = decode_text(&text).unwrap();
        assert_eq!(back.encrypt_key.as_deref(), Some("K7mP-2xQw"));
        assert_eq!(back.identity_pub_key.as_deref(), Some("AAAA"));
        assert!(decode_text("not a pair code").is_none());
    }
}
