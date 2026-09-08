//! 统一消息信封（对应 Dart 版 `message.dart` / `protocol.dart`）。
//!
//! 控制消息为 JSON：`{type, from, to, session, data:{...}, v}`。
//! `v` 为协议版本；主版本不兼容时直接拒绝，不猜测字段含义。

use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// 当前协议版本。
pub const PROTOCOL_VERSION: u32 = 2;
/// 仍可解析的历史版本（不代表可以建立连接）。
pub const LEGACY_VERSIONS: [u32; 1] = [1];

/// 判断对端消息版本是否"可解析"。缺失版本按 v1 处理。
pub fn is_known_message_version(raw: Option<u32>) -> bool {
    match raw {
        None => true,
        Some(v) => v == PROTOCOL_VERSION || LEGACY_VERSIONS.contains(&v),
    }
}

/// 判断对端是否满足建立 v2 安全连接的版本要求。
pub fn is_connection_version_supported(version: Option<u32>) -> bool {
    version == Some(PROTOCOL_VERSION)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Hello,
    AuthChallenge,
    AuthResponse,
    FileRequest,
    FileAccept,
    FileReject,
    FileResume,
    FileComplete,
    Error,
    Ping,
    Pong,
    Unknown,
}

impl MessageType {
    pub fn name(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::AuthChallenge => "authChallenge",
            Self::AuthResponse => "authResponse",
            Self::FileRequest => "fileRequest",
            Self::FileAccept => "fileAccept",
            Self::FileReject => "fileReject",
            Self::FileResume => "fileResume",
            Self::FileComplete => "fileComplete",
            Self::Error => "error",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(raw: Option<&str>) -> Self {
        match raw {
            Some("hello") => Self::Hello,
            Some("authChallenge") => Self::AuthChallenge,
            Some("authResponse") => Self::AuthResponse,
            Some("fileRequest") => Self::FileRequest,
            Some("fileAccept") => Self::FileAccept,
            Some("fileReject") => Self::FileReject,
            Some("fileResume") => Self::FileResume,
            Some("fileComplete") => Self::FileComplete,
            Some("error") => Self::Error,
            Some("ping") => Self::Ping,
            Some("pong") => Self::Pong,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub kind: MessageType,
    pub from_id: String,
    pub to_id: String,
    pub session_id: String,
    pub data: Map<String, Value>,
    pub version: u32,
}

impl Message {
    pub fn new(kind: MessageType) -> Self {
        Self {
            kind,
            from_id: String::new(),
            to_id: String::new(),
            session_id: String::new(),
            data: Map::new(),
            version: PROTOCOL_VERSION,
        }
    }

    /// 从 JSON 字节流解码；版本不可识别或类型未知一律返回 `None`。
    pub fn decode_bytes(bytes: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(bytes).ok()?;
        Self::decode(s)
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(raw).ok()?;
        let map = value.as_object()?;

        let version = match map.get("v") {
            None => 1,
            Some(Value::Number(n)) => n.as_u64()? as u32,
            Some(_) => return None,
        };
        if !is_known_message_version(Some(version)) {
            return None;
        }
        let kind = MessageType::parse(map.get("type").and_then(|v| v.as_str()));
        if kind == MessageType::Unknown {
            return None;
        }
        // 兼顾历史键名（fromId / toIdId / sessionId）。
        let str_field = |keys: [&str; 2]| -> String {
            keys.iter()
                .find_map(|k| map.get(*k).and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string()
        };
        let data = match map.get("data") {
            Some(Value::Object(o)) => o.clone(),
            _ => Map::new(),
        };
        Some(Self {
            kind,
            from_id: str_field(["from", "fromId"]),
            to_id: str_field(["to", "toIdId"]),
            session_id: str_field(["session", "sessionId"]),
            data,
            version,
        })
    }
}

impl Serialize for Message {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(6))?;
        m.serialize_entry("type", self.kind.name())?;
        m.serialize_entry("from", &self.from_id)?;
        m.serialize_entry("to", &self.to_id)?;
        m.serialize_entry("session", &self.session_id)?;
        m.serialize_entry("data", &self.data)?;
        m.serialize_entry("v", &self.version)?;
        m.end()
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Message::decode(&s).ok_or_else(|| serde::de::Error::custom("非法消息"))
    }
}

/// 便捷取值：从 data 里取字符串。
pub fn data_str<'a>(m: &'a Message, key: &str) -> Option<&'a str> {
    m.data.get(key).and_then(|v| v.as_str())
}

pub fn data_u64(m: &Message, key: &str) -> Option<u64> {
    m.data.get(key).and_then(|v| v.as_u64())
}

pub fn data_bool(m: &Message, key: &str) -> Option<bool> {
    m.data.get(key).and_then(|v| v.as_bool())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_json_shape() {
        let mut m = Message::new(MessageType::FileRequest);
        m.from_id = "a".into();
        m.to_id = "b".into();
        m.data.insert("name".into(), Value::String("x.txt".into()));
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"type\":\"fileRequest\""));
        assert!(json.contains("\"v\":2"));
        let back = Message::decode(&json).unwrap();
        assert_eq!(back.kind, MessageType::FileRequest);
        assert_eq!(data_str(&back, "name"), Some("x.txt"));
    }

    #[test]
    fn legacy_keys_and_unknown_version() {
        let raw = r#"{"type":"ping","fromId":"a","toIdId":"b","sessionId":"s","data":{}}"#;
        let m = Message::decode(raw).unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.from_id, "a");
        assert_eq!(m.to_id, "b");
        assert!(Message::decode(r#"{"type":"ping","v":9}"#).is_none());
        assert!(!is_connection_version_supported(Some(1)));
        assert!(is_connection_version_supported(Some(2)));
    }
}
